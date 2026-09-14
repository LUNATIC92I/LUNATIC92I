import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.auth.dependencies import AuthContext, get_auth_context
from app.core.config import get_settings
from app.core.metrics import auth_rate_limited_total
from app.core.redis import get_redis
from app.models.identity import User
from app.schemas.auth import (
    AccessTokenResponse,
    LoginRequest,
    MfaEnrollResponse,
    MfaVerifyRequest,
    RegisterOrganizationRequest,
    RegisterOrganizationResponse,
)
from app.services import auth as auth_service

router = APIRouter(prefix="/auth", tags=["auth"])

_REFRESH_COOKIE_NAME = "refresh_token"
_REFRESH_COOKIE_PATH = "/auth"


async def _enforce_ip_rate_limit(
    request: Request, *, action: str, limit: int, window_seconds: int
) -> None:
    """A second, independent control on top of per-account lockout (OWASP
    ASVS V2.2.1): lockout alone does nothing about a low-and-slow spray
    across many different accounts, or a flood of organization
    registrations, from one source. Fixed-window per-IP counter, the same
    shape as the ingestion and hunt-export rate limiters.

    A request with no client IP (only possible from a non-HTTP test
    transport) is allowed through rather than guessed at — there is no
    real deployment where a request reaches this API without one."""
    if request.client is None:
        return
    redis = get_redis()
    window = int(time.time() // window_seconds)
    key = f"auth:ratelimit:{action}:{request.client.host}:{window}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window_seconds)
    if count > limit:
        auth_rate_limited_total.labels(action=action).inc()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many requests")


def _set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=token,
        max_age=settings.jwt_refresh_token_ttl_seconds,
        path=_REFRESH_COOKIE_PATH,
        httponly=True,
        secure=settings.is_production,
        samesite="strict",
    )


@router.post(
    "/register-organization",
    response_model=RegisterOrganizationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_organization(
    payload: RegisterOrganizationRequest, request: Request
) -> RegisterOrganizationResponse:
    settings = get_settings()
    await _enforce_ip_rate_limit(
        request,
        action="register",
        limit=settings.auth_register_rate_limit_per_hour,
        window_seconds=3600,
    )
    try:
        org, user = await auth_service.register_organization(
            organization_name=payload.organization_name,
            organization_slug=payload.organization_slug,
            admin_email=payload.admin_email,
            admin_password=payload.admin_password,
            admin_full_name=payload.admin_full_name,
        )
    except auth_service.OrganizationSlugTakenError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "organization slug already taken") from exc

    return RegisterOrganizationResponse(
        organization_id=str(org.id), organization_slug=org.slug, user_id=str(user.id)
    )


@router.post("/login", response_model=AccessTokenResponse)
async def login(payload: LoginRequest, request: Request, response: Response) -> AccessTokenResponse:
    settings = get_settings()
    await _enforce_ip_rate_limit(
        request,
        action="login",
        limit=settings.auth_login_rate_limit_per_minute,
        window_seconds=60,
    )
    try:
        access_token, refresh_token = await auth_service.authenticate(
            organization_slug=payload.organization_slug,
            email=payload.email,
            password=payload.password,
            mfa_code=payload.mfa_code,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except auth_service.AccountLockedError as exc:
        raise HTTPException(
            status.HTTP_423_LOCKED,
            "account temporarily locked due to repeated failed logins",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except auth_service.MfaRequiredError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, {"message": "mfa code required", "mfa_required": True}
        ) from exc
    except (auth_service.InvalidCredentialsError, auth_service.MfaInvalidError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials") from exc

    _set_refresh_cookie(response, refresh_token)
    return AccessTokenResponse(
        access_token=access_token, expires_in=settings.jwt_access_token_ttl_seconds
    )


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh(request: Request, response: Response) -> AccessTokenResponse:
    settings = get_settings()
    await _enforce_ip_rate_limit(
        request,
        action="refresh",
        limit=settings.auth_refresh_rate_limit_per_minute,
        window_seconds=60,
    )
    refresh_token = request.cookies.get(_REFRESH_COOKIE_NAME)
    if refresh_token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing refresh token")

    try:
        access_token, new_refresh_token = await auth_service.rotate_refresh_token(
            refresh_token,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )
    except auth_service.InvalidCredentialsError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "invalid or expired refresh token"
        ) from exc

    _set_refresh_cookie(response, new_refresh_token)
    return AccessTokenResponse(
        access_token=access_token, expires_in=settings.jwt_access_token_ttl_seconds
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response) -> None:
    refresh_token = request.cookies.get(_REFRESH_COOKIE_NAME)
    if refresh_token is not None:
        await auth_service.revoke_session(refresh_token)
    response.delete_cookie(_REFRESH_COOKIE_NAME, path=_REFRESH_COOKIE_PATH)


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(ctx: AuthContext = Depends(get_auth_context)) -> MfaEnrollResponse:
    user = await ctx.db.get(User, ctx.user.id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    secret, provisioning_uri = await auth_service.enroll_mfa(ctx.db, user)
    return MfaEnrollResponse(secret=secret, provisioning_uri=provisioning_uri)


@router.post("/mfa/verify", status_code=status.HTTP_204_NO_CONTENT)
async def mfa_verify(
    payload: MfaVerifyRequest, ctx: AuthContext = Depends(get_auth_context)
) -> None:
    user = await ctx.db.get(User, ctx.user.id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    try:
        await auth_service.confirm_mfa(ctx.db, user, payload.code)
    except auth_service.MfaInvalidError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid mfa code") from exc
