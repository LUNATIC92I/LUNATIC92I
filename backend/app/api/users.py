import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from app.auth.dependencies import AuthContext, get_auth_context, require_permission
from app.models.identity import ROLE_NAMES, User
from app.schemas.auth import MeResponse
from app.schemas.users import RoleCatalogResponse, UserCreate, UserPublic, UserUpdate
from app.services import users as service

router = APIRouter(tags=["users"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _user_uuid(user_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(user_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found") from exc


@router.get("/users/me", response_model=MeResponse)
async def get_me(ctx: AuthContext = Depends(get_auth_context)) -> MeResponse:
    roles = await service.roles_for(ctx.db, ctx.user.id)
    return MeResponse(
        id=str(ctx.user.id),
        email=ctx.user.email,
        full_name=ctx.user.full_name,
        tenant_id=str(ctx.user.tenant_id),
        roles=roles,
        permissions=[f"{resource}:{action}" for resource, action in sorted(ctx.user.permissions)],
    )


@router.get("/users/roles", response_model=RoleCatalogResponse)
async def list_role_catalog(
    ctx: AuthContext = Depends(require_permission("user", "read")),
) -> RoleCatalogResponse:
    return RoleCatalogResponse(roles=list(ROLE_NAMES))


@router.get("/users", response_model=list[UserPublic])
async def list_users(
    ctx: AuthContext = Depends(require_permission("user", "read")),
) -> list[UserPublic]:
    # ctx.db is already scoped to ctx.user.tenant_id (ARCHITECTURE.md §1 row
    # 3) — this SELECT can only ever return rows RLS allows, so it needs no
    # explicit tenant_id filter to be safe, but omitting one entirely would
    # be fragile against future refactors, so it's included as a second,
    # redundant layer matching THREAT_MODEL.md §3.2's defense-in-depth.
    users = (
        await ctx.db.execute(select(User).where(User.tenant_id == ctx.user.tenant_id))
    ).scalars().all()

    result = []
    for user in users:
        roles = await service.roles_for(ctx.db, user.id)
        result.append(
            UserPublic(
                id=str(user.id),
                email=user.email,
                full_name=user.full_name,
                is_active=user.is_active,
                mfa_enabled=user.mfa_enabled,
                roles=roles,
            )
        )
    return result


@router.post("/users", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("user", "write")),
) -> UserPublic:
    try:
        user, roles = await service.create_user(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            email=payload.email,
            full_name=payload.full_name,
            password=payload.password,
            role=payload.role,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.DuplicateEmail as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "a user with this email already exists"
        ) from exc
    await ctx.db.commit()
    return UserPublic(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        roles=roles,
    )


@router.patch("/users/{user_id}", response_model=UserPublic)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("user", "write")),
) -> UserPublic:
    if payload.is_active is None and payload.role is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "nothing to update")
    try:
        user, roles = await service.update_user(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            user_id=_user_uuid(user_id),
            is_active=payload.is_active,
            role=payload.role,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.UserNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found") from exc
    await ctx.db.commit()
    return UserPublic(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        mfa_enabled=user.mfa_enabled,
        roles=roles,
    )
