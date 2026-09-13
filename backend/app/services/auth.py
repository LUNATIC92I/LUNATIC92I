import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.core.config import get_settings
from app.core.db import async_session_factory, tenant_scoped_session
from app.core.security import (
    create_access_token,
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    generate_refresh_token,
    generate_totp_secret,
    hash_password,
    hash_refresh_token,
    parse_refresh_token_tenant_id,
    totp_provisioning_uri,
    verify_password,
    verify_totp_code,
)
from app.models.identity import Organization, Role, User, UserRole
from app.models.identity import Session as SessionModel

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Base class for auth-flow errors the API layer maps to HTTP responses."""


class InvalidCredentialsError(AuthError):
    pass


class AccountLockedError(AuthError):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__("account locked")
        self.retry_after_seconds = retry_after_seconds


class MfaRequiredError(AuthError):
    pass


class MfaInvalidError(AuthError):
    pass


class OrganizationSlugTakenError(AuthError):
    pass


async def register_organization(
    *,
    organization_name: str,
    organization_slug: str,
    admin_email: str,
    admin_password: str,
    admin_full_name: str,
) -> tuple[Organization, User]:
    """Bootstraps a brand-new tenant: creates the organization (its own
    transaction, since `organizations` carries no RLS) and, once that has
    committed and is visible to other connections, creates its first
    ORG_ADMIN user in a tenant-scoped transaction. These are deliberately
    two separate commits, not a single distributed transaction — a second
    connection cannot satisfy the `users.tenant_id` foreign key against an
    uncommitted `organizations` row. A failure between the two steps leaves
    an organization with no admin user; acceptable for this bootstrap-only
    flow and noted as follow-up hardening rather than solved here.
    """
    async with async_session_factory() as db:
        existing = await db.scalar(
            select(Organization).where(Organization.slug == organization_slug)
        )
        if existing is not None:
            raise OrganizationSlugTakenError(organization_slug)

        org = Organization(name=organization_name, slug=organization_slug)
        db.add(org)
        await db.commit()

    async with tenant_scoped_session(org.id) as db:
        admin_role = await db.scalar(select(Role).where(Role.name == "ORG_ADMIN"))
        if admin_role is None:
            raise RuntimeError("ORG_ADMIN role missing — RBAC seed migration did not run")

        user = User(
            tenant_id=org.id,
            email=admin_email,
            password_hash=hash_password(admin_password),
            full_name=admin_full_name,
        )
        db.add(user)
        await db.flush()
        db.add(UserRole(user_id=user.id, role_id=admin_role.id, tenant_id=org.id))
        await record_audit_event(
            db,
            tenant_id=org.id,
            actor_id=user.id,
            action="CREATE_USER",
            object_type="user",
            object_id=str(user.id),
            result="success",
            after_state={"email": admin_email, "role": "ORG_ADMIN"},
        )
        await _install_default_detection_rules(db, org.id, user.id)
        await _install_default_playbooks(db, org.id, user.id)
        await db.commit()

    return org, user


async def _install_default_detection_rules(
    db: AsyncSession, tenant_id: uuid.UUID, actor_id: uuid.UUID
) -> None:
    """A tenant with no detections is a tenant that sees nothing, so the
    shipped rule pack is installed at registration rather than left as a
    setup step someone has to remember. It is best-effort on purpose: a
    missing or unreadable rules directory must not make it impossible to
    create an organization, and the failure is loud in the logs and
    recoverable through POST /rules/install-defaults."""
    from app.services.detection_rules import install_default_rules

    try:
        await install_default_rules(db, tenant_id=tenant_id, actor_id=actor_id)
    except Exception:  # noqa: BLE001  never block tenant creation on this
        logger.exception(
            "default detection rules were not installed for the new tenant",
            extra={"tenant_id": str(tenant_id)},
        )


async def _install_default_playbooks(
    db: AsyncSession, tenant_id: uuid.UUID, actor_id: uuid.UUID
) -> None:
    """Same reasoning and the same best-effort shape as the detection rule
    pack above: recoverable through POST /playbooks/install-defaults."""
    from app.services.playbooks import install_default_playbooks

    try:
        await install_default_playbooks(db, tenant_id=tenant_id, actor_id=actor_id)
    except Exception:  # noqa: BLE001  never block tenant creation on this
        logger.exception(
            "default playbooks were not installed for the new tenant",
            extra={"tenant_id": str(tenant_id)},
        )


async def authenticate(
    *,
    organization_slug: str,
    email: str,
    password: str,
    mfa_code: str | None,
    ip: str | None,
    user_agent: str | None,
) -> tuple[str, str]:
    """Returns (access_token, refresh_token) on success. Deliberately raises
    the same InvalidCredentialsError whether the organization, the email, or
    the password was wrong — an attacker must not be able to enumerate
    valid organizations or accounts from the error alone."""
    settings = get_settings()

    async with async_session_factory() as db:
        org = await db.scalar(select(Organization).where(Organization.slug == organization_slug))
    if org is None:
        raise InvalidCredentialsError()

    async with tenant_scoped_session(org.id) as db:
        user = await db.scalar(
            select(User).where(User.tenant_id == org.id, User.email == email)
        )
        if user is None:
            raise InvalidCredentialsError()

        now = datetime.now(UTC)
        if user.locked_until is not None and user.locked_until > now:
            raise AccountLockedError(int((user.locked_until - now).total_seconds()))

        if not verify_password(user.password_hash, password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_failed_login_attempts:
                user.locked_until = now + timedelta(minutes=settings.lockout_duration_minutes)
                user.failed_login_attempts = 0
            await record_audit_event(
                db, tenant_id=org.id, actor_id=user.id, action="FAILED_LOGIN",
                object_type="user", object_id=str(user.id), result="failure",
                actor_ip=ip, user_agent=user_agent,
            )
            await db.commit()
            raise InvalidCredentialsError()

        if user.mfa_enabled:
            if mfa_code is None:
                raise MfaRequiredError()
            secret = decrypt_mfa_secret(user.mfa_secret_enc) if user.mfa_secret_enc else None
            if secret is None or not verify_totp_code(secret=secret, code=mfa_code):
                await record_audit_event(
                    db, tenant_id=org.id, actor_id=user.id, action="FAILED_LOGIN",
                    object_type="user", object_id=str(user.id), result="failure",
                    actor_ip=ip, user_agent=user_agent,
                )
                await db.commit()
                raise MfaInvalidError()

        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now

        access_token = create_access_token(user_id=user.id, tenant_id=org.id)
        refresh_token = generate_refresh_token(org.id)
        db.add(
            SessionModel(
                user_id=user.id,
                tenant_id=org.id,
                refresh_token_hash=hash_refresh_token(refresh_token),
                user_agent=user_agent,
                ip_address=ip,
                expires_at=now + timedelta(seconds=settings.jwt_refresh_token_ttl_seconds),
            )
        )
        await record_audit_event(
            db, tenant_id=org.id, actor_id=user.id, action="LOGIN",
            object_type="user", object_id=str(user.id), result="success",
            actor_ip=ip, user_agent=user_agent,
        )
        await db.commit()
        return access_token, refresh_token


async def rotate_refresh_token(
    refresh_token: str, *, ip: str | None, user_agent: str | None
) -> tuple[str, str]:
    """Rotates a refresh token: the old session row is revoked and a new
    one issued. A revoked or expired token is rejected outright — reusing
    an already-rotated token does not silently succeed."""
    try:
        tenant_id = parse_refresh_token_tenant_id(refresh_token)
    except ValueError as exc:
        raise InvalidCredentialsError() from exc

    token_hash = hash_refresh_token(refresh_token)
    settings = get_settings()

    async with tenant_scoped_session(tenant_id) as db:
        now = datetime.now(UTC)
        session_row = await db.scalar(
            select(SessionModel).where(
                SessionModel.refresh_token_hash == token_hash,
                SessionModel.revoked_at.is_(None),
                SessionModel.expires_at > now,
            )
        )
        if session_row is None:
            raise InvalidCredentialsError()

        user = await db.get(User, session_row.user_id)
        if user is None or not user.is_active:
            raise InvalidCredentialsError()

        session_row.revoked_at = now
        new_refresh_token = generate_refresh_token(tenant_id)
        db.add(
            SessionModel(
                user_id=user.id,
                tenant_id=tenant_id,
                refresh_token_hash=hash_refresh_token(new_refresh_token),
                user_agent=user_agent,
                ip_address=ip,
                expires_at=now + timedelta(seconds=settings.jwt_refresh_token_ttl_seconds),
            )
        )
        access_token = create_access_token(user_id=user.id, tenant_id=tenant_id)
        await db.commit()
        return access_token, new_refresh_token


async def revoke_session(refresh_token: str) -> None:
    try:
        tenant_id = parse_refresh_token_tenant_id(refresh_token)
    except ValueError:
        return

    token_hash = hash_refresh_token(refresh_token)
    async with tenant_scoped_session(tenant_id) as db:
        session_row = await db.scalar(
            select(SessionModel).where(SessionModel.refresh_token_hash == token_hash)
        )
        if session_row is not None and session_row.revoked_at is None:
            session_row.revoked_at = datetime.now(UTC)
            await record_audit_event(
                db, tenant_id=tenant_id, actor_id=session_row.user_id, action="LOGOUT",
                object_type="session", object_id=str(session_row.id), result="success",
            )
            await db.commit()


async def enroll_mfa(db: AsyncSession, user: User) -> tuple[str, str]:
    """Generates a new TOTP secret and stores it encrypted, but leaves
    `mfa_enabled` False until `confirm_mfa` proves the analyst actually has
    it loaded in an authenticator app."""
    secret = generate_totp_secret()
    user.mfa_secret_enc = encrypt_mfa_secret(secret)
    user.mfa_enabled = False
    await db.commit()
    return secret, totp_provisioning_uri(secret=secret, account_email=user.email)


async def confirm_mfa(db: AsyncSession, user: User, code: str) -> None:
    if user.mfa_secret_enc is None:
        raise MfaInvalidError()
    secret = decrypt_mfa_secret(user.mfa_secret_enc)
    if not verify_totp_code(secret=secret, code=code):
        raise MfaInvalidError()
    user.mfa_enabled = True
    await db.commit()
