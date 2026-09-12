import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from dataclasses import dataclass
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import tenant_scoped_session
from app.core.security import decode_access_token
from app.models.identity import Permission, RolePermission, User, UserRole

# auto_error=False so a missing bearer token yields our own 401 rather than
# HTTPBearer's default (and semantically wrong for "not authenticated") 403.
_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthenticatedUser:
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    full_name: str
    permissions: frozenset[tuple[str, str]]

    def has_permission(self, resource: str, action: str) -> bool:
        return (resource, action) in self.permissions


@dataclass(frozen=True)
class AuthContext:
    db: AsyncSession
    user: AuthenticatedUser


async def _load_permissions(db: AsyncSession, user_id: uuid.UUID) -> frozenset[tuple[str, str]]:
    stmt = (
        select(Permission.resource, Permission.action)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id)
    )
    rows = (await db.execute(stmt)).all()
    return frozenset((resource, action) for resource, action in rows)


async def get_auth_context(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AsyncIterator[AuthContext]:
    """Authenticates the bearer token, then yields a DB session already
    scoped to the token's tenant (see `tenant_scoped_session`) together with
    the caller's identity and freshly-loaded permissions. Every route that
    depends on this (directly or via `require_permission`) is therefore
    tenant-scoped by construction — there is no separate opt-in step to
    forget, unlike a standalone `require_tenant_scope()` dependency would be.

    Permissions are recomputed from the database on every single call: a
    role or permission change takes effect on the caller's very next
    request, and nothing about authorization is ever trusted from the token
    itself beyond identity (`sub`) and tenant (`tenant_id`) — both of which
    are meaningless without our signature, unlike a client-supplied header.
    """
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")

    try:
        payload = decode_access_token(credentials.credentials)
        tenant_id = uuid.UUID(payload["tenant_id"])
        user_id = uuid.UUID(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token") from exc

    async with tenant_scoped_session(tenant_id) as db:
        user = await db.get(User, user_id)
        if user is None or not user.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")

        permissions = await _load_permissions(db, user.id)
        yield AuthContext(
            db=db,
            user=AuthenticatedUser(
                id=user.id,
                tenant_id=user.tenant_id,
                email=user.email,
                full_name=user.full_name,
                permissions=permissions,
            ),
        )


def require_permission(
    resource: str, action: str
) -> Callable[[AuthContext], Coroutine[Any, Any, AuthContext]]:
    """Deny-by-default permission gate. Every protected route must depend on
    this (or on `get_auth_context` directly for "any authenticated user, no
    specific permission") — there is no route that skips a check because a
    permission mapping was forgotten (a missing (resource, action) in
    app/auth/permissions.py simply means no role can ever pass this check)."""

    async def _dependency(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not ctx.user.has_permission(resource, action):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient permissions")
        return ctx

    return _dependency
