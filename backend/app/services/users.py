"""User account management (Administration screen, spec §23; the identity
model from Phase 2). Every write here is audit-logged in the same
transaction as the change, matching the pattern already established for
assets and IOCs — who can access the SOC and with what role is exactly the
kind of change a later incident review needs to be able to reconstruct.

A user holds exactly one role in this UI's model of the world. The
underlying join table (`UserRole`) supports many, but nothing in this
codebase assigns more than one to a single user, and giving the
Administration screen a single-role picker keeps "who can do what" legible
at a glance rather than a set an admin has to reason about combinations of.
"""

import uuid

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.core.security import hash_password
from app.models.identity import Role, User, UserRole


class UserNotFound(LookupError):
    pass


class DuplicateEmail(ValueError):
    pass


class InsufficientPrivilege(PermissionError):
    """Raised when an actor without an elevated role tries to grant one.
    `user:write` alone is not enough to hand out `ORG_ADMIN`/`SUPER_ADMIN`
    — otherwise any role holding it (`SOC_MANAGER`) could mint its own
    tenant admin, a vertical privilege escalation `require_permission`'s
    single resource:action check has no way to express (Phase 17,
    OWASP API5:2023 Broken Function Level Authorization)."""


# Roles that can manage the tenant's own user base outright. Granting one
# of these is different in kind from every other role grant: it is
# handing out the ability to grant *any* role, including this one — so
# only an actor who already holds one may do it.
_ELEVATED_ROLES = {"SUPER_ADMIN", "ORG_ADMIN"}


async def roles_for(db: AsyncSession, user_id: uuid.UUID) -> list[str]:
    stmt = (
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    return [name for (name,) in (await db.execute(stmt)).all()]


async def _assert_can_grant_role(
    db: AsyncSession, *, actor_id: uuid.UUID | None, role: str
) -> None:
    if role not in _ELEVATED_ROLES:
        return
    actor_roles = await roles_for(db, actor_id) if actor_id is not None else []
    if not _ELEVATED_ROLES.intersection(actor_roles):
        raise InsufficientPrivilege(f"granting {role} requires an existing org admin")


async def create_user(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    email: str,
    full_name: str,
    password: str,
    role: str,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> tuple[User, list[str]]:
    role_row = await db.scalar(select(Role).where(Role.name == role))
    assert role_row is not None  # nosec B101 - role is validated against ROLE_NAMES by the request schema
    await _assert_can_grant_role(db, actor_id=actor_id, role=role)

    user = User(
        tenant_id=tenant_id,
        email=email,
        password_hash=hash_password(password),
        full_name=full_name,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise DuplicateEmail(email) from exc

    db.add(UserRole(user_id=user.id, role_id=role_row.id, tenant_id=tenant_id))
    await db.flush()
    await db.refresh(user)

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="CREATE_USER",
        object_type="user",
        object_id=str(user.id),
        after_state={"email": email, "role": role},
        result="success",
    )
    return user, [role]


async def update_user(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    is_active: bool | None,
    role: str | None,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> tuple[User, list[str]]:
    user = await db.get(User, user_id)
    if user is None or user.tenant_id != tenant_id:
        raise UserNotFound(str(user_id))

    before = {"is_active": user.is_active, "roles": await roles_for(db, user.id)}

    if is_active is not None:
        user.is_active = is_active
    if role is not None:
        role_row = await db.scalar(select(Role).where(Role.name == role))
        assert role_row is not None  # nosec B101 - role is validated against ROLE_NAMES by the request schema
        await _assert_can_grant_role(db, actor_id=actor_id, role=role)
        await db.execute(delete(UserRole).where(UserRole.user_id == user.id))
        db.add(UserRole(user_id=user.id, role_id=role_row.id, tenant_id=tenant_id))

    await db.flush()
    await db.refresh(user)
    after_roles = await roles_for(db, user.id)

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="UPDATE_USER",
        object_type="user",
        object_id=str(user.id),
        before_state=before,
        after_state={"is_active": user.is_active, "roles": after_roles},
        result="success",
    )
    return user, after_roles
