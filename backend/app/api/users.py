from fastapi import APIRouter, Depends
from sqlalchemy import select

from app.auth.dependencies import AuthContext, get_auth_context, require_permission
from app.models.identity import Role, User, UserRole
from app.schemas.auth import MeResponse
from app.schemas.users import UserPublic

router = APIRouter(tags=["users"])


async def _roles_for_user(ctx: AuthContext, user_id: str) -> list[str]:
    stmt = (
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    return [name for (name,) in (await ctx.db.execute(stmt)).all()]


@router.get("/users/me", response_model=MeResponse)
async def get_me(ctx: AuthContext = Depends(get_auth_context)) -> MeResponse:
    roles = await _roles_for_user(ctx, str(ctx.user.id))
    return MeResponse(
        id=str(ctx.user.id),
        email=ctx.user.email,
        full_name=ctx.user.full_name,
        tenant_id=str(ctx.user.tenant_id),
        roles=roles,
        permissions=[f"{resource}:{action}" for resource, action in sorted(ctx.user.permissions)],
    )


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
        roles = await _roles_for_user(ctx, str(user.id))
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
