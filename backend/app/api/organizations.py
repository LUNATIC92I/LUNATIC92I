from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import AuthContext, require_permission
from app.models.identity import Organization
from app.schemas.organizations import OrganizationPublic

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.get("/me", response_model=OrganizationPublic)
async def get_my_organization(
    ctx: AuthContext = Depends(require_permission("organization", "read")),
) -> OrganizationPublic:
    # `organizations` intentionally carries no Row-Level Security policy —
    # unlike every other tenant-scoped table, a row in this table IS a
    # tenant, and resolving *which* tenant a request belongs to (at
    # registration and at login, before any JWT/GUC exists) necessarily
    # requires reading it before any tenant scope can be established. RLS
    # there would make bootstrapping and login impossible, not just
    # inconvenient. The tenant-isolation guarantee for this one table comes
    # entirely from application code always filtering by the
    # server-derived `ctx.user.tenant_id` — never a client-supplied id — so
    # this WHERE clause is not optional defense-in-depth, it is the only
    # defense. See THREAT_MODEL.md §3.2.
    org = await ctx.db.get(Organization, ctx.user.tenant_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    return OrganizationPublic(id=str(org.id), name=org.name, slug=org.slug, is_active=org.is_active)
