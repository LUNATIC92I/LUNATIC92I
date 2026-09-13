"""The audit log, read-only (spec §23's Audit screen; THREAT_MODEL.md §3.7).

Every other phase has written to `audit_logs`; nothing before this exposed
it. The table is append-only at the database level (a trigger, not just
convention — see the migration that creates it), so this endpoint is
strictly read-only by construction as well as by not defining a write.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.auth.dependencies import AuthContext, require_permission
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogPublic

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogPublic])
async def list_audit_log(
    action: str | None = Query(default=None, max_length=100),
    object_type: str | None = Query(default=None, max_length=100),
    since: datetime | None = Query(default=None),  # noqa: B008 - fastapi's own documented pattern
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_permission("audit", "read")),
) -> list[AuditLogPublic]:
    # ctx.db is tenant-scoped (RLS), so this can only ever return this
    # tenant's own entries regardless of what's asked for.
    stmt = select(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(limit).offset(offset)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if object_type:
        stmt = stmt.where(AuditLog.object_type == object_type)
    if since:
        stmt = stmt.where(AuditLog.occurred_at >= since)

    rows = (await ctx.db.execute(stmt)).scalars().all()
    return [
        AuditLogPublic(
            id=str(row.id),
            actor_id=str(row.actor_id) if row.actor_id else None,
            actor_ip=str(row.actor_ip) if row.actor_ip else None,
            user_agent=row.user_agent,
            action=row.action,
            object_type=row.object_type,
            object_id=row.object_id,
            before_state=row.before_state,
            after_state=row.after_state,
            result=row.result,
            occurred_at=row.occurred_at,
        )
        for row in rows
    ]
