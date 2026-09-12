import uuid
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


async def record_audit_event(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    action: str,
    object_type: str,
    result: Literal["success", "failure"],
    actor_id: uuid.UUID | None = None,
    actor_ip: str | None = None,
    user_agent: str | None = None,
    object_id: str | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
) -> None:
    """Writes one audit log row on the caller's existing session/transaction
    — it does not commit. Callers commit as part of their own unit of work
    so an audit entry and the action it describes land atomically together.
    """
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_ip=actor_ip,
            user_agent=user_agent,
            action=action,
            object_type=object_type,
            object_id=object_id,
            before_state=before_state,
            after_state=after_state,
            result=result,
        )
    )
