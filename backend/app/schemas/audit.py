"""Audit log read API schemas (Administration/Audit screen, spec §23)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AuditLogPublic(BaseModel):
    id: str
    actor_id: str | None
    actor_ip: str | None
    user_agent: str | None
    action: str
    object_type: str
    object_id: str | None
    before_state: dict[str, Any] | None
    after_state: dict[str, Any] | None
    result: str
    occurred_at: datetime
