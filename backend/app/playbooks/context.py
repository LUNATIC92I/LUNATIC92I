"""What an action sees while it runs."""

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alerts import Alert
from app.models.incidents import Incident


@dataclass
class PlaybookContext:
    db: AsyncSession
    tenant_id: uuid.UUID
    # Whoever triggered the run — every audit entry an action writes
    # attributes to this id, never to a service account.
    actor_id: uuid.UUID | None
    alert: Alert | None = None
    incident: Incident | None = None
    # This step's own params, from the playbook definition.
    params: dict[str, Any] = field(default_factory=dict)
    # Prior steps' results, keyed by action name — how "enrich_ip" hands
    # its findings to "calculate_reputation" without a templating language.
    state: dict[str, Any] = field(default_factory=dict)
