"""Saved hunts (spec §15, postgresql_schema.sql §9).

A saved hunt stores the **analyst-facing query**, not compiled OpenSearch
DSL. The draft schema names the column `query_dsl` and describes it as "an
OpenSearch query representation"; this deliberately stores the same
`HuntQuery` shape the search API accepts instead (filters, free text, time
range) — the compiler that turns it into Lucene lives in one place
(`app/hunting/query.py`) and can change without a migration or a
re-save-every-hunt maintenance chore. It also means a saved hunt is
re-validated against the current field allowlist every time it runs, so a
field that stopped existing does not silently start matching nothing.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class SavedHunt(Base):
    __tablename__ = "saved_hunts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The HuntQuery request body (schemas/hunting.py), as submitted — see
    # the module docstring for why this is the analyst-facing shape rather
    # than compiled Lucene.
    query: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
