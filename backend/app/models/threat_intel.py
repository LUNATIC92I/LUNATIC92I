"""Threat intelligence storage (postgresql_schema.sql §6).

`tenant_id` is nullable here, and that is a deliberate difference from
detection rules (where it is NOT NULL). A detection rule is a judgement the
tenant tunes; an indicator is a claim about the outside world, and a feed of
a million indicators duplicated per tenant is neither affordable nor
meaningful. So a NULL tenant means "shared/global feed indicator": every
tenant can read it, no tenant can write it, and a tenant's own indicators
sit alongside carrying their tenant id.

The RLS policy therefore reads global rows but only accepts writes stamped
with the caller's own tenant — the feed sync path writes global rows through
a session with no tenant context, which is the only writer that can.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

# The ten types spec §11 requires.
IOC_TYPES = (
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
    "email",
    "asn",
    "certificate",
)
CLASSIFICATIONS = ("malicious", "suspicious", "benign", "unknown")


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "ioc_type", "value", "source", name="uq_iocs_identity"),
        CheckConstraint(f"ioc_type IN {IOC_TYPES}", name="ck_iocs_type"),
        CheckConstraint(f"classification IN {CLASSIFICATIONS}", name="ck_iocs_classification"),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="ck_iocs_confidence"),
        # Spec §11's hard rule, enforced by the database and not only by the
        # service layer: nothing may be recorded as malicious or suspicious
        # without naming where that claim came from.
        CheckConstraint(
            "classification IN ('unknown','benign') OR length(trim(source)) > 0",
            name="ck_iocs_source_required",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # NULL = shared/global feed indicator (see the module docstring).
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # Stored canonicalized (lowercased, refanged) by
    # app/threat_intel/normalize.py — an indicator that only matches when
    # the case happens to line up is worse than no indicator.
    value: Mapped[str] = mapped_column(Text, nullable=False)
    classification: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    source: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # An indicator with no expiry is a permanent claim about the world, which
    # is almost never true; the API defaults one for feed-sourced rows.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IocHistory(Base):
    """Per-field change history.

    Confidence and classification are the fields that decide whether an
    alert fires and how hard; "who downgraded this indicator to benign, and
    when" has to be answerable months later, so changes are appended here
    field by field rather than reconstructed from an audit diff.
    """

    __tablename__ = "ioc_history"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False
    )
    # Denormalized so the RLS policy on this table is the same simple
    # predicate as everywhere else instead of a join to the parent.
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    changed_field: Mapped[str] = mapped_column(String(64), nullable=False)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    changed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IocFeed(Base):
    """A configured intelligence source.

    `config` holds non-secret configuration only. Credentials are referenced
    by name (`credential_ref`) and resolved from the environment/secrets
    manager at sync time — a feed API key sitting in a JSONB column would be
    readable by anyone with database access and would end up in backups
    (spec §27).
    """

    __tablename__ = "ioc_feeds"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_ioc_feeds_tenant_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(64), nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    credential_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
