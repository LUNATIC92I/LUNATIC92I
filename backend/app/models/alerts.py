"""Alerts: the unit of work an analyst actually holds (spec §13).

A detection is a machine statement ("this rule matched"); an alert is a
human one ("somebody needs to look at this, and here is where they got to").
That difference is why alerts live in PostgreSQL with a state machine and an
audit trail, while detections live in the event store as immutable records.

`dedup_key` is what stops the two from being the same thing. A brute-force
rule firing sixty times against one account is one alert with sixty
occurrences, not sixty alerts — alert fatigue is an attack surface
(THREAT_MODEL.md §3.4), and a queue nobody can read is a queue nobody reads.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    SmallInteger,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

ALERT_STATUSES = (
    "NEW",
    "IN_PROGRESS",
    "ESCALATED",
    "FALSE_POSITIVE",
    "RESOLVED",
    "CLOSED",
)
# Terminal in the sense that work has stopped; reopening is an explicit,
# audited act rather than an ordinary transition (see services/alerts.py).
CLOSING_STATUSES = ("FALSE_POSITIVE", "RESOLVED", "CLOSED")

ALERT_SEVERITIES = ("informational", "low", "medium", "high", "critical")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(f"status IN {ALERT_STATUSES}", name="ck_alerts_status"),
        CheckConstraint(f"severity IN {ALERT_SEVERITIES}", name="ck_alerts_severity"),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_alerts_risk"),
        CheckConstraint("confidence BETWEEN 0 AND 100", name="ck_alerts_confidence"),
        CheckConstraint("occurrence_count >= 1", name="ck_alerts_occurrences"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    # Human-facing identifier (ALT-2026-000123). An analyst quoting "the
    # alert about alice" in a ticket needs something shorter than a uuid.
    display_id: Mapped[str] = mapped_column(String(32), nullable=False)

    # What produced it. Nullable because a correlation-sourced alert has no
    # single detection rule, and because a rule can be deleted while its
    # alerts must survive.
    rule_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True
    )
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="detection")

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    risk_bucket: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # Carried from the risk engine so an analyst can see *why* this outranked
    # the alert below it without recomputing anything (spec §10).
    risk_explanation: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )

    # Evidence lineage: the OpenSearch documents behind the alert. Stored by
    # value, never joined — the event store is rebuildable and the alert
    # must survive it being reindexed (ARCHITECTURE.md §1 row 2).
    event_ids: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    detection_ids: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    affected_user: Mapped[str | None] = mapped_column(String(300), nullable=True)
    affected_host: Mapped[str | None] = mapped_column(String(300), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )

    status: Mapped[str] = mapped_column(String(20), nullable=False, default="NEW")
    analyst_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Deduplication. `dedup_key` identifies "the same thing happening again";
    # occurrence_count and last_seen_at record how often and how recently,
    # so a suppressed repeat is still visible rather than discarded.
    dedup_key: Mapped[str] = mapped_column(String(500), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # Triage timing, for the MTTA/MTTR metrics spec §23 asks the SOC
    # overview to show. Recorded when the transition happens rather than
    # derived later from the audit log, which would tie a dashboard query to
    # log parsing.
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AlertNote(Base):
    """An analyst's note on an alert.

    Append-only: triage notes are the reasoning behind a decision, and a
    decision whose reasoning can be edited afterwards cannot be reviewed.
    """

    __tablename__ = "alert_notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertTransition(Base):
    """Every status change, append-only.

    The audit log records that a change happened; this records the alert's
    own history in the shape the UI shows it, and is what MTTA/MTTR are
    computed from when the aggregate columns are not enough.
    """

    __tablename__ = "alert_transitions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AlertSequence(Base):
    """Per-tenant, per-year counter behind `display_id`.

    A row per (tenant, year) locked with SELECT FOR UPDATE: display ids must
    be gapless and unique per tenant, and a max()+1 read would hand two
    concurrent workers the same number.
    """

    __tablename__ = "alert_sequences"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), primary_key=True
    )
    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
