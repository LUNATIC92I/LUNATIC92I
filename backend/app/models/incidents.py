"""Incidents: the case an investigation actually lives in (spec §14).

An alert is one thing that fired. An incident is what a team works: several
alerts, the hosts and accounts involved, the indicators found along the way,
the tasks people are doing about it, and a timeline that says who did what
and when.

The timeline is the part that has to be right. Every state change, note,
task and linkage writes an entry, and the table is append-only at the
database level — an incident record whose history can be edited afterwards
is worthless for the two things it exists for: handing the case to the next
shift, and explaining afterwards what was known and when.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

# The IR lifecycle from spec §14, in the order NIST 800-61 walks it.
INCIDENT_STATUSES = (
    "NEW",
    "TRIAGE",
    "INVESTIGATION",
    "CONTAINMENT",
    "ERADICATION",
    "RECOVERY",
    "CLOSED",
)
INCIDENT_SEVERITIES = ("low", "medium", "high", "critical")
INCIDENT_PRIORITIES = ("P1", "P2", "P3", "P4")
TASK_STATUSES = ("open", "in_progress", "done")

# What a timeline entry can be about. Kept as a small fixed vocabulary so
# the UI can render each kind, and so a new event type is a deliberate
# addition rather than a free-text string nobody knows how to display.
TIMELINE_KINDS = (
    "status_change",
    "note",
    "task",
    "alert_linked",
    "asset_linked",
    "ioc_linked",
    "assignment",
    "created",
)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        UniqueConstraint("tenant_id", "display_id", name="uq_incidents_display_id"),
        CheckConstraint(f"status IN {INCIDENT_STATUSES}", name="ck_incidents_status"),
        CheckConstraint(f"severity IN {INCIDENT_SEVERITIES}", name="ck_incidents_severity"),
        CheckConstraint(f"priority IN {INCIDENT_PRIORITIES}", name="ck_incidents_priority"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    display_id: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    priority: Mapped[str] = mapped_column(String(4), nullable=False, default="P3")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="NEW")
    analyst_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Deliberately a column rather than a note: the post-incident review is
    # the only part of IR that improves the next incident, and burying it in
    # a note thread is how it stops being written at all.
    lessons_learned: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Recorded at transition time for MTTD/MTTC/MTTR reporting, rather than
    # reconstructed later from the timeline.
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    __table_args__ = (UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentAsset(Base):
    __tablename__ = "incident_assets"
    __table_args__ = (UniqueConstraint("incident_id", "asset_id", name="uq_incident_asset"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentIoc(Base):
    __tablename__ = "incident_iocs"
    __table_args__ = (UniqueConstraint("incident_id", "ioc_id", name="uq_incident_ioc"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False
    )
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentUser(Base):
    """An account involved in the incident.

    A plain string rather than a foreign key to `users`: the accounts in an
    incident are the *estate's* accounts (a domain user, a service
    principal), not this platform's operators, and most of them will never
    have a row here.
    """

    __tablename__ = "incident_users"
    __table_args__ = (UniqueConstraint("incident_id", "username", name="uq_incident_user"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    username: Mapped[str] = mapped_column(String(300), nullable=False)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentTask(Base):
    """Work someone owes the incident.

    Tasks are mutable — that is the point of them — but every change writes
    a timeline entry, so the record of who was asked to do what, and when it
    was done, is still append-only.
    """

    __tablename__ = "incident_tasks"
    __table_args__ = (
        CheckConstraint(f"status IN {TASK_STATUSES}", name="ck_incident_tasks_status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IncidentTimeline(Base):
    """Append-only history of everything that happened to the incident."""

    __tablename__ = "incident_timeline"
    __table_args__ = (
        CheckConstraint(f"kind IN {TIMELINE_KINDS}", name="ck_incident_timeline_kind"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    # clock_timestamp(), not now(): now() is frozen at transaction start, so
    # several timeline entries written in one transaction (opening a case
    # and promoting alerts into it, say) would all get the identical
    # timestamp and the read-back order would fall to tiebreaking on a
    # random UUID — exactly the property "timeline completeness" (spec §14)
    # depends on not happening.
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.clock_timestamp()
    )


class IncidentSequence(Base):
    """Per-tenant, per-year counter behind `display_id` (INC-2026-000123)."""

    __tablename__ = "incident_sequences"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), primary_key=True
    )
    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
