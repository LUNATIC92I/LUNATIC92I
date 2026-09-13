"""SOAR playbooks (spec §18; ARCHITECTURE.md §7.5).

Three tables, three questions:

- `Playbook` — what steps exist, in what order, ready to run.
- `PlaybookRun` — one execution of one playbook, carrying its own state
  (`current_step`, per-step `results`) so an approval-halted run can be
  resumed exactly where it stopped rather than replayed from the start.
- `PlaybookActionApproval` — one destructive step's dual-control record.

`ck_playbook_action_approvals_dual_control` is the one constraint that
matters most in this file: the database itself refuses a row where the
approver is the requester, so "requester != approver" is not a rule the
application has to remember to check — see `THREAT_MODEL.md §3.6`.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

TRIGGER_TYPES = ("manual", "alert")
PLAYBOOK_STATUSES = ("enabled", "disabled")

RUN_STATUSES = (
    "PENDING",
    "RUNNING",
    "AWAITING_APPROVAL",
    "COMPLETED",
    "FAILED",
    "REJECTED",
)

APPROVAL_STATUSES = ("PENDING_APPROVAL", "APPROVED", "REJECTED", "EXECUTED")


class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (
        CheckConstraint(f"trigger_type IN {TRIGGER_TYPES}", name="ck_playbooks_trigger_type"),
        CheckConstraint(f"status IN {PLAYBOOK_STATUSES}", name="ck_playbooks_status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    # Human-assigned, stable identifier ("PB-001") — referenced in run
    # records and API paths instead of the surrogate UUID, matching the
    # detection rule pack's `rule_key` convention.
    key: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    trigger_type: Mapped[str] = mapped_column(String, nullable=False, default="manual")
    # The step list: [{"action": "enrich_ip", "params": {...}}, ...]. Data,
    # never code — the same reason the detection rule DSL has no eval
    # (THREAT_MODEL.md §3.4): a playbook step names a registered action by
    # its fixed identifier, it cannot supply arbitrary behavior.
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="enabled")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    __table_args__ = (CheckConstraint(f"status IN {RUN_STATUSES}", name="ck_playbook_runs_status"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbooks.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String, nullable=False, default="PENDING")
    # A dry run never mutates anything and never creates an approval record
    # — every step, destructive or not, only ever previews (see
    # app/playbooks/engine.py). Kept on the run itself so a run's own
    # history unambiguously records which kind it was.
    dry_run: Mapped[bool] = mapped_column(nullable=False, default=False)
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id"), nullable=True
    )
    # Index of the next step to run — how a run halted at
    # AWAITING_APPROVAL resumes from exactly where it stopped rather than
    # replaying already-executed steps (which would re-run non-idempotent
    # actions like notify_analyst a second time).
    current_step: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    results: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PlaybookActionApproval(Base):
    __tablename__ = "playbook_action_approvals"
    __table_args__ = (
        CheckConstraint(f"status IN {APPROVAL_STATUSES}", name="ck_playbook_approvals_status"),
        # Dual control at the schema level: a decided row can never name the
        # same person as both requester and approver. NULL decided_by
        # (still pending) is unconstrained, as it must be.
        CheckConstraint(
            "decided_by IS NULL OR decided_by != requested_by",
            name="ck_playbook_action_approvals_dual_control",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    playbook_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("playbook_runs.id"), nullable=False
    )
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    action_name: Mapped[str] = mapped_column(String, nullable=False)
    # A snapshot of what the step would do, shown to the approver — the
    # same content `dry_run()` would have produced, so approving is an
    # informed decision rather than a rubber stamp on a step name.
    preview: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="PENDING_APPROVAL")
    # NOT NULL is load-bearing: the dual-control CHECK below is
    # `decided_by != requested_by`, and SQL's three-valued logic treats a
    # NULL comparison as unknown, not false — a NULL requested_by would let
    # any decided_by through the constraint unchecked.
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    decided_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(String, nullable=True)
