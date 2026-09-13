"""Detection rule persistence (postgresql_schema.sql §4).

PostgreSQL is the source of truth for rule *state* — which rules exist, what
they currently say, whether they are enabled — while the YAML in `rules/` is
the default pack that gets installed into a tenant. The authored YAML is
stored verbatim in `definition_yaml` rather than being exploded into
columns: the DSL is the contract, and keeping a second, half-normalized copy
of it in table columns would guarantee the two drift. The few columns that
*are* duplicated out of the YAML (name, severity, status, rule_type) exist
because they are filtered and sorted on, and they are always written from
the parsed rule, never edited independently.

One deliberate deviation from the Phase 0 draft schema: `tenant_id` is NOT
NULL here, where the draft allowed NULL for "global" rules. A shared global
rule cannot be tuned, excepted, or disabled by one tenant without affecting
every other tenant — and per-tenant tuning is most of what detection
engineering *is*. The default pack is therefore installed per tenant
(`install_default_rules`), which costs a few rows and buys a blast radius of
exactly one tenant for every rule edit.
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
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

RULE_STATUSES = ("enabled", "disabled", "testing")
RULE_TYPES = ("streaming", "windowed")
RULE_SEVERITIES = ("informational", "low", "medium", "high", "critical")


class DetectionRuleRecord(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "rule_key", name="uq_detection_rules_tenant_key"),
        CheckConstraint(f"status IN {RULE_STATUSES}", name="ck_detection_rules_status"),
        CheckConstraint(f"rule_type IN {RULE_TYPES}", name="ck_detection_rules_type"),
        CheckConstraint(f"severity IN {RULE_SEVERITIES}", name="ck_detection_rules_severity"),
        CheckConstraint(
            "confidence BETWEEN 0 AND 100", name="ck_detection_rules_confidence"
        ),
        CheckConstraint("risk_score BETWEEN 0 AND 100", name="ck_detection_rules_risk"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    # The DSL's `rule_id` (AUTH-001). Called rule_key in the database because
    # `id` is the row's own primary key, and one column meaning two things is
    # how a query ends up joining on the wrong one.
    rule_key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=50)
    risk_score: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String, nullable=False, default="disabled")
    rule_type: Mapped[str] = mapped_column(String, nullable=False)
    definition_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    false_positive_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    investigation_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    references_urls: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String), nullable=False, default=list
    )
    author: Mapped[str | None] = mapped_column(String, nullable=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class DetectionRuleVersion(Base):
    """Every version a rule has ever had, kept forever.

    A detection that stops firing because someone narrowed a condition is
    indistinguishable from an attacker having stopped — unless the change is
    recoverable and dated. Together with the audit log entry written by the
    same transaction, this answers "what did this rule say on the day we
    missed it?" (THREAT_MODEL.md §3.4).
    """

    __tablename__ = "detection_rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_detection_rule_versions_rule_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    # Denormalized from the parent row purely so the RLS policy on this
    # table can be the same simple tenant predicate as everywhere else.
    # A policy that has to join to its parent to decide is a policy that
    # eventually gets written wrong.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    definition_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    changed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    change_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RuleExceptionRecord(Base):
    """A tenant's carve-out from a rule.

    `expires_at` is nullable in the schema but the API defaults it: an
    exception with no end date is a permanent, undocumented coverage hole,
    and the engine counts every event one removes so the hole stays visible.
    """

    __tablename__ = "rule_exceptions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    match_criteria: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
