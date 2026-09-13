"""MITRE ATT&CK catalog and rule mapping (postgresql_schema.sql §4, spec §12).

The catalog is **imported, never hardcoded** (spec §12 and the Phase 10
acceptance criteria). ATT&CK ships several revisions a year: techniques are
added, renamed, deprecated and revoked, and a matrix baked into source code
is a matrix that silently drifts out of date while claiming coverage against
a version nobody is running any more. `x_mitre_version` and the import
timestamp are therefore stored per technique, so "which ATT&CK are we
measuring against?" always has an answer.

Nothing here is tenant-scoped: ATT&CK is public knowledge, identical for
everyone, and duplicating 800 techniques per tenant would buy nothing.
`rule_mitre_map` is the exception — it links a tenant's own detection rules
to the shared catalog, so it carries a tenant id and the usual RLS policy.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

# Technique ids are the platform's join key everywhere (rules, detections,
# risk scoring), so the shape is pinned rather than trusted from the import.
TECHNIQUE_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"
TACTIC_ID_PATTERN = r"^TA\d{4}$"


class MitreTactic(Base):
    __tablename__ = "mitre_tactics"

    # The ATT&CK id (TA0006) is the primary key: it is stable across
    # revisions, which a surrogate uuid would not make any more true, and it
    # is what every other system talks in.
    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # The STIX kill-chain phase name ("credential-access"), which is how
    # techniques reference their tactics in the bundle.
    shortname: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    parent_id: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    platforms: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    data_sources: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    # Kept rather than dropped: a rule mapped to a technique that ATT&CK has
    # since deprecated or revoked is a coverage claim that needs review, and
    # deleting the row would just make the rule's mapping dangle silently.
    is_deprecated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_by: Mapped[str | None] = mapped_column(String(16), nullable=True)
    attack_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class MitreTechniqueTactic(Base):
    """Which tactics a technique belongs to. A technique commonly serves
    several (credential access *and* lateral movement), so coverage cannot
    be computed from a single tactic column."""

    __tablename__ = "mitre_technique_tactics"
    __table_args__ = (
        UniqueConstraint("technique_id", "tactic_id", name="uq_technique_tactic"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technique_id: Mapped[str] = mapped_column(
        String(16), ForeignKey("mitre_techniques.id", ondelete="CASCADE"), nullable=False
    )
    tactic_id: Mapped[str] = mapped_column(
        String(16), ForeignKey("mitre_tactics.id", ondelete="CASCADE"), nullable=False
    )


class RuleMitreMap(Base):
    """A tenant's detection rule ↔ ATT&CK technique link.

    Derived from the rule's own `mitre_attack` list, but stored as rows with
    a foreign key so a coverage query is a join rather than a scan over
    arrays, and so a rule can only claim techniques that exist in the
    imported catalog. Techniques a rule claims that ATT&CK does not know
    about are not silently dropped — they are reported by the coverage API
    as unknown, because a typo'd technique id is a coverage claim that is
    quietly false.
    """

    __tablename__ = "rule_mitre_map"
    __table_args__ = (
        UniqueConstraint("rule_id", "technique_id", name="uq_rule_mitre_map"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False
    )
    technique_id: Mapped[str] = mapped_column(
        String(16), ForeignKey("mitre_techniques.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class MitreImport(Base):
    """One import run.

    Recorded because "measuring coverage against ATT&CK v14" and "against
    v19" are different claims, and because an import that silently failed
    six months ago is indistinguishable from a matrix that has not changed.
    """

    __tablename__ = "mitre_imports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(500), nullable=False)
    attack_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    spec_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tactics_imported: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    techniques_imported: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    objects_rejected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(500), nullable=False, default="ok")
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
