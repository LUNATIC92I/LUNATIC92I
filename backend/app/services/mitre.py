"""ATT&CK catalog storage, rule mapping, and coverage (spec §12).

Three jobs:

1. **Import** a parsed bundle idempotently. Re-running an import must
   converge on the same state, never duplicate rows and never lose a
   mapping — ATT&CK is re-imported on a schedule, so a non-idempotent
   import would corrupt the catalog on its second run.
2. **Map** each tenant's detection rules onto the catalog, so coverage is a
   join rather than a scan over string arrays, and so a rule claiming a
   technique that does not exist is visible instead of silently counted.
3. **Measure** coverage: what the tenant can detect, what it cannot, and —
   because a rule that never fires is not the same as a rule that does —
   how many detections each technique actually produced.

Two deliberate choices in the measurement:

- **Revoked and deprecated techniques are excluded from the denominator.**
  Measuring against techniques MITRE itself has withdrawn inflates the gap
  with entries no one should write a rule for, which makes the number
  useless for deciding what to build next.
- **A parent technique with a covered sub-technique is *partial*, not
  covered.** Detecting LSASS dumping (T1003.001) is not detecting all of
  OS Credential Dumping (T1003), and a coverage page that says otherwise is
  telling the SOC a comfortable lie.
"""

import logging
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.mitre.importer import ParsedBundle
from app.models.detection import DetectionRuleRecord
from app.models.mitre import (
    MitreImport,
    MitreTactic,
    MitreTechnique,
    MitreTechniqueTactic,
    RuleMitreMap,
)

logger = logging.getLogger(__name__)

COVERED = "covered"
PARTIAL = "partial"
UNCOVERED = "uncovered"


@dataclass
class MappingResult:
    mapped: int = 0
    removed: int = 0
    # Techniques a rule claims that the imported catalog does not contain: a
    # typo, or a rule written against a newer ATT&CK than the one imported.
    # Reported rather than dropped — a false coverage claim is worse than a
    # visible gap.
    unknown: dict[str, list[str]] = field(default_factory=dict)


async def import_bundle(db: AsyncSession, *, bundle: ParsedBundle, source: str) -> MitreImport:
    """Upserts the catalog. Safe to run repeatedly (the idempotency the
    acceptance criteria require)."""
    now = datetime.now(UTC)

    for tactic in bundle.tactics:
        await db.execute(
            insert(MitreTactic)
            .values(
                id=tactic.id,
                name=tactic.name,
                shortname=tactic.shortname,
                description=tactic.description,
                url=tactic.url,
                imported_at=now,
            )
            .on_conflict_do_update(
                index_elements=[MitreTactic.id],
                set_={
                    "name": tactic.name,
                    "shortname": tactic.shortname,
                    "description": tactic.description,
                    "url": tactic.url,
                    "imported_at": now,
                },
            )
        )

    for technique in bundle.techniques:
        await db.execute(
            insert(MitreTechnique)
            .values(
                id=technique.id,
                name=technique.name,
                description=technique.description,
                is_subtechnique=technique.is_subtechnique,
                parent_id=technique.parent_id,
                platforms=technique.platforms,
                data_sources=technique.data_sources,
                is_deprecated=technique.is_deprecated,
                is_revoked=technique.is_revoked,
                attack_version=technique.attack_version,
                url=technique.url,
                imported_at=now,
            )
            .on_conflict_do_update(
                index_elements=[MitreTechnique.id],
                set_={
                    "name": technique.name,
                    "description": technique.description,
                    "is_subtechnique": technique.is_subtechnique,
                    "parent_id": technique.parent_id,
                    "platforms": technique.platforms,
                    "data_sources": technique.data_sources,
                    # Deprecation and revocation are the fields most likely
                    # to change between releases, and the ones a coverage
                    # page most needs to be current about.
                    "is_deprecated": technique.is_deprecated,
                    "is_revoked": technique.is_revoked,
                    "attack_version": technique.attack_version,
                    "url": technique.url,
                    "imported_at": now,
                },
            )
        )

    await _replace_technique_tactics(db, bundle)

    record = MitreImport(
        source=source[:500],
        attack_version=bundle.attack_version,
        spec_version=bundle.spec_version,
        tactics_imported=len(bundle.tactics),
        techniques_imported=len(bundle.techniques),
        objects_rejected=bundle.rejected,
        status="ok",
    )
    db.add(record)
    await db.flush()
    logger.info(
        "attack catalog imported",
        extra={
            "source": source,
            "attack_version": bundle.attack_version,
            "techniques": len(bundle.techniques),
            "rejected": bundle.rejected,
        },
    )
    return record


async def _replace_technique_tactics(db: AsyncSession, bundle: ParsedBundle) -> None:
    """Technique→tactic links are rebuilt rather than merged: ATT&CK moves
    techniques between tactics, and a merge would leave the old link behind
    forever, quietly inflating coverage for a tactic the technique no longer
    belongs to."""
    shortname_to_id = {
        shortname: tactic_id
        for tactic_id, shortname in (
            await db.execute(select(MitreTactic.id, MitreTactic.shortname))
        ).all()
    }

    technique_ids = [technique.id for technique in bundle.techniques]
    if technique_ids:
        await db.execute(
            delete(MitreTechniqueTactic).where(
                MitreTechniqueTactic.technique_id.in_(technique_ids)
            )
        )

    rows = [
        {"id": uuid.uuid4(), "technique_id": technique.id, "tactic_id": shortname_to_id[shortname]}
        for technique in bundle.techniques
        for shortname in technique.tactic_shortnames
        if shortname in shortname_to_id
    ]
    if rows:
        await db.execute(insert(MitreTechniqueTactic).values(rows))


async def sync_rule_mappings(db: AsyncSession, tenant_id: uuid.UUID) -> MappingResult:
    """Rebuilds `rule_mitre_map` for one tenant from its rules' own
    technique lists. Called after an import and after a rule changes, so the
    coverage page never lags the rules it describes."""
    known = {
        row for row in (await db.execute(select(MitreTechnique.id))).scalars()
    }
    rules = list(
        (
            await db.execute(
                select(DetectionRuleRecord).where(DetectionRuleRecord.tenant_id == tenant_id)
            )
        ).scalars()
    )

    result = MappingResult()
    wanted: set[tuple[uuid.UUID, str]] = set()
    for rule in rules:
        unknown = [technique for technique in rule.mitre_techniques if technique not in known]
        if unknown:
            result.unknown[rule.rule_key] = sorted(unknown)
        for technique in rule.mitre_techniques:
            if technique in known:
                wanted.add((rule.id, technique))

    existing = {
        (row.rule_id, row.technique_id)
        for row in (
            await db.execute(select(RuleMitreMap).where(RuleMitreMap.tenant_id == tenant_id))
        ).scalars()
    }

    for rule_id, technique_id in sorted(wanted - existing, key=lambda pair: str(pair)):
        db.add(RuleMitreMap(tenant_id=tenant_id, rule_id=rule_id, technique_id=technique_id))
        result.mapped += 1

    for rule_id, technique_id in existing - wanted:
        await db.execute(
            delete(RuleMitreMap).where(
                RuleMitreMap.tenant_id == tenant_id,
                RuleMitreMap.rule_id == rule_id,
                RuleMitreMap.technique_id == technique_id,
            )
        )
        result.removed += 1

    await db.flush()
    return result


@dataclass
class TechniqueCoverage:
    technique_id: str
    name: str
    is_subtechnique: bool
    parent_id: str | None
    tactics: list[str]
    status: str
    rule_keys: list[str]
    detection_count: int = 0


@dataclass
class TacticCoverage:
    tactic_id: str
    name: str
    shortname: str
    total: int
    covered: int
    partial: int

    @property
    def coverage_rate(self) -> float:
        return round(100 * self.covered / self.total, 1) if self.total else 0.0


@dataclass
class CoverageReport:
    attack_version: str | None
    imported_at: datetime | None
    total_techniques: int
    covered_techniques: int
    partially_covered_techniques: int
    coverage_rate: float
    tactics: list[TacticCoverage]
    techniques: list[TechniqueCoverage]
    unknown_technique_claims: dict[str, list[str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_version": self.attack_version,
            "imported_at": self.imported_at.isoformat() if self.imported_at else None,
            "total_techniques": self.total_techniques,
            "covered_techniques": self.covered_techniques,
            "partially_covered_techniques": self.partially_covered_techniques,
            "coverage_rate": self.coverage_rate,
            "tactics": [
                {
                    "tactic_id": tactic.tactic_id,
                    "name": tactic.name,
                    "shortname": tactic.shortname,
                    "total": tactic.total,
                    "covered": tactic.covered,
                    "partial": tactic.partial,
                    "coverage_rate": tactic.coverage_rate,
                }
                for tactic in self.tactics
            ],
            "unknown_technique_claims": self.unknown_technique_claims,
        }


async def latest_import(db: AsyncSession) -> MitreImport | None:
    stmt = select(MitreImport).order_by(MitreImport.imported_at.desc()).limit(1)
    return (await db.execute(stmt)).scalar_one_or_none()


async def coverage(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    detection_counts: dict[str, int] | None = None,
    include_deprecated: bool = False,
) -> CoverageReport:
    """Coverage for one tenant.

    `detection_counts` comes from the event store (the API passes it in) so
    this function stays a pure calculation over the catalog and the rules —
    which is what makes the arithmetic testable without a cluster.
    """
    # Mappings are refreshed *before* anything is measured, not after: a
    # rule edited a second ago must not be reported against yesterday's
    # mapping, and the very first coverage call for a tenant would otherwise
    # show zero coverage no matter how many rules it has.
    unknown = (await sync_rule_mappings(db, tenant_id)).unknown

    technique_stmt = select(MitreTechnique)
    if not include_deprecated:
        technique_stmt = technique_stmt.where(
            MitreTechnique.is_revoked.is_(False), MitreTechnique.is_deprecated.is_(False)
        )
    techniques = list((await db.execute(technique_stmt)).scalars())

    tactics = list(
        (await db.execute(select(MitreTactic).order_by(MitreTactic.id))).scalars()
    )
    tactic_by_id = {tactic.id: tactic for tactic in tactics}

    links: dict[str, list[str]] = defaultdict(list)
    for technique_id, tactic_id in (
        await db.execute(
            select(MitreTechniqueTactic.technique_id, MitreTechniqueTactic.tactic_id)
        )
    ).all():
        links[technique_id].append(tactic_id)

    covering_rules: dict[str, list[str]] = defaultdict(list)
    rows = (
        await db.execute(
            select(RuleMitreMap.technique_id, DetectionRuleRecord.rule_key)
            .join(DetectionRuleRecord, DetectionRuleRecord.id == RuleMitreMap.rule_id)
            .where(
                RuleMitreMap.tenant_id == tenant_id,
                # A disabled rule detects nothing, so it cannot count as
                # coverage — the single most common way a coverage page
                # overstates what a SOC can actually see.
                DetectionRuleRecord.status != "disabled",
            )
        )
    ).all()
    for technique_id, rule_key in rows:
        covering_rules[technique_id].append(rule_key)

    # A parent whose sub-technique is covered is partial, not covered.
    partial_parents = {
        technique.parent_id
        for technique in techniques
        if technique.parent_id and covering_rules.get(technique.id)
    }

    counts = detection_counts or {}
    reported: list[TechniqueCoverage] = []
    per_tactic_total: dict[str, int] = defaultdict(int)
    per_tactic_covered: dict[str, int] = defaultdict(int)
    per_tactic_partial: dict[str, int] = defaultdict(int)
    covered_total = partial_total = 0

    for technique in sorted(techniques, key=lambda item: item.id):
        rule_keys = sorted(covering_rules.get(technique.id, []))
        if rule_keys:
            status = COVERED
            covered_total += 1
        elif technique.id in partial_parents:
            status = PARTIAL
            partial_total += 1
        else:
            status = UNCOVERED

        technique_tactics = links.get(technique.id, [])
        for tactic_id in technique_tactics:
            per_tactic_total[tactic_id] += 1
            if status == COVERED:
                per_tactic_covered[tactic_id] += 1
            elif status == PARTIAL:
                per_tactic_partial[tactic_id] += 1

        reported.append(
            TechniqueCoverage(
                technique_id=technique.id,
                name=technique.name,
                is_subtechnique=technique.is_subtechnique,
                parent_id=technique.parent_id,
                tactics=sorted(technique_tactics),
                status=status,
                rule_keys=rule_keys,
                detection_count=counts.get(technique.id, 0),
            )
        )

    last_import = await latest_import(db)

    return CoverageReport(
        attack_version=last_import.attack_version if last_import else None,
        imported_at=last_import.imported_at if last_import else None,
        total_techniques=len(techniques),
        covered_techniques=covered_total,
        partially_covered_techniques=partial_total,
        coverage_rate=round(100 * covered_total / len(techniques), 1) if techniques else 0.0,
        tactics=[
            TacticCoverage(
                tactic_id=tactic_id,
                name=tactic_by_id[tactic_id].name,
                shortname=tactic_by_id[tactic_id].shortname,
                total=per_tactic_total[tactic_id],
                covered=per_tactic_covered[tactic_id],
                partial=per_tactic_partial[tactic_id],
            )
            for tactic_id in sorted(per_tactic_total)
            if tactic_id in tactic_by_id
        ],
        techniques=reported,
        unknown_technique_claims=unknown,
    )


async def technique_count(db: AsyncSession) -> int:
    return int((await db.execute(select(func.count()).select_from(MitreTechnique))).scalar_one())


async def stale_import(db: AsyncSession, *, max_age_days: int = 90) -> bool:
    """True when the catalog has not been refreshed recently. ATT&CK ships
    several revisions a year; a coverage page measured against a matrix from
    last year is measuring the wrong thing."""
    last = await latest_import(db)
    if last is None:
        return True
    return last.imported_at < datetime.now(UTC) - timedelta(days=max_age_days)
