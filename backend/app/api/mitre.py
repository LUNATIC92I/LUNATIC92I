"""MITRE ATT&CK coverage API (spec §22 `/mitre`, §23's ATT&CK screen).

The coverage page exists to answer one question honestly: *what can this SOC
actually detect, and what can it not?* Which is why the numbers here are
deliberately conservative — a disabled rule is not coverage, a dry-run
detection is not a detection, and a covered sub-technique does not make its
parent covered.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.audit.service import record_audit_event
from app.auth.dependencies import AuthContext, require_permission
from app.core.config import get_settings
from app.core.opensearch import get_opensearch
from app.mitre.importer import ImportError_, load_bundle, parse_bundle
from app.models.mitre import MitreTactic, MitreTechnique
from app.schemas.mitre import (
    CoveragePublic,
    DetectionSummary,
    ImportRequest,
    ImportResult,
    TacticCoveragePublic,
    TacticPublic,
    TechniqueCoveragePublic,
    TechniqueDetail,
    TechniquePublic,
)
from app.services import detections as detection_store
from app.services import mitre as service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mitre", tags=["mitre"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("/tactics", response_model=list[TacticPublic])
async def list_tactics(
    ctx: AuthContext = Depends(require_permission("mitre", "read")),
) -> list[TacticPublic]:
    from sqlalchemy import select

    rows = list((await ctx.db.execute(select(MitreTactic).order_by(MitreTactic.id))).scalars())
    return [
        TacticPublic(id=row.id, name=row.name, shortname=row.shortname, url=row.url)
        for row in rows
    ]


@router.get("/techniques", response_model=list[TechniquePublic])
async def list_techniques(
    tactic: str | None = Query(default=None, max_length=16),
    include_deprecated: bool = Query(default=False),
    limit: int = Query(default=1000, ge=1, le=2000),
    ctx: AuthContext = Depends(require_permission("mitre", "read")),
) -> list[TechniquePublic]:
    from sqlalchemy import select

    from app.models.mitre import MitreTechniqueTactic

    stmt = select(MitreTechnique)
    if not include_deprecated:
        stmt = stmt.where(
            MitreTechnique.is_revoked.is_(False), MitreTechnique.is_deprecated.is_(False)
        )
    if tactic:
        stmt = stmt.join(
            MitreTechniqueTactic, MitreTechniqueTactic.technique_id == MitreTechnique.id
        ).where(MitreTechniqueTactic.tactic_id == tactic)
    rows = list((await ctx.db.execute(stmt.order_by(MitreTechnique.id).limit(limit))).scalars())

    links = {
        technique_id: tactic_id
        for technique_id, tactic_id in (
            await ctx.db.execute(
                select(MitreTechniqueTactic.technique_id, MitreTechniqueTactic.tactic_id)
            )
        ).all()
    }
    return [
        TechniquePublic(
            id=row.id,
            name=row.name,
            is_subtechnique=row.is_subtechnique,
            parent_id=row.parent_id,
            tactics=[links[row.id]] if row.id in links else [],
            platforms=list(row.platforms),
            is_deprecated=row.is_deprecated,
            is_revoked=row.is_revoked,
            url=row.url,
        )
        for row in rows
    ]


@router.get("/coverage", response_model=CoveragePublic)
async def coverage(
    days: int = Query(default=30, ge=1, le=365),
    include_deprecated: bool = Query(default=False),
    ctx: AuthContext = Depends(require_permission("mitre", "read")),
) -> CoveragePublic:
    counts = await detection_store.detections_per_technique(
        get_opensearch(), str(ctx.user.tenant_id), days=days
    )
    report = await service.coverage(
        ctx.db,
        ctx.user.tenant_id,
        detection_counts=counts,
        include_deprecated=include_deprecated,
    )
    # sync_rule_mappings inside coverage() may have written mappings.
    await ctx.db.commit()

    return CoveragePublic(
        attack_version=report.attack_version,
        imported_at=report.imported_at,
        catalog_is_stale=await service.stale_import(ctx.db),
        total_techniques=report.total_techniques,
        covered_techniques=report.covered_techniques,
        partially_covered_techniques=report.partially_covered_techniques,
        coverage_rate=report.coverage_rate,
        detection_window_days=days,
        tactics=[
            TacticCoveragePublic(
                tactic_id=tactic.tactic_id,
                name=tactic.name,
                shortname=tactic.shortname,
                total=tactic.total,
                covered=tactic.covered,
                partial=tactic.partial,
                coverage_rate=tactic.coverage_rate,
            )
            for tactic in report.tactics
        ],
        techniques=[
            TechniqueCoveragePublic(
                technique_id=technique.technique_id,
                name=technique.name,
                is_subtechnique=technique.is_subtechnique,
                parent_id=technique.parent_id,
                tactics=technique.tactics,
                status=technique.status,
                rule_keys=technique.rule_keys,
                detection_count=technique.detection_count,
            )
            for technique in report.techniques
        ],
        unknown_technique_claims=report.unknown_technique_claims,
    )


@router.get("/techniques/{technique_id}", response_model=TechniqueDetail)
async def technique_detail(
    technique_id: str,
    days: int = Query(default=30, ge=1, le=365),
    ctx: AuthContext = Depends(require_permission("mitre", "read")),
) -> TechniqueDetail:
    technique = await ctx.db.get(MitreTechnique, technique_id)
    if technique is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "technique not found")

    counts = await detection_store.detections_per_technique(
        get_opensearch(), str(ctx.user.tenant_id), days=days
    )
    report = await service.coverage(
        ctx.db, ctx.user.tenant_id, detection_counts=counts, include_deprecated=True
    )
    await ctx.db.commit()
    entry = next(
        (item for item in report.techniques if item.technique_id == technique_id), None
    )

    recent = await detection_store.recent_detections(
        get_opensearch(), str(ctx.user.tenant_id), technique_id=technique_id, days=days
    )
    return TechniqueDetail(
        technique=TechniquePublic(
            id=technique.id,
            name=technique.name,
            is_subtechnique=technique.is_subtechnique,
            parent_id=technique.parent_id,
            tactics=entry.tactics if entry else [],
            platforms=list(technique.platforms),
            is_deprecated=technique.is_deprecated,
            is_revoked=technique.is_revoked,
            url=technique.url,
        ),
        status=entry.status if entry else "uncovered",
        rule_keys=entry.rule_keys if entry else [],
        detection_count=counts.get(technique_id, 0),
        recent_detections=[DetectionSummary(**item) for item in recent],
    )


@router.post("/import", response_model=ImportResult)
async def import_catalog(
    payload: ImportRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("mitre", "write")),
) -> ImportResult:
    """Imports (or re-imports) the ATT&CK catalog. Idempotent.

    The catalog is global, so this is an administrative action that affects
    every tenant's coverage page — hence `mitre:write`, which only admins
    and SOC managers hold, and an audit entry naming the source.
    """
    source = payload.source or get_settings().mitre_attack_source
    if not source:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "no ATT&CK source configured (set MITRE_ATTACK_SOURCE or pass one)",
        )

    try:
        raw, resolved = await load_bundle(source)
        bundle = parse_bundle(raw)
    except ImportError_ as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    record = await service.import_bundle(ctx.db, bundle=bundle, source=resolved)
    mapping = await service.sync_rule_mappings(ctx.db, ctx.user.tenant_id)

    await record_audit_event(
        ctx.db,
        tenant_id=ctx.user.tenant_id,
        actor_id=ctx.user.id,
        actor_ip=_client_ip(request),
        action="IMPORT_MITRE_ATTACK",
        object_type="mitre",
        object_id=record.attack_version or "unknown",
        after_state={
            "source": resolved,
            "techniques": record.techniques_imported,
            "rejected": record.objects_rejected,
        },
        result="success",
    )
    await ctx.db.commit()

    return ImportResult(
        source=resolved,
        attack_version=record.attack_version,
        tactics_imported=record.tactics_imported,
        techniques_imported=record.techniques_imported,
        objects_rejected=record.objects_rejected,
        rules_mapped=mapping.mapped,
        mappings_removed=mapping.removed,
    )
