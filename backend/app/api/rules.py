"""Detection rule management API (spec §22 `/rules`).

Read is separated from write by permission, and both are separated from
`rule:execute` (the dry-run endpoint), because those are genuinely different
levels of trust: an L1 analyst should be able to read why a rule fired, an
L2 to test one, and only L3/engineering to change what the platform detects.
Every write is audit-logged by the service layer inside the same
transaction as the change itself.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth.dependencies import AuthContext, require_permission
from app.detection.conditions import evaluate_node
from app.detection.engine import entity_key, matching_exception
from app.detection.loader import RuleLoadError, parse_rule
from app.models.detection import DetectionRuleRecord
from app.schemas.rules import (
    DefaultRulesInstalled,
    RuleExceptionPublic,
    RuleExceptionSubmission,
    RulePublic,
    RuleStatusUpdate,
    RuleSubmission,
    RuleTestRequest,
    RuleTestResult,
    RuleVersionPublic,
)
from app.services import detection_rules as service

router = APIRouter(prefix="/rules", tags=["rules"])


def _public(record: DetectionRuleRecord) -> RulePublic:
    return RulePublic(
        id=str(record.id),
        rule_key=record.rule_key,
        name=record.name,
        description=record.description,
        severity=record.severity,
        confidence=record.confidence,
        risk_score=record.risk_score,
        status=record.status,
        rule_type=record.rule_type,
        mitre_techniques=list(record.mitre_techniques),
        references_urls=list(record.references_urls),
        false_positive_notes=record.false_positive_notes,
        investigation_steps=record.investigation_steps,
        author=record.author,
        current_version=record.current_version,
        definition_yaml=record.definition_yaml,
    )


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


@router.get("", response_model=list[RulePublic])
async def list_rules(
    ctx: AuthContext = Depends(require_permission("rule", "read")),
) -> list[RulePublic]:
    records = await service.list_rules(ctx.db, ctx.user.tenant_id)
    return [_public(record) for record in records]


@router.get("/{rule_key}", response_model=RulePublic)
async def get_rule(
    rule_key: str,
    ctx: AuthContext = Depends(require_permission("rule", "read")),
) -> RulePublic:
    try:
        record = await service.get_rule(ctx.db, ctx.user.tenant_id, rule_key)
    except service.RuleNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found") from exc
    return _public(record)


@router.post("", response_model=RulePublic, status_code=status.HTTP_201_CREATED)
async def create_rule(
    payload: RuleSubmission,
    request: Request,
    ctx: AuthContext = Depends(require_permission("rule", "write")),
) -> RulePublic:
    try:
        record = await service.create_rule(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            yaml_text=payload.definition_yaml,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
            change_summary=payload.change_summary,
        )
    except RuleLoadError as exc:
        # 422, not 500: an invalid rule is a client error, and the parser's
        # message is the most useful thing we can hand the author back.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except service.DuplicateRule as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, f"rule {exc} already exists") from exc
    await ctx.db.commit()
    return _public(record)


@router.put("/{rule_key}", response_model=RulePublic)
async def update_rule(
    rule_key: str,
    payload: RuleSubmission,
    request: Request,
    ctx: AuthContext = Depends(require_permission("rule", "write")),
) -> RulePublic:
    try:
        record = await service.update_rule(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            rule_key=rule_key,
            yaml_text=payload.definition_yaml,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
            change_summary=payload.change_summary,
        )
    except service.RuleNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found") from exc
    except RuleLoadError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await ctx.db.commit()
    return _public(record)


@router.post("/{rule_key}/status", response_model=RulePublic)
async def set_status(
    rule_key: str,
    payload: RuleStatusUpdate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("rule", "write")),
) -> RulePublic:
    try:
        record = await service.set_rule_status(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            rule_key=rule_key,
            status=payload.status,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.RuleNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found") from exc
    await ctx.db.commit()
    return _public(record)


@router.get("/{rule_key}/versions", response_model=list[RuleVersionPublic])
async def list_versions(
    rule_key: str,
    ctx: AuthContext = Depends(require_permission("rule", "read")),
) -> list[RuleVersionPublic]:
    try:
        record = await service.get_rule(ctx.db, ctx.user.tenant_id, rule_key)
    except service.RuleNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found") from exc
    versions = await service.list_versions(ctx.db, ctx.user.tenant_id, record.id)
    return [
        RuleVersionPublic(
            version=version.version,
            change_summary=version.change_summary,
            changed_by=str(version.changed_by) if version.changed_by else None,
            created_at=version.created_at,
            definition_yaml=version.definition_yaml,
        )
        for version in versions
    ]


@router.post(
    "/{rule_key}/exceptions",
    response_model=RuleExceptionPublic,
    status_code=status.HTTP_201_CREATED,
)
async def create_exception(
    rule_key: str,
    payload: RuleExceptionSubmission,
    request: Request,
    ctx: AuthContext = Depends(require_permission("rule", "write")),
) -> RuleExceptionPublic:
    try:
        row = await service.add_exception(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            rule_key=rule_key,
            reason=payload.reason,
            conditions=payload.conditions,
            expires_at=payload.expires_at,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.RuleNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found") from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await ctx.db.commit()
    return RuleExceptionPublic(
        id=str(row.id),
        reason=row.reason,
        conditions=row.match_criteria,
        expires_at=row.expires_at,
        created_at=row.created_at,
    )


@router.get("/{rule_key}/exceptions", response_model=list[RuleExceptionPublic])
async def list_rule_exceptions(
    rule_key: str,
    ctx: AuthContext = Depends(require_permission("rule", "read")),
) -> list[RuleExceptionPublic]:
    try:
        record = await service.get_rule(ctx.db, ctx.user.tenant_id, rule_key)
    except service.RuleNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found") from exc
    rows = await service.list_exceptions(ctx.db, ctx.user.tenant_id, record.id)
    return [
        RuleExceptionPublic(
            id=str(row.id),
            reason=row.reason,
            conditions=row.match_criteria,
            expires_at=row.expires_at,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post("/test", response_model=RuleTestResult)
async def test_rule(
    payload: RuleTestRequest,
    ctx: AuthContext = Depends(require_permission("rule", "execute")),
) -> RuleTestResult:
    """Evaluates a candidate rule against one supplied event. Nothing is
    stored and no detection is emitted — this is a pure function of the two
    inputs, which is what makes it safe to expose at `rule:execute`."""
    try:
        rule = parse_rule(payload.definition_yaml, origin="submitted rule")
    except RuleLoadError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    note = None
    if rule.rule_type == "windowed":
        # Be explicit rather than quietly returning a misleading false: a
        # threshold rule cannot be judged from a single event, and an author
        # who reads "no match" as "my rule is wrong" will break a good rule.
        note = (
            "this is a windowed rule; a single event is tested against its "
            "conditions only, not against its threshold"
        )

    matched = evaluate_node(rule.conditions, payload.event)
    excepted = matching_exception(rule, payload.event) if matched else None
    return RuleTestResult(
        matched=matched and excepted is None,
        rule_id=rule.rule_id,
        rule_type=rule.rule_type,
        excepted_by=excepted.reason if excepted else None,
        entity=entity_key(rule, payload.event) if matched else {},
        note=note,
    )


@router.post("/install-defaults", response_model=DefaultRulesInstalled)
async def install_defaults(
    ctx: AuthContext = Depends(require_permission("rule", "write")),
) -> DefaultRulesInstalled:
    """Re-runs the default pack install. Idempotent and non-destructive:
    rules the tenant already has are left exactly as they are, tuning
    included."""
    try:
        installed = await service.install_default_rules(
            ctx.db, tenant_id=ctx.user.tenant_id, actor_id=ctx.user.id
        )
    except RuleLoadError as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from exc
    await ctx.db.commit()
    return DefaultRulesInstalled(installed=installed)

