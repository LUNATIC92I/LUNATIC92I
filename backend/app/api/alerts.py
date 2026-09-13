"""Alerts API (spec §22 `/alerts`).

The permission split here is the phase's security review item made real:
`alert:read` to see the queue, `alert:write` to triage (acknowledge,
escalate, assign, annotate), and **`alert:close` to end the work** —
resolve, dismiss as a false positive, or close. An L1 analyst holds the
first two, not the third, so the tier distinction is enforced by the
authorization layer rather than written on an org chart.

Every status change is audit-logged inside the same transaction as the
change (see `services/alerts.py`), and the alert's own transition history is
append-only at the database level.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.auth.dependencies import AuthContext, get_auth_context, require_permission
from app.core.opensearch import get_opensearch
from app.models.alerts import ALERT_STATUSES, Alert
from app.schemas.alerts import (
    AlertCounts,
    AlertDetail,
    AlertPublic,
    AssignRequest,
    EvidenceDocument,
    EvidenceResponse,
    NotePublic,
    NoteRequest,
    TransitionPublic,
    TransitionRequest,
)
from app.services import alerts as service
from app.services.evidence import resolve_events

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _alert_uuid(alert_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(alert_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found") from exc


def _public(alert: Alert) -> AlertPublic:
    return AlertPublic(
        id=str(alert.id),
        display_id=alert.display_id,
        title=alert.title,
        description=alert.description,
        source=alert.source,
        rule_key=alert.rule_key,
        correlation_id=alert.correlation_id,
        severity=alert.severity,
        confidence=alert.confidence,
        risk_score=alert.risk_score,
        risk_bucket=alert.risk_bucket,
        status=alert.status,
        analyst_id=str(alert.analyst_id) if alert.analyst_id else None,
        affected_user=alert.affected_user,
        affected_host=alert.affected_host,
        source_ip=str(alert.source_ip) if alert.source_ip else None,
        destination_ip=str(alert.destination_ip) if alert.destination_ip else None,
        mitre_techniques=list(alert.mitre_techniques),
        occurrence_count=alert.occurrence_count,
        first_seen_at=alert.first_seen_at,
        last_seen_at=alert.last_seen_at,
        acknowledged_at=alert.acknowledged_at,
        closed_at=alert.closed_at,
        created_at=alert.created_at,
    )


def _detail(alert: Alert) -> AlertDetail:
    return AlertDetail(
        **_public(alert).model_dump(),
        event_ids=list(alert.event_ids),
        detection_ids=list(alert.detection_ids),
        evidence=alert.evidence,
        risk_explanation=alert.risk_explanation,
        resolution_note=alert.resolution_note,
    )


@router.get("", response_model=list[AlertPublic])
async def list_alerts(
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    severity: str | None = Query(default=None, max_length=16),
    mine: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_permission("alert", "read")),
) -> list[AlertPublic]:
    rows = await service.list_alerts(
        ctx.db,
        ctx.user.tenant_id,
        status=status_filter,
        severity=severity,
        assigned_to=ctx.user.id if mine else None,
        limit=limit,
        offset=offset,
    )
    return [_public(row) for row in rows]


@router.get("/counts", response_model=AlertCounts)
async def alert_counts(
    ctx: AuthContext = Depends(require_permission("alert", "read")),
) -> AlertCounts:
    counts = await service.count_by_status(ctx.db, ctx.user.tenant_id)
    return AlertCounts(
        by_status=counts,
        open_total=sum(counts.get(state, 0) for state in service.OPEN_STATUSES),
    )


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(
    alert_id: str,
    ctx: AuthContext = Depends(require_permission("alert", "read")),
) -> AlertDetail:
    try:
        alert = await service.get_alert(ctx.db, ctx.user.tenant_id, _alert_uuid(alert_id))
    except service.AlertNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found") from exc
    return _detail(alert)


async def _require_transition_permission(ctx: AuthContext, target: str) -> None:
    """Triage needs `alert:write`; ending the work needs `alert:close`."""
    needed = "close" if target in service.CLOSING else "write"
    if not ctx.user.has_permission("alert", needed):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"moving an alert to {target} requires the alert:{needed} permission",
        )


@router.post("/{alert_id}/status", response_model=AlertDetail)
async def change_status(
    alert_id: str,
    payload: TransitionRequest,
    request: Request,
    # Deliberately only "any authenticated user" here: which permission is
    # required depends on the *target* status, so the check happens below
    # rather than in the dependency.
    ctx: AuthContext = Depends(get_auth_context),
) -> AlertDetail:
    if not ctx.user.has_permission("alert", "read"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient permissions")
    if payload.status not in ALERT_STATUSES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"status must be one of {', '.join(ALERT_STATUSES)}",
        )
    await _require_transition_permission(ctx, payload.status)

    try:
        alert = await service.transition(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            alert_id=_alert_uuid(alert_id),
            target=payload.status,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
            note=payload.note,
        )
    except service.AlertNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found") from exc
    except service.InvalidTransition as exc:
        # 409, not 422: the request is well-formed, the alert is simply not
        # in a state where this makes sense — usually because somebody else
        # moved it first.
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    await ctx.db.commit()
    return _detail(alert)


@router.post("/{alert_id}/assign", response_model=AlertDetail)
async def assign_alert(
    alert_id: str,
    payload: AssignRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("alert", "write")),
) -> AlertDetail:
    try:
        alert = await service.assign(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            alert_id=_alert_uuid(alert_id),
            analyst_id=payload.analyst_id,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.AlertNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found") from exc
    await ctx.db.commit()
    return _detail(alert)


@router.get("/{alert_id}/notes", response_model=list[NotePublic])
async def list_notes(
    alert_id: str,
    ctx: AuthContext = Depends(require_permission("alert", "read")),
) -> list[NotePublic]:
    try:
        rows = await service.notes_for(ctx.db, ctx.user.tenant_id, _alert_uuid(alert_id))
    except service.AlertNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found") from exc
    return [
        NotePublic(
            id=str(row.id),
            author_id=str(row.author_id) if row.author_id else None,
            body=row.body,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post("/{alert_id}/notes", response_model=NotePublic, status_code=status.HTTP_201_CREATED)
async def add_note(
    alert_id: str,
    payload: NoteRequest,
    ctx: AuthContext = Depends(require_permission("alert", "write")),
) -> NotePublic:
    try:
        note = await service.add_note(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            alert_id=_alert_uuid(alert_id),
            body=payload.body,
            author_id=ctx.user.id,
        )
    except service.AlertNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found") from exc
    await ctx.db.commit()
    return NotePublic(
        id=str(note.id),
        author_id=str(note.author_id) if note.author_id else None,
        body=note.body,
        created_at=note.created_at,
    )


@router.get("/{alert_id}/history", response_model=list[TransitionPublic])
async def alert_history(
    alert_id: str,
    ctx: AuthContext = Depends(require_permission("alert", "read")),
) -> list[TransitionPublic]:
    try:
        rows = await service.transitions_for(ctx.db, ctx.user.tenant_id, _alert_uuid(alert_id))
    except service.AlertNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found") from exc
    return [
        TransitionPublic(
            from_status=row.from_status,
            to_status=row.to_status,
            actor_id=str(row.actor_id) if row.actor_id else None,
            note=row.note,
            occurred_at=row.occurred_at,
        )
        for row in rows
    ]


@router.get("/{alert_id}/evidence", response_model=EvidenceResponse)
async def alert_evidence(
    alert_id: str,
    ctx: AuthContext = Depends(require_permission("alert", "read")),
) -> EvidenceResponse:
    """Resolves the alert's cited event ids back to the documents in the
    event store — the lineage the whole alert rests on.

    Ids that no longer resolve (retention aged them out, or the index was
    rebuilt) are listed rather than silently omitted: "no evidence" and "the
    evidence expired" are different findings for the analyst.
    """
    try:
        alert = await service.get_alert(ctx.db, ctx.user.tenant_id, _alert_uuid(alert_id))
    except service.AlertNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found") from exc

    found = await resolve_events(
        get_opensearch(), tenant_id=str(ctx.user.tenant_id), event_ids=list(alert.event_ids)
    )
    documents = [
        EvidenceDocument(event_id=event_id, found=event_id in found, document=found.get(event_id))
        for event_id in alert.event_ids
    ]
    return EvidenceResponse(
        alert_id=str(alert.id),
        display_id=alert.display_id,
        total_event_ids=len(alert.event_ids),
        resolved=len(found),
        missing_event_ids=[doc.event_id for doc in documents if not doc.found],
        documents=documents,
    )
