"""Incidents API (spec §22 `/incidents`, spec §14's IR workflow).

An incident is the case a team works: several alerts, the hosts and
accounts involved, the indicators found, tasks, and a timeline. Promoting an
alert links it rather than copying it — the alert keeps its own lifecycle,
and one alert can belong to more than one case (the same compromised host
often does).

Every mutating endpoint writes a timeline entry through the service layer,
which is what the acceptance criteria's "timeline completeness" property
depends on: nothing here bypasses `services/incidents.py` to touch the
database directly.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.auth.dependencies import AuthContext, require_permission
from app.core.opensearch import get_opensearch
from app.models.incidents import INCIDENT_STATUSES, Incident, IncidentTask
from app.schemas.incidents import (
    EvidenceDocument,
    EvidenceResponse,
    IncidentCounts,
    IncidentCreate,
    IncidentDetail,
    IncidentPublic,
    IncidentUpdate,
    LinkAlertRequest,
    LinkAssetRequest,
    LinkedAlertPublic,
    LinkIocRequest,
    LinkUserRequest,
    NotePublic,
    NoteRequest,
    TaskCreate,
    TaskPublic,
    TaskUpdate,
    TimelineEntryPublic,
    TransitionRequest,
)
from app.services import incidents as service
from app.services.evidence import resolve_events

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _incident_uuid(incident_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(incident_id)
    except ValueError as exc:
        # 404 rather than 422: a malformed id and one belonging to another
        # tenant must be indistinguishable from outside (THREAT_MODEL.md §3.2).
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc


def _public(incident: Incident) -> IncidentPublic:
    return IncidentPublic(
        id=str(incident.id),
        display_id=incident.display_id,
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        priority=incident.priority,
        status=incident.status,
        analyst_id=str(incident.analyst_id) if incident.analyst_id else None,
        resolution=incident.resolution,
        lessons_learned=incident.lessons_learned,
        detected_at=incident.detected_at,
        contained_at=incident.contained_at,
        closed_at=incident.closed_at,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


@router.get("", response_model=list[IncidentPublic])
async def list_incidents(
    status_filter: str | None = Query(default=None, alias="status", max_length=20),
    severity: str | None = Query(default=None, max_length=16),
    mine: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_permission("incident", "read")),
) -> list[IncidentPublic]:
    rows = await service.list_incidents(
        ctx.db,
        ctx.user.tenant_id,
        status=status_filter,
        severity=severity,
        assigned_to=ctx.user.id if mine else None,
        limit=limit,
        offset=offset,
    )
    return [_public(row) for row in rows]


@router.get("/counts", response_model=IncidentCounts)
async def incident_counts(
    ctx: AuthContext = Depends(require_permission("incident", "read")),
) -> IncidentCounts:
    counts = await service.count_by_status(ctx.db, ctx.user.tenant_id)
    return IncidentCounts(
        by_status=counts,
        open_total=sum(counts.get(state, 0) for state in service.OPEN_STATUSES),
    )


@router.post("", response_model=IncidentDetail, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> IncidentDetail:
    draft = service.IncidentDraft(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        priority=payload.priority,
        alert_ids=tuple(payload.alert_ids),
    )
    try:
        incident = await service.create_incident(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            draft=draft,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.IncidentNotFound as exc:
        # One of the alert_ids did not resolve in this tenant.
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    await ctx.db.commit()
    return await _detail(ctx, incident)


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: str,
    ctx: AuthContext = Depends(require_permission("incident", "read")),
) -> IncidentDetail:
    try:
        incident = await service.get_incident(
            ctx.db, ctx.user.tenant_id, _incident_uuid(incident_id)
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc
    return await _detail(ctx, incident)


async def _detail(ctx: AuthContext, incident: Incident) -> IncidentDetail:
    alerts = await service.linked_alerts(ctx.db, ctx.user.tenant_id, incident.id)
    linked = await service.linked_entities(ctx.db, ctx.user.tenant_id, incident.id)
    return IncidentDetail(
        **_public(incident).model_dump(),
        alerts=[
            LinkedAlertPublic(
                id=str(alert.id),
                display_id=alert.display_id,
                title=alert.title,
                severity=alert.severity,
                risk_score=alert.risk_score,
                status=alert.status,
            )
            for alert in alerts
        ],
        linked=linked,
    )


@router.patch("/{incident_id}", response_model=IncidentDetail)
async def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> IncidentDetail:
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no fields to update")
    try:
        incident = await service.update_incident(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            incident_id=_incident_uuid(incident_id),
            values=values,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc
    await ctx.db.commit()
    return await _detail(ctx, incident)


@router.post("/{incident_id}/status", response_model=IncidentDetail)
async def change_status(
    incident_id: str,
    payload: TransitionRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> IncidentDetail:
    if payload.status not in INCIDENT_STATUSES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"status must be one of {', '.join(INCIDENT_STATUSES)}",
        )
    try:
        incident = await service.transition(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            incident_id=_incident_uuid(incident_id),
            target=payload.status,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
            note=payload.note,
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc
    except service.InvalidTransition as exc:
        # 409, not 422: the request is well-formed, the incident is simply
        # not in a state where this move makes sense.
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await ctx.db.commit()
    return await _detail(ctx, incident)


# ---------------------------------------------------------------------------
# Linkage
# ---------------------------------------------------------------------------


@router.post("/{incident_id}/alerts", response_model=IncidentDetail)
async def link_alert(
    incident_id: str,
    payload: LinkAlertRequest,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> IncidentDetail:
    incident_uuid = _incident_uuid(incident_id)
    try:
        await service.get_incident(ctx.db, ctx.user.tenant_id, incident_uuid)
        await service.link_alert(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            incident_id=incident_uuid,
            alert_id=payload.alert_id,
            actor_id=ctx.user.id,
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    await ctx.db.commit()
    incident = await service.get_incident(ctx.db, ctx.user.tenant_id, incident_uuid)
    return await _detail(ctx, incident)


@router.post("/{incident_id}/assets", response_model=IncidentDetail)
async def link_asset(
    incident_id: str,
    payload: LinkAssetRequest,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> IncidentDetail:
    incident_uuid = _incident_uuid(incident_id)
    try:
        await service.get_incident(ctx.db, ctx.user.tenant_id, incident_uuid)
        await service.link_asset(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            incident_id=incident_uuid,
            asset_id=payload.asset_id,
            actor_id=ctx.user.id,
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    await ctx.db.commit()
    incident = await service.get_incident(ctx.db, ctx.user.tenant_id, incident_uuid)
    return await _detail(ctx, incident)


@router.post("/{incident_id}/iocs", response_model=IncidentDetail)
async def link_ioc(
    incident_id: str,
    payload: LinkIocRequest,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> IncidentDetail:
    incident_uuid = _incident_uuid(incident_id)
    try:
        await service.get_incident(ctx.db, ctx.user.tenant_id, incident_uuid)
        await service.link_ioc(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            incident_id=incident_uuid,
            ioc_id=payload.ioc_id,
            actor_id=ctx.user.id,
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    await ctx.db.commit()
    incident = await service.get_incident(ctx.db, ctx.user.tenant_id, incident_uuid)
    return await _detail(ctx, incident)


@router.post("/{incident_id}/users", response_model=IncidentDetail)
async def link_user(
    incident_id: str,
    payload: LinkUserRequest,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> IncidentDetail:
    incident_uuid = _incident_uuid(incident_id)
    try:
        incident = await service.get_incident(ctx.db, ctx.user.tenant_id, incident_uuid)
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    await service.link_user(
        ctx.db,
        tenant_id=ctx.user.tenant_id,
        incident_id=incident_uuid,
        username=payload.username,
        actor_id=ctx.user.id,
    )
    await ctx.db.commit()
    return await _detail(ctx, incident)


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


@router.get("/{incident_id}/notes", response_model=list[NotePublic])
async def list_notes(
    incident_id: str,
    ctx: AuthContext = Depends(require_permission("incident", "read")),
) -> list[NotePublic]:
    try:
        rows = await service.notes_for(ctx.db, ctx.user.tenant_id, _incident_uuid(incident_id))
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc
    return [
        NotePublic(
            id=str(row.id),
            author_id=str(row.author_id) if row.author_id else None,
            body=row.body,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post(
    "/{incident_id}/notes", response_model=NotePublic, status_code=status.HTTP_201_CREATED
)
async def add_note(
    incident_id: str,
    payload: NoteRequest,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> NotePublic:
    try:
        note = await service.add_note(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            incident_id=_incident_uuid(incident_id),
            body=payload.body,
            author_id=ctx.user.id,
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc
    await ctx.db.commit()
    return NotePublic(
        id=str(note.id),
        author_id=str(note.author_id) if note.author_id else None,
        body=note.body,
        created_at=note.created_at,
    )


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


def _task_public(task: IncidentTask) -> TaskPublic:
    return TaskPublic(
        id=str(task.id),
        title=task.title,
        description=task.description,
        assignee_id=str(task.assignee_id) if task.assignee_id else None,
        status=task.status,
        due_at=task.due_at,
        completed_at=task.completed_at,
        created_at=task.created_at,
    )


@router.get("/{incident_id}/tasks", response_model=list[TaskPublic])
async def list_tasks(
    incident_id: str,
    ctx: AuthContext = Depends(require_permission("incident", "read")),
) -> list[TaskPublic]:
    try:
        rows = await service.tasks_for(ctx.db, ctx.user.tenant_id, _incident_uuid(incident_id))
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc
    return [_task_public(row) for row in rows]


@router.post(
    "/{incident_id}/tasks", response_model=TaskPublic, status_code=status.HTTP_201_CREATED
)
async def create_task(
    incident_id: str,
    payload: TaskCreate,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> TaskPublic:
    try:
        task = await service.add_task(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            incident_id=_incident_uuid(incident_id),
            title=payload.title,
            description=payload.description,
            assignee_id=payload.assignee_id,
            due_at=payload.due_at,
            actor_id=ctx.user.id,
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc
    await ctx.db.commit()
    return _task_public(task)


@router.patch("/{incident_id}/tasks/{task_id}", response_model=TaskPublic)
async def update_task(
    incident_id: str,
    task_id: str,
    payload: TaskUpdate,
    ctx: AuthContext = Depends(require_permission("incident", "write")),
) -> TaskPublic:
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no fields to update")
    try:
        task = await service.update_task(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            incident_id=_incident_uuid(incident_id),
            task_id=_incident_uuid(task_id),
            values=values,
            actor_id=ctx.user.id,
        )
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    await ctx.db.commit()
    return _task_public(task)


# ---------------------------------------------------------------------------
# Timeline and evidence
# ---------------------------------------------------------------------------


@router.get("/{incident_id}/timeline", response_model=list[TimelineEntryPublic])
async def incident_timeline(
    incident_id: str,
    ctx: AuthContext = Depends(require_permission("incident", "read")),
) -> list[TimelineEntryPublic]:
    try:
        rows = await service.timeline_for(ctx.db, ctx.user.tenant_id, _incident_uuid(incident_id))
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc
    return [
        TimelineEntryPublic(
            kind=row.kind,
            summary=row.summary,
            detail=row.detail,
            actor_id=str(row.actor_id) if row.actor_id else None,
            occurred_at=row.occurred_at,
        )
        for row in rows
    ]


@router.get("/{incident_id}/evidence", response_model=EvidenceResponse)
async def incident_evidence(
    incident_id: str,
    ctx: AuthContext = Depends(require_permission("incident", "read")),
) -> EvidenceResponse:
    """Resolves every event id cited by every alert on the case back to the
    documents in the event store — the incident's evidence, rolled up from
    its alerts rather than duplicated onto it.

    Ids that no longer resolve are listed rather than omitted: "no
    evidence" and "the evidence expired" are different findings.
    """
    incident_uuid = _incident_uuid(incident_id)
    try:
        incident = await service.get_incident(ctx.db, ctx.user.tenant_id, incident_uuid)
    except service.IncidentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found") from exc

    event_ids = await service.evidence_event_ids(ctx.db, ctx.user.tenant_id, incident_uuid)
    found = await resolve_events(
        get_opensearch(), tenant_id=str(ctx.user.tenant_id), event_ids=event_ids
    )
    documents = [
        EvidenceDocument(event_id=event_id, found=event_id in found, document=found.get(event_id))
        for event_id in event_ids
    ]
    return EvidenceResponse(
        incident_id=str(incident.id),
        display_id=incident.display_id,
        total_event_ids=len(event_ids),
        resolved=len(found),
        missing_event_ids=[doc.event_id for doc in documents if not doc.found],
        documents=documents,
    )
