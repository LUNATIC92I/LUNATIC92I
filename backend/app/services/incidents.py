"""Incident workflow, linkage, and the timeline that records all of it.

The state machine mirrors the IR lifecycle (spec §14, NIST 800-61): you
triage before you investigate, contain before you eradicate, and recover
before you close. It is not a strict pipeline — real incidents go backwards,
and containment that failed sends you back to investigation — but it is not
a free-for-all either: jumping straight from NEW to RECOVERY is a mistake,
not a shortcut, and the machine says so.

**Every mutating operation writes a timeline entry.** That is the invariant
this module is built around, and it is what the acceptance criteria's
"timeline completeness" test checks. An incident record whose history is
partial is worse than none: it looks authoritative and is not.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.core import metrics
from app.models.alerts import Alert
from app.models.assets import Asset
from app.models.incidents import (
    Incident,
    IncidentAlert,
    IncidentAsset,
    IncidentIoc,
    IncidentNote,
    IncidentSequence,
    IncidentTask,
    IncidentTimeline,
    IncidentUser,
)
from app.models.threat_intel import Ioc

logger = logging.getLogger(__name__)

NEW = "NEW"
TRIAGE = "TRIAGE"
INVESTIGATION = "INVESTIGATION"
CONTAINMENT = "CONTAINMENT"
ERADICATION = "ERADICATION"
RECOVERY = "RECOVERY"
CLOSED = "CLOSED"

# Forward through the lifecycle, backward when a step turns out to be
# premature, and closable from anywhere — an incident that turns out to be
# nothing should not have to be walked through five stages to file it.
TRANSITIONS: dict[str, frozenset[str]] = {
    NEW: frozenset({TRIAGE, INVESTIGATION, CLOSED}),
    TRIAGE: frozenset({INVESTIGATION, CONTAINMENT, CLOSED, NEW}),
    INVESTIGATION: frozenset({CONTAINMENT, ERADICATION, TRIAGE, CLOSED}),
    CONTAINMENT: frozenset({ERADICATION, INVESTIGATION, CLOSED}),
    ERADICATION: frozenset({RECOVERY, CONTAINMENT, INVESTIGATION, CLOSED}),
    RECOVERY: frozenset({CLOSED, ERADICATION, INVESTIGATION}),
    # Reopening is deliberate and audited: "we thought it was over" is a
    # thing that happens, and hiding it helps nobody.
    CLOSED: frozenset({INVESTIGATION, TRIAGE}),
}

OPEN_STATUSES = frozenset(TRANSITIONS) - {CLOSED}

SEVERITY_TO_PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}


class IncidentNotFound(LookupError):
    pass


class InvalidTransition(ValueError):
    def __init__(self, current: str, target: str) -> None:
        allowed = ", ".join(sorted(TRANSITIONS.get(current, frozenset()))) or "nothing"
        super().__init__(
            f"cannot move an incident from {current} to {target}; allowed: {allowed}"
        )
        self.current = current
        self.target = target


@dataclass(frozen=True)
class IncidentDraft:
    title: str
    description: str | None = None
    severity: str = "medium"
    priority: str | None = None
    alert_ids: tuple[uuid.UUID, ...] = ()


async def next_display_id(db: AsyncSession, tenant_id: uuid.UUID) -> str:
    """INC-2026-000123 — unique and gapless per tenant per year.

    Creating the counter row and locking it are two different problems, and
    conflating them is exactly what breaks under real concurrency: a plain
    "SELECT ... FOR UPDATE, and INSERT if it's missing" locks nothing on a
    tenant's first incident of the year, because there is no row yet for
    FOR UPDATE to hold — so N concurrent creators all see no row, all try
    to INSERT, and all but one fail with a unique-constraint violation
    (caught by this phase's own concurrency test). The fix is to make row
    creation itself the atomic, contended step: `INSERT ... ON CONFLICT DO
    NOTHING` either creates the row or (harmlessly) no-ops if another
    transaction just did, and only then do we SELECT ... FOR UPDATE a row
    that is now guaranteed to exist, which is what actually serializes the
    increment.
    """
    year = datetime.now(UTC).year
    await db.execute(
        insert(IncidentSequence)
        .values(tenant_id=tenant_id, year=year, last_number=0)
        .on_conflict_do_nothing(index_elements=["tenant_id", "year"])
    )
    row = (
        await db.execute(
            select(IncidentSequence)
            .where(IncidentSequence.tenant_id == tenant_id, IncidentSequence.year == year)
            .with_for_update()
        )
    ).scalar_one()

    row.last_number += 1
    return f"INC-{year}-{row.last_number:06d}"


async def record_timeline(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    kind: str,
    summary: str,
    detail: dict[str, Any] | None = None,
    actor_id: uuid.UUID | None = None,
) -> IncidentTimeline:
    entry = IncidentTimeline(
        tenant_id=tenant_id,
        incident_id=incident_id,
        kind=kind,
        summary=summary,
        detail=detail or {},
        actor_id=actor_id,
    )
    db.add(entry)
    await db.flush()
    return entry


async def get_incident(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> Incident:
    stmt = select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    incident = (await db.execute(stmt)).scalar_one_or_none()
    if incident is None:
        raise IncidentNotFound(str(incident_id))
    return incident


async def list_incidents(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    status: str | None = None,
    severity: str | None = None,
    assigned_to: uuid.UUID | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Incident]:
    stmt = select(Incident).where(Incident.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if assigned_to:
        stmt = stmt.where(Incident.analyst_id == assigned_to)
    stmt = stmt.order_by(Incident.priority, Incident.created_at.desc())
    return list((await db.execute(stmt.limit(limit).offset(offset))).scalars())


async def count_by_status(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, int]:
    rows = (
        await db.execute(
            select(Incident.status, func.count())
            .where(Incident.tenant_id == tenant_id)
            .group_by(Incident.status)
        )
    ).all()
    return {status: int(count) for status, count in rows}


async def create_incident(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    draft: IncidentDraft,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> Incident:
    """Opens a case, optionally promoting alerts into it.

    Promoting an alert is not a copy: the alert keeps its own lifecycle and
    is *linked*, so closing the incident does not silently rewrite the alert
    queue, and an alert can belong to more than one case (the same
    compromised host often does).
    """
    incident = Incident(
        tenant_id=tenant_id,
        display_id=await next_display_id(db, tenant_id),
        title=draft.title[:300],
        description=draft.description,
        severity=draft.severity,
        priority=draft.priority or SEVERITY_TO_PRIORITY.get(draft.severity, "P3"),
        status=NEW,
        analyst_id=actor_id,
        detected_at=datetime.now(UTC),
    )
    db.add(incident)
    await db.flush()

    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident.id,
        kind="created",
        summary=f"{incident.display_id} opened",
        detail={"severity": incident.severity, "priority": incident.priority},
        actor_id=actor_id,
    )

    for alert_id in draft.alert_ids:
        await link_alert(
            db, tenant_id=tenant_id, incident_id=incident.id, alert_id=alert_id, actor_id=actor_id
        )

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="CREATE_INCIDENT",
        object_type="incident",
        object_id=incident.display_id,
        after_state={
            "title": incident.title,
            "severity": incident.severity,
            "alerts": len(draft.alert_ids),
        },
        result="success",
    )
    metrics.incidents_created_total.labels(severity=incident.severity).inc()
    return incident


async def transition(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    target: str,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
    note: str | None = None,
) -> Incident:
    incident = await get_incident(db, tenant_id, incident_id)
    current = incident.status
    if target == current:
        return incident
    if target not in TRANSITIONS.get(current, frozenset()):
        raise InvalidTransition(current, target)

    now = datetime.now(UTC)
    incident.status = target
    if target == CONTAINMENT and incident.contained_at is None:
        # First containment only: an incident that goes back to
        # investigation and is contained again has not been contained twice
        # for the purposes of MTTC.
        incident.contained_at = now
    if target == CLOSED:
        incident.closed_at = now
        if note:
            incident.resolution = note
    else:
        incident.closed_at = None

    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident.id,
        kind="status_change",
        summary=f"{current} → {target}",
        detail={"from": current, "to": target, "note": note},
        actor_id=actor_id,
    )
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="REOPEN_INCIDENT" if current == CLOSED else f"INCIDENT_{target}",
        object_type="incident",
        object_id=incident.display_id,
        before_state={"status": current},
        after_state={"status": target, "note": note},
        result="success",
    )
    await db.flush()
    # `updated_at` has an onupdate=func.now() server-side default, which an
    # UPDATE flush does not fetch back automatically (unlike an INSERT's
    # RETURNING). Left unrefreshed, the attribute is expired-on-access, and
    # a caller reading it after a later commit hits a lazy load with no
    # event loop to await it in. Refreshing here, inside the same
    # transaction, is cheaper than teaching every caller about the trap.
    await db.refresh(incident)
    metrics.incident_transitions_total.labels(to_status=target).inc()
    return incident


async def update_incident(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    values: dict[str, Any],
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> Incident:
    incident = await get_incident(db, tenant_id, incident_id)
    before = {key: getattr(incident, key) for key in values}
    for key, value in values.items():
        setattr(incident, key, value)
    await db.flush()

    if "analyst_id" in values:
        await record_timeline(
            db,
            tenant_id=tenant_id,
            incident_id=incident.id,
            kind="assignment",
            summary=f"assigned to {values['analyst_id'] or 'nobody'}",
            detail={"analyst_id": str(values["analyst_id"]) if values["analyst_id"] else None},
            actor_id=actor_id,
        )

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="UPDATE_INCIDENT",
        object_type="incident",
        object_id=incident.display_id,
        before_state={key: str(value) for key, value in before.items()},
        after_state={key: str(getattr(incident, key)) for key in values},
        result="success",
    )
    # Same onupdate/refresh note as transition() above.
    await db.refresh(incident)
    return incident


# ---------------------------------------------------------------------------
# Linkage
# ---------------------------------------------------------------------------


async def link_alert(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    alert_id: uuid.UUID,
    actor_id: uuid.UUID | None,
) -> bool:
    """Links an alert. Returns False if it was already linked.

    The alert is checked to exist *in this tenant* first: linking is a
    cross-object operation, and an unchecked id here would be an IDOR into
    another tenant's alert queue (THREAT_MODEL.md §3.2).
    """
    alert = (
        await db.execute(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
        )
    ).scalar_one_or_none()
    if alert is None:
        raise IncidentNotFound(f"alert {alert_id}")

    existing = (
        await db.execute(
            select(IncidentAlert).where(
                IncidentAlert.incident_id == incident_id, IncidentAlert.alert_id == alert_id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return False

    db.add(IncidentAlert(tenant_id=tenant_id, incident_id=incident_id, alert_id=alert_id))
    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        kind="alert_linked",
        summary=f"alert {alert.display_id} linked",
        detail={"alert_id": str(alert_id), "display_id": alert.display_id, "title": alert.title},
        actor_id=actor_id,
    )
    await db.flush()
    return True


async def link_asset(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    asset_id: uuid.UUID,
    actor_id: uuid.UUID | None,
) -> bool:
    asset = (
        await db.execute(
            select(Asset).where(Asset.id == asset_id, Asset.tenant_id == tenant_id)
        )
    ).scalar_one_or_none()
    if asset is None:
        raise IncidentNotFound(f"asset {asset_id}")

    existing = (
        await db.execute(
            select(IncidentAsset).where(
                IncidentAsset.incident_id == incident_id, IncidentAsset.asset_id == asset_id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return False

    db.add(IncidentAsset(tenant_id=tenant_id, incident_id=incident_id, asset_id=asset_id))
    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        kind="asset_linked",
        summary=f"asset {asset.hostname or asset.id} linked",
        detail={"asset_id": str(asset_id), "hostname": asset.hostname},
        actor_id=actor_id,
    )
    await db.flush()
    return True


async def link_ioc(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    ioc_id: uuid.UUID,
    actor_id: uuid.UUID | None,
) -> bool:
    ioc = (
        await db.execute(
            select(Ioc).where(
                Ioc.id == ioc_id,
                # A shared feed indicator (tenant_id IS NULL) is legitimately
                # linkable: the incident is about *this* tenant seeing it.
                (Ioc.tenant_id == tenant_id) | (Ioc.tenant_id.is_(None)),
            )
        )
    ).scalar_one_or_none()
    if ioc is None:
        raise IncidentNotFound(f"ioc {ioc_id}")

    existing = (
        await db.execute(
            select(IncidentIoc).where(
                IncidentIoc.incident_id == incident_id, IncidentIoc.ioc_id == ioc_id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return False

    db.add(IncidentIoc(tenant_id=tenant_id, incident_id=incident_id, ioc_id=ioc_id))
    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        kind="ioc_linked",
        summary=f"indicator {ioc.value} linked",
        detail={"ioc_id": str(ioc_id), "value": ioc.value, "type": ioc.ioc_type},
        actor_id=actor_id,
    )
    await db.flush()
    return True


async def link_user(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    username: str,
    actor_id: uuid.UUID | None,
) -> bool:
    existing = (
        await db.execute(
            select(IncidentUser).where(
                IncidentUser.incident_id == incident_id, IncidentUser.username == username
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return False

    db.add(IncidentUser(tenant_id=tenant_id, incident_id=incident_id, username=username))
    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        kind="note",
        summary=f"account {username} linked",
        detail={"username": username},
        actor_id=actor_id,
    )
    await db.flush()
    return True


# ---------------------------------------------------------------------------
# Notes, tasks, reads
# ---------------------------------------------------------------------------


async def add_note(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    body: str,
    author_id: uuid.UUID | None,
) -> IncidentNote:
    await get_incident(db, tenant_id, incident_id)
    note = IncidentNote(
        tenant_id=tenant_id, incident_id=incident_id, author_id=author_id, body=body
    )
    db.add(note)
    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        kind="note",
        # The first line only: the timeline is a summary view, and the note
        # itself is one click away.
        summary=body.splitlines()[0][:200],
        detail={"length": len(body)},
        actor_id=author_id,
    )
    await db.flush()
    return note


async def add_task(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    title: str,
    description: str | None,
    assignee_id: uuid.UUID | None,
    due_at: datetime | None,
    actor_id: uuid.UUID | None,
) -> IncidentTask:
    await get_incident(db, tenant_id, incident_id)
    task = IncidentTask(
        tenant_id=tenant_id,
        incident_id=incident_id,
        title=title[:300],
        description=description,
        assignee_id=assignee_id,
        due_at=due_at,
    )
    db.add(task)
    await db.flush()
    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        kind="task",
        summary=f"task created: {task.title}",
        detail={"task_id": str(task.id), "status": task.status},
        actor_id=actor_id,
    )
    return task


async def update_task(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    task_id: uuid.UUID,
    values: dict[str, Any],
    actor_id: uuid.UUID | None,
) -> IncidentTask:
    task = (
        await db.execute(
            select(IncidentTask).where(
                IncidentTask.id == task_id,
                IncidentTask.incident_id == incident_id,
                IncidentTask.tenant_id == tenant_id,
            )
        )
    ).scalar_one_or_none()
    if task is None:
        raise IncidentNotFound(f"task {task_id}")

    before_status = task.status
    for key, value in values.items():
        setattr(task, key, value)
    if values.get("status") == "done" and task.completed_at is None:
        task.completed_at = datetime.now(UTC)
    await db.flush()

    await record_timeline(
        db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        kind="task",
        summary=f"task {task.title}: {before_status} → {task.status}",
        detail={"task_id": str(task.id), "from": before_status, "to": task.status},
        actor_id=actor_id,
    )
    return task


async def timeline_for(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> list[IncidentTimeline]:
    await get_incident(db, tenant_id, incident_id)
    stmt = (
        select(IncidentTimeline)
        .where(
            IncidentTimeline.incident_id == incident_id,
            IncidentTimeline.tenant_id == tenant_id,
        )
        .order_by(IncidentTimeline.occurred_at, IncidentTimeline.id)
    )
    return list((await db.execute(stmt)).scalars())


async def notes_for(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> list[IncidentNote]:
    await get_incident(db, tenant_id, incident_id)
    stmt = (
        select(IncidentNote)
        .where(IncidentNote.incident_id == incident_id, IncidentNote.tenant_id == tenant_id)
        .order_by(IncidentNote.created_at)
    )
    return list((await db.execute(stmt)).scalars())


async def tasks_for(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> list[IncidentTask]:
    await get_incident(db, tenant_id, incident_id)
    stmt = (
        select(IncidentTask)
        .where(IncidentTask.incident_id == incident_id, IncidentTask.tenant_id == tenant_id)
        .order_by(IncidentTask.created_at)
    )
    return list((await db.execute(stmt)).scalars())


async def linked_alerts(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> list[Alert]:
    stmt = (
        select(Alert)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .where(IncidentAlert.incident_id == incident_id, IncidentAlert.tenant_id == tenant_id)
        .order_by(Alert.risk_score.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def linked_entities(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> dict[str, list[dict[str, Any]]]:
    assets = (
        await db.execute(
            select(Asset)
            .join(IncidentAsset, IncidentAsset.asset_id == Asset.id)
            .where(IncidentAsset.incident_id == incident_id, IncidentAsset.tenant_id == tenant_id)
        )
    ).scalars()
    iocs = (
        await db.execute(
            select(Ioc)
            .join(IncidentIoc, IncidentIoc.ioc_id == Ioc.id)
            .where(IncidentIoc.incident_id == incident_id, IncidentIoc.tenant_id == tenant_id)
        )
    ).scalars()
    users = (
        await db.execute(
            select(IncidentUser).where(
                IncidentUser.incident_id == incident_id, IncidentUser.tenant_id == tenant_id
            )
        )
    ).scalars()

    return {
        "assets": [
            {"id": str(asset.id), "hostname": asset.hostname, "criticality": asset.criticality}
            for asset in assets
        ],
        "iocs": [
            {
                "id": str(ioc.id),
                "value": ioc.value,
                "type": ioc.ioc_type,
                "classification": ioc.classification,
            }
            for ioc in iocs
        ],
        "users": [{"username": user.username} for user in users],
    }


async def evidence_event_ids(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> list[str]:
    """Every event id cited by every alert on the case — the incident's
    evidence, rolled up from its alerts rather than duplicated onto it."""
    alerts = await linked_alerts(db, tenant_id, incident_id)
    seen: list[str] = []
    for alert in alerts:
        for event_id in alert.event_ids:
            if event_id not in seen:
                seen.append(event_id)
    return seen
