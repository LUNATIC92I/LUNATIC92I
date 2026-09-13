"""Alert lifecycle: creation with deduplication, and a real state machine.

Two things here are load-bearing.

**Deduplication.** A brute-force rule firing sixty times against one account
must produce one alert with sixty occurrences, not sixty alerts. The
`dedup_key` is derived from what makes two firings "the same thing" — the
rule and the entity it fired about — and a repeat inside the dedup window
updates the existing alert instead of creating another. Repeats are counted
and timestamped, never discarded: suppression that hides the fact it
happened is indistinguishable from a detection that stopped working.

**The state machine is explicit.** `TRANSITIONS` is the whole truth about
what may follow what; anything not listed is refused. A lifecycle enforced
by scattered `if` statements is one where the fifth caller invents a sixth
path, and an alert queue whose states are unreliable cannot be reported on
(MTTA/MTTR, false-positive rate) or trusted during a handover.

Reopening a closed alert is deliberately allowed but is its own transition
with its own audit action: new evidence arriving on something an analyst
called a false positive is exactly the case worth being able to find later.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.core import metrics
from app.models.alerts import Alert, AlertNote, AlertSequence, AlertTransition

logger = logging.getLogger(__name__)

DEFAULT_DEDUP_WINDOW_MINUTES = 60
# One alert cannot grow without bound: an entity that fires ten thousand
# times is one alert whose count says ten thousand, not one alert carrying
# ten thousand event ids into every API response.
MAX_EVENT_IDS = 200

NEW = "NEW"
IN_PROGRESS = "IN_PROGRESS"
ESCALATED = "ESCALATED"
FALSE_POSITIVE = "FALSE_POSITIVE"
RESOLVED = "RESOLVED"
CLOSED = "CLOSED"

# The lifecycle from spec §13, as data. Read it as "from → what may follow".
TRANSITIONS: dict[str, frozenset[str]] = {
    NEW: frozenset({IN_PROGRESS, ESCALATED, FALSE_POSITIVE, RESOLVED, CLOSED}),
    IN_PROGRESS: frozenset({ESCALATED, FALSE_POSITIVE, RESOLVED, CLOSED, NEW}),
    ESCALATED: frozenset({IN_PROGRESS, FALSE_POSITIVE, RESOLVED, CLOSED}),
    # Reopening: allowed, audited, and never implicit.
    FALSE_POSITIVE: frozenset({IN_PROGRESS, CLOSED}),
    RESOLVED: frozenset({IN_PROGRESS, CLOSED}),
    CLOSED: frozenset({IN_PROGRESS}),
}

# Transitions that end analyst work. Gated by `alert:close` rather than
# `alert:write`, which is what makes the L1/L2 distinction real instead of
# a label (see app/auth/permissions.py).
CLOSING = frozenset({FALSE_POSITIVE, RESOLVED, CLOSED})

# Statuses that count as "still open" for deduplication. A repeat of
# something already resolved starts a new alert: the analyst's decision was
# about what they saw, not about everything that will ever look like it.
OPEN_STATUSES = frozenset({NEW, IN_PROGRESS, ESCALATED})


class AlertNotFound(LookupError):
    pass


class InvalidTransition(ValueError):
    def __init__(self, current: str, target: str) -> None:
        allowed = ", ".join(sorted(TRANSITIONS.get(current, frozenset()))) or "nothing"
        super().__init__(f"cannot move an alert from {current} to {target}; allowed: {allowed}")
        self.current = current
        self.target = target


@dataclass(frozen=True)
class AlertInput:
    """What an alert is built from — a detection or a correlation, already
    scored and enriched."""

    tenant_id: uuid.UUID
    source: str  # "detection" | "correlation"
    title: str
    description: str
    severity: str
    confidence: int
    risk_score: int
    risk_bucket: str | None
    risk_explanation: dict[str, Any]
    dedup_key: str
    event_ids: list[str]
    detection_ids: list[str]
    evidence: dict[str, Any]
    mitre_techniques: list[str]
    rule_key: str | None = None
    correlation_id: str | None = None
    affected_user: str | None = None
    affected_host: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None


async def next_display_id(db: AsyncSession, tenant_id: uuid.UUID) -> str:
    """ALT-2026-000123, unique and gapless per tenant per year.

    Creating the counter row and locking it are two different problems, and
    conflating them is exactly what breaks under real concurrency: a plain
    "SELECT ... FOR UPDATE, and INSERT if it's missing" locks nothing on the
    first alert of a tenant's year, because there is no row yet for FOR
    UPDATE to hold — so N concurrent creators all see no row, all try to
    INSERT, and all but one fail with a unique-constraint violation. The fix
    is to make row creation itself the atomic, contended step: `INSERT ...
    ON CONFLICT DO NOTHING` either creates the row or (harmlessly) no-ops if
    another transaction just did, and only then do we SELECT ... FOR UPDATE
    a row that is now guaranteed to exist, which is what actually
    serializes the increment.
    """
    year = datetime.now(UTC).year
    await db.execute(
        insert(AlertSequence)
        .values(tenant_id=tenant_id, year=year, last_number=0)
        .on_conflict_do_nothing(index_elements=["tenant_id", "year"])
    )
    row = (
        await db.execute(
            select(AlertSequence)
            .where(AlertSequence.tenant_id == tenant_id, AlertSequence.year == year)
            .with_for_update()
        )
    ).scalar_one()

    row.last_number += 1
    return f"ALT-{year}-{row.last_number:06d}"


async def find_duplicate(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    dedup_key: str,
    *,
    window_minutes: int = DEFAULT_DEDUP_WINDOW_MINUTES,
) -> Alert | None:
    """An open alert with the same dedup key, seen recently enough to be the
    same episode."""
    cutoff = datetime.now(UTC) - timedelta(minutes=window_minutes)
    stmt = (
        select(Alert)
        .where(
            Alert.tenant_id == tenant_id,
            Alert.dedup_key == dedup_key,
            Alert.status.in_(OPEN_STATUSES),
            Alert.last_seen_at >= cutoff,
        )
        .order_by(Alert.last_seen_at.desc())
        .limit(1)
        .with_for_update()
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create_or_update(
    db: AsyncSession,
    payload: AlertInput,
    *,
    window_minutes: int = DEFAULT_DEDUP_WINDOW_MINUTES,
) -> tuple[Alert, bool]:
    """Creates an alert, or folds the input into the open one it duplicates.

    Returns (alert, created). The caller decides what to publish: a new
    alert is worth notifying about, a fifty-first occurrence usually is not.
    """
    existing = await find_duplicate(
        db, payload.tenant_id, payload.dedup_key, window_minutes=window_minutes
    )
    now = datetime.now(UTC)

    if existing is not None:
        existing.occurrence_count += 1
        existing.last_seen_at = now
        # Keep the worst severity and score seen in the episode: an
        # escalating attack must not be hidden behind the first, milder
        # firing that opened the alert.
        if payload.risk_score > existing.risk_score:
            existing.risk_score = payload.risk_score
            existing.risk_bucket = payload.risk_bucket
            existing.risk_explanation = payload.risk_explanation
        if _severity_rank(payload.severity) > _severity_rank(existing.severity):
            existing.severity = payload.severity
        merged = [*existing.event_ids, *payload.event_ids]
        existing.event_ids = merged[-MAX_EVENT_IDS:]
        existing.detection_ids = [*existing.detection_ids, *payload.detection_ids][-MAX_EVENT_IDS:]
        await db.flush()

        metrics.alerts_deduplicated_total.labels(source=payload.source).inc()
        return existing, False

    alert = Alert(
        tenant_id=payload.tenant_id,
        display_id=await next_display_id(db, payload.tenant_id),
        rule_key=payload.rule_key,
        correlation_id=payload.correlation_id,
        source=payload.source,
        title=payload.title[:300],
        description=payload.description,
        severity=payload.severity,
        confidence=payload.confidence,
        risk_score=payload.risk_score,
        risk_bucket=payload.risk_bucket,
        risk_explanation=payload.risk_explanation,
        event_ids=payload.event_ids[-MAX_EVENT_IDS:],
        detection_ids=payload.detection_ids[-MAX_EVENT_IDS:],
        evidence=payload.evidence,
        affected_user=payload.affected_user,
        affected_host=payload.affected_host,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        mitre_techniques=payload.mitre_techniques,
        status=NEW,
        dedup_key=payload.dedup_key,
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(alert)
    await db.flush()
    db.add(
        AlertTransition(
            alert_id=alert.id,
            tenant_id=payload.tenant_id,
            from_status=None,
            to_status=NEW,
            note="alert created",
        )
    )
    await db.flush()

    metrics.alerts_created_total.labels(source=payload.source, severity=payload.severity).inc()
    return alert, True


_SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")


def _severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


async def get_alert(db: AsyncSession, tenant_id: uuid.UUID, alert_id: uuid.UUID) -> Alert:
    stmt = select(Alert).where(Alert.id == alert_id, Alert.tenant_id == tenant_id)
    alert = (await db.execute(stmt)).scalar_one_or_none()
    if alert is None:
        raise AlertNotFound(str(alert_id))
    return alert


async def list_alerts(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    status: str | None = None,
    severity: str | None = None,
    assigned_to: uuid.UUID | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Alert]:
    stmt = select(Alert).where(Alert.tenant_id == tenant_id)
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if assigned_to:
        stmt = stmt.where(Alert.analyst_id == assigned_to)
    # Highest risk first, then most recent: the queue's order is the SOC's
    # working order, so it is not an afterthought.
    stmt = stmt.order_by(Alert.risk_score.desc(), Alert.last_seen_at.desc())
    return list((await db.execute(stmt.limit(limit).offset(offset))).scalars())


async def count_by_status(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, int]:
    rows = (
        await db.execute(
            select(Alert.status, func.count())
            .where(Alert.tenant_id == tenant_id)
            .group_by(Alert.status)
        )
    ).all()
    return {status: int(count) for status, count in rows}


async def transition(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    target: str,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
    note: str | None = None,
) -> Alert:
    """Moves an alert through the lifecycle, or refuses.

    Every change writes a transition row and an audit entry in the same
    transaction as the change itself — "who called this a false positive,
    and when" is the question asked after every missed incident.
    """
    alert = await get_alert(db, tenant_id, alert_id)
    current = alert.status

    if target == current:
        # Not an error, but not a transition either: recording it would fill
        # the history with noise from a double-clicked button.
        return alert
    if target not in TRANSITIONS.get(current, frozenset()):
        raise InvalidTransition(current, target)

    now = datetime.now(UTC)
    alert.status = target
    if target == IN_PROGRESS and alert.acknowledged_at is None:
        # First acknowledgement only: MTTA is about the first human contact,
        # and re-opening later must not rewrite it.
        alert.acknowledged_at = now
    if target in CLOSING:
        alert.closed_at = now
        if note:
            alert.resolution_note = note
    else:
        alert.closed_at = None

    if actor_id and alert.analyst_id is None and target != NEW:
        # Touching an alert takes ownership of it, unless someone else
        # already owns it — an unassigned in-progress alert is how work
        # falls between two analysts.
        alert.analyst_id = actor_id

    db.add(
        AlertTransition(
            alert_id=alert.id,
            tenant_id=tenant_id,
            from_status=current,
            to_status=target,
            actor_id=actor_id,
            note=note,
        )
    )
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action=_audit_action(current, target),
        object_type="alert",
        object_id=alert.display_id,
        before_state={"status": current},
        after_state={"status": target, "note": note},
        result="success",
    )
    await db.flush()

    metrics.alert_transitions_total.labels(to_status=target).inc()
    return alert


def _audit_action(current: str, target: str) -> str:
    if target in CLOSING:
        return f"CLOSE_ALERT_{target}"
    if current in CLOSING:
        # Its own action: new evidence on something already dismissed is
        # exactly what a reviewer goes looking for.
        return "REOPEN_ALERT"
    return f"ALERT_{target}"


async def assign(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    analyst_id: uuid.UUID | None,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> Alert:
    alert = await get_alert(db, tenant_id, alert_id)
    before = str(alert.analyst_id) if alert.analyst_id else None
    alert.analyst_id = analyst_id
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="ASSIGN_ALERT",
        object_type="alert",
        object_id=alert.display_id,
        before_state={"analyst_id": before},
        after_state={"analyst_id": str(analyst_id) if analyst_id else None},
        result="success",
    )
    await db.flush()
    return alert


async def add_note(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    alert_id: uuid.UUID,
    body: str,
    author_id: uuid.UUID | None,
) -> AlertNote:
    await get_alert(db, tenant_id, alert_id)
    note = AlertNote(alert_id=alert_id, tenant_id=tenant_id, author_id=author_id, body=body)
    db.add(note)
    await db.flush()
    return note


async def notes_for(db: AsyncSession, tenant_id: uuid.UUID, alert_id: uuid.UUID) -> list[AlertNote]:
    await get_alert(db, tenant_id, alert_id)
    stmt = (
        select(AlertNote)
        .where(AlertNote.alert_id == alert_id, AlertNote.tenant_id == tenant_id)
        .order_by(AlertNote.created_at)
    )
    return list((await db.execute(stmt)).scalars())


async def transitions_for(
    db: AsyncSession, tenant_id: uuid.UUID, alert_id: uuid.UUID
) -> list[AlertTransition]:
    await get_alert(db, tenant_id, alert_id)
    stmt = (
        select(AlertTransition)
        .where(AlertTransition.alert_id == alert_id, AlertTransition.tenant_id == tenant_id)
        .order_by(AlertTransition.occurred_at)
    )
    return list((await db.execute(stmt)).scalars())
