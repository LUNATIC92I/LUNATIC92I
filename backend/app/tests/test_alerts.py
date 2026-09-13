"""Alert lifecycle, deduplication, and the worker that creates alerts.

The state machine is the part worth being strict about: an alert queue whose
states are unreliable cannot be reported on (MTTA, MTTR, false-positive
rate) and cannot survive a shift handover.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text

from app.core.db import async_session_factory, tenant_scoped_session
from app.core.eventbus import (
    TOPIC_ALERTS_CREATED,
    TOPIC_CORRELATIONS_CREATED,
    TOPIC_DETECTIONS_CREATED,
    EventBusMessage,
    InMemoryEventBus,
)
from app.models.alerts import Alert, AlertTransition
from app.models.identity import Organization
from app.services import alerts as service
from app.services.alerts import (
    CLOSED,
    ESCALATED,
    FALSE_POSITIVE,
    IN_PROGRESS,
    NEW,
    RESOLVED,
    TRANSITIONS,
    AlertInput,
    InvalidTransition,
)
from app.workers.alert_worker import CONSUMER_GROUP, AlertWorker


async def _tenant() -> uuid.UUID:
    slug = f"t{uuid.uuid4().hex[:12]}"
    async with async_session_factory() as db:
        org = Organization(name=slug, slug=slug)
        db.add(org)
        await db.commit()
        return org.id


def _input(tenant_id: uuid.UUID, **overrides) -> AlertInput:
    payload = {
        "tenant_id": tenant_id,
        "source": "detection",
        "rule_key": "AUTH-001",
        "title": "Brute force against a single account",
        "description": "AUTH-001 fired for user.name=alice",
        "severity": "high",
        "confidence": 75,
        "risk_score": 65,
        "risk_bucket": "HIGH",
        "risk_explanation": {"score": 65},
        "dedup_key": "detection:AUTH-001:user.name=alice",
        "event_ids": [str(uuid.uuid4())],
        "detection_ids": [str(uuid.uuid4())],
        "evidence": {"hostname": "web01"},
        "mitre_techniques": ["T1110.001"],
        "affected_user": "alice",
        "affected_host": "web01",
        "source_ip": "203.0.113.5",
    }
    payload.update(overrides)
    return AlertInput(**payload)


async def _create(tenant_id: uuid.UUID, **overrides) -> Alert:
    async with tenant_scoped_session(tenant_id) as db:
        alert, _created = await service.create_or_update(db, _input(tenant_id, **overrides))
        await db.commit()
        return alert


# ---------------------------------------------------------------------------
# Creation and display ids
# ---------------------------------------------------------------------------


async def test_an_alert_carries_its_detection_context() -> None:
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    assert alert.status == NEW
    assert alert.display_id.startswith(f"ALT-{datetime.now(UTC).year}-")
    assert alert.occurrence_count == 1
    assert alert.risk_score == 65
    assert alert.mitre_techniques == ["T1110.001"]
    assert alert.event_ids, "an alert with no evidence lineage is not actionable"


async def test_display_ids_are_sequential_and_per_tenant() -> None:
    tenant_a, tenant_b = await _tenant(), await _tenant()

    first = await _create(tenant_a, dedup_key="a1")
    second = await _create(tenant_a, dedup_key="a2")
    other = await _create(tenant_b, dedup_key="b1")

    year = datetime.now(UTC).year
    assert first.display_id == f"ALT-{year}-000001"
    assert second.display_id == f"ALT-{year}-000002"
    # Each tenant counts from one: display ids are quoted in tickets and
    # must not leak how much traffic anybody else has.
    assert other.display_id == f"ALT-{year}-000001"


async def test_creating_an_alert_records_its_first_transition() -> None:
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        history = await service.transitions_for(db, tenant_id, alert.id)

    assert [(row.from_status, row.to_status) for row in history] == [(None, NEW)]


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


async def test_a_repeat_folds_into_the_open_alert() -> None:
    """Sixty firings against one account are one alert with sixty
    occurrences: a queue nobody can read is a queue nobody reads."""
    tenant_id = await _tenant()
    await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        alert, created = await service.create_or_update(db, _input(tenant_id))
        await db.commit()
        total = len(await service.list_alerts(db, tenant_id))

    assert created is False
    assert alert.occurrence_count == 2
    assert total == 1


async def test_a_different_entity_is_a_different_alert() -> None:
    tenant_id = await _tenant()
    await _create(tenant_id)
    await _create(tenant_id, dedup_key="detection:AUTH-001:user.name=bob", affected_user="bob")

    async with tenant_scoped_session(tenant_id) as db:
        assert len(await service.list_alerts(db, tenant_id)) == 2


async def test_a_repeat_outside_the_window_starts_a_new_alert() -> None:
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        stored = await service.get_alert(db, tenant_id, alert.id)
        stored.last_seen_at = datetime.now(UTC) - timedelta(hours=3)
        await db.commit()

        _new_alert, created = await service.create_or_update(
            db, _input(tenant_id), window_minutes=60
        )
        await db.commit()
        assert created is True
        assert len(await service.list_alerts(db, tenant_id)) == 2


async def test_a_repeat_of_a_resolved_alert_starts_a_new_one() -> None:
    """The analyst's decision was about what they saw, not about everything
    that will ever look like it."""
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=RESOLVED, actor_id=None
        )
        await db.commit()

        _second, created = await service.create_or_update(db, _input(tenant_id))
        await db.commit()

    assert created is True


async def test_a_worse_repeat_raises_the_alerts_severity_and_score() -> None:
    """An escalating attack must not stay hidden behind the milder firing
    that happened to open the alert."""
    tenant_id = await _tenant()
    await _create(tenant_id, severity="medium", risk_score=40, risk_bucket="MEDIUM")

    async with tenant_scoped_session(tenant_id) as db:
        alert, _created = await service.create_or_update(
            db, _input(tenant_id, severity="critical", risk_score=95, risk_bucket="CRITICAL")
        )
        await db.commit()

    assert alert.severity == "critical"
    assert alert.risk_score == 95
    assert alert.risk_bucket == "CRITICAL"


async def test_a_milder_repeat_does_not_lower_the_alert() -> None:
    tenant_id = await _tenant()
    await _create(tenant_id, severity="critical", risk_score=95)

    async with tenant_scoped_session(tenant_id) as db:
        alert, _created = await service.create_or_update(
            db, _input(tenant_id, severity="low", risk_score=10)
        )
        await db.commit()

    assert alert.severity == "critical"
    assert alert.risk_score == 95


async def test_event_ids_accumulate_but_stay_bounded() -> None:
    tenant_id = await _tenant()
    await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        for _ in range(5):
            alert, _created = await service.create_or_update(db, _input(tenant_id))
        await db.commit()

    assert alert.occurrence_count == 6
    assert len(alert.event_ids) == 6
    assert len(alert.event_ids) <= service.MAX_EVENT_IDS


# ---------------------------------------------------------------------------
# The state machine
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("start", "target"),
    [
        (NEW, IN_PROGRESS),
        (NEW, ESCALATED),
        (NEW, FALSE_POSITIVE),
        (IN_PROGRESS, ESCALATED),
        (IN_PROGRESS, RESOLVED),
        (ESCALATED, RESOLVED),
        (RESOLVED, CLOSED),
        (FALSE_POSITIVE, CLOSED),
        # Reopening: allowed, but as its own explicit transition.
        (CLOSED, IN_PROGRESS),
        (RESOLVED, IN_PROGRESS),
    ],
)
async def test_valid_transitions(start: str, target: str) -> None:
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        if start != NEW:
            await _force_status(db, alert.id, start)
        moved = await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=target, actor_id=None
        )
        await db.commit()

    assert moved.status == target


@pytest.mark.parametrize(
    ("start", "target"),
    [
        (FALSE_POSITIVE, RESOLVED),
        (RESOLVED, FALSE_POSITIVE),
        (RESOLVED, ESCALATED),
        (CLOSED, RESOLVED),
        (CLOSED, ESCALATED),
        (FALSE_POSITIVE, NEW),
    ],
)
async def test_invalid_transitions_are_refused(start: str, target: str) -> None:
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await _force_status(db, alert.id, start)
        with pytest.raises(InvalidTransition):
            await service.transition(
                db, tenant_id=tenant_id, alert_id=alert.id, target=target, actor_id=None
            )


async def _force_status(db, alert_id: uuid.UUID, status: str) -> None:
    """Sets a status directly, to set up a transition test from a state the
    machine would otherwise need several steps to reach."""
    await db.execute(
        text("UPDATE alerts SET status = :status WHERE id = :id"),
        {"status": status, "id": alert_id},
    )
    await db.commit()


def test_the_state_machine_covers_every_status() -> None:
    from app.models.alerts import ALERT_STATUSES

    assert set(TRANSITIONS) == set(ALERT_STATUSES)
    for targets in TRANSITIONS.values():
        assert targets <= set(ALERT_STATUSES)


async def test_moving_to_the_same_status_is_a_no_op_not_an_error() -> None:
    """A double-clicked button must not fill the history with noise."""
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=IN_PROGRESS, actor_id=None
        )
        await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=IN_PROGRESS, actor_id=None
        )
        await db.commit()
        history = await service.transitions_for(db, tenant_id, alert.id)

    assert [row.to_status for row in history] == [NEW, IN_PROGRESS]


async def test_acknowledgement_time_is_recorded_once() -> None:
    """MTTA is about first human contact; reopening later must not rewrite
    it."""
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        acknowledged = await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=IN_PROGRESS, actor_id=None
        )
        first_time = acknowledged.acknowledged_at
        await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=RESOLVED, actor_id=None
        )
        reopened = await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=IN_PROGRESS, actor_id=None
        )
        await db.commit()

    assert first_time is not None
    assert reopened.acknowledged_at == first_time
    # Reopening clears the closure, so the alert is genuinely open again.
    assert reopened.closed_at is None


async def test_closing_records_the_resolution_note() -> None:
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        closed = await service.transition(
            db,
            tenant_id=tenant_id,
            alert_id=alert.id,
            target=FALSE_POSITIVE,
            actor_id=None,
            note="scheduled password rotation on the backup host",
        )
        await db.commit()

    assert closed.closed_at is not None
    assert closed.resolution_note is not None
    assert "backup host" in closed.resolution_note


async def test_alert_history_cannot_be_rewritten() -> None:
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=IN_PROGRESS, actor_id=None
        )
        await db.commit()

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(text("UPDATE alert_transitions SET to_status = 'CLOSED'"))
        await db.rollback()
    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(text("DELETE FROM alert_transitions"))
        await db.rollback()


async def test_one_tenants_alerts_are_invisible_to_another() -> None:
    tenant_a, tenant_b = await _tenant(), await _tenant()
    alert = await _create(tenant_a)

    async with tenant_scoped_session(tenant_b) as db:
        assert await service.list_alerts(db, tenant_b) == []
        with pytest.raises(service.AlertNotFound):
            await service.get_alert(db, tenant_b, alert.id)


# ---------------------------------------------------------------------------
# The worker
# ---------------------------------------------------------------------------


class _AckTrackingBus(InMemoryEventBus):
    def __init__(self) -> None:
        super().__init__()
        self.acked: list[tuple[str, str]] = []

    async def ack(self, topic: str, group: str, message_id: str) -> None:
        self.acked.append((topic, message_id))


def _detection(tenant_id: uuid.UUID, **overrides) -> dict:
    document = {
        "detection_id": str(uuid.uuid4()),
        "tenant_id": str(tenant_id),
        "rule_id": "AUTH-001",
        "rule_name": "Brute force against a single account",
        "rule_type": "windowed",
        "severity": "high",
        "confidence": 75,
        "risk_score": 65,
        "risk_bucket": "HIGH",
        "risk_explanation": {"score": 65},
        "mitre_attack": ["T1110.001"],
        "event_ids": [str(uuid.uuid4())],
        "entity": {"user.name": "alice", "source_ip": "203.0.113.5"},
        "entity_summary": "source_ip=203.0.113.5|user.name=alice",
        "matched_at": datetime.now(UTC).isoformat(),
        "dry_run": False,
        "evidence": {"hostname": "web01"},
    }
    document.update(overrides)
    return document


def _message(payload: dict | bytes, message_id: str = "1-0") -> EventBusMessage:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return EventBusMessage(
        tenant_id="t", key="k", payload=body, headers={}, message_id=message_id
    )


async def test_a_detection_becomes_an_alert_and_is_published() -> None:
    tenant_id = await _tenant()
    bus = _AckTrackingBus()
    worker = AlertWorker(bus=bus)

    await worker.accept(TOPIC_DETECTIONS_CREATED, _message(_detection(tenant_id)))

    published = await bus.peek(TOPIC_ALERTS_CREATED)
    assert len(published) == 1
    summary = json.loads(published[0].payload)
    assert summary["display_id"].startswith("ALT-")
    assert summary["severity"] == "high"

    async with tenant_scoped_session(tenant_id) as db:
        alerts = await service.list_alerts(db, tenant_id)
    assert len(alerts) == 1
    assert alerts[0].affected_user == "alice"
    # asyncpg returns INET columns as ipaddress objects; the API serializes
    # them back to strings.
    assert str(alerts[0].source_ip) == "203.0.113.5"


async def test_a_repeat_detection_does_not_publish_again() -> None:
    """`alerts.created` is what notifications hang off: a fifty-first
    occurrence must not page anyone."""
    tenant_id = await _tenant()
    bus = _AckTrackingBus()
    worker = AlertWorker(bus=bus)

    await worker.accept(TOPIC_DETECTIONS_CREATED, _message(_detection(tenant_id), "1-0"))
    await worker.accept(TOPIC_DETECTIONS_CREATED, _message(_detection(tenant_id), "2-0"))

    assert len(await bus.peek(TOPIC_ALERTS_CREATED)) == 1
    async with tenant_scoped_session(tenant_id) as db:
        alerts = await service.list_alerts(db, tenant_id)
    assert alerts[0].occurrence_count == 2


async def test_a_dry_run_detection_never_becomes_an_alert() -> None:
    tenant_id = await _tenant()
    bus = _AckTrackingBus()
    worker = AlertWorker(bus=bus)

    await worker.accept(
        TOPIC_DETECTIONS_CREATED, _message(_detection(tenant_id, dry_run=True))
    )

    assert await bus.peek(TOPIC_ALERTS_CREATED) == []
    async with tenant_scoped_session(tenant_id) as db:
        assert await service.list_alerts(db, tenant_id) == []
    # Still acked: it was handled correctly, not skipped in error.
    assert bus.acked == [(TOPIC_DETECTIONS_CREATED, "1-0")]


async def test_a_detection_below_the_risk_floor_is_recorded_but_not_alerted() -> None:
    tenant_id = await _tenant()
    bus = _AckTrackingBus()
    worker = AlertWorker(bus=bus, min_risk_score=50)

    await worker.accept(TOPIC_DETECTIONS_CREATED, _message(_detection(tenant_id, risk_score=10)))

    async with tenant_scoped_session(tenant_id) as db:
        assert await service.list_alerts(db, tenant_id) == []


async def test_a_correlation_becomes_an_alert_carrying_its_timeline() -> None:
    tenant_id = await _tenant()
    bus = _AckTrackingBus()
    worker = AlertWorker(bus=bus)

    correlation = {
        "correlation_uid": str(uuid.uuid4()),
        "correlation_id": "CORR-001",
        "name": "Account takeover chain",
        "tenant_id": str(tenant_id),
        "severity": "critical",
        "confidence": 85,
        "risk_score": 93,
        "risk_bucket": "CRITICAL",
        "mitre_attack": ["T1078"],
        "entity": {"user.name": "alice"},
        "stages_matched": ["brute_force", "successful_login", "privilege_escalation"],
        "event_ids": [str(uuid.uuid4()), str(uuid.uuid4())],
        "first_seen": "2026-09-13T09:00:00+00:00",
        "last_seen": "2026-09-13T09:02:00+00:00",
        "span_seconds": 120,
        "timeline": [{"stage": "brute_force", "time": "2026-09-13T09:00:00+00:00"}],
    }
    await worker.accept(TOPIC_CORRELATIONS_CREATED, _message(correlation))

    async with tenant_scoped_session(tenant_id) as db:
        alerts = await service.list_alerts(db, tenant_id)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.source == "correlation"
    assert alert.correlation_id == "CORR-001"
    assert alert.risk_score == 93
    # The chain is the point of a correlation alert: an analyst opening it
    # should see it, not go and rebuild it.
    assert alert.evidence["timeline"]
    assert alert.evidence["stages_matched"] == [
        "brute_force",
        "successful_login",
        "privilege_escalation",
    ]


async def test_an_undecodable_message_is_dead_lettered() -> None:
    bus = _AckTrackingBus()
    worker = AlertWorker(bus=bus)

    await worker.accept(TOPIC_DETECTIONS_CREATED, _message(b"not json"))

    dead = await bus.peek(f"{TOPIC_DETECTIONS_CREATED}.deadletter")
    assert len(dead) == 1
    assert "undecodable" in dead[0].headers["dead_letter_reason"]


async def test_a_detection_without_a_tenant_is_acked_not_alerted() -> None:
    bus = _AckTrackingBus()
    worker = AlertWorker(bus=bus)

    await worker.accept(TOPIC_DETECTIONS_CREATED, _message({"detection_id": "d1"}))

    assert await bus.peek(TOPIC_ALERTS_CREATED) == []
    assert bus.acked == [(TOPIC_DETECTIONS_CREATED, "1-0")]


def test_the_consumer_group_is_stable() -> None:
    assert CONSUMER_GROUP == "alerting"


async def test_two_alerts_created_concurrently_get_distinct_display_ids() -> None:
    """The display id counter is locked per tenant: two workers creating
    alerts at the same instant must not both read the same maximum."""
    import asyncio

    tenant_id = await _tenant()

    async def create(index: int) -> str:
        async with tenant_scoped_session(tenant_id) as db:
            alert, _created = await service.create_or_update(
                db, _input(tenant_id, dedup_key=f"key-{index}")
            )
            await db.commit()
            return alert.display_id

    display_ids = await asyncio.gather(*(create(index) for index in range(5)))
    assert len(set(display_ids)) == 5


async def test_the_alert_table_is_the_source_of_truth_for_counts() -> None:
    tenant_id = await _tenant()
    await _create(tenant_id, dedup_key="a")
    second = await _create(tenant_id, dedup_key="b")

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, alert_id=second.id, target=IN_PROGRESS, actor_id=None
        )
        await db.commit()
        counts = await service.count_by_status(db, tenant_id)

    assert counts == {NEW: 1, IN_PROGRESS: 1}


async def test_alerts_are_ordered_by_risk_then_recency() -> None:
    tenant_id = await _tenant()
    await _create(tenant_id, dedup_key="low", risk_score=20)
    await _create(tenant_id, dedup_key="high", risk_score=90)

    async with tenant_scoped_session(tenant_id) as db:
        queue = await service.list_alerts(db, tenant_id)

    assert [alert.risk_score for alert in queue] == [90, 20]


async def test_transitions_and_alerts_share_one_transaction() -> None:
    """If the transition row could commit without the status change (or the
    other way round), the history would lie."""
    tenant_id = await _tenant()
    alert = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, alert_id=alert.id, target=IN_PROGRESS, actor_id=None
        )
        await db.rollback()

    async with tenant_scoped_session(tenant_id) as db:
        stored = await service.get_alert(db, tenant_id, alert.id)
        rows = list(
            (
                await db.execute(
                    select(AlertTransition).where(AlertTransition.alert_id == alert.id)
                )
            ).scalars()
        )

    assert stored.status == NEW
    assert [row.to_status for row in rows] == [NEW]
