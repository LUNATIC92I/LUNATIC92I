"""Correlation worker: two input streams, one delivery contract.

The worker's own job is small — decode, adapt, hand to the engine, publish,
ack — so these tests are about the edges: that both streams are consumed,
that nothing is acked before its correlations are published, that garbage is
dead-lettered with a reason, and that an input the engine cannot use is
acked rather than treated as a failure.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.eventbus import (
    TOPIC_CORRELATIONS_CREATED,
    TOPIC_DETECTIONS_CREATED,
    TOPIC_EVENTS_NORMALIZED,
    EventBusMessage,
    InMemoryEventBus,
)
from app.correlation.engine import CorrelationEngine
from app.correlation.loader import parse_correlation_rule
from app.correlation.state import InMemoryCorrelationStateStore
from app.detection.engine import InMemorySuppressionStore
from app.workers.correlation_worker import CONSUMER_GROUP, CorrelationWorker

T0 = datetime(2026, 9, 13, 9, 0, tzinfo=UTC)

RULE = """
correlation_id: TEST-900
name: Detection then event
description: A detection followed by an event, for worker tests.
severity: high
confidence: 70
risk_score: 70
status: enabled
author: tests
window: 30m
correlate_by:
  - user.name
ordered: true
stages:
  - name: detected
    matches: detection
    conditions:
      field: detection.rule_id
      operator: equals
      value: AUTH-001
  - name: followed_by
    matches: event
    conditions:
      field: activity
      operator: equals
      value: logon_success
false_positive_notes: none
investigation_steps: none
suppression: 1h
"""


class _AckTrackingBus(InMemoryEventBus):
    def __init__(self) -> None:
        super().__init__()
        self.acked: list[tuple[str, str]] = []

    async def ack(self, topic: str, group: str, message_id: str) -> None:
        self.acked.append((topic, message_id))


def _worker(bus: InMemoryEventBus) -> CorrelationWorker:
    engine = CorrelationEngine(
        [parse_correlation_rule(RULE)],
        state=InMemoryCorrelationStateStore(),
        suppression=InMemorySuppressionStore(),
    )
    return CorrelationWorker(bus=bus, engine=engine)


def _message(payload: dict | bytes, message_id: str = "1-0") -> EventBusMessage:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return EventBusMessage(
        tenant_id="t", key="k", payload=body, headers={}, message_id=message_id
    )


def _detection(tenant: str, *, dry_run: bool = False) -> dict:
    return {
        "detection_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "rule_id": "AUTH-001",
        "rule_name": "Brute force",
        "severity": "high",
        "confidence": 75,
        "risk_score": 65,
        "mitre_attack": ["T1110"],
        "event_ids": [str(uuid.uuid4())],
        "entity": {"user.name": "alice"},
        "matched_at": T0.isoformat(),
        "dry_run": dry_run,
        "evidence": {"timestamp": T0.isoformat()},
    }


def _event(tenant: str, minutes: float = 1) -> dict:
    moment = (T0 + timedelta(minutes=minutes)).isoformat()
    return {
        "event_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "timestamp": moment,
        "ingestion_timestamp": moment,
        "activity": "logon_success",
        "user": {"name": "alice"},
    }


async def test_a_chain_across_both_streams_publishes_one_correlation() -> None:
    bus, tenant = _AckTrackingBus(), str(uuid.uuid4())
    worker = _worker(bus)

    await worker.accept(TOPIC_DETECTIONS_CREATED, _message(_detection(tenant), "1-0"))
    assert await bus.peek(TOPIC_CORRELATIONS_CREATED) == []

    await worker.accept(TOPIC_EVENTS_NORMALIZED, _message(_event(tenant), "2-0"))

    published = await bus.peek(TOPIC_CORRELATIONS_CREATED)
    assert len(published) == 1
    document = json.loads(published[0].payload)
    assert document["correlation_id"] == "TEST-900"
    assert document["entity"] == {"user.name": "alice"}
    assert len(document["timeline"]) == 2
    assert published[0].headers["severity"] == "high"


async def test_nothing_is_acked_before_its_correlations_are_published() -> None:
    class _FailingBus(_AckTrackingBus):
        async def publish(self, topic: str, message: EventBusMessage) -> str:
            if topic == TOPIC_CORRELATIONS_CREATED:
                raise RuntimeError("broker down")
            return await super().publish(topic, message)

    bus, tenant = _FailingBus(), str(uuid.uuid4())
    worker = _worker(bus)
    await worker.accept(TOPIC_DETECTIONS_CREATED, _message(_detection(tenant), "1-0"))

    with pytest.raises(RuntimeError):
        await worker.accept(TOPIC_EVENTS_NORMALIZED, _message(_event(tenant), "2-0"))

    assert ("events.normalized", "2-0") not in bus.acked


async def test_an_undecodable_payload_is_dead_lettered_with_a_reason() -> None:
    bus = _AckTrackingBus()
    worker = _worker(bus)

    await worker.accept(TOPIC_EVENTS_NORMALIZED, _message(b"not json", "1-0"))

    dead = await bus.peek(f"{TOPIC_EVENTS_NORMALIZED}.deadletter")
    assert len(dead) == 1
    assert "undecodable" in dead[0].headers["dead_letter_reason"]
    assert (TOPIC_EVENTS_NORMALIZED, "1-0") in bus.acked


async def test_an_input_that_cannot_be_correlated_is_acked_not_dead_lettered() -> None:
    """A dry-run detection is not a failure — it is simply not part of any
    chain, and dead-lettering it would fill the DLQ with healthy traffic."""
    bus, tenant = _AckTrackingBus(), str(uuid.uuid4())
    worker = _worker(bus)

    await worker.accept(
        TOPIC_DETECTIONS_CREATED, _message(_detection(tenant, dry_run=True), "1-0")
    )

    assert await bus.peek(f"{TOPIC_DETECTIONS_CREATED}.deadletter") == []
    assert bus.acked == [(TOPIC_DETECTIONS_CREATED, "1-0")]


async def test_both_topics_are_consumed_by_the_same_group() -> None:
    """One group name across both streams: scaling the worker out shares the
    load instead of every replica re-processing everything."""
    assert CONSUMER_GROUP == "correlation"


async def test_the_worker_consumes_from_both_streams_when_running() -> None:
    import asyncio

    bus, tenant = _AckTrackingBus(), str(uuid.uuid4())
    worker = _worker(bus)
    await bus.publish(TOPIC_DETECTIONS_CREATED, _message(_detection(tenant), "1-0"))
    await bus.publish(TOPIC_EVENTS_NORMALIZED, _message(_event(tenant), "2-0"))

    stop = asyncio.Event()
    runner = asyncio.create_task(worker.run(stop))
    for _ in range(50):
        await asyncio.sleep(0.01)
        if await bus.peek(TOPIC_CORRELATIONS_CREATED):
            break
    stop.set()
    runner.cancel()

    assert len(await bus.peek(TOPIC_CORRELATIONS_CREATED)) == 1
