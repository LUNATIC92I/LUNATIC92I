"""Detection worker: delivery contract and rule refresh.

The pipeline guarantee from spec §26 continues here — an event is acked only
once its detections are published, and anything unusable is dead-lettered
with a reason rather than dropped. The refresh behaviour matters just as
much operationally: a rule set that only changes on restart is a rule set
nobody dares to change during an incident.
"""

import json
import uuid

import pytest

from app.core.eventbus import (
    TOPIC_DETECTIONS_CREATED,
    TOPIC_EVENTS_NORMALIZED,
    EventBusMessage,
    InMemoryEventBus,
)
from app.detection.engine import InMemorySuppressionStore, StreamingEngine
from app.detection.loader import parse_rule
from app.workers.detection_worker import CONSUMER_GROUP, DetectionWorker, RuleRegistry

TENANT = str(uuid.uuid4())

RULE = """
rule_id: TEST-200
name: Failed logon
description: Any failed authentication.
severity: high
confidence: 70
risk_score: 60
status: enabled
author: tests
conditions:
  field: authentication.outcome
  operator: equals
  value: failure
false_positive_notes: none
investigation_steps: none
"""


class _AckTrackingBus(InMemoryEventBus):
    def __init__(self) -> None:
        super().__init__()
        self.acked: list[str] = []

    async def ack(self, topic: str, group: str, message_id: str) -> None:
        self.acked.append(message_id)


class _StubRegistry:
    """Stands in for the database-backed registry: rule loading is covered
    against real PostgreSQL in test_detection_rules_api.py, and mixing it in
    here would make a delivery failure look like a persistence failure."""

    def __init__(self, engine: StreamingEngine) -> None:
        self._engine = engine
        self.tenants: list[uuid.UUID] = []

    async def engine_for(self, tenant_id: uuid.UUID) -> StreamingEngine:
        self.tenants.append(tenant_id)
        return self._engine


def _message(payload: dict | bytes, message_id: str = "1-0") -> EventBusMessage:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return EventBusMessage(
        tenant_id=TENANT, key="k", payload=body, headers={}, message_id=message_id
    )


def _event(**overrides) -> dict:
    document = {
        "event_id": str(uuid.uuid4()),
        "tenant_id": TENANT,
        "class": "Authentication",
        "authentication": {"outcome": "failure"},
        "user": {"name": "alice"},
        "source_ip": "203.0.113.4",
    }
    document.update(overrides)
    return document


def _worker(bus: InMemoryEventBus, rules: list[str] | None = None) -> DetectionWorker:
    engine = StreamingEngine(
        [parse_rule(rule) for rule in (rules or [RULE])],
        suppression=InMemorySuppressionStore(),
    )
    return DetectionWorker(bus=bus, registry=_StubRegistry(engine))  # type: ignore[arg-type]


async def test_a_match_is_published_as_a_detection() -> None:
    bus = _AckTrackingBus()
    worker = _worker(bus)

    await worker.accept(_message(_event()))

    published = await bus.peek(TOPIC_DETECTIONS_CREATED)
    assert len(published) == 1
    detection = json.loads(published[0].payload)
    assert detection["rule_id"] == "TEST-200"
    assert detection["tenant_id"] == TENANT
    assert detection["dry_run"] is False
    # Headers carry the routing-relevant bits so a downstream consumer can
    # filter without deserializing every detection.
    assert published[0].headers["severity"] == "high"
    assert published[0].headers["dry_run"] == "false"


async def test_an_event_is_acked_only_after_its_detections_are_published() -> None:
    class _FailingBus(_AckTrackingBus):
        async def publish(self, topic: str, message: EventBusMessage) -> str:
            if topic == TOPIC_DETECTIONS_CREATED:
                raise RuntimeError("broker down")
            return await super().publish(topic, message)

    bus = _FailingBus()
    worker = _worker(bus)

    with pytest.raises(RuntimeError):
        await worker.accept(_message(_event()))

    assert bus.acked == [], "the event was acked despite its detection being lost"


async def test_a_non_matching_event_is_still_acked() -> None:
    bus = _AckTrackingBus()
    worker = _worker(bus)

    await worker.accept(_message(_event(authentication={"outcome": "success"})))

    assert await bus.peek(TOPIC_DETECTIONS_CREATED) == []
    assert bus.acked == ["1-0"]


async def test_an_undecodable_payload_is_dead_lettered_with_a_reason() -> None:
    bus = _AckTrackingBus()
    worker = _worker(bus)

    await worker.accept(_message(b"not json"))

    dead = await bus.peek(f"{TOPIC_EVENTS_NORMALIZED}.deadletter")
    assert len(dead) == 1
    assert "undecodable" in dead[0].headers["dead_letter_reason"]
    assert bus.acked == ["1-0"], "a dead-lettered event must still be acked"


async def test_an_event_without_a_tenant_is_dead_lettered_not_guessed() -> None:
    """There is no safe default tenant: evaluating an event against another
    tenant's rules would breach the isolation boundary itself."""
    bus = _AckTrackingBus()
    worker = _worker(bus)

    await worker.accept(_message({"event_id": "x", "class": "Authentication"}))

    dead = await bus.peek(f"{TOPIC_EVENTS_NORMALIZED}.deadletter")
    assert "tenant_id" in dead[0].headers["dead_letter_reason"]
    assert await bus.peek(TOPIC_DETECTIONS_CREATED) == []


async def test_several_rules_matching_one_event_produce_several_detections() -> None:
    bus = _AckTrackingBus()
    second = RULE.replace("TEST-200", "TEST-201").replace("severity: high", "severity: low")
    worker = _worker(bus, [RULE, second])

    await worker.accept(_message(_event()))

    published = await bus.peek(TOPIC_DETECTIONS_CREATED)
    assert {json.loads(m.payload)["rule_id"] for m in published} == {"TEST-200", "TEST-201"}


async def test_the_consumer_group_is_stable() -> None:
    """Renaming it would silently replay the whole stream through a new
    group on the next deploy."""
    assert CONSUMER_GROUP == "detection"


async def test_the_registry_reloads_rules_when_its_cache_expires(monkeypatch) -> None:
    registry = RuleRegistry(refresh_seconds=0)
    tenant_id = uuid.uuid4()
    loads: list[uuid.UUID] = []

    async def fake_load(_db, tenant: uuid.UUID):
        loads.append(tenant)
        return [parse_rule(RULE)]

    monkeypatch.setattr("app.workers.detection_worker.load_active_rules", fake_load)

    engine_one = await registry.engine_for(tenant_id)
    engine_two = await registry.engine_for(tenant_id)

    assert len(loads) == 2, "the rule set was not refreshed"
    # Same engine instance across refreshes, so suppression state survives a
    # reload instead of every suppressed rule firing again.
    assert engine_one is engine_two


async def test_the_registry_caches_within_its_refresh_interval(monkeypatch) -> None:
    registry = RuleRegistry(refresh_seconds=3600)
    tenant_id = uuid.uuid4()
    loads: list[uuid.UUID] = []

    async def fake_load(_db, tenant: uuid.UUID):
        loads.append(tenant)
        return [parse_rule(RULE)]

    monkeypatch.setattr("app.workers.detection_worker.load_active_rules", fake_load)

    await registry.engine_for(tenant_id)
    await registry.engine_for(tenant_id)

    assert len(loads) == 1, "a database round trip per event"


async def test_the_registry_separates_streaming_from_windowed_rules(monkeypatch) -> None:
    windowed = RULE.replace("TEST-200", "TEST-300") + (
        "window:\n  duration: 5m\n  threshold: 5\n  group_by: [user.name]\nsuppression: 10m\n"
    )

    async def fake_load(_db, tenant: uuid.UUID):
        return [parse_rule(RULE), parse_rule(windowed)]

    monkeypatch.setattr("app.workers.detection_worker.load_active_rules", fake_load)
    registry = RuleRegistry(refresh_seconds=3600)
    tenant_id = uuid.uuid4()

    engine = await registry.engine_for(tenant_id)
    windowed_rules = await registry.windowed_rules_for(tenant_id)

    assert [rule.rule_id for rule in engine.rules] == ["TEST-200"]
    assert [rule.rule_id for rule in windowed_rules] == ["TEST-300"]
