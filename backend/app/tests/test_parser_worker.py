"""Parser worker tests.

The contract under test is the delivery guarantee, not the parsing (covered
in test_parsers.py): every message read reaches a terminal state —
published onward or dead-lettered — and is then acked. Nothing is dropped,
and nothing is acked without one of those two things having happened.
"""

import asyncio
import json
import uuid

import pytest

from app.core.config import get_settings
from app.core.eventbus import (
    TOPIC_EVENTS_NORMALIZED,
    TOPIC_EVENTS_RAW,
    EventBusMessage,
    InMemoryEventBus,
    RedisStreamsEventBus,
)
from app.workers.parser_worker import CONSUMER_GROUP, ParserWorker

_HEADERS = {
    "source_type": "syslog_udp",
    "collector_id": "syslog-1",
    "received_at": "2026-09-12T05:00:00+00:00",
    "content_hash": "abc123",
}


def _raw_message(payload: bytes, tenant_id: str | None = None) -> EventBusMessage:
    return EventBusMessage(
        tenant_id=tenant_id or str(uuid.uuid4()),
        key="k",
        payload=payload,
        headers=dict(_HEADERS),
    )


async def test_parsable_event_is_published_normalized() -> None:
    bus = InMemoryEventBus()
    worker = ParserWorker(bus=bus)
    message = _raw_message(
        b"<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password for root from 10.0.0.9"
    )

    await worker.handle(message)

    [published] = await bus.peek(TOPIC_EVENTS_NORMALIZED)
    document = json.loads(published.payload)
    assert document["class"] == "Authentication"
    assert document["user"]["name"] == "root"
    assert document["source_type"] == "syslog_udp"
    assert published.tenant_id == message.tenant_id
    assert published.headers["schema_version"] == document["schema_version"]


async def test_unparsable_event_is_dead_lettered_with_a_reason_not_dropped() -> None:
    bus = InMemoryEventBus()
    worker = ParserWorker(bus=bus)

    await worker.handle(_raw_message(b"\x00\x01\x02 unparseable \xff"))

    assert await bus.peek(TOPIC_EVENTS_NORMALIZED) == []
    [dead] = await bus.peek(f"{TOPIC_EVENTS_RAW}.deadletter")
    assert dead.payload == b"\x00\x01\x02 unparseable \xff"  # payload preserved for replay
    assert dead.headers["dead_letter_reason"].startswith("parse:")


async def test_worker_survives_a_parser_that_crashes() -> None:
    """A bug in one parser must degrade to a dead-lettered event, never take
    down the worker and stall the whole pipeline."""
    from app.parsers.base import ParsedEvent, Parser
    from app.parsers.registry import ParserRegistry
    from app.services.processing import EventProcessor

    class _ExplodingParser(Parser):
        format_name = "exploding"
        priority = 1

        def can_parse(self, raw: bytes) -> bool:
            return True

        def parse(self, raw: bytes) -> ParsedEvent:
            raise RuntimeError("boom")

    bus = InMemoryEventBus()
    worker = ParserWorker(
        bus=bus, processor=EventProcessor(registry=ParserRegistry((_ExplodingParser(),)))
    )

    await worker.handle(_raw_message(b"anything"))

    [dead] = await bus.peek(f"{TOPIC_EVENTS_RAW}.deadletter")
    assert "crashed" in dead.headers["dead_letter_reason"]


async def test_tenant_id_is_carried_through_unchanged() -> None:
    """The normalized event must stay attributed to the tenant that sent it
    — losing that would put one tenant's events in another's index."""
    bus = InMemoryEventBus()
    worker = ParserWorker(bus=bus)
    tenant_id = str(uuid.uuid4())

    await worker.handle(_raw_message(b'{"action":"login"}', tenant_id=tenant_id))

    [published] = await bus.peek(TOPIC_EVENTS_NORMALIZED)
    assert published.tenant_id == tenant_id
    assert json.loads(published.payload)["tenant_id"] == tenant_id


@pytest.fixture
async def redis_bus():
    bus = RedisStreamsEventBus(get_settings().redis_url)
    yield bus
    await bus.aclose()


async def test_end_to_end_over_real_redis_acks_processed_messages(
    redis_bus: RedisStreamsEventBus,
) -> None:
    """Full loop against a real broker: publish raw, let the worker consume,
    confirm the normalized event lands AND that nothing is left pending
    (i.e. it was genuinely acked, not just processed)."""
    # Throwaway topics so the test never collides with a real stream or
    # with a concurrent run.
    suffix = uuid.uuid4().hex[:8]
    raw_topic = f"{TOPIC_EVENTS_RAW}.test-{suffix}"
    normalized_topic = f"{TOPIC_EVENTS_NORMALIZED}.test-{suffix}"
    consumer = f"test-{suffix}"

    tenant_id = str(uuid.uuid4())
    await redis_bus.publish(
        raw_topic,
        EventBusMessage(
            tenant_id=tenant_id,
            key="k",
            payload=b"<34>Oct 11 22:14:15 web01 sshd[1234]: Accepted password for alice",
            headers=dict(_HEADERS),
        ),
    )

    worker = ParserWorker(
        bus=redis_bus,
        consumer_name=consumer,
        raw_topic=raw_topic,
        normalized_topic=normalized_topic,
    )
    generator = redis_bus.subscribe(raw_topic, CONSUMER_GROUP, consumer)
    message = await asyncio.wait_for(generator.__anext__(), timeout=5.0)
    await worker.handle(message)
    await generator.aclose()

    [published] = await redis_bus.peek(normalized_topic)
    assert json.loads(published.payload)["user"]["name"] == "alice"

    # Acked: nothing reclaimable, so no redelivery will occur.
    assert await redis_bus.claim_stale(raw_topic, CONSUMER_GROUP, consumer, min_idle_ms=0) == []
