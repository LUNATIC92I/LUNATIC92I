import asyncio
import contextlib
import uuid

import pytest

from app.core.config import get_settings
from app.core.eventbus import EventBusMessage, InMemoryEventBus, RedisStreamsEventBus


async def _collect(bus, topic: str, group: str, consumer: str, n: int, limit_seconds: float = 5.0):
    messages = []
    gen = bus.subscribe(topic, group, consumer)

    async def _run():
        async for message in gen:
            messages.append(message)
            await bus.ack(topic, group, message.message_id)
            if len(messages) >= n:
                break

    await asyncio.wait_for(_run(), timeout=limit_seconds)
    await gen.aclose()
    return messages


@pytest.fixture
async def redis_bus():
    bus = RedisStreamsEventBus(get_settings().redis_url)
    yield bus
    await bus.aclose()


async def test_redis_publish_and_consume_roundtrip(redis_bus: RedisStreamsEventBus) -> None:
    topic = f"test.{uuid.uuid4()}"
    message = EventBusMessage(tenant_id="tenant-a", key="k1", payload=b"hello", headers={"h": "1"})
    await redis_bus.publish(topic, message)

    [received] = await _collect(redis_bus, topic, "group1", "consumer1", 1)
    assert received.tenant_id == "tenant-a"
    assert received.payload == b"hello"
    assert received.headers == {"h": "1"}
    assert received.message_id is not None


async def test_unacked_message_is_reclaimable_by_another_consumer(
    redis_bus: RedisStreamsEventBus,
) -> None:
    """Never silently lose an event (spec §26): a consumer that dies before
    acking must have its in-flight message recoverable by another consumer
    in the same group."""
    topic = f"test.{uuid.uuid4()}"
    await redis_bus.publish(topic, EventBusMessage(tenant_id="t", key="k", payload=b"data"))

    # First consumer reads the message, then "crashes" without acking.
    gen = redis_bus.subscribe(topic, "group1", "consumer-a")
    first = await asyncio.wait_for(gen.__anext__(), timeout=5.0)
    assert first.payload == b"data"
    await gen.aclose()

    # A surviving consumer reclaims it (min_idle_ms=0 so the test doesn't
    # have to wait out a realistic idle threshold).
    reclaimed = await redis_bus.claim_stale(topic, "group1", "consumer-b", min_idle_ms=0)
    assert [message.payload for message in reclaimed] == [b"data"]

    # Once acked, it is no longer reclaimable — no infinite redelivery.
    await redis_bus.ack(topic, "group1", reclaimed[0].message_id)
    assert await redis_bus.claim_stale(topic, "group1", "consumer-b", min_idle_ms=0) == []


async def test_redis_dead_letter_routes_to_deadletter_topic(redis_bus: RedisStreamsEventBus) -> None:
    topic = f"test.{uuid.uuid4()}"
    message = EventBusMessage(tenant_id="t", key="k", payload=b"bad-data")
    await redis_bus.dead_letter(topic, message, reason="parse failure: not valid syslog")

    [dlq_message] = await redis_bus.peek(f"{topic}.deadletter")
    assert dlq_message.payload == b"bad-data"
    assert dlq_message.headers["dead_letter_reason"] == "parse failure: not valid syslog"
    assert dlq_message.headers["original_topic"] == topic


async def test_subscribing_to_an_idle_topic_survives_past_the_servers_own_block_window(
    redis_bus: RedisStreamsEventBus,
) -> None:
    """Phase 18 found this the hard way while load testing: `subscribe()`
    asks Redis to block for `_SUBSCRIBE_BLOCK_MS` (5s) waiting for a
    message. With no explicit client-side `socket_timeout`, recent
    redis-py versions apply their own default read timeout of exactly 5
    seconds — so a topic with nothing published to it for 5+ seconds
    would raise an unhandled `redis.exceptions.TimeoutError` and crash the
    worker on every quiet period (any night, any weekend), independent of
    load or network conditions. Never publishes anything: the whole point
    is proving the *empty* wait itself survives."""
    topic = f"test.{uuid.uuid4()}"
    gen = redis_bus.subscribe(topic, "group1", "consumer1")
    task = asyncio.ensure_future(gen.__anext__())
    try:
        # Longer than the server's own 5-second BLOCK window, so this only
        # passes if the client-side read timeout is wider than that too.
        done, _pending = await asyncio.wait([task], timeout=7)
        assert not done, "subscribe() returned/raised before any message was ever published"
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await gen.aclose()


async def test_in_memory_event_bus_matches_same_interface() -> None:
    """The in-memory double proves ingestion/pipeline code depends only on
    the EventBus abstraction, not on Redis specifics (ARCHITECTURE.md §1
    row 1) — it is exercised with the exact same test as the Redis-backed
    dead-letter behavior above."""
    bus = InMemoryEventBus()
    topic = "events.raw"
    message = EventBusMessage(tenant_id="t", key="k", payload=b"bad-data")
    await bus.dead_letter(topic, message, reason="malformed payload")

    [dlq_message] = await bus.peek(f"{topic}.deadletter")
    assert dlq_message.payload == b"bad-data"
    assert dlq_message.headers["dead_letter_reason"] == "malformed payload"
