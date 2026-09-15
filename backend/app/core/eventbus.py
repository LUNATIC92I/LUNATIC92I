"""EventBus abstraction (ARCHITECTURE.md §7.1): the durable, replayable log
every pipeline stage (ingestion -> parsing -> normalization -> enrichment ->
detection -> ...) reads from and writes to. `RedisStreamsEventBus` is the
production implementation for now; a future `KafkaEventBus` implements the
same `EventBus` interface with zero changes to callers once Phase 18 load
testing shows Redis Streams is no longer enough (ARCHITECTURE.md §1 row 1).
`InMemoryEventBus` is a dependency-free test double proving the interface
really is swappable, not just in theory.
"""

import abc
import json
import logging
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from functools import lru_cache
from typing import cast

import redis.asyncio as aioredis

from app.core.config import get_settings
from app.core.redis import build_redis_client

logger = logging.getLogger(__name__)


def consumer_identity(prefix: str) -> str:
    """A per-replica consumer identity for a Redis Streams consumer group.

    Every worker used to hardcode a literal default (`"parser-1"`,
    `"detection-1"`, ...), so two replicas of the same Kubernetes
    Deployment shared one logical consumer name — reclaim
    (`claim_stale`) still recovers a dead replica's pending entries
    correctly regardless, since it works by idle time, not by name
    (verified directly in the Phase 19 chaos test, docs/KUBERNETES.md),
    but `XINFO CONSUMERS` couldn't tell the replicas apart. Kubernetes
    sets `HOSTNAME` to the pod name for every pod with no extra wiring,
    so using it here makes each replica's identity distinct for free.
    Falls back to `"<prefix>-1"` — the old literal — only when `HOSTNAME`
    is entirely unset (local dev without a container, some test runners).
    """
    hostname = os.environ.get("HOSTNAME")
    return f"{prefix}-{hostname}" if hostname else f"{prefix}-1"


def _as_bytes(value: object) -> bytes:
    """Normalizes a redis-py response value to bytes. Raises rather than
    coercing silently: if a value is not bytes, the client was built with
    the wrong decode mode and every payload in the pipeline is suspect."""
    if isinstance(value, bytes):
        return value
    raise TypeError(f"expected bytes from Redis, got {type(value).__name__}")

# EventBus topic names (ARCHITECTURE.md §7.1).
TOPIC_EVENTS_RAW = "events.raw"
TOPIC_EVENTS_DEADLETTER = "events.raw.deadletter"
TOPIC_EVENTS_NORMALIZED = "events.normalized"
TOPIC_DETECTIONS_CREATED = "detections.created"
TOPIC_CORRELATIONS_CREATED = "correlations.created"
TOPIC_ALERTS_CREATED = "alerts.created"


@dataclass(frozen=True)
class EventBusMessage:
    tenant_id: str
    key: str
    payload: bytes
    headers: dict[str, str] = field(default_factory=dict)
    message_id: str | None = None  # set when read back from the bus, ignored on publish


class EventBus(abc.ABC):
    @abc.abstractmethod
    async def publish(self, topic: str, message: EventBusMessage) -> str:
        """Returns the broker-assigned message id."""

    @abc.abstractmethod
    def subscribe(self, topic: str, group: str, consumer: str) -> AsyncIterator[EventBusMessage]:
        """Yields messages for `group`, at-least-once delivery. Callers must
        call `ack()` after successfully processing each message — an
        unacked message is redelivered (to this or another consumer in the
        same group), which is exactly the "never silently lose an event"
        guarantee from spec §26."""

    @abc.abstractmethod
    async def ack(self, topic: str, group: str, message_id: str) -> None: ...

    @abc.abstractmethod
    async def claim_stale(
        self, topic: str, group: str, consumer: str, min_idle_ms: int = 60_000, count: int = 100
    ) -> list[EventBusMessage]:
        """Reclaims messages delivered to a consumer that never acked them
        (it crashed, was killed mid-deploy, hung). Without this, a dead
        consumer's in-flight messages would sit pending forever — which is
        exactly the silent event loss spec §26 forbids. Workers call this
        periodically alongside their normal `subscribe()` loop."""

    @abc.abstractmethod
    async def dead_letter(self, topic: str, message: EventBusMessage, reason: str) -> None:
        """Publishes to `<topic>.deadletter` with the failure reason
        attached. Callers still ack() the original message themselves —
        dead-lettering is a deliberate, successful outcome for that
        message, not a failure to retry."""

    @abc.abstractmethod
    async def peek(self, topic: str, count: int = 100) -> list[EventBusMessage]:
        """Reads up to `count` messages from the start of `topic` without a
        consumer group — for inspection/tests/admin tooling, never for the
        pipeline's own at-least-once processing path."""

    async def aclose(self) -> None:  # noqa: B027  optional hook, not every bus holds connections
        """Release underlying connections. Implementations that hold none
        (the in-memory double) inherit this no-op rather than being forced
        to implement an empty override."""
        return None


_SUBSCRIBE_BLOCK_MS = 5000


class RedisStreamsEventBus(EventBus):
    """Note on typing: this client is constructed with
    `decode_responses=False`, so every value redis-py hands back is `bytes`.
    redis-py's annotations cannot express that (they return broad
    `bytes | str | None` unions covering both decode modes), so the reads
    below normalize through `_as_bytes`, which raises rather than guesses if
    the runtime shape is ever not what we configured for.

    `socket_timeout` is set explicitly, wider than `_SUBSCRIBE_BLOCK_MS`
    (Phase 18 load testing found this the hard way): recent redis-py
    versions apply their own default *client-side* read timeout of 5
    seconds independent of any `block=` argument passed to a blocking
    command. `subscribe()`'s `XREADGROUP ... BLOCK 5000` asks the *server*
    to hold the connection open for up to 5s waiting for new messages —
    with no override here, redis-py would tear the connection down from
    the client side at almost exactly the same instant, so every quiet
    period of 5+ seconds with no new events (any night, any weekend) would
    crash every worker with an unhandled `redis.exceptions.TimeoutError`.
    Nothing about that is specific to a slow network; it reproduces on a
    bare loopback connection to a healthy Redis with no messages pending.

    Connects via `build_redis_client()` (app/core/redis.py), which
    transparently follows a Redis Sentinel failover when Sentinel is
    configured (`REDIS_SENTINEL_HOSTS`) instead of holding a static
    connection to whichever node was master when this process started —
    see that function's own docstring for why a plain `redis://` URL
    alone cannot do that."""

    def __init__(self, redis_url: str) -> None:
        self._redis: aioredis.Redis = build_redis_client(
            redis_url, socket_timeout=(_SUBSCRIBE_BLOCK_MS / 1000) + 5
        )

    async def publish(self, topic: str, message: EventBusMessage) -> str:
        message_id = await self._redis.xadd(
            topic,
            {
                "tenant_id": message.tenant_id.encode(),
                "key": message.key.encode(),
                "payload": message.payload,
                "headers": json.dumps(message.headers).encode(),
            },
        )
        return _as_bytes(message_id).decode()

    async def _ensure_group(self, topic: str, group: str) -> None:
        try:
            await self._redis.xgroup_create(topic, group, id="0", mkstream=True)
        except aioredis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def subscribe(
        self, topic: str, group: str, consumer: str
    ) -> AsyncIterator[EventBusMessage]:
        await self._ensure_group(topic, group)
        while True:
            response = cast(
                list[tuple[object, list[tuple[object, object]]]],
                await self._redis.xreadgroup(
                    group, consumer, {topic: ">"}, count=10, block=_SUBSCRIBE_BLOCK_MS
                ),
            )
            if not response:
                continue
            for _stream_name, entries in response:
                for message_id, fields in entries:
                    yield self._decode(message_id, fields)

    async def ack(self, topic: str, group: str, message_id: str) -> None:
        await self._redis.xack(topic, group, message_id)

    async def claim_stale(
        self, topic: str, group: str, consumer: str, min_idle_ms: int = 60_000, count: int = 100
    ) -> list[EventBusMessage]:
        await self._ensure_group(topic, group)
        _cursor, entries, _deleted = cast(
            tuple[object, list[tuple[object, object]], object],
            await self._redis.xautoclaim(
                topic, group, consumer, min_idle_time=min_idle_ms, start_id="0-0", count=count
            ),
        )
        return [self._decode(message_id, fields) for message_id, fields in entries]

    async def dead_letter(self, topic: str, message: EventBusMessage, reason: str) -> None:
        dlq_topic = f"{topic}.deadletter"
        headers = {**message.headers, "dead_letter_reason": reason, "original_topic": topic}
        await self.publish(
            dlq_topic,
            EventBusMessage(
                tenant_id=message.tenant_id,
                key=message.key,
                payload=message.payload,
                headers=headers,
            ),
        )
        logger.warning(
            "event dead-lettered",
            extra={"topic": topic, "reason": reason, "tenant_id": message.tenant_id},
        )

    async def peek(self, topic: str, count: int = 100) -> list[EventBusMessage]:
        entries = cast(
            list[tuple[object, object]], await self._redis.xrange(topic, count=count)
        )
        return [self._decode(message_id, fields) for message_id, fields in entries]

    async def aclose(self) -> None:
        await self._redis.aclose()

    @staticmethod
    def _decode(message_id: object, raw_fields: object) -> EventBusMessage:
        fields = cast(dict[bytes, bytes], raw_fields)
        headers_raw = fields.get(b"headers")
        return EventBusMessage(
            tenant_id=_as_bytes(fields[b"tenant_id"]).decode(),
            key=_as_bytes(fields[b"key"]).decode(),
            payload=_as_bytes(fields[b"payload"]),
            headers=json.loads(_as_bytes(headers_raw).decode()) if headers_raw else {},
            message_id=_as_bytes(message_id).decode(),
        )


class InMemoryEventBus(EventBus):
    """A dependency-free test double implementing the exact same
    `EventBus` interface as `RedisStreamsEventBus` — used to unit-test
    ingestion logic without a live Redis, and as a concrete demonstration
    that pipeline code depends only on the abstraction."""

    def __init__(self) -> None:
        self._topics: dict[str, list[tuple[str, EventBusMessage]]] = {}
        self._next_id = 0

    def _stream(self, topic: str) -> list[tuple[str, EventBusMessage]]:
        return self._topics.setdefault(topic, [])

    async def publish(self, topic: str, message: EventBusMessage) -> str:
        self._next_id += 1
        message_id = f"{self._next_id}-0"
        self._stream(topic).append((message_id, message))
        return message_id

    async def subscribe(
        self, topic: str, group: str, consumer: str
    ) -> AsyncIterator[EventBusMessage]:
        index = 0
        stream = self._stream(topic)
        while True:
            if index < len(stream):
                message_id, message = stream[index]
                index += 1
                yield EventBusMessage(
                    tenant_id=message.tenant_id,
                    key=message.key,
                    payload=message.payload,
                    headers=message.headers,
                    message_id=message_id,
                )
            else:
                return

    async def ack(self, topic: str, group: str, message_id: str) -> None:
        return  # no redelivery semantics to model for the in-memory double

    async def claim_stale(
        self, topic: str, group: str, consumer: str, min_idle_ms: int = 60_000, count: int = 100
    ) -> list[EventBusMessage]:
        return []  # the in-memory double has no crashed consumers to recover from

    async def dead_letter(self, topic: str, message: EventBusMessage, reason: str) -> None:
        dlq_topic = f"{topic}.deadletter"
        headers = {**message.headers, "dead_letter_reason": reason, "original_topic": topic}
        await self.publish(
            dlq_topic,
            EventBusMessage(
                tenant_id=message.tenant_id,
                key=message.key,
                payload=message.payload,
                headers=headers,
            ),
        )

    async def peek(self, topic: str, count: int = 100) -> list[EventBusMessage]:
        return [msg for _id, msg in self._stream(topic)[:count]]


@lru_cache
def get_event_bus() -> EventBus:
    """Process-wide EventBus singleton. Swapping to Kafka later is a
    one-line change here, not a refactor of every caller."""
    return RedisStreamsEventBus(get_settings().redis_url)
