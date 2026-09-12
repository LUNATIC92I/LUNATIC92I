"""Ingestion service: the single funnel every collector's events pass
through, whatever their transport (ARCHITECTURE.md §5, spec §6/§26).

Responsibilities, in the order they are applied:

1. **Rate limit** per tenant — a flood from one tenant must not starve
   another (THREAT_MODEL.md §3.1). Applied first so that abusive traffic is
   rejected before it can cause any other work, including dead-lettering.
2. **Validate** size/emptiness — a malformed or oversized payload is
   dead-lettered, never dropped and never allowed to crash the worker.
3. **Deduplicate** on the collector's idempotency key, so a retry after a
   network timeout does not create a second copy of the same event.
4. **Publish** to the event bus for the parsing stage to pick up.

The one rule this module exists to uphold: an event that reaches here is
either published, dead-lettered, or explicitly refused with a reason the
caller can act on. It is never silently discarded.
"""

import logging
import time
from dataclasses import dataclass
from enum import StrEnum

import redis.asyncio as aioredis

from app.collectors.base import RawIngestEvent
from app.core import metrics
from app.core.config import get_settings
from app.core.eventbus import TOPIC_EVENTS_RAW, EventBus, EventBusMessage

logger = logging.getLogger(__name__)


class IngestOutcome(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    RATE_LIMITED = "rate_limited"
    DEAD_LETTERED = "dead_lettered"
    DROPPED = "dropped"


class DeadLetterReason(StrEnum):
    """Fixed set — these become Prometheus label values, so they must not be
    free text (see app/core/metrics.py)."""

    PAYLOAD_TOO_LARGE = "payload_too_large"
    EMPTY_PAYLOAD = "empty_payload"
    PUBLISH_FAILED = "publish_failed"


@dataclass(frozen=True)
class IngestResult:
    outcome: IngestOutcome
    message_id: str | None = None
    reason: str | None = None


class IngestionService:
    def __init__(
        self,
        *,
        bus: EventBus,
        redis: aioredis.Redis,
        max_payload_bytes: int | None = None,
        rate_limit_per_minute: int | None = None,
        dedup_ttl_seconds: int | None = None,
    ) -> None:
        settings = get_settings()
        self._bus = bus
        self._redis = redis
        self._max_payload_bytes = max_payload_bytes or settings.ingest_max_payload_bytes
        self._rate_limit_per_minute = rate_limit_per_minute or settings.ingest_rate_limit_per_minute
        self._dedup_ttl_seconds = dedup_ttl_seconds or settings.ingest_dedup_ttl_seconds

    async def ingest(self, event: RawIngestEvent) -> IngestResult:
        started = time.perf_counter()

        if not await self._within_rate_limit(event):
            metrics.events_rate_limited_total.labels(source_type=event.source_type).inc()
            return IngestResult(
                IngestOutcome.RATE_LIMITED, reason="tenant ingestion quota exceeded"
            )

        invalid_reason = self._validate(event)
        if invalid_reason is not None:
            return await self._dead_letter(event, invalid_reason)

        if not await self._claim_idempotency_key(event):
            metrics.events_duplicate_total.labels(source_type=event.source_type).inc()
            return IngestResult(IngestOutcome.DUPLICATE, reason="already ingested")

        message = EventBusMessage(
            tenant_id=str(event.tenant_id),
            key=event.idempotency_key,
            payload=event.raw_payload,
            headers={
                "source_type": event.source_type,
                "collector_id": event.collector_id,
                "received_at": event.received_at.isoformat(),
                "content_hash": event.content_hash,
                "source_ip": event.source_ip or "",
            },
        )

        try:
            message_id = await self._bus.publish(TOPIC_EVENTS_RAW, message)
        except Exception as exc:  # noqa: BLE001  any bus failure must be contained
            logger.exception("failed to publish event to bus")
            # Release the dedup claim: this event was never actually
            # ingested, so a retry of it must not be mistaken for a
            # duplicate and discarded.
            await self._release_idempotency_key(event)
            return await self._dead_letter(event, DeadLetterReason.PUBLISH_FAILED, cause=str(exc))

        metrics.events_ingested_total.labels(source_type=event.source_type).inc()
        metrics.ingestion_latency_seconds.labels(source_type=event.source_type).observe(
            time.perf_counter() - started
        )
        return IngestResult(IngestOutcome.ACCEPTED, message_id=message_id)

    def _validate(self, event: RawIngestEvent) -> DeadLetterReason | None:
        if not event.raw_payload:
            return DeadLetterReason.EMPTY_PAYLOAD
        if len(event.raw_payload) > self._max_payload_bytes:
            return DeadLetterReason.PAYLOAD_TOO_LARGE
        return None

    async def _within_rate_limit(self, event: RawIngestEvent) -> bool:
        # Fixed-window counter: simple and predictable, at the cost of
        # allowing up to 2x the quota across a window boundary. Acceptable
        # for a coarse anti-flood control; if Phase 18 load testing shows
        # the boundary burst matters, this becomes a sliding window without
        # any change to callers.
        window = int(time.time() // 60)
        key = f"ingest:ratelimit:{event.tenant_id}:{window}"
        count = await self._redis.incr(key)
        if count == 1:
            await self._redis.expire(key, 120)
        return bool(count <= self._rate_limit_per_minute)

    async def _claim_idempotency_key(self, event: RawIngestEvent) -> bool:
        """True if this event is new. The dedup window is deliberately finite
        (`dedup_ttl_seconds`): it exists to absorb collector retries, not to
        guarantee uniqueness for all time, which at SIEM volumes would need
        far more memory than Redis should hold."""
        key = f"ingest:idem:{event.idempotency_key}"
        claimed = await self._redis.set(key, b"1", nx=True, ex=self._dedup_ttl_seconds)
        return bool(claimed)

    async def _release_idempotency_key(self, event: RawIngestEvent) -> None:
        await self._redis.delete(f"ingest:idem:{event.idempotency_key}")

    async def _dead_letter(
        self, event: RawIngestEvent, reason: DeadLetterReason, cause: str | None = None
    ) -> IngestResult:
        detail = f"{reason.value}: {cause}" if cause else reason.value
        message = EventBusMessage(
            tenant_id=str(event.tenant_id),
            key=event.idempotency_key,
            payload=event.raw_payload,
            headers={
                "source_type": event.source_type,
                "collector_id": event.collector_id,
                "received_at": event.received_at.isoformat(),
                "content_hash": event.content_hash,
                "payload_bytes": str(len(event.raw_payload)),
            },
        )
        try:
            await self._bus.dead_letter(TOPIC_EVENTS_RAW, message, reason=detail)
        except Exception:  # noqa: BLE001
            # Publishing failed AND dead-lettering failed: this is the only
            # path where an event is genuinely lost, so it increments the
            # silent-loss canary and logs at error rather than warning.
            metrics.events_dropped_total.labels(source_type=event.source_type).inc()
            logger.exception(
                "EVENT LOST: could not publish or dead-letter",
                extra={"content_hash": event.content_hash, "source_type": event.source_type},
            )
            return IngestResult(IngestOutcome.DROPPED, reason=detail)

        metrics.events_deadlettered_total.labels(
            source_type=event.source_type, reason=reason.value
        ).inc()
        return IngestResult(IngestOutcome.DEAD_LETTERED, reason=detail)
