"""Detection worker: `events.normalized` -> rules -> `detections.created`.

Run with:  python -m app.workers.detection_worker

The worker runs both execution shapes in one process because they share
everything that matters — the rule set, the suppression store, the output
topic — and differ only in what triggers them:

- the **streaming** path is event-driven, evaluating each normalized event
  against the tenant's single-event rules as it arrives;
- the **windowed** path is time-driven, running each threshold rule's
  aggregation against the event store on a fixed interval.

Rules are read from PostgreSQL, not from disk, and refreshed on an interval.
That is what makes "disable this rule" take effect in a minute rather than
at the next deploy — during an incident, the ability to silence a
misfiring rule without a restart is the difference between a tuning change
and an outage.

Delivery follows the same at-least-once contract as every other worker: a
message is acked only after its detections are published. A crash between
publishing and acking replays the event, which can duplicate a detection —
deliberately preferred over the alternative, since Phase 11 deduplicates
alerts on a `dedup_key` and a duplicated alert is recoverable while a lost
detection is not.
"""

import asyncio
import contextlib
import json
import logging
import signal
import time
import uuid

from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import async_session_factory, tenant_scoped_session
from app.core.eventbus import (
    TOPIC_DETECTIONS_CREATED,
    TOPIC_EVENTS_NORMALIZED,
    EventBus,
    EventBusMessage,
    get_event_bus,
)
from app.core.logging import configure_logging
from app.core.opensearch import get_opensearch
from app.core.redis import get_redis
from app.detection.engine import (
    RedisSuppressionStore,
    RuleMatch,
    StreamingEngine,
    SuppressionStore,
)
from app.detection.schema import DetectionRule
from app.detection.windowed import WindowedEvaluator
from app.models.identity import Organization
from app.services.detection_rules import load_active_rules

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "detection"


class RuleRegistry:
    """Per-tenant rule cache, refreshed from the database on an interval.

    Cached because the alternative is a database round trip per event, and
    refreshed because a rule set that only changes on restart is a rule set
    nobody dares to change.
    """

    def __init__(
        self, *, refresh_seconds: int, suppression: SuppressionStore | None = None
    ) -> None:
        self._refresh_seconds = refresh_seconds
        self._suppression = suppression
        self._engines: dict[uuid.UUID, StreamingEngine] = {}
        self._windowed: dict[uuid.UUID, list[DetectionRule]] = {}
        self._loaded_at: dict[uuid.UUID, float] = {}
        self._locks: dict[uuid.UUID, asyncio.Lock] = {}

    def _lock(self, tenant_id: uuid.UUID) -> asyncio.Lock:
        return self._locks.setdefault(tenant_id, asyncio.Lock())

    async def _refresh_if_stale(self, tenant_id: uuid.UUID) -> None:
        loaded_at = self._loaded_at.get(tenant_id)
        if loaded_at is not None and time.monotonic() - loaded_at < self._refresh_seconds:
            return
        async with self._lock(tenant_id):
            # Re-checked inside the lock: without this, a burst of events for
            # a tenant whose cache just expired would all queue up and reload
            # the rule set once each.
            loaded_at = self._loaded_at.get(tenant_id)
            if loaded_at is not None and time.monotonic() - loaded_at < self._refresh_seconds:
                return
            await self._load(tenant_id)

    async def _load(self, tenant_id: uuid.UUID) -> None:
        async with tenant_scoped_session(tenant_id) as db:
            rules = await load_active_rules(db, tenant_id)

        engine = self._engines.get(tenant_id)
        if engine is None:
            # One engine per tenant, reused across refreshes so its
            # suppression state survives a rule reload — otherwise every
            # refresh would let every suppressed rule fire again.
            engine = StreamingEngine(rules, suppression=self._suppression)
            self._engines[tenant_id] = engine
        else:
            engine.replace_rules(rules)

        self._windowed[tenant_id] = [rule for rule in rules if rule.rule_type == "windowed"]
        self._loaded_at[tenant_id] = time.monotonic()
        logger.info(
            "detection rules loaded",
            extra={
                "tenant_id": str(tenant_id),
                "streaming": len(engine.rules),
                "windowed": len(self._windowed[tenant_id]),
            },
        )

    async def engine_for(self, tenant_id: uuid.UUID) -> StreamingEngine:
        await self._refresh_if_stale(tenant_id)
        return self._engines[tenant_id]

    async def windowed_rules_for(self, tenant_id: uuid.UUID) -> list[DetectionRule]:
        await self._refresh_if_stale(tenant_id)
        return list(self._windowed.get(tenant_id, []))


class DetectionWorker:
    def __init__(
        self,
        *,
        bus: EventBus,
        registry: RuleRegistry,
        consumer_name: str = "detection-1",
        topic: str = TOPIC_EVENTS_NORMALIZED,
        output_topic: str = TOPIC_DETECTIONS_CREATED,
    ) -> None:
        self._bus = bus
        self._registry = registry
        self._consumer_name = consumer_name
        self._topic = topic
        self._output_topic = output_topic

    async def accept(self, message: EventBusMessage) -> None:
        try:
            document = json.loads(message.payload)
        except (json.JSONDecodeError, ValueError) as exc:
            await self._reject(message, f"undecodable normalized document: {exc}")
            return
        if not isinstance(document, dict):
            await self._reject(message, "normalized document is not an object")
            return

        try:
            tenant_id = uuid.UUID(str(document.get("tenant_id")))
        except (TypeError, ValueError):
            # Without a tenant there is no rule set and no isolation
            # boundary; evaluating it against some default tenant's rules
            # would be worse than dead-lettering it.
            await self._reject(message, "normalized document has no usable tenant_id")
            return

        engine = await self._registry.engine_for(tenant_id)
        matches = await engine.evaluate(document)
        await self.publish(matches)

        if message.message_id is not None:
            await self._bus.ack(self._topic, CONSUMER_GROUP, message.message_id)

    async def publish(self, matches: list[RuleMatch]) -> None:
        for match in matches:
            await self._bus.publish(
                self._output_topic,
                EventBusMessage(
                    tenant_id=match.tenant_id,
                    key=match.detection_id,
                    payload=json.dumps(match.to_document()).encode(),
                    headers={
                        "rule_id": match.rule_id,
                        "severity": match.severity,
                        # Carried in a header as well as the body so a
                        # downstream consumer can drop dry-run detections
                        # without deserializing them.
                        "dry_run": str(match.dry_run).lower(),
                    },
                ),
            )

    async def _reject(self, message: EventBusMessage, reason: str) -> None:
        await self._bus.dead_letter(self._topic, message, reason=reason)
        if message.message_id is not None:
            await self._bus.ack(self._topic, CONSUMER_GROUP, message.message_id)

    async def run(self, stop: asyncio.Event) -> None:
        async for message in self._bus.subscribe(self._topic, CONSUMER_GROUP, self._consumer_name):
            await self.accept(message)
            if stop.is_set():
                break


class WindowedScheduler:
    """Runs every tenant's threshold rules on a fixed interval.

    Tenants come from the organizations table rather than from traffic: a
    tenant that has stopped sending events entirely is exactly the case
    where a threshold rule ("no events from this source in an hour") would
    matter, and a scheduler that only knows about tenants it has recently
    seen would never notice.
    """

    def __init__(
        self,
        *,
        registry: RuleRegistry,
        evaluator: WindowedEvaluator,
        worker: DetectionWorker,
        interval_seconds: int,
    ) -> None:
        self._registry = registry
        self._evaluator = evaluator
        self._worker = worker
        self._interval_seconds = interval_seconds

    async def _active_tenants(self) -> list[uuid.UUID]:
        async with async_session_factory() as db:
            stmt = select(Organization.id).where(Organization.is_active.is_(True))
            return list((await db.execute(stmt)).scalars())

    async def run_once(self) -> int:
        emitted = 0
        for tenant_id in await self._active_tenants():
            try:
                rules = await self._registry.windowed_rules_for(tenant_id)
            except Exception:  # noqa: BLE001  one tenant's failure is not the others'
                logger.exception("could not load windowed rules", extra={"tenant": str(tenant_id)})
                continue

            for rule in rules:
                try:
                    matches = await self._evaluator.run(rule, str(tenant_id))
                except Exception:  # noqa: BLE001  already counted in metrics by the evaluator
                    logger.exception(
                        "windowed rule failed", extra={"rule_id": rule.rule_id}
                    )
                    continue
                await self._worker.publish(matches)
                emitted += len(matches)
        return emitted

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            started = time.monotonic()
            try:
                await self.run_once()
            except Exception:  # noqa: BLE001  the scheduler must outlive any single pass
                logger.exception("windowed rule pass failed")
            elapsed = time.monotonic() - started
            if elapsed > self._interval_seconds:
                # Loud, because silently falling behind means windows start
                # skipping events and detections go missing without any error.
                logger.warning(
                    "windowed rule pass took longer than its interval",
                    extra={"elapsed_seconds": round(elapsed, 1)},
                )
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    stop.wait(), timeout=max(1.0, self._interval_seconds - elapsed)
                )


def build(bus: EventBus | None = None) -> tuple[DetectionWorker, WindowedScheduler]:
    settings = get_settings()
    registry = RuleRegistry(
        refresh_seconds=settings.detection_rule_refresh_seconds,
        # Redis-backed so suppression holds across every replica of this
        # worker, not just within one process (see engine.SuppressionStore).
        suppression=RedisSuppressionStore(get_redis()),
    )
    worker = DetectionWorker(bus=bus or get_event_bus(), registry=registry)
    scheduler = WindowedScheduler(
        registry=registry,
        evaluator=WindowedEvaluator(
            get_opensearch(), suppression=RedisSuppressionStore(get_redis())
        ),
        worker=worker,
        interval_seconds=settings.detection_window_interval_seconds,
    )
    return worker, scheduler


async def run() -> None:
    configure_logging()
    worker, scheduler = build()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    logger.info("detection worker running")
    windowed = asyncio.create_task(scheduler.run(stop))
    try:
        await worker.run(stop)
    finally:
        windowed.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await windowed
    logger.info("detection worker stopped")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
