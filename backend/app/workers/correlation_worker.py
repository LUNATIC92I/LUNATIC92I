"""Correlation worker: events + detections -> `correlations.created`.

Run with:  python -m app.workers.correlation_worker

It subscribes to two topics at once, because a chain is rarely made of one
kind of thing: `detections.created` carries what the Phase 6 rules already
recognised, and `events.normalized` carries the activity no single rule
flags but that means something in sequence.

All the state lives in Redis (`app/correlation/state.py`), so this process
holds nothing that matters. Restarting it, scaling it out, or losing a
replica mid-chain does not lose the chain — which is Technical Risk #4, and
is covered by a test that kills the engine and rebuilds it from the store.
"""

import asyncio
import contextlib
import json
import logging
import signal
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.eventbus import (
    TOPIC_CORRELATIONS_CREATED,
    TOPIC_DETECTIONS_CREATED,
    TOPIC_EVENTS_NORMALIZED,
    EventBus,
    EventBusMessage,
    consumer_identity,
    get_event_bus,
)
from app.core.logging import configure_logging
from app.core.observability import redis_ready, start_observability_server
from app.core.redis import get_redis
from app.core.tracing import configure_tracing
from app.correlation.engine import (
    CorrelationEngine,
    CorrelationInput,
    CorrelationMatch,
    detection_input,
    event_input,
)
from app.correlation.loader import load_correlation_rules_or_raise
from app.correlation.state import RedisCorrelationStateStore
from app.detection.engine import RedisSuppressionStore
from app.risk.engine import apply_to_correlation

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "correlation"


class CorrelationWorker:
    def __init__(
        self,
        *,
        bus: EventBus,
        engine: CorrelationEngine,
        consumer_name: str = "correlation-1",
        output_topic: str = TOPIC_CORRELATIONS_CREATED,
    ) -> None:
        self._bus = bus
        self._engine = engine
        self._consumer_name = consumer_name
        self._output_topic = output_topic

    async def accept(self, topic: str, message: EventBusMessage) -> None:
        try:
            document = json.loads(message.payload)
        except (json.JSONDecodeError, ValueError) as exc:
            await self._reject(topic, message, f"undecodable payload: {exc}")
            return
        if not isinstance(document, dict):
            await self._reject(topic, message, "payload is not an object")
            return

        correlation_input = self._to_input(topic, document)
        if correlation_input is not None:
            matches = await self._engine.process(correlation_input)
            await self.publish(matches)
        # An input that cannot be correlated (a dry-run detection, an event
        # with no id) is not a failure: it is simply not part of any chain,
        # and it is acked like anything else rather than dead-lettered.
        if message.message_id is not None:
            await self._bus.ack(topic, CONSUMER_GROUP, message.message_id)

    def _to_input(self, topic: str, document: dict[str, Any]) -> CorrelationInput | None:
        skew = get_settings().correlation_max_clock_skew_seconds
        if topic == TOPIC_DETECTIONS_CREATED:
            return detection_input(document, max_skew_seconds=skew)
        return event_input(document, max_skew_seconds=skew)

    async def publish(self, matches: list[CorrelationMatch]) -> None:
        for match in matches:
            # A correlation is scored on the worst context its whole chain
            # touched, which is only knowable once the chain is complete
            # (app/risk/engine.py).
            document = apply_to_correlation(match.to_document())
            await self._bus.publish(
                self._output_topic,
                EventBusMessage(
                    tenant_id=match.tenant_id,
                    key=match.correlation_uid,
                    payload=json.dumps(document).encode(),
                    headers={
                        "correlation_id": match.correlation_id,
                        "severity": match.severity,
                        "risk_bucket": str(document["risk_bucket"]),
                    },
                ),
            )

    async def _reject(self, topic: str, message: EventBusMessage, reason: str) -> None:
        await self._bus.dead_letter(topic, message, reason=reason)
        if message.message_id is not None:
            await self._bus.ack(topic, CONSUMER_GROUP, message.message_id)

    async def _consume(self, topic: str, stop: asyncio.Event) -> None:
        async for message in self._bus.subscribe(topic, CONSUMER_GROUP, self._consumer_name):
            await self.accept(topic, message)
            if stop.is_set():
                break

    async def run(self, stop: asyncio.Event) -> None:
        tasks = [
            asyncio.create_task(self._consume(topic, stop))
            for topic in (TOPIC_EVENTS_NORMALIZED, TOPIC_DETECTIONS_CREATED)
        ]
        try:
            # If either consumer dies, the worker is only half-working —
            # which would silently degrade every chain that needs the other
            # stream. Exit instead and let the orchestrator restart it.
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task


def build(bus: EventBus | None = None) -> CorrelationWorker:
    settings = get_settings()
    redis = get_redis()
    rules = load_correlation_rules_or_raise(Path(settings.detection_rules_path))
    engine = CorrelationEngine(
        rules,
        state=RedisCorrelationStateStore(redis),
        suppression=RedisSuppressionStore(redis, prefix="correlation:suppress:"),
        max_clock_skew_seconds=settings.correlation_max_clock_skew_seconds,
    )
    return CorrelationWorker(
        bus=bus or get_event_bus(), engine=engine, consumer_name=consumer_identity("correlation")
    )


async def run() -> None:
    configure_logging()
    configure_tracing()
    worker = build()
    obs = await start_observability_server(get_settings().metrics_port, ready_check=redis_ready)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    logger.info("correlation worker running")
    try:
        await worker.run(stop)
    finally:
        obs.close()
        await obs.wait_closed()
    logger.info("correlation worker stopped")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
