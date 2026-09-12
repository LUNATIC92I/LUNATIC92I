"""Parser worker: `events.raw` -> parse -> normalize -> `events.normalized`.

Run with:  python -m app.workers.parser_worker

Delivery contract (spec §26): every message read is either published onward
and acked, or dead-lettered and acked. A message is never acked without one
of those two outcomes having durably happened, and never left unacked
silently — a periodic reclaim sweep picks up anything a crashed instance
left in flight.
"""

import asyncio
import contextlib
import logging
import signal

from app.core.eventbus import (
    TOPIC_EVENTS_NORMALIZED,
    TOPIC_EVENTS_RAW,
    EventBus,
    EventBusMessage,
    get_event_bus,
)
from app.core.logging import configure_logging
from app.services.processing import EventProcessor, ProcessingFailure, serialize_document

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "parser"
RECLAIM_INTERVAL_SECONDS = 60
RECLAIM_MIN_IDLE_MS = 120_000


class ParserWorker:
    def __init__(
        self,
        *,
        bus: EventBus,
        processor: EventProcessor | None = None,
        consumer_name: str = "parser-1",
        raw_topic: str = TOPIC_EVENTS_RAW,
        normalized_topic: str = TOPIC_EVENTS_NORMALIZED,
    ) -> None:
        self._bus = bus
        self._processor = processor or EventProcessor()
        self._consumer_name = consumer_name
        self._raw_topic = raw_topic
        self._normalized_topic = normalized_topic

    async def handle(self, message: EventBusMessage) -> None:
        """Processes exactly one message to a terminal state, then acks."""
        outcome = self._processor.process(
            raw_payload=message.payload,
            tenant_id=message.tenant_id,
            headers=message.headers,
        )

        if isinstance(outcome, ProcessingFailure):
            await self._bus.dead_letter(
                self._raw_topic, message, reason=f"{outcome.stage}: {outcome.reason}"
            )
            logger.warning(
                "event dead-lettered during processing",
                extra={"stage": outcome.stage, "tenant_id": message.tenant_id},
            )
        else:
            document = outcome.document
            await self._bus.publish(
                self._normalized_topic,
                EventBusMessage(
                    tenant_id=message.tenant_id,
                    key=document["event_id"],
                    payload=serialize_document(document),
                    headers={
                        "source_type": document.get("source_type", "unknown"),
                        "class": str(document.get("class", "")),
                        "schema_version": document["schema_version"],
                    },
                ),
            )

        if message.message_id is not None:
            await self._bus.ack(self._raw_topic, CONSUMER_GROUP, message.message_id)

    async def run_once_over(self, messages: list[EventBusMessage]) -> None:
        for message in messages:
            await self.handle(message)

    async def run(self, stop: asyncio.Event) -> None:
        reclaim_task = asyncio.create_task(self._reclaim_loop(stop))
        try:
            async for message in self._bus.subscribe(
                self._raw_topic, CONSUMER_GROUP, self._consumer_name
            ):
                await self.handle(message)
                if stop.is_set():
                    break
        finally:
            reclaim_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reclaim_task

    async def _reclaim_loop(self, stop: asyncio.Event) -> None:
        """Recovers messages a previous consumer took but never acked (it
        crashed or was killed mid-deploy). Without this they stay pending
        forever, which is silent event loss wearing a different hat."""
        while not stop.is_set():
            await asyncio.sleep(RECLAIM_INTERVAL_SECONDS)
            try:
                reclaimed = await self._bus.claim_stale(
                    self._raw_topic,
                    CONSUMER_GROUP,
                    self._consumer_name,
                    min_idle_ms=RECLAIM_MIN_IDLE_MS,
                )
                if reclaimed:
                    logger.info("reclaimed stale messages", extra={"count": len(reclaimed)})
                    await self.run_once_over(reclaimed)
            except Exception:  # noqa: BLE001  the reclaim sweep must never kill the worker
                logger.exception("reclaim sweep failed")


async def run() -> None:
    configure_logging()
    bus = get_event_bus()
    worker = ParserWorker(bus=bus)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    logger.info("parser worker running")
    await worker.run(stop)
    logger.info("parser worker stopped")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
