"""Indexer worker: `events.normalized` -> enrich -> OpenSearch.

Run with:  python -m app.workers.indexer_worker

Batching changes the delivery contract slightly from the parser worker's:
messages are acked only after the batch containing them is durably written.
A crash mid-batch therefore redelivers the whole batch, and because the
document `_id` is the event id, re-indexing overwrites rather than
duplicating (spec §26 idempotency).
"""

import asyncio
import contextlib
import json
import logging
import signal
import time
from typing import Any

from app.core.eventbus import TOPIC_EVENTS_NORMALIZED, EventBus, EventBusMessage, get_event_bus
from app.core.logging import configure_logging
from app.core.opensearch import get_opensearch
from app.enrichment.base import EnrichmentPipeline
from app.enrichment.providers import (
    AssetContextProvider,
    IocMatchProvider,
    NetworkContextProvider,
)
from app.services.index_management import bootstrap_indices
from app.services.indexing import EventIndexer

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "indexer"
DEFAULT_BATCH_SIZE = 500
DEFAULT_FLUSH_INTERVAL_SECONDS = 2.0


def default_pipeline() -> EnrichmentPipeline:
    # Order is irrelevant to correctness (providers run concurrently and
    # merge), but is listed cheapest-first for readability: network context
    # needs no I/O, asset context is one indexed lookup, indicator matching
    # is one indexed lookup over every observable in the event.
    return EnrichmentPipeline(
        (NetworkContextProvider(), AssetContextProvider(), IocMatchProvider())
    )


class IndexerWorker:
    def __init__(
        self,
        *,
        bus: EventBus,
        indexer: EventIndexer,
        pipeline: EnrichmentPipeline | None = None,
        consumer_name: str = "indexer-1",
        topic: str = TOPIC_EVENTS_NORMALIZED,
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval_seconds: float = DEFAULT_FLUSH_INTERVAL_SECONDS,
    ) -> None:
        self._bus = bus
        self._indexer = indexer
        self._pipeline = pipeline or default_pipeline()
        self._consumer_name = consumer_name
        self._topic = topic
        self._batch_size = batch_size
        self._flush_interval_seconds = flush_interval_seconds
        self._pending: list[tuple[EventBusMessage, dict[str, Any]]] = []
        self._last_flush = time.monotonic()

    async def accept(self, message: EventBusMessage) -> None:
        """Decodes, enriches and queues one message; flushes when the batch
        is full. A message whose payload is not a usable document is
        dead-lettered immediately rather than poisoning the batch."""
        try:
            document = json.loads(message.payload)
        except (json.JSONDecodeError, ValueError) as exc:
            await self._reject(message, f"undecodable normalized document: {exc}")
            return
        if not isinstance(document, dict) or "event_id" not in document:
            await self._reject(message, "normalized document missing event_id")
            return

        enriched = await self._pipeline.enrich(document)
        self._pending.append((message, enriched))

        if len(self._pending) >= self._batch_size:
            await self.flush()

    async def flush(self) -> None:
        if not self._pending:
            self._last_flush = time.monotonic()
            return

        batch = self._pending
        self._pending = []
        self._last_flush = time.monotonic()

        outcome = await self._indexer.index_batch([document for _message, document in batch])

        rejected_ids = {
            document.get("event_id"): reason for document, reason in outcome.rejected
        }
        for message, document in batch:
            reason = rejected_ids.get(document.get("event_id"))
            if reason is not None:
                await self._reject(message, f"index rejected: {reason}")
            elif message.message_id is not None:
                # Acked only now: the document is durably in the index, so a
                # crash before this point safely redelivers it.
                await self._bus.ack(self._topic, CONSUMER_GROUP, message.message_id)

    async def _reject(self, message: EventBusMessage, reason: str) -> None:
        await self._bus.dead_letter(self._topic, message, reason=reason)
        if message.message_id is not None:
            await self._bus.ack(self._topic, CONSUMER_GROUP, message.message_id)

    async def run(self, stop: asyncio.Event) -> None:
        flusher = asyncio.create_task(self._flush_on_interval(stop))
        try:
            async for message in self._bus.subscribe(
                self._topic, CONSUMER_GROUP, self._consumer_name
            ):
                await self.accept(message)
                if stop.is_set():
                    break
        finally:
            flusher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await flusher
            # Graceful shutdown: never exit holding un-indexed events that
            # have already been read off the bus.
            await self.flush()

    async def _flush_on_interval(self, stop: asyncio.Event) -> None:
        """Without this, a partially-filled batch during a lull would sit
        unindexed indefinitely — the events would be invisible to the SOC
        for as long as the estate stayed quiet."""
        while not stop.is_set():
            await asyncio.sleep(self._flush_interval_seconds / 2)
            if time.monotonic() - self._last_flush >= self._flush_interval_seconds:
                try:
                    await self.flush()
                except Exception:  # noqa: BLE001  a flush failure must not kill the worker
                    logger.exception("scheduled flush failed")


async def run() -> None:
    configure_logging()
    client = get_opensearch()
    await bootstrap_indices(client)

    worker = IndexerWorker(bus=get_event_bus(), indexer=EventIndexer(client))

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    logger.info("indexer worker running")
    await worker.run(stop)
    await client.close()
    logger.info("indexer worker stopped")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
