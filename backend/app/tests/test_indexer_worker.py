"""Indexer worker tests.

The contract is narrower than the parser worker's but stricter: a message is
acked only once the document it carries is durably in the index. Anything
else means a crash between "acked" and "written" loses an event silently.
"""

import asyncio
import json
import uuid
from typing import Any

import pytest

from app.core.eventbus import TOPIC_EVENTS_NORMALIZED, EventBusMessage, InMemoryEventBus
from app.core.opensearch import get_opensearch
from app.enrichment.base import EnrichmentPipeline
from app.services.index_management import NORMALIZED_ALIAS, bootstrap_indices
from app.services.indexing import BulkIndexOutcome, EventIndexer
from app.workers.indexer_worker import CONSUMER_GROUP, IndexerWorker


class _RecordingIndexer:
    """Stands in for OpenSearch so batching/acking can be tested without a
    cluster; the real cluster is exercised in test_opensearch.py and in the
    end-to-end test at the bottom of this file."""

    def __init__(self, reject: set[str] | None = None) -> None:
        self.batches: list[list[dict[str, Any]]] = []
        self._reject = reject or set()

    async def index_batch(self, documents: list[dict[str, Any]]) -> BulkIndexOutcome:
        self.batches.append(documents)
        rejected = [
            (document, "mapper_parsing_exception: bad field")
            for document in documents
            if document["event_id"] in self._reject
        ]
        return BulkIndexOutcome(indexed=len(documents) - len(rejected), rejected=rejected)


class _AckTrackingBus(InMemoryEventBus):
    def __init__(self) -> None:
        super().__init__()
        self.acked: list[str] = []

    async def ack(self, topic: str, group: str, message_id: str) -> None:
        self.acked.append(message_id)


def _message(event_id: str, message_id: str = "1-0") -> EventBusMessage:
    document = {
        "event_id": event_id,
        "tenant_id": str(uuid.uuid4()),
        "source_type": "syslog_udp",
        "schema_version": "lunatic-1",
    }
    return EventBusMessage(
        tenant_id=document["tenant_id"],
        key=event_id,
        payload=json.dumps(document).encode(),
        headers={},
        message_id=message_id,
    )


def _worker(bus: InMemoryEventBus, indexer: Any, **kwargs: Any) -> IndexerWorker:
    # An empty enrichment pipeline: enrichment is covered in
    # test_enrichment.py, and mixing it in here would make failures
    # ambiguous between the two concerns.
    return IndexerWorker(bus=bus, indexer=indexer, pipeline=EnrichmentPipeline(()), **kwargs)


async def test_events_are_batched_rather_than_written_one_at_a_time() -> None:
    bus, indexer = _AckTrackingBus(), _RecordingIndexer()
    worker = _worker(bus, indexer, batch_size=3)

    for index in range(3):
        await worker.accept(_message(f"e{index}", message_id=f"{index}-0"))

    assert len(indexer.batches) == 1
    assert len(indexer.batches[0]) == 3


async def test_nothing_is_acked_before_the_batch_is_written() -> None:
    """The ordering that makes at-least-once actually hold."""
    bus, indexer = _AckTrackingBus(), _RecordingIndexer()
    worker = _worker(bus, indexer, batch_size=5)

    await worker.accept(_message("e0", message_id="0-0"))
    assert bus.acked == [], "acked before the document was written"

    await worker.flush()
    assert bus.acked == ["0-0"]


async def test_a_rejected_document_is_dead_lettered_and_its_peers_still_ack() -> None:
    bus = _AckTrackingBus()
    indexer = _RecordingIndexer(reject={"bad"})
    worker = _worker(bus, indexer, batch_size=2)

    await worker.accept(_message("good", message_id="1-0"))
    await worker.accept(_message("bad", message_id="2-0"))

    dead = await bus.peek(f"{TOPIC_EVENTS_NORMALIZED}.deadletter")
    assert len(dead) == 1
    assert "mapper_parsing_exception" in dead[0].headers["dead_letter_reason"]
    # Both are acked: the good one because it was written, the bad one
    # because it is durably in the dead-letter topic. Neither is lost.
    assert sorted(bus.acked) == ["1-0", "2-0"]


async def test_an_undecodable_payload_is_dead_lettered_without_poisoning_the_batch() -> None:
    bus, indexer = _AckTrackingBus(), _RecordingIndexer()
    worker = _worker(bus, indexer, batch_size=10)

    await worker.accept(
        EventBusMessage(
            tenant_id="t", key="k", payload=b"not json at all", headers={}, message_id="1-0"
        )
    )
    await worker.accept(_message("good", message_id="2-0"))
    await worker.flush()

    dead = await bus.peek(f"{TOPIC_EVENTS_NORMALIZED}.deadletter")
    assert len(dead) == 1
    assert "undecodable" in dead[0].headers["dead_letter_reason"]
    assert [document["event_id"] for document in indexer.batches[0]] == ["good"]


async def test_a_document_without_an_event_id_is_rejected() -> None:
    """The event id is the document _id, which is what makes re-indexing
    idempotent. A document without one cannot be safely written."""
    bus, indexer = _AckTrackingBus(), _RecordingIndexer()
    worker = _worker(bus, indexer)

    await worker.accept(
        EventBusMessage(
            tenant_id="t", key="k", payload=b'{"no": "id"}', headers={}, message_id="1-0"
        )
    )

    dead = await bus.peek(f"{TOPIC_EVENTS_NORMALIZED}.deadletter")
    assert "missing event_id" in dead[0].headers["dead_letter_reason"]
    assert indexer.batches == []


async def test_a_partial_batch_is_flushed_on_the_interval_not_held_indefinitely() -> None:
    """Without this, events would sit invisible to the SOC for as long as
    the estate stayed quiet — exactly when a lone event matters most."""
    bus, indexer = _AckTrackingBus(), _RecordingIndexer()
    worker = _worker(bus, indexer, batch_size=1000, flush_interval_seconds=0.1)

    await worker.accept(_message("e0", message_id="0-0"))
    assert indexer.batches == []

    stop = asyncio.Event()
    flusher = asyncio.create_task(worker._flush_on_interval(stop))
    await asyncio.sleep(0.3)
    stop.set()
    flusher.cancel()

    assert len(indexer.batches) == 1
    assert bus.acked == ["0-0"]


async def test_shutdown_flushes_events_already_taken_off_the_bus() -> None:
    bus, indexer = _AckTrackingBus(), _RecordingIndexer()
    worker = _worker(bus, indexer, batch_size=1000)
    await bus.publish(TOPIC_EVENTS_NORMALIZED, _message("e0", message_id="0-0"))

    stop = asyncio.Event()
    stop.set()
    await worker.run(stop)

    assert len(indexer.batches) == 1, "worker exited holding un-indexed events"


async def test_enrichment_is_applied_before_indexing() -> None:
    from app.enrichment.providers import NetworkContextProvider

    bus, indexer = _AckTrackingBus(), _RecordingIndexer()
    worker = IndexerWorker(
        bus=bus,
        indexer=indexer,
        pipeline=EnrichmentPipeline((NetworkContextProvider(),)),
        batch_size=1,
    )

    message = _message("e0")
    document = json.loads(message.payload)
    document["source_ip"] = "10.1.1.5"
    await worker.accept(
        EventBusMessage(
            tenant_id=message.tenant_id,
            key=message.key,
            payload=json.dumps(document).encode(),
            headers={},
            message_id="0-0",
        )
    )

    assert indexer.batches[0][0]["geo"]["source_is_private"] is True


@pytest.fixture
async def real_indexer():
    client = get_opensearch()
    await bootstrap_indices(client)
    return EventIndexer(client)


async def test_end_to_end_normalized_event_becomes_searchable(real_indexer) -> None:
    """The Phase 5 round trip: a normalized event on the bus ends up
    queryable in the real event store."""
    bus = _AckTrackingBus()
    worker = _worker(bus, real_indexer, batch_size=1)
    tenant_id = str(uuid.uuid4())
    event_id = str(uuid.uuid4())

    document = {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "timestamp": "2026-09-13T05:00:00+00:00",
        "source_type": "syslog_udp",
        "class": "Authentication",
        "severity": "high",
        "source_ip": "10.1.1.5",
        "user": {"name": "alice"},
        "schema_version": "lunatic-1",
    }
    await worker.accept(
        EventBusMessage(
            tenant_id=tenant_id,
            key=event_id,
            payload=json.dumps(document).encode(),
            headers={},
            message_id="0-0",
        )
    )

    client = get_opensearch()
    await client.indices.refresh(index=NORMALIZED_ALIAS)
    found = await client.search(
        index=NORMALIZED_ALIAS, body={"query": {"term": {"event_id": event_id}}}
    )

    assert found["hits"]["total"]["value"] == 1
    source = found["hits"]["hits"][0]["_source"]
    assert source["user"]["name"] == "alice"
    assert source["tenant_id"] == tenant_id
    assert bus.acked == ["0-0"]
    assert CONSUMER_GROUP == "indexer"
