"""Writing normalized events into the OpenSearch event store.

Bulk, not per-document: a SIEM's write path is the one place where
per-event round trips are the difference between keeping up and falling
permanently behind. Batches are flushed on size or on a deadline, so a quiet
tenant's events are not held hostage waiting for a batch to fill.

Partial failure is the interesting case. OpenSearch's bulk API succeeds at
the HTTP level while rejecting individual documents (a mapping conflict, a
malformed value). Treating a 200 as success would silently lose exactly
those events, so per-item errors are extracted and reported back to the
caller, which dead-letters them.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from opensearchpy import AsyncOpenSearch

from app.core import metrics
from app.services.index_management import NORMALIZED_ALIAS

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500
DEFAULT_FLUSH_INTERVAL_SECONDS = 2.0


@dataclass
class BulkIndexOutcome:
    indexed: int = 0
    # (document, reason) for each rejected document, so the caller can
    # dead-letter it with a cause rather than logging and moving on.
    rejected: list[tuple[dict[str, Any], str]] = field(default_factory=list)


class EventIndexer:
    """Bulk writer for one index family.

    Parameterized by alias and id field so detections (Phase 10) reuse the
    same batching, per-item error extraction and idempotent overwrite as
    events, rather than getting a second, subtly different writer.
    """

    def __init__(
        self,
        client: AsyncOpenSearch,
        *,
        alias: str = NORMALIZED_ALIAS,
        id_field: str = "event_id",
    ) -> None:
        self._client = client
        self._alias = alias
        self._id_field = id_field

    async def index_batch(self, documents: list[dict[str, Any]]) -> BulkIndexOutcome:
        if not documents:
            return BulkIndexOutcome()

        operations: list[dict[str, Any]] = []
        for document in documents:
            # The event_id is the document _id, which makes indexing
            # idempotent: a replay after a crash overwrites rather than
            # duplicating (spec §26).
            operations.append(
                {"index": {"_index": self._alias, "_id": document[self._id_field]}}
            )
            operations.append(document)

        started = time.perf_counter()
        try:
            response = await self._client.bulk(body=operations, refresh=False)
        except Exception as exc:  # noqa: BLE001  transport failure: nothing was written
            logger.exception("bulk index request failed")
            metrics.index_failures_total.labels(reason="transport").inc()
            return BulkIndexOutcome(
                rejected=[(document, f"transport failure: {exc}") for document in documents]
            )
        finally:
            metrics.index_latency_seconds.observe(time.perf_counter() - started)

        return self._interpret(documents, response)

    def _interpret(
        self, documents: list[dict[str, Any]], response: dict[str, Any]
    ) -> BulkIndexOutcome:
        outcome = BulkIndexOutcome()
        items = response.get("items", [])

        if not response.get("errors"):
            outcome.indexed = len(items) or len(documents)
            for document in documents:
                metrics.events_indexed_total.labels(
                    source_type=document.get("source_type", "unknown")
                ).inc()
            return outcome

        for document, item in zip(documents, items, strict=False):
            error = item.get("index", {}).get("error")
            if error is None:
                outcome.indexed += 1
                metrics.events_indexed_total.labels(
                    source_type=document.get("source_type", "unknown")
                ).inc()
                continue
            reason = f"{error.get('type', 'unknown')}: {error.get('reason', '')}".strip()
            outcome.rejected.append((document, reason))
            metrics.index_failures_total.labels(reason=error.get("type", "unknown")).inc()

        if outcome.rejected:
            logger.warning(
                "opensearch rejected documents in bulk batch",
                extra={"rejected": len(outcome.rejected), "indexed": outcome.indexed},
            )
        return outcome
