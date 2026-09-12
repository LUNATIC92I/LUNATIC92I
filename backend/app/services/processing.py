"""Parse + normalize one raw event (spec §6 steps 1-5).

Separated from the worker that drives it so the transformation can be
tested directly, without a broker in the loop.
"""

import json
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.core import metrics
from app.normalization.ocsf import NormalizationError, normalize
from app.parsers.base import ParserError
from app.parsers.registry import ParserRegistry

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessingSuccess:
    document: dict[str, Any]


@dataclass(frozen=True)
class ProcessingFailure:
    """Why an event could not be turned into a normalized document. Always
    carries a reason: a dead-lettered event with no explanation cannot be
    triaged or replayed intelligently."""

    stage: str
    reason: str


# A union rather than `(document | None, failure | None)`: the tuple form
# cannot express "exactly one of these is set", so every caller ends up
# either re-checking both or being silently wrong when it guesses.
ProcessingOutcome = ProcessingSuccess | ProcessingFailure


class EventProcessor:
    def __init__(self, registry: ParserRegistry | None = None) -> None:
        self._registry = registry or ParserRegistry()

    def process(
        self,
        *,
        raw_payload: bytes,
        tenant_id: str,
        headers: dict[str, str],
    ) -> ProcessingOutcome:
        """Never raises for bad input — malformed data is the normal case
        for a SIEM, not an exceptional one, and a worker that crashes on it
        stops the whole pipeline."""
        started = time.perf_counter()

        try:
            parsed = self._registry.parse(raw_payload)
        except ParserError as exc:
            metrics.parser_errors_total.labels(stage="parse").inc()
            return ProcessingFailure(stage="parse", reason=str(exc))
        except Exception as exc:  # noqa: BLE001  a parser bug must not kill the worker
            logger.exception("unexpected parser failure")
            metrics.parser_errors_total.labels(stage="parse").inc()
            return ProcessingFailure(
                stage="parse", reason=f"unexpected parser failure: {type(exc).__name__}: {exc}"
            )

        try:
            document = normalize(
                parsed=parsed,
                tenant_id=tenant_id,
                raw_payload=raw_payload,
                source_type=headers.get("source_type", "unknown"),
                collector_id=headers.get("collector_id", "unknown"),
                received_at=_received_at(headers),
                source_ip=headers.get("source_ip") or None,
            )
        except NormalizationError as exc:
            metrics.parser_errors_total.labels(stage="normalize").inc()
            return ProcessingFailure(stage="normalize", reason=str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.exception("unexpected normalization failure")
            metrics.parser_errors_total.labels(stage="normalize").inc()
            return ProcessingFailure(
                stage="normalize",
                reason=f"unexpected normalization failure: {type(exc).__name__}: {exc}",
            )

        metrics.events_processed_total.labels(format=parsed.format_name).inc()
        metrics.processing_latency_seconds.labels(format=parsed.format_name).observe(
            time.perf_counter() - started
        )
        return ProcessingSuccess(document=document)


def serialize_document(document: dict[str, Any]) -> bytes:
    return json.dumps(document, separators=(",", ":"), default=str).encode()


def _received_at(headers: dict[str, str]) -> datetime:
    raw = headers.get("received_at")
    if raw:
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    return datetime.now(UTC)
