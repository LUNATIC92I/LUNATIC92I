"""The common collector interface (spec §5, ARCHITECTURE.md §5).

Every log source — syslog, REST, Windows Event Log, cloud APIs, EDR — is
adapted by a `Collector` into the same `RawIngestEvent`, which is the only
thing the ingestion pipeline downstream ever sees. Collectors do NOT parse,
normalize, or interpret payloads: they capture bytes verbatim (forensic
fidelity, spec §4) plus the transport metadata only they can know.

Two transport shapes exist and the interface reflects that honestly rather
than forcing one abstraction over both:

- **Listener collectors** (`ListenerCollector`) own a socket and run for the
  lifetime of the worker process: `start()` / `stop()`.
- **Request-driven collectors** (plain `Collector`) are invoked per inbound
  request by a server someone else owns — the REST collector is called by a
  FastAPI route, so it has nothing to start or stop.

Both build events through the same `build_event()` and hand them to the same
`IngestionService`, so the pipeline behind them is identical.

Adding a new collector: subclass `Collector` (or `ListenerCollector`), set
`source_type`, and hand `build_event(...)` output to the ingestion service.
Nothing else in the pipeline needs to change.
"""

import abc
import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar


@dataclass(frozen=True)
class RawIngestEvent:
    """One captured event, before any parsing. `raw_payload` is preserved
    byte-for-byte so a forensic investigation can always go back to exactly
    what the source sent (spec §4)."""

    tenant_id: uuid.UUID
    source_type: str
    collector_id: str
    raw_payload: bytes
    received_at: datetime
    source_ip: str | None = None
    content_hash: str = field(init=False)

    def __post_init__(self) -> None:
        digest = hashlib.sha256(self.raw_payload).hexdigest()
        object.__setattr__(self, "content_hash", digest)

    @property
    def idempotency_key(self) -> str:
        """Deterministic across retries of the same event from the same
        source, so a collector that re-sends after a network timeout does
        not create a duplicate event (spec §26)."""
        material = f"{self.tenant_id}:{self.source_type}:{self.content_hash}"
        return hashlib.sha256(material.encode()).hexdigest()


class Collector(abc.ABC):
    """Request-driven collector: something else receives the bytes and
    calls into this."""

    source_type: ClassVar[str]

    def __init__(self, collector_id: str) -> None:
        self.collector_id = collector_id

    def build_event(
        self, *, tenant_id: uuid.UUID, raw_payload: bytes, source_ip: str | None = None
    ) -> RawIngestEvent:
        return RawIngestEvent(
            tenant_id=tenant_id,
            source_type=self.source_type,
            collector_id=self.collector_id,
            raw_payload=raw_payload,
            received_at=datetime.now(UTC),
            source_ip=source_ip,
        )


class ListenerCollector(Collector):
    """Collector that owns a listening socket for the life of the worker."""

    @abc.abstractmethod
    async def start(self) -> None: ...

    @abc.abstractmethod
    async def stop(self) -> None: ...
