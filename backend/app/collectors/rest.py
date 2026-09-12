"""REST collector (spec §5).

Request-driven: the FastAPI ingestion route owns the socket, authenticates
the caller with a collector API key, and calls `build_event()` here. Unlike
syslog, this transport is authenticated and integrity-protected by TLS, so
it needs no source-IP allowlist — the API key is the identity.
"""

from typing import ClassVar

from app.collectors.base import Collector


class RestCollector(Collector):
    source_type: ClassVar[str] = "rest"
