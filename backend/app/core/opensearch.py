"""Shared OpenSearch client.

OpenSearch is the event store: raw and normalized events, and the searches,
aggregations and hunting queries over them (ARCHITECTURE.md §1 row 2). It is
deliberately treated as *rebuildable* — PostgreSQL holds the state of record,
and events can be replayed from the raw index or the dead-letter topic — so
losing this cluster is an availability incident, not a data-loss one.
"""

from functools import lru_cache

from opensearchpy import AsyncOpenSearch

from app.core.config import get_settings


@lru_cache
def get_opensearch() -> AsyncOpenSearch:
    settings = get_settings()
    return AsyncOpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=(
            (settings.opensearch_username, settings.opensearch_password)
            if settings.opensearch_username
            else None
        ),
        # The demo/self-signed certificates that ship with a local cluster are
        # not verifiable, so local development sets OPENSEARCH_VERIFY_CERTS
        # false. Production must leave it true — an unverified TLS connection
        # to the event store is a silent MITM opportunity for everything the
        # SOC sees (THREAT_MODEL.md §1).
        verify_certs=settings.opensearch_verify_certs,
        ssl_show_warn=settings.opensearch_verify_certs,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )
