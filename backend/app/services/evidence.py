"""Resolving alert evidence back to the events behind it.

An alert cites OpenSearch document ids by value rather than by join: the
event store is rebuildable and the alert must survive it being reindexed
(ARCHITECTURE.md §1 row 2). The cost of that choice is that the link can go
stale, so resolution reports what it could not find instead of quietly
returning fewer documents.

The tenant filter here is not decoration. This query runs as the service
account, so it is the isolation boundary for this path; DLS is the second
layer for user-issued queries (THREAT_MODEL.md §3.2). Without it, an alert
carrying a guessed event id could read another tenant's event.
"""

import logging
from typing import Any

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import NotFoundError

from app.services.index_management import NORMALIZED_ALIAS

logger = logging.getLogger(__name__)

MAX_EVIDENCE_DOCUMENTS = 200


async def resolve_events(
    client: AsyncOpenSearch, *, tenant_id: str, event_ids: list[str]
) -> dict[str, dict[str, Any]]:
    """Returns {event_id: document} for the ids that exist and belong to
    this tenant. Missing ids are simply absent from the mapping."""
    if not event_ids:
        return {}

    body = {
        "size": min(len(event_ids), MAX_EVIDENCE_DOCUMENTS),
        "query": {
            "bool": {
                "filter": [
                    {"term": {"tenant_id": tenant_id}},
                    {"terms": {"event_id": event_ids[:MAX_EVIDENCE_DOCUMENTS]}},
                ]
            }
        },
    }
    try:
        response = await client.search(index=NORMALIZED_ALIAS, body=body)
    except NotFoundError:
        return {}
    except Exception:  # noqa: BLE001  an unreachable store must not 500 the alert view
        logger.warning("could not resolve alert evidence", exc_info=True)
        return {}

    return {
        hit["_source"]["event_id"]: hit["_source"]
        for hit in response.get("hits", {}).get("hits", [])
        if "event_id" in hit.get("_source", {})
    }
