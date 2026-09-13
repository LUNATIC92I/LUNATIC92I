"""Reading detections back out of the event store.

Detections are written by the indexer worker (Phase 10) and read here for
ATT&CK coverage and, in Phase 14, for the SOC overview. Everything in this
module is tenant-filtered explicitly: these queries run as the service
account, so the filter here is the isolation boundary, with OpenSearch DLS
as the second layer for user-issued queries (THREAT_MODEL.md §3.2).

Dry-run detections are excluded from every count. A rule in `testing` status
produces detections deliberately, and letting them inflate a coverage page
would make "we detect this technique" true for a rule that never alerts.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import NotFoundError

from app.services.index_management import DETECTION_ALIAS

logger = logging.getLogger(__name__)

DEFAULT_WINDOW_DAYS = 30
MAX_TECHNIQUE_BUCKETS = 2000


def _base_filter(tenant_id: str, since: datetime, include_dry_run: bool) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = [
        {"term": {"tenant_id": tenant_id}},
        {"range": {"matched_at": {"gte": since.isoformat()}}},
    ]
    if not include_dry_run:
        filters.append({"term": {"dry_run": False}})
    return filters


async def detections_per_technique(
    client: AsyncOpenSearch,
    tenant_id: str,
    *,
    days: int = DEFAULT_WINDOW_DAYS,
    include_dry_run: bool = False,
) -> dict[str, int]:
    """How many detections each ATT&CK technique produced in the window.

    Returns an empty mapping — never raises — when the detections index does
    not exist yet or the cluster is unreachable: a coverage page that 500s
    because nothing has fired yet would be worse than one showing zeros, and
    the rule-derived half of coverage is still meaningful without it.
    """
    since = datetime.now(UTC) - timedelta(days=days)
    body = {
        "size": 0,
        "query": {"bool": {"filter": _base_filter(tenant_id, since, include_dry_run)}},
        "aggs": {
            "techniques": {
                "terms": {"field": "mitre_attack", "size": MAX_TECHNIQUE_BUCKETS}
            }
        },
    }
    try:
        response = await client.search(index=DETECTION_ALIAS, body=body)
    except NotFoundError:
        return {}
    except Exception:  # noqa: BLE001  coverage degrades, it does not fail
        logger.warning("could not read detection counts", exc_info=True)
        return {}

    buckets = response.get("aggregations", {}).get("techniques", {}).get("buckets", [])
    return {bucket["key"]: int(bucket["doc_count"]) for bucket in buckets}


async def recent_detections(
    client: AsyncOpenSearch,
    tenant_id: str,
    *,
    technique_id: str | None = None,
    days: int = DEFAULT_WINDOW_DAYS,
    limit: int = 20,
    include_dry_run: bool = False,
) -> list[dict[str, Any]]:
    since = datetime.now(UTC) - timedelta(days=days)
    filters = _base_filter(tenant_id, since, include_dry_run)
    if technique_id:
        filters.append({"term": {"mitre_attack": technique_id}})

    body = {
        "size": limit,
        "query": {"bool": {"filter": filters}},
        "sort": [{"matched_at": {"order": "desc"}}],
        "_source": [
            "detection_id",
            "rule_id",
            "rule_name",
            "severity",
            "risk_score",
            "risk_bucket",
            "mitre_attack",
            "entity_summary",
            "matched_at",
            "event_ids",
        ],
    }
    try:
        response = await client.search(index=DETECTION_ALIAS, body=body)
    except NotFoundError:
        return []
    except Exception:  # noqa: BLE001
        logger.warning("could not read recent detections", exc_info=True)
        return []

    return [hit["_source"] for hit in response.get("hits", {}).get("hits", [])]
