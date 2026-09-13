"""The pivot set (spec §15): the fixed jumps an analyst makes while hunting.

A pivot answers one of two shapes of question:

- **"What did X do?"** — IP→Events, Hash→Events, Domain→Events, and
  User→Timeline all return the matching events themselves. User→Timeline is
  the odd one out on purpose: the other three are triage lists (newest
  first, so the most recent activity is what an analyst sees), while a
  timeline is a narrative and reads in the order it happened (oldest
  first).
- **"What else touched X?"** — IP→Users, User→Hosts and Host→Processes
  return the *distinct entities* seen alongside X, as a terms aggregation
  rather than a document list. Returning every matching event and asking
  the analyst to mentally de-duplicate the user/host/process column would
  turn a five-second pivot into a spreadsheet exercise.

Every pivot is tenant-scoped the same way every other backend-driven
OpenSearch query in this platform is (THREAT_MODEL.md §3.2): a `term` on
`tenant_id` in the query itself, because this runs as the service account
rather than a per-user DLS-scoped credential.
"""

from dataclasses import dataclass, field
from typing import Any, Literal

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import NotFoundError

from app.detection.query import case_insensitive_allowed
from app.services.index_management import NORMALIZED_ALIAS

DEFAULT_EVENT_LIMIT = 100
MAX_EVENT_LIMIT = 1000
DEFAULT_VALUE_LIMIT = 50
MAX_VALUE_LIMIT = 500

# Fields returned with each pivoted event — a fixed excerpt rather than the
# whole document, matching the same data-minimization choice the detection
# engine's evidence excerpt makes (app/detection/engine.py::_EVIDENCE_FIELDS).
# Public: `app.services.hunting` reuses it for free-text/filtered search
# results and exports, so a hunt looks the same shape everywhere it appears.
EVENT_FIELDS = (
    "event_id",
    "timestamp",
    "class",
    "severity",
    "hostname",
    "source_ip",
    "destination_ip",
    "user",
    "process",
    "domain",
    "url",
    "hash",
    "mitre_techniques",
)

PivotName = Literal[
    "ip_to_events",
    "ip_to_users",
    "user_to_hosts",
    "host_to_processes",
    "hash_to_events",
    "domain_to_events",
    "user_to_timeline",
]

PIVOT_NAMES: tuple[PivotName, ...] = (
    "ip_to_events",
    "ip_to_users",
    "user_to_hosts",
    "host_to_processes",
    "hash_to_events",
    "domain_to_events",
    "user_to_timeline",
)


class UnknownPivot(ValueError):
    pass


@dataclass
class ValueCount:
    value: str
    count: int


@dataclass
class PivotResult:
    pivot: str
    result_type: Literal["events", "values"]
    total: int
    events: list[dict[str, Any]] = field(default_factory=list)
    values: list[ValueCount] = field(default_factory=list)


def _term(field_name: str, value: str) -> dict[str, Any]:
    """A single case-insensitive term match — except on field types
    (`ip`, numeric...) OpenSearch refuses the option on outright, where the
    comparison is exact instead. `ip`-typed fields accept CIDR notation
    directly in a term query, which is what makes address pivots work
    without a separate CIDR code path."""
    insensitive = case_insensitive_allowed(field_name, True)
    return {"term": {field_name: {"value": value, "case_insensitive": insensitive}}}


def _term_or(field_names: tuple[str, ...], value: str) -> dict[str, Any]:
    """`field_a == value OR field_b == value OR ...`. Used where one logical
    entity (an address, a hash) can appear in more than one field of the
    normalized document."""
    return {
        "bool": {
            "should": [_term(name, value) for name in field_names],
            "minimum_should_match": 1,
        }
    }


async def _search_events(
    client: AsyncOpenSearch,
    *,
    pivot: str,
    tenant_id: str,
    match: dict[str, Any],
    limit: int,
    ascending: bool,
) -> PivotResult:
    limit = max(1, min(limit, MAX_EVENT_LIMIT))
    body = {
        "size": limit,
        "query": {"bool": {"filter": [{"term": {"tenant_id": tenant_id}}, match]}},
        "sort": [{"timestamp": {"order": "asc" if ascending else "desc"}}],
        "_source": list(EVENT_FIELDS),
    }
    try:
        response = await client.search(index=NORMALIZED_ALIAS, body=body)
    except NotFoundError:
        return PivotResult(pivot=pivot, result_type="events", total=0)

    hits = response.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    events = [hit["_source"] for hit in hits.get("hits", [])]
    return PivotResult(pivot=pivot, result_type="events", total=total, events=events)


async def _distinct_values(
    client: AsyncOpenSearch,
    *,
    pivot: str,
    tenant_id: str,
    match: dict[str, Any],
    agg_field: str,
    limit: int,
) -> PivotResult:
    limit = max(1, min(limit, MAX_VALUE_LIMIT))
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"tenant_id": tenant_id}}, match]}},
        "aggs": {"distinct": {"terms": {"field": agg_field, "size": limit}}},
    }
    try:
        response = await client.search(index=NORMALIZED_ALIAS, body=body)
    except NotFoundError:
        return PivotResult(pivot=pivot, result_type="values", total=0)

    buckets = response.get("aggregations", {}).get("distinct", {}).get("buckets", [])
    values = [
        ValueCount(value=str(bucket["key"]), count=int(bucket["doc_count"])) for bucket in buckets
    ]
    total = int(response.get("hits", {}).get("total", {}).get("value", 0))
    return PivotResult(pivot=pivot, result_type="values", total=total, values=values)


async def ip_to_events(
    client: AsyncOpenSearch, tenant_id: str, ip: str, *, limit: int = DEFAULT_EVENT_LIMIT
) -> PivotResult:
    match = _term_or(("source_ip", "destination_ip", "device.ip"), ip)
    return await _search_events(
        client, pivot="ip_to_events", tenant_id=tenant_id, match=match, limit=limit, ascending=False
    )


async def ip_to_users(
    client: AsyncOpenSearch, tenant_id: str, ip: str, *, limit: int = DEFAULT_VALUE_LIMIT
) -> PivotResult:
    match = _term_or(("source_ip", "destination_ip", "device.ip"), ip)
    return await _distinct_values(
        client,
        pivot="ip_to_users",
        tenant_id=tenant_id,
        match=match,
        agg_field="user.name",
        limit=limit,
    )


async def user_to_hosts(
    client: AsyncOpenSearch, tenant_id: str, username: str, *, limit: int = DEFAULT_VALUE_LIMIT
) -> PivotResult:
    match = _term("user.name", username)
    return await _distinct_values(
        client,
        pivot="user_to_hosts",
        tenant_id=tenant_id,
        match=match,
        agg_field="hostname",
        limit=limit,
    )


async def host_to_processes(
    client: AsyncOpenSearch, tenant_id: str, hostname: str, *, limit: int = DEFAULT_VALUE_LIMIT
) -> PivotResult:
    match = _term("hostname", hostname)
    return await _distinct_values(
        client,
        pivot="host_to_processes",
        tenant_id=tenant_id,
        match=match,
        agg_field="process.name",
        limit=limit,
    )


async def hash_to_events(
    client: AsyncOpenSearch, tenant_id: str, file_hash: str, *, limit: int = DEFAULT_EVENT_LIMIT
) -> PivotResult:
    # The algorithm is not asked for: an md5/sha1/sha256 value is
    # unambiguous by construction (no two of them are ever the same
    # length), so matching all three fields finds it regardless.
    match = _term_or(("hash.md5", "hash.sha1", "hash.sha256"), file_hash)
    return await _search_events(
        client,
        pivot="hash_to_events",
        tenant_id=tenant_id,
        match=match,
        limit=limit,
        ascending=False,
    )


async def domain_to_events(
    client: AsyncOpenSearch, tenant_id: str, domain: str, *, limit: int = DEFAULT_EVENT_LIMIT
) -> PivotResult:
    match = {
        "bool": {
            "should": [
                _term("domain", domain),
                # `url` carries the full URL, so a subpath on the domain
                # (http://evil.com/a/b) is only found by substring match,
                # not an exact term.
                {"wildcard": {"url": {"value": f"*{domain}*", "case_insensitive": True}}},
            ],
            "minimum_should_match": 1,
        }
    }
    return await _search_events(
        client,
        pivot="domain_to_events",
        tenant_id=tenant_id,
        match=match,
        limit=limit,
        ascending=False,
    )


async def user_to_timeline(
    client: AsyncOpenSearch, tenant_id: str, username: str, *, limit: int = DEFAULT_EVENT_LIMIT
) -> PivotResult:
    match = _term("user.name", username)
    return await _search_events(
        client,
        pivot="user_to_timeline",
        tenant_id=tenant_id,
        match=match,
        limit=limit,
        # Ascending: a timeline is read in the order it happened, unlike
        # the triage-oriented *_to_events pivots above.
        ascending=True,
    )


_PIVOTS = {
    "ip_to_events": ip_to_events,
    "ip_to_users": ip_to_users,
    "user_to_hosts": user_to_hosts,
    "host_to_processes": host_to_processes,
    "hash_to_events": hash_to_events,
    "domain_to_events": domain_to_events,
    "user_to_timeline": user_to_timeline,
}


async def run_pivot(
    client: AsyncOpenSearch, name: str, tenant_id: str, value: str, *, limit: int | None = None
) -> PivotResult:
    try:
        pivot_fn = _PIVOTS[name]
    except KeyError as exc:
        raise UnknownPivot(
            f"unknown pivot: {name}. Valid pivots: {', '.join(PIVOT_NAMES)}"
        ) from exc
    if not value or not value.strip():
        raise ValueError("pivot value must not be empty")
    kwargs: dict[str, Any] = {}
    if limit is not None:
        kwargs["limit"] = limit
    return await pivot_fn(client, tenant_id, value.strip(), **kwargs)
