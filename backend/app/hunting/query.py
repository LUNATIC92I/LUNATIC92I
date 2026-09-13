"""The hunting query builder (spec §15).

Free-text search and structured filters compile to real OpenSearch query
DSL, tenant-scoped, over `events-normalized-*`. Two design choices carry
the weight here:

**Structured filters reuse the detection engine's condition grammar.**
`HuntFilters` is exactly `app.detection.schema.ConditionNode` — the same
`equals`/`contains`/`cidr`/`gt`/... operators an analyst already sees when
reading a detection rule, compiled by the exact same, already-tested
`app.detection.query.compile_conditions`. One grammar for "does this event
match" wherever that question is asked (a streaming rule, a windowed rule,
a hunt) is one set of safety properties to reason about instead of three:
no `eval`, no free-form query string handed to the cluster, and the same
`matches` (regex) refusal — Lucene regexp has no per-query timeout, so
allowing it here would open the exact denial-of-service door the detection
engine's operator table was built to keep shut.

**Free text is a bounded, escaped multi-field search, not `query_string`.**
OpenSearch's `query_string` parses a small expression language out of
whatever the analyst typed (`AND`, `OR`, field:value, wildcards, ranges);
handing an analyst's search-box input straight to it means the search box
*is* a query language interpreter reachable by anyone who can search. This
searches a fixed, reviewed field list instead, and userland `*`/`?`
characters are escaped so a literal ip address or filename cannot
accidentally expand into a wildcard scan.

**Every field name is validated against the index mapping before it
reaches the cluster.** With `dynamic: false`, a filter on a field the
mapping never declared does not error, it silently matches nothing — which
in a hunting tool looks exactly like "there's nothing here" instead of "you
mistyped the field". Rejecting it at request time turns a silent false
negative into an error the analyst can fix.
"""

from datetime import datetime
from functools import lru_cache
from typing import Any

from app.detection.query import (
    UNSUPPORTED_IN_QUERY,
    compile_conditions,
    non_textual_fields,
    unsupported_operators,
)
from app.detection.schema import ConditionNode

# The fixed, reviewed field list free text is matched against — deliberately
# not "every keyword field in the mapping": these are the ones an analyst
# actually searches by name/value/path, not machine bookkeeping fields like
# `schema_version` or `enrichment_errors`.
FREE_TEXT_FIELDS: tuple[str, ...] = (
    "hostname",
    "user.name",
    "process.name",
    "process.cmd_line",
    "command_line",
    "domain",
    "url",
    "hash.md5",
    "hash.sha1",
    "hash.sha256",
    "source_ip",
    "destination_ip",
    "mitre_techniques",
    "event_code",
    "class",
)

MAX_FREE_TEXT_LENGTH = 512


class InvalidHuntQuery(ValueError):
    pass


@lru_cache(maxsize=1)
def _known_fields() -> frozenset[str]:
    """Every dotted field path the normalized-event mapping declares.
    Cached and derived from the mapping itself — a field added there is
    immediately huntable, and a typo in a filter is caught here rather than
    matching nothing on the cluster."""
    from app.services.index_management import normalized_mapping

    found: set[str] = set()

    def walk(properties: dict[str, Any], prefix: str) -> None:
        for name, definition in properties.items():
            path = f"{prefix}{name}"
            found.add(path)
            if "properties" in definition:
                walk(definition["properties"], f"{path}.")

    walk(normalized_mapping()["properties"], "")
    return frozenset(found)


def known_fields() -> frozenset[str]:
    """Public accessor for the searchable field allowlist — what
    `GET /hunting/fields` reports (app/api/hunting.py)."""
    return _known_fields()


def _leaf_conditions(node: ConditionNode) -> list[Any]:
    from app.detection.schema import Condition, ConditionGroup

    if isinstance(node, ConditionGroup):
        children = node.all_of or node.any_of or ([node.not_of] if node.not_of else [])
        return [leaf for child in children for leaf in _leaf_conditions(child)]
    assert isinstance(node, Condition)  # nosec B101 - ConditionNode is Condition | ConditionGroup
    return [node]


def validate_filter_fields(node: ConditionNode) -> None:
    """Every field a filter tree touches must be one the mapping actually
    declares, or the filter is refused rather than silently matching
    nothing (see the module docstring)."""
    known = _known_fields()
    unknown = sorted({condition.field_path for condition in _leaf_conditions(node)} - known)
    if unknown:
        raise InvalidHuntQuery(
            f"unknown field(s) for hunting: {', '.join(unknown)}. "
            "See GET /hunting/fields for the searchable list."
        )


def compile_filters(node: ConditionNode) -> dict[str, Any]:
    """Validates and compiles a filter tree. Raises `InvalidHuntQuery` for
    an unknown field or an operator with no faithful OpenSearch translation
    (`matches` — see the module docstring)."""
    validate_filter_fields(node)
    unsupported = sorted(set(unsupported_operators(node)))
    if unsupported:
        raise InvalidHuntQuery(
            f"operator(s) not supported in hunting filters: {', '.join(unsupported)}. "
            "Regex has no per-query timeout on the cluster side; use "
            "contains/starts_with/ends_with/in instead."
        )
    return compile_conditions(node)


def _escape_free_text(value: str) -> str:
    """Escapes Lucene wildcard metacharacters so a literal search term
    (an IP, a filename with a `?` in it) cannot be misread as a pattern —
    the same escaping `contains` uses for structured filters."""
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def compile_free_text(text: str) -> dict[str, Any]:
    """A bounded, case-insensitive substring search across
    `FREE_TEXT_FIELDS`. See the module docstring for why this is not
    `query_string`.

    `source_ip`/`destination_ip` are `ip`-typed: OpenSearch rejects a
    `wildcard` query on them outright (`Can only use wildcard queries on
    keyword and text fields`), the same restriction `case_insensitive`
    hits on the same field types — see `non_textual_fields()`. A substring
    search on an address is not a meaningful question anyway; an analyst
    hunting a specific IP uses a structured filter (`equals`/`cidr`)
    instead, so these two are skipped here rather than worked around.
    """
    if not text or not text.strip():
        raise InvalidHuntQuery("free-text query must not be empty")
    if len(text) > MAX_FREE_TEXT_LENGTH:
        raise InvalidHuntQuery(f"free-text query exceeds {MAX_FREE_TEXT_LENGTH} characters")

    escaped = _escape_free_text(text.strip())
    excluded = non_textual_fields()
    should: list[dict[str, Any]] = [
        {"wildcard": {field: {"value": f"*{escaped}*", "case_insensitive": True}}}
        for field in FREE_TEXT_FIELDS
        if field != "command_line" and field not in excluded
    ]
    # `command_line` is analyzed text, not keyword — searched with a normal
    # match rather than a wildcard, which is both correct (wildcards on an
    # analyzed field query the raw term dictionary, not the tokens an
    # analyst expects to match) and cheaper.
    should.append({"match": {"command_line": escaped}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def compile_time_range(*, since: datetime | None, until: datetime | None) -> dict[str, Any] | None:
    if since is None and until is None:
        return None
    bounds: dict[str, str] = {}
    if since is not None:
        bounds["gte"] = since.isoformat()
    if until is not None:
        bounds["lte"] = until.isoformat()
    return {"range": {"timestamp": bounds}}


def build_query(
    *,
    tenant_id: str,
    free_text: str | None,
    filters: ConditionNode | None,
    since: datetime | None,
    until: datetime | None,
) -> dict[str, Any]:
    """The full query for a hunt: tenant scope (the isolation boundary for
    this service-account path — DLS is the second layer for user-issued
    queries, THREAT_MODEL.md §3.2), plus whichever of free text, structured
    filters and a time range were given."""
    clauses: list[dict[str, Any]] = [{"term": {"tenant_id": tenant_id}}]
    if free_text:
        clauses.append(compile_free_text(free_text))
    if filters is not None:
        clauses.append(compile_filters(filters))
    time_clause = compile_time_range(since=since, until=until)
    if time_clause is not None:
        clauses.append(time_clause)
    return {"bool": {"filter": clauses}}


__all__ = [
    "FREE_TEXT_FIELDS",
    "MAX_FREE_TEXT_LENGTH",
    "UNSUPPORTED_IN_QUERY",
    "InvalidHuntQuery",
    "build_query",
    "compile_filters",
    "compile_free_text",
    "compile_time_range",
    "known_fields",
    "validate_filter_fields",
]
