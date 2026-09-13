"""The windowed (threshold) evaluator (ARCHITECTURE.md §1 row 4).

Some detections are not statements about an event, they are statements about
a *rate*: five failed logins for one account in five minutes, one password
tried against thirty accounts, a hundred files read in a minute. No amount
of looking at a single event answers those, so these rules are evaluated by
asking the event store — a filtered composite aggregation per rule, run on a
schedule, with the threshold applied per bucket.

Design notes that matter operationally:

- **The window is closed, not open-ended.** Each run looks at
  `[now - duration, now]`. Runs therefore overlap when the schedule is
  shorter than the window, which is deliberate: an attack that straddles two
  runs still lands entirely inside one window. Suppression is what keeps the
  overlap from producing duplicate alerts — a windowed rule without
  `suppression` will re-fire on every run while the events are still in
  window, which the loader warns about.
- **Exceptions are applied inside the query.** Excluding excepted events
  from the *count* is the only correct place to apply them: filtering after
  aggregation would count benign events toward a threshold and fire on them.
  A second, cheap `count` measures how many events an exception removed, so
  a carve-out that quietly eats thousands of events a day stays visible in
  `detection_exceptions_applied_total` rather than becoming an invisible
  coverage hole.
- **Distinct counting is approximate above the precision threshold.**
  `cardinality` trades exactness for memory. The precision threshold is set
  well above any realistic rule threshold, so it is exact in practice; a
  rule counting distinct values in the tens of thousands should be treated
  as an estimate, which is stated here rather than discovered later.
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from opensearchpy import AsyncOpenSearch

from app.core import metrics
from app.detection.engine import (
    RuleMatch,
    SuppressionStore,
    build_match,
    exception_is_active,
    suppression_key,
)
from app.detection.query import compile_conditions
from app.detection.schema import DetectionRule, RuleStatus, WindowSpec
from app.services.index_management import NORMALIZED_ALIAS

logger = logging.getLogger(__name__)

TIMESTAMP_FIELD = "timestamp"
# Above this many distinct values, `cardinality` becomes an estimate. Set
# far above any realistic detection threshold (see the module docstring).
CARDINALITY_PRECISION = 40_000
DEFAULT_PAGE_SIZE = 500
# A hard stop on pagination: a misconfigured rule grouping by a
# high-cardinality field (event_id, say) must not walk millions of buckets
# and take the detection scheduler down with it.
DEFAULT_MAX_BUCKETS = 10_000
EVIDENCE_EVENTS = 10


def _window_of(rule: DetectionRule) -> WindowSpec:
    """Narrows `rule.window` for the type checker in one place. `run()`
    rejects a non-windowed rule before any of this is reached, so raising
    here is a guard against a future caller, not an expected path."""
    if rule.window is None:  # pragma: no cover - run() rejects these first
        raise ValueError(f"{rule.rule_id} is not a windowed rule")
    return rule.window


class WindowedEvaluator:
    def __init__(
        self,
        client: AsyncOpenSearch,
        *,
        alias: str = NORMALIZED_ALIAS,
        suppression: SuppressionStore | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        max_buckets: int = DEFAULT_MAX_BUCKETS,
    ) -> None:
        self._client = client
        self._alias = alias
        self._suppression = suppression
        self._page_size = page_size
        self._max_buckets = max_buckets

    async def run(
        self, rule: DetectionRule, tenant_id: str, *, now: datetime | None = None
    ) -> list[RuleMatch]:
        if rule.window is None:
            raise ValueError(f"{rule.rule_id} is not a windowed rule")
        if rule.status is RuleStatus.DISABLED:
            return []

        now = now or datetime.now(UTC)
        window_start = now - timedelta(seconds=rule.window.duration_seconds)
        base_filter = self._base_filter(rule, tenant_id, window_start, now)
        exception_clauses = self._exception_clauses(rule, now)

        await self._count_excepted(rule, base_filter, exception_clauses)

        try:
            matches = await self._collect(
                rule, tenant_id, base_filter, exception_clauses, window_start, now
            )
        except Exception:
            logger.exception("windowed rule evaluation failed", extra={"rule_id": rule.rule_id})
            metrics.windowed_rule_runs_total.labels(rule_id=rule.rule_id, outcome="error").inc()
            metrics.detection_rule_errors_total.labels(rule_id=rule.rule_id).inc()
            # Re-raised deliberately: unlike a single streaming event, a
            # failed windowed run means the whole window went unevaluated,
            # and the scheduler decides whether to retry it.
            raise

        metrics.windowed_rule_runs_total.labels(
            rule_id=rule.rule_id, outcome="matched" if matches else "no_match"
        ).inc()
        return matches

    # -- query construction -------------------------------------------------

    def _base_filter(
        self, rule: DetectionRule, tenant_id: str, window_start: datetime, now: datetime
    ) -> list[dict[str, Any]]:
        return [
            # Application-level tenant scoping. OpenSearch DLS enforces the
            # same thing independently for user-issued queries; this path
            # runs as the service account, so the filter here is the one
            # that must be right (THREAT_MODEL.md §3.2).
            {"term": {"tenant_id": tenant_id}},
            {
                "range": {
                    TIMESTAMP_FIELD: {
                        "gte": window_start.isoformat(),
                        "lte": now.isoformat(),
                    }
                }
            },
            compile_conditions(rule.conditions),
        ]

    def _exception_clauses(self, rule: DetectionRule, now: datetime) -> list[dict[str, Any]]:
        return [
            compile_conditions(exception.conditions)
            for exception in rule.exceptions
            if exception_is_active(exception, now)
        ]

    async def _count_excepted(
        self,
        rule: DetectionRule,
        base_filter: list[dict[str, Any]],
        exception_clauses: list[dict[str, Any]],
    ) -> None:
        if not exception_clauses:
            return
        body = {
            "query": {
                "bool": {
                    "filter": base_filter,
                    "should": exception_clauses,
                    "minimum_should_match": 1,
                }
            }
        }
        try:
            response = await self._client.count(index=self._alias, body=body)
        except Exception:  # noqa: BLE001  visibility must never break detection
            logger.warning("could not measure exception impact", extra={"rule_id": rule.rule_id})
            return
        excluded = int(response.get("count", 0))
        if excluded:
            metrics.detection_exceptions_applied_total.labels(rule_id=rule.rule_id).inc(excluded)

    def _aggregation_body(
        self,
        rule: DetectionRule,
        base_filter: list[dict[str, Any]],
        exception_clauses: list[dict[str, Any]],
        after_key: dict[str, Any] | None,
    ) -> dict[str, Any]:
        window = _window_of(rule)

        composite: dict[str, Any] = {
            "size": self._page_size,
            "sources": [{field: {"terms": {"field": field}}} for field in window.group_by],
        }
        if after_key is not None:
            composite["after"] = after_key

        aggregations: dict[str, Any] = {
            "events": {
                "top_hits": {
                    "size": EVIDENCE_EVENTS,
                    "_source": [
                        "event_id",
                        TIMESTAMP_FIELD,
                        "source_ip",
                        "user",
                        "hostname",
                    ],
                    "sort": [{TIMESTAMP_FIELD: {"order": "desc"}}],
                }
            }
        }
        if window.distinct_field is not None:
            aggregations["distinct"] = {
                "cardinality": {
                    "field": window.distinct_field,
                    "precision_threshold": CARDINALITY_PRECISION,
                }
            }

        return {
            "size": 0,
            "query": {
                "bool": {
                    "filter": base_filter,
                    "must_not": exception_clauses,
                }
            },
            "aggs": {"entities": {"composite": composite, "aggs": aggregations}},
        }

    # -- bucket handling ----------------------------------------------------

    async def _collect(
        self,
        rule: DetectionRule,
        tenant_id: str,
        base_filter: list[dict[str, Any]],
        exception_clauses: list[dict[str, Any]],
        window_start: datetime,
        now: datetime,
    ) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        after_key: dict[str, Any] | None = None
        seen = 0

        while True:
            body = self._aggregation_body(rule, base_filter, exception_clauses, after_key)
            response = await self._client.search(index=self._alias, body=body)
            entities = response.get("aggregations", {}).get("entities", {})
            buckets = entities.get("buckets", [])

            for bucket in buckets:
                match = await self._bucket_match(rule, tenant_id, bucket, window_start, now)
                if match is not None:
                    matches.append(match)

            seen += len(buckets)
            after_key = entities.get("after_key")
            if after_key is None or not buckets:
                break
            if seen >= self._max_buckets:
                logger.warning(
                    "windowed rule stopped at the bucket cap; group_by is too "
                    "high-cardinality for a threshold rule",
                    extra={"rule_id": rule.rule_id, "buckets": seen},
                )
                metrics.windowed_rule_runs_total.labels(
                    rule_id=rule.rule_id, outcome="bucket_cap"
                ).inc()
                break

        return matches

    async def _bucket_match(
        self,
        rule: DetectionRule,
        tenant_id: str,
        bucket: dict[str, Any],
        window_start: datetime,
        now: datetime,
    ) -> RuleMatch | None:
        window = _window_of(rule)

        if window.distinct_field is not None:
            observed = int(bucket.get("distinct", {}).get("value", 0))
        else:
            observed = int(bucket.get("doc_count", 0))

        if observed < window.threshold:
            return None

        entity = dict(bucket.get("key", {}))
        if rule.suppression_seconds > 0 and self._suppression is not None:
            key = suppression_key(rule, tenant_id, entity)
            if not await self._suppression.claim(key, rule.suppression_seconds):
                metrics.detections_suppressed_total.labels(rule_id=rule.rule_id).inc()
                return None

        hits = bucket.get("events", {}).get("hits", {}).get("hits", [])
        event_ids = [hit["_source"]["event_id"] for hit in hits if "event_id" in hit["_source"]]

        match = build_match(
            rule=rule,
            tenant_id=tenant_id,
            event_ids=event_ids,
            entity=entity,
            evidence={
                "observed": observed,
                "threshold": window.threshold,
                "distinct_field": window.distinct_field,
                "window_start": window_start.isoformat(),
                "window_end": now.isoformat(),
                # Stated because `event_ids` is capped: an analyst must not
                # read "3 event ids" as "3 events matched".
                "event_ids_truncated": observed > len(event_ids),
                "sample_events": [hit["_source"] for hit in hits],
            },
        )
        metrics.detections_total.labels(
            rule_id=rule.rule_id, severity=match.severity, dry_run=str(match.dry_run).lower()
        ).inc()
        return match
