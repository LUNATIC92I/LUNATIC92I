"""The correlation engine (spec §9, ARCHITECTURE.md §6 `correlation`).

Takes one input at a time — a normalized event, or a detection produced by
Phase 6 — decides which stage of which rule it satisfies, records it against
the entity the rule correlates by, and fires when a chain is complete.

Three decisions in here are worth reading before changing anything:

**Time is judged, not trusted.** Ordering and windowing use an *effective*
time: the source's own timestamp when it is plausible, and the ingestion
timestamp when it is not (Technical Risk #5). Without that backstop, a
correlation window is evadable with a text editor — stamp the privilege
escalation two days earlier and the chain never closes. The cost is that
genuinely delayed or backfilled logs correlate at ingestion time; every hit
records which clock it was judged on, so a timeline never hides it.

**Arrival order is not event order.** Stages are ordered by effective time,
not by the order the worker happened to see them. A backlogged collector, a
retried batch, or two workers racing must not be able to break a chain that
really happened.

**Completion is re-evaluated on every input.** There is no timer that
"closes" a window. A chain completes the moment the input that completes it
arrives — including when that input is the *first* stage arriving last,
which is exactly the out-of-order case above.
"""

import logging
import time
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core import metrics
from app.correlation.schema import CorrelationRule, CorrelationStage, InputKind
from app.correlation.state import CorrelationStateStore, StageHit
from app.detection.conditions import evaluate_node, resolve_path
from app.detection.engine import SuppressionStore
from app.detection.schema import RuleStatus

logger = logging.getLogger(__name__)

# How far a source's own timestamp may sit from its ingestion time before it
# stops being believed. Wide enough for ordinary clock drift and collector
# lag, narrow enough that it cannot be used to step outside a rule window.
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 900

# Fields copied into a timeline entry. Fixed, because a timeline is carried
# into alerts and incidents and must stay small (data minimization, and a
# 5-stage chain of whole events is a large object).
_SUMMARY_FIELDS = (
    "class",
    "event_code",
    "hostname",
    "source_ip",
    "destination_ip",
    "user",
    "process",
    "authentication",
    "severity",
)


@dataclass(frozen=True)
class CorrelationInput:
    """One thing to correlate, normalized across the two input streams."""

    kind: str  # "event" | "detection"
    tenant_id: str
    event_id: str
    document: dict[str, Any]
    claimed_at_ms: int
    ingested_at_ms: int
    occurred_at_ms: int
    time_source: str


@dataclass(frozen=True)
class CorrelationMatch:
    correlation_uid: str
    correlation_id: str
    name: str
    tenant_id: str
    severity: str
    confidence: int
    risk_score: int
    mitre_attack: list[str]
    entity: dict[str, Any]
    stages_matched: list[str]
    event_ids: list[str]
    first_seen: str
    last_seen: str
    span_seconds: int
    timeline: list[dict[str, Any]] = field(default_factory=list)

    def to_document(self) -> dict[str, Any]:
        return {
            "correlation_uid": self.correlation_uid,
            "correlation_id": self.correlation_id,
            "name": self.name,
            "tenant_id": self.tenant_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "mitre_attack": list(self.mitre_attack),
            "entity": dict(self.entity),
            "stages_matched": list(self.stages_matched),
            "event_ids": list(self.event_ids),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "span_seconds": self.span_seconds,
            "timeline": [dict(entry) for entry in self.timeline],
        }


def _parse_time(value: Any) -> int | None:
    if isinstance(value, int | float):
        # Treat a bare number as epoch milliseconds if it is implausibly
        # large for seconds — the OCSF object uses milliseconds.
        return int(value if value > 1e11 else value * 1000)
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


def _iso(milliseconds: int) -> str:
    return datetime.fromtimestamp(milliseconds / 1000, tz=UTC).isoformat()


def effective_time(
    claimed_at_ms: int, ingested_at_ms: int, *, max_skew_seconds: int
) -> tuple[int, str]:
    """The time a chain is judged on, and which clock it came from.

    A source timestamp further from ingestion than the tolerance is not
    used: it is either a badly-skewed clock or a deliberate attempt to step
    a stage outside the correlation window, and neither should decide
    whether an attack is detected.
    """
    skew_ms = claimed_at_ms - ingested_at_ms
    if abs(skew_ms) <= max_skew_seconds * 1000:
        return claimed_at_ms, "event"
    metrics.correlation_timestamp_clamped_total.labels(
        direction="future" if skew_ms > 0 else "past"
    ).inc()
    logger.warning(
        "event timestamp is too far from its ingestion time to be trusted; "
        "correlating on ingestion time instead",
        extra={"skew_seconds": round(skew_ms / 1000)},
    )
    return ingested_at_ms, "ingestion"


def event_input(
    document: dict[str, Any], *, max_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS
) -> CorrelationInput | None:
    tenant_id = str(document.get("tenant_id") or "")
    event_id = str(document.get("event_id") or "")
    if not tenant_id or not event_id:
        return None

    ingested = _parse_time(document.get("ingestion_timestamp"))
    claimed = _parse_time(document.get("timestamp"))
    if ingested is None:
        # No trustworthy clock at all: fall back to the claimed time, or to
        # now. Recorded as "ingestion" so the timeline does not overstate
        # what is known about when this happened.
        ingested = claimed if claimed is not None else int(time.time() * 1000)
    if claimed is None:
        claimed = ingested

    occurred, source = effective_time(claimed, ingested, max_skew_seconds=max_skew_seconds)
    return CorrelationInput(
        kind="event",
        tenant_id=tenant_id,
        event_id=event_id,
        document=document,
        claimed_at_ms=claimed,
        ingested_at_ms=ingested,
        occurred_at_ms=occurred,
        time_source=source,
    )


def detection_input(
    detection: dict[str, Any], *, max_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS
) -> CorrelationInput | None:
    """Turns a Phase 6 detection into something stages can match.

    The document a stage sees carries the detection under `detection.*` and
    the originating event's evidence flattened alongside it, so a stage can
    say either "AUTH-001 fired" or "...for user X from an external address"
    without the rule author needing to know which stream it came from.

    Dry-run detections are dropped: a rule in `testing` status must not be
    able to drive a correlation that alerts, or "testing" would not mean
    what it says.
    """
    tenant_id = str(detection.get("tenant_id") or "")
    detection_id = str(detection.get("detection_id") or "")
    if not tenant_id or not detection_id or detection.get("dry_run"):
        return None

    evidence = detection.get("evidence") or {}
    document: dict[str, Any] = {
        **(evidence if isinstance(evidence, dict) else {}),
        "tenant_id": tenant_id,
        "detection": {
            "rule_id": detection.get("rule_id"),
            "rule_name": detection.get("rule_name"),
            "severity": detection.get("severity"),
            "confidence": detection.get("confidence"),
            "risk_score": detection.get("risk_score"),
            "mitre_attack": detection.get("mitre_attack") or [],
        },
    }
    # A detection's entity is keyed by dotted path ("user.name"), which is
    # how the detection engine names it. Grafting it into the document as a
    # literal key would make it unreachable to `resolve_path`, so a windowed
    # detection (whose only entity is its bucket key) would never correlate.
    _graft_entity(document, detection.get("entity") or {})

    matched_at = _parse_time(detection.get("matched_at")) or int(time.time() * 1000)
    claimed = _parse_time(document.get("timestamp")) or matched_at
    occurred, source = effective_time(claimed, matched_at, max_skew_seconds=max_skew_seconds)

    # The detection cites the events behind it; the first is the one whose
    # id a timeline entry should point at.
    event_ids = detection.get("event_ids") or []
    return CorrelationInput(
        kind="detection",
        tenant_id=tenant_id,
        event_id=str(event_ids[0]) if event_ids else detection_id,
        document=document,
        claimed_at_ms=claimed,
        ingested_at_ms=matched_at,
        occurred_at_ms=occurred,
        time_source=source,
    )


def _graft_entity(document: dict[str, Any], entity: dict[str, Any]) -> None:
    """Writes dotted entity paths into the document as nested values,
    without overwriting anything the evidence already carried."""
    for path, value in entity.items():
        if value in (None, ""):
            continue
        target = document
        *parents, leaf = path.split(".")
        for part in parents:
            child = target.get(part)
            if not isinstance(child, dict):
                child = {}
                target[part] = child
            target = child
        target.setdefault(leaf, value)


def _entity_of(rule: CorrelationRule, document: dict[str, Any]) -> dict[str, Any] | None:
    """The entity this input belongs to, or None if it cannot be
    determined. An input missing an entity field is not correlated at all —
    guessing would chain unrelated activity together."""
    entity: dict[str, Any] = {}
    for path in rule.correlate_by:
        values = [value for value in resolve_path(document, path) if value not in (None, "")]
        if not values:
            return None
        entity[path] = values[0]
    return entity


def _stage_accepts(stage: CorrelationStage, kind: str) -> bool:
    return stage.matches is InputKind.ANY or stage.matches.value == kind


def state_key(rule: CorrelationRule, tenant_id: str, entity: dict[str, Any]) -> str:
    parts = "|".join(f"{path}={entity[path]!r}" for path in sorted(entity))
    return f"{tenant_id}:{rule.correlation_id}:v{rule.version}:{parts}"


def _ordered_completion(
    rule: CorrelationRule, hits_by_stage: dict[str, list[StageHit]]
) -> list[StageHit] | None:
    """Greedy earliest-feasible selection.

    For each required stage in order, take the earliest `min_count` hits at
    or after the previous stage's last selected time. Taking the earliest
    feasible hit each time never rules out a later one, so if this fails no
    valid ordering exists.
    """
    selected: list[StageHit] = []
    cursor = -1
    for stage in rule.required_stages:
        candidates = [
            hit for hit in hits_by_stage.get(stage.name, []) if hit.occurred_at_ms >= cursor
        ]
        if len(candidates) < stage.min_count:
            return None
        taken = candidates[: stage.min_count]
        selected.extend(taken)
        cursor = taken[-1].occurred_at_ms
    return selected


def _unordered_completion(
    rule: CorrelationRule, hits_by_stage: dict[str, list[StageHit]]
) -> list[StageHit] | None:
    selected: list[StageHit] = []
    for stage in rule.required_stages:
        hits = hits_by_stage.get(stage.name, [])
        if len(hits) < stage.min_count:
            return None
        selected.extend(hits[: stage.min_count])
    return selected


def build_timeline(hits: Sequence[StageHit]) -> list[dict[str, Any]]:
    """The chain as an analyst reads it: what happened, in what order, on
    which clock. Built automatically (spec §9) rather than assembled by hand
    during triage — reconstructing a chain manually is where most of an
    investigation's time goes."""
    return [
        {
            "time": _iso(hit.occurred_at_ms),
            "stage": hit.stage,
            "kind": hit.kind,
            "event_id": hit.event_id,
            # Surfaced so a reader can tell a chain judged on the source's
            # own clock from one judged on ours.
            "time_source": hit.time_source,
            "claimed_time": _iso(hit.claimed_at_ms),
            "summary": hit.summary,
        }
        for hit in sorted(hits, key=lambda hit: hit.occurred_at_ms)
    ]


class CorrelationEngine:
    def __init__(
        self,
        rules: Iterable[CorrelationRule],
        *,
        state: CorrelationStateStore,
        suppression: SuppressionStore | None = None,
        max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
    ) -> None:
        self._state = state
        self._suppression = suppression
        self._max_clock_skew_seconds = max_clock_skew_seconds
        self.replace_rules(rules)

    def replace_rules(self, rules: Iterable[CorrelationRule]) -> None:
        self._rules = [rule for rule in rules if rule.status is not RuleStatus.DISABLED]

    @property
    def rules(self) -> list[CorrelationRule]:
        return list(self._rules)

    async def process(self, correlation_input: CorrelationInput) -> list[CorrelationMatch]:
        started = time.perf_counter()
        metrics.correlation_inputs_total.labels(kind=correlation_input.kind).inc()

        matches: list[CorrelationMatch] = []
        for rule in self._rules:
            try:
                match = await self._process_rule(rule, correlation_input)
            except Exception:  # noqa: BLE001  one broken rule must not blind the rest
                logger.exception(
                    "correlation rule failed", extra={"correlation_id": rule.correlation_id}
                )
                continue
            if match is not None:
                matches.append(match)

        metrics.correlation_latency_seconds.observe(time.perf_counter() - started)
        return matches

    async def _process_rule(
        self, rule: CorrelationRule, correlation_input: CorrelationInput
    ) -> CorrelationMatch | None:
        document = correlation_input.document
        stages = [
            stage
            for stage in rule.stages
            if _stage_accepts(stage, correlation_input.kind)
            and evaluate_node(stage.conditions, document)
        ]
        if not stages:
            return None

        entity = _entity_of(rule, document)
        if entity is None:
            return None

        key = state_key(rule, correlation_input.tenant_id, entity)
        held: list[StageHit] = []
        for stage in stages:
            # An input can satisfy more than one stage (a rule may look for
            # "any failure" and "a failure from outside"); each is recorded,
            # so the chain is not silently short-changed by a stage it also
            # matched.
            metrics.correlation_stage_hits_total.labels(
                correlation_id=rule.correlation_id, stage=stage.name
            ).inc()
            held = await self._state.append(
                key,
                StageHit(
                    stage=stage.name,
                    occurred_at_ms=correlation_input.occurred_at_ms,
                    claimed_at_ms=correlation_input.claimed_at_ms,
                    ingested_at_ms=correlation_input.ingested_at_ms,
                    time_source=correlation_input.time_source,
                    kind=correlation_input.kind,
                    event_id=correlation_input.event_id,
                    summary=_summarize(document),
                ),
                ttl_seconds=rule.window_seconds,
            )

        return await self._evaluate(rule, correlation_input.tenant_id, entity, key, held)

    async def _evaluate(
        self,
        rule: CorrelationRule,
        tenant_id: str,
        entity: dict[str, Any],
        key: str,
        held: list[StageHit],
    ) -> CorrelationMatch | None:
        if not held:
            return None

        # The window is anchored on the newest hit rather than on wall-clock
        # now, so a batch of events replayed after the fact still correlates
        # among themselves instead of all falling out of an empty window.
        newest = max(hit.occurred_at_ms for hit in held)
        window_start = newest - rule.window_seconds * 1000
        in_window = sorted(
            (hit for hit in held if hit.occurred_at_ms >= window_start),
            key=lambda hit: hit.occurred_at_ms,
        )

        hits_by_stage: dict[str, list[StageHit]] = {}
        for hit in in_window:
            hits_by_stage.setdefault(hit.stage, []).append(hit)

        selected = (
            _ordered_completion(rule, hits_by_stage)
            if rule.ordered
            else _unordered_completion(rule, hits_by_stage)
        )
        if selected is None:
            return None

        if rule.suppression_seconds > 0 and self._suppression is not None:
            claimed = await self._suppression.claim(
                f"correlation:{key}", rule.suppression_seconds
            )
            if not claimed:
                metrics.correlations_suppressed_total.labels(
                    correlation_id=rule.correlation_id
                ).inc()
                return None

        # The timeline carries every hit in window, including optional
        # stages: those exist precisely to give the analyst context that did
        # not gate the correlation.
        timeline = build_timeline(in_window)
        first, last = in_window[0].occurred_at_ms, in_window[-1].occurred_at_ms

        metrics.correlations_total.labels(
            correlation_id=rule.correlation_id, severity=rule.severity.value
        ).inc()
        logger.info(
            "correlation completed",
            extra={"correlation_id": rule.correlation_id, "entity": entity},
        )
        return CorrelationMatch(
            correlation_uid=str(uuid.uuid4()),
            correlation_id=rule.correlation_id,
            name=rule.name,
            tenant_id=tenant_id,
            severity=rule.severity.value,
            confidence=rule.confidence,
            risk_score=rule.risk_score,
            mitre_attack=list(rule.mitre_attack),
            entity=entity,
            stages_matched=[hit.stage for hit in selected],
            event_ids=list(dict.fromkeys(hit.event_id for hit in in_window)),
            first_seen=_iso(first),
            last_seen=_iso(last),
            span_seconds=round((last - first) / 1000),
            timeline=timeline,
        )


def _summarize(document: dict[str, Any]) -> dict[str, Any]:
    summary = {key: document[key] for key in _SUMMARY_FIELDS if key in document}
    detection = document.get("detection")
    if isinstance(detection, dict) and detection.get("rule_id"):
        summary["detection_rule"] = detection["rule_id"]
    return summary
