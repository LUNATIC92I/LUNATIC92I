"""The streaming detection engine (spec §7).

Given a normalized event, decide which enabled rules match it and turn each
match into a `RuleMatch` — the single object every downstream stage
(correlation, risk scoring, alerting) consumes.

Three things happen between "the conditions matched" and "a detection is
emitted", and each of them exists because of a specific way SOCs fail:

- **Exceptions** — a documented, expiring carve-out for known-benign
  activity. Applied *after* the match so it can be counted: an exception
  that silently suppresses 10,000 events a day is a coverage hole nobody
  can see. `detection_exceptions_applied_total` makes it visible, and the
  expiry means it cannot outlive the reason it was created for.
- **Suppression** — once a rule has fired for an entity, hold further
  matches for the configured window. Alert fatigue is an attack surface in
  its own right (THREAT_MODEL.md §3.4): a rule that fires 500 times buries
  the one alert that mattered.
- **Dry run** — a rule in `testing` status is evaluated exactly like an
  enabled one, and its matches are recorded with `dry_run=True` so they can
  be counted and reviewed, but they never become alerts. That is how a new
  rule earns production status on real traffic instead of on a guess.

A rule that raises while evaluating is isolated and counted, never allowed
to stop the loop: one broken rule must not blind the other ninety-nine.
"""

import abc
import logging
import time
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core import metrics
from app.detection.conditions import evaluate_node, resolve_path
from app.detection.schema import DetectionRule, RuleException, RuleStatus

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuleMatch:
    """One rule firing. `event_ids` is a list because a windowed match cites
    every event in the bucket; a streaming match cites exactly one."""

    detection_id: str
    tenant_id: str
    rule_id: str
    rule_name: str
    rule_type: str
    severity: str
    confidence: int
    risk_score: int
    mitre_attack: list[str]
    event_ids: list[str]
    entity: dict[str, Any]
    matched_at: str
    dry_run: bool
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_document(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "tenant_id": self.tenant_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_type": self.rule_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "mitre_attack": list(self.mitre_attack),
            "event_ids": list(self.event_ids),
            "entity": dict(self.entity),
            "matched_at": self.matched_at,
            "dry_run": self.dry_run,
            "evidence": dict(self.evidence),
        }


class SuppressionStore(abc.ABC):
    """Deliberately an interface: in-process suppression is correct for a
    single worker and wrong the moment a second replica starts, because each
    replica would then fire once per entity. `RedisSuppressionStore` is the
    deployable implementation; the in-memory one is for tests and
    single-process runs."""

    @abc.abstractmethod
    async def claim(self, key: str, ttl_seconds: int) -> bool:
        """True if the caller may fire (nothing held the key), False if the
        entity is currently suppressed. Claiming and testing must be one
        atomic operation, or two workers racing both fire."""


class InMemorySuppressionStore(SuppressionStore):
    def __init__(self) -> None:
        self._until: dict[str, float] = {}

    async def claim(self, key: str, ttl_seconds: int) -> bool:
        now = time.monotonic()
        expiry = self._until.get(key)
        if expiry is not None and expiry > now:
            return False
        self._until[key] = now + ttl_seconds
        # Opportunistic cleanup: without it a long-running worker would
        # accumulate one entry per entity ever seen.
        if len(self._until) > 10_000:
            self._until = {k: v for k, v in self._until.items() if v > now}
        return True


class RedisSuppressionStore(SuppressionStore):
    """`SET key 1 NX EX ttl` is the whole implementation: Redis makes the
    test-and-set atomic across every worker replica, and the TTL means a
    crashed worker cannot leave a rule suppressed forever."""

    def __init__(self, redis: Any, prefix: str = "detection:suppress:") -> None:
        self._redis = redis
        self._prefix = prefix

    async def claim(self, key: str, ttl_seconds: int) -> bool:
        acquired = await self._redis.set(f"{self._prefix}{key}", b"1", nx=True, ex=ttl_seconds)
        return bool(acquired)


def exception_is_active(exception: RuleException, now: datetime) -> bool:
    if exception.expires_at is None:
        return True
    try:
        expires = datetime.fromisoformat(exception.expires_at)
    except ValueError:
        # An unparseable expiry is treated as already expired: an exception
        # nobody can date is exactly the kind that quietly erodes coverage.
        logger.warning("rule exception has an unparseable expires_at; ignoring the exception")
        return False
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires > now


def matching_exception(
    rule: DetectionRule, document: dict[str, Any], now: datetime | None = None
) -> RuleException | None:
    now = now or datetime.now(UTC)
    for exception in rule.exceptions:
        if not exception_is_active(exception, now):
            continue
        if evaluate_node(exception.conditions, document):
            return exception
    return None


def entity_key(rule: DetectionRule, document: dict[str, Any]) -> dict[str, Any]:
    entity: dict[str, Any] = {}
    for path in rule.suppression_fields:
        values = resolve_path(document, path)
        entity[path] = values[0] if values else None
    return entity


def suppression_key(rule: DetectionRule, tenant_id: str, entity: dict[str, Any]) -> str:
    parts = [f"{path}={entity.get(path)!r}" for path in sorted(entity)]
    return f"{tenant_id}:{rule.rule_id}:v{rule.version}:" + "|".join(parts)


def build_match(
    *,
    rule: DetectionRule,
    tenant_id: str,
    event_ids: Sequence[str],
    entity: dict[str, Any],
    evidence: dict[str, Any] | None = None,
) -> RuleMatch:
    return RuleMatch(
        detection_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        rule_id=rule.rule_id,
        rule_name=rule.name,
        rule_type=rule.rule_type,
        severity=rule.severity.value,
        confidence=rule.confidence,
        risk_score=rule.risk_score,
        mitre_attack=list(rule.mitre_attack),
        event_ids=list(event_ids),
        entity=entity,
        matched_at=datetime.now(UTC).isoformat(),
        # A rule under test produces detections that are recorded and
        # counted but never alert. Nothing else about its evaluation differs.
        dry_run=rule.status is RuleStatus.TESTING,
        evidence=evidence or {},
    )


class StreamingEngine:
    """Evaluates single-event rules. Windowed rules are the windowed
    evaluator's job (`app/detection/windowed.py`) and are skipped here — the
    engine holding both kinds and quietly ignoring half of them is how a
    rule ends up loaded, enabled, and never actually evaluated."""

    def __init__(
        self,
        rules: Iterable[DetectionRule],
        *,
        suppression: SuppressionStore | None = None,
    ) -> None:
        self._suppression = suppression or InMemorySuppressionStore()
        self.replace_rules(rules)

    def replace_rules(self, rules: Iterable[DetectionRule]) -> None:
        """Hot-swaps the rule set. Enabling a rule must not require a worker
        restart, or nobody will enable rules during an incident."""
        every_rule = list(rules)
        self._rules = [
            rule
            for rule in every_rule
            if rule.rule_type == "streaming" and rule.status is not RuleStatus.DISABLED
        ]
        self._skipped_windowed = [rule for rule in every_rule if rule.rule_type == "windowed"]

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    async def evaluate(self, document: dict[str, Any]) -> list[RuleMatch]:
        tenant_id = str(document.get("tenant_id") or "")
        event_id = str(document.get("event_id") or "")
        matches: list[RuleMatch] = []
        started = time.perf_counter()

        for rule in self._rules:
            try:
                match = await self._evaluate_one(rule, document, tenant_id, event_id)
            except Exception:  # noqa: BLE001  one broken rule must not blind the rest
                logger.exception("rule evaluation failed", extra={"rule_id": rule.rule_id})
                metrics.detection_rule_errors_total.labels(rule_id=rule.rule_id).inc()
                continue
            if match is not None:
                matches.append(match)

        metrics.detection_latency_seconds.observe(time.perf_counter() - started)
        return matches

    async def _evaluate_one(
        self, rule: DetectionRule, document: dict[str, Any], tenant_id: str, event_id: str
    ) -> RuleMatch | None:
        if not evaluate_node(rule.conditions, document):
            return None

        exception = matching_exception(rule, document)
        if exception is not None:
            metrics.detection_exceptions_applied_total.labels(rule_id=rule.rule_id).inc()
            logger.info(
                "detection suppressed by rule exception",
                extra={"rule_id": rule.rule_id, "reason": exception.reason},
            )
            return None

        entity = entity_key(rule, document)
        if rule.suppression_seconds > 0:
            key = suppression_key(rule, tenant_id, entity)
            if not await self._suppression.claim(key, rule.suppression_seconds):
                metrics.detections_suppressed_total.labels(rule_id=rule.rule_id).inc()
                return None

        match = build_match(
            rule=rule,
            tenant_id=tenant_id,
            event_ids=[event_id] if event_id else [],
            entity=entity,
            evidence=_evidence(document),
        )
        metrics.detections_total.labels(
            rule_id=rule.rule_id,
            severity=match.severity,
            dry_run=str(match.dry_run).lower(),
        ).inc()
        return match


_EVIDENCE_FIELDS = (
    "timestamp",
    "source_type",
    "class",
    "hostname",
    "source_ip",
    "destination_ip",
    "user",
    "process",
    "authentication",
)


def _evidence(document: dict[str, Any]) -> dict[str, Any]:
    """A small, fixed excerpt of the event, carried with the detection so an
    analyst sees why it fired without a round trip to the event store. Fixed
    rather than "the whole document" on purpose: detections are copied into
    alerts, incidents and notifications, and a full event in each of those
    is both a storage problem and a data-minimization one."""
    return {key: document[key] for key in _EVIDENCE_FIELDS if key in document}
