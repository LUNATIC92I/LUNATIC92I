"""The risk engine (spec §10, ARCHITECTURE.md §1 row 10).

Assembles the factors into one 0–100 score with a breakdown an analyst can
read back. The arithmetic is deliberately boring — a weighted mean over the
factors that had data — because the requirement here is explainability, not
cleverness: a black-box model that cannot answer "why is this a 78?" fails
the phase no matter how good its ranking is (ARCHITECTURE.md §11 records
that trade-off explicitly).

    score = 100 * Σ(weight_i × value_i) / max(Σ(weight_i for available i), 60)

The denominator is what makes a missing factor honest. With a fixed
denominator of 100, a detection scored before threat intel exists would lose
15 points for a feed nobody consulted, and every score in the platform would
be quietly deflated by however many factors were not yet implemented. The
floor of 60 is the other half of that: without it, a medium-severity
detection with no context normalizes to 53 and is bucketed HIGH purely
because so little was known (see `model.MINIMUM_DENOMINATOR`).
"""

import logging
from dataclasses import dataclass, field
from typing import Any

from app.core import metrics
from app.risk.factors import (
    asset_criticality_factor,
    behavioral_anomaly_factor,
    confidence_factor,
    mitre_context_factor,
    severity_factor,
    threat_intel_factor,
    user_risk_factor,
)
from app.risk.model import (
    FORMULA_VERSION,
    MINIMUM_DENOMINATOR,
    WEIGHTS_FINGERPRINT,
    FactorScore,
    RiskAssessment,
    bucket_for,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RiskContext:
    """Everything the formula reads, in one place.

    Built from a detection or correlation document by `context_from_*` so
    the engine itself never has to know the shape of either.
    """

    severity: str | None = None
    confidence: int | float | None = None
    asset_criticality: str | None = None
    user_risk_score: float | int | None = None
    ioc_matches: list[Any] | None = None
    enrichment_ran: bool = True
    mitre_attack: list[str] = field(default_factory=list)
    anomaly: dict[str, Any] | None = None


def assess(context: RiskContext) -> RiskAssessment:
    factors: list[FactorScore] = [
        severity_factor(context.severity),
        confidence_factor(context.confidence),
        asset_criticality_factor(context.asset_criticality),
        user_risk_factor(context.user_risk_score),
        threat_intel_factor(context.ioc_matches, enrichment_ran=context.enrichment_ran),
        mitre_context_factor(context.mitre_attack),
        behavioral_anomaly_factor(context.anomaly),
    ]

    available = [factor for factor in factors if factor.available]
    available_weight = sum(factor.weight for factor in available)
    if available_weight <= 0:
        # No input at all. Zero is the only defensible answer, and the
        # explanation says why rather than leaving a bare 0 to be read as
        # "we assessed this and it is fine".
        score = 0
    else:
        denominator = max(available_weight, MINIMUM_DENOMINATOR)
        score = round(100 * sum(factor.points for factor in available) / denominator)

    score = max(0, min(100, score))
    bucket = bucket_for(score)
    metrics.risk_scores_total.labels(bucket=bucket.value).inc()
    return RiskAssessment(
        score=score,
        bucket=bucket,
        formula_version=FORMULA_VERSION,
        weights_fingerprint=WEIGHTS_FINGERPRINT,
        factors=factors,
    )


def _asset_criticality_of(document: dict[str, Any]) -> str | None:
    asset = document.get("asset")
    if isinstance(asset, dict) and asset.get("criticality"):
        return str(asset["criticality"])
    risk_context = document.get("risk_context")
    if isinstance(risk_context, dict) and risk_context.get("asset_criticality"):
        return str(risk_context["asset_criticality"])
    return None


def _user_risk_of(document: dict[str, Any]) -> float | None:
    risk_context = document.get("risk_context")
    if isinstance(risk_context, dict) and risk_context.get("user_risk_score") is not None:
        return float(risk_context["user_risk_score"])
    return None


def _intel_of(document: dict[str, Any]) -> tuple[list[Any] | None, bool]:
    """Distinguishes "no indicator matched" from "intel was never
    consulted": the key is present once enrichment has run, and a partial
    enrichment (a provider that timed out) counts as not consulted, because
    the missing provider may well have been the intel one."""
    if document.get("enrichment_partial"):
        return None, False
    matches = document.get("ioc_matches")
    if matches is None:
        return None, False
    return list(matches), True


def context_from_detection(
    detection: dict[str, Any], event: dict[str, Any] | None = None
) -> RiskContext:
    """A detection carries the rule's own severity/confidence and a small
    evidence excerpt; the enriched event (when the caller has it) carries
    asset, user and intel context. Both are read, with the event's
    enrichment preferred because it is the fuller record."""
    source: dict[str, Any] = {**(detection.get("evidence") or {}), **(event or {})}
    matches, enrichment_ran = _intel_of(source)
    return RiskContext(
        severity=detection.get("severity"),
        confidence=detection.get("confidence"),
        asset_criticality=_asset_criticality_of(source),
        user_risk_score=_user_risk_of(source),
        ioc_matches=matches,
        enrichment_ran=enrichment_ran,
        mitre_attack=list(detection.get("mitre_attack") or []),
        anomaly=source.get("anomaly"),
    )


def context_from_correlation(correlation: dict[str, Any]) -> RiskContext:
    """A correlation's own severity and confidence come from its rule; the
    asset and intel context come from the timeline entries, taking the worst
    of each — a chain is as serious as the most critical thing it touched."""
    summaries = [
        entry.get("summary", {})
        for entry in correlation.get("timeline", [])
        if isinstance(entry, dict)
    ]
    criticalities = [
        value
        for value in (_asset_criticality_of(summary) for summary in summaries)
        if value is not None
    ]
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    worst = max(criticalities, key=lambda value: order.get(value.upper(), -1), default=None)

    matches: list[Any] = []
    for summary in summaries:
        found, ran = _intel_of(summary)
        if ran and found:
            matches.extend(found)

    return RiskContext(
        severity=correlation.get("severity"),
        confidence=correlation.get("confidence"),
        asset_criticality=worst,
        user_risk_score=next(
            (value for value in (_user_risk_of(summary) for summary in summaries) if value),
            None,
        ),
        # A correlation is scored on the indicators its own steps carried;
        # if none did, intel is absent rather than clean.
        ioc_matches=matches or None,
        enrichment_ran=bool(matches),
        mitre_attack=list(correlation.get("mitre_attack") or []),
    )


def apply_to_detection(
    detection: dict[str, Any], event: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Stamps `risk_score`, `risk_bucket` and `risk_explanation` onto a
    detection document, in place-ish (a new dict is returned).

    The rule's own `risk_score` is kept as `rule_risk_score`: it is the
    detection engineer's static judgement about the rule, while this is the
    computed judgement about this instance, and conflating the two is how a
    score becomes unexplainable.
    """
    assessment = assess(context_from_detection(detection, event))
    return {
        **detection,
        "rule_risk_score": detection.get("risk_score"),
        "risk_score": assessment.score,
        "risk_bucket": assessment.bucket.value,
        "risk_explanation": assessment.explanation(),
    }


def apply_to_correlation(correlation: dict[str, Any]) -> dict[str, Any]:
    assessment = assess(context_from_correlation(correlation))
    return {
        **correlation,
        "rule_risk_score": correlation.get("risk_score"),
        "risk_score": assessment.score,
        "risk_bucket": assessment.bucket.value,
        "risk_explanation": assessment.explanation(),
    }
