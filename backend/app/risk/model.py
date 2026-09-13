"""Risk scoring types and the versioned weight table (spec §10).

The spec's hard requirement for this phase is not the number, it is the
*why*: "l'analyste doit pouvoir voir pourquoi". So the score is a weighted
sum of named factors, each capped, each recording the input it was derived
from, and the whole breakdown travels with the detection — an analyst (or
the Phase 14 UI) can reconstruct the arithmetic without re-running anything.

Two decisions worth reading before touching the numbers:

**The formula is versioned, and the version is not decoration.** Every
assessment records `formula_version`. Scores computed under different
versions are not comparable, so a stored explanation is the only way to
understand an old alert's number. `WEIGHTS_FINGERPRINT` is derived from the
weight table and a test fails the build if the table changes without the
version changing — the same drift-detection trick as the RBAC seed.

**A missing factor is not a zero.** Threat intel arrives in Phase 9, user
risk needs UEBA, and behavioural anomaly is later still. Treating "no data"
as "no risk" would silently suppress every score in the meantime and would
mean a detection on an unknown asset outranks the identical detection on a
domain controller only by luck. Instead the weighted sum is normalized over
the weights of the factors that actually had data, and the explanation says
which those were.

**...but the denominator has a floor.** Pure renormalization has the
opposite failure: with only severity and confidence available, a *medium*
detection at 60% confidence normalizes to 53/100 and is bucketed HIGH,
because it is being scored against a 45-point scale rather than a
100-point one. `MINIMUM_DENOMINATOR` stops that — an assessment made from a
sliver of context can still reach the top of the scale when that sliver is
maximal, but a mid-range factor can no longer be inflated into a high score
purely by the absence of everything else. It is part of the formula, so it
is inside the fingerprint below.
"""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

# Bump on ANY change to weights, factor semantics, or bucket boundaries.
FORMULA_VERSION = "risk-v1"


class RiskBucket(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Boundaries are inclusive at the lower end: 25 is MEDIUM, 24 is LOW.
BUCKET_BOUNDARIES: tuple[tuple[int, RiskBucket], ...] = (
    (75, RiskBucket.CRITICAL),
    (50, RiskBucket.HIGH),
    (25, RiskBucket.MEDIUM),
    (0, RiskBucket.LOW),
)


class Factor(StrEnum):
    SEVERITY = "severity"
    CONFIDENCE = "confidence"
    ASSET_CRITICALITY = "asset_criticality"
    USER_RISK = "user_risk"
    THREAT_INTEL = "threat_intel"
    MITRE_CONTEXT = "mitre_context"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"


# Relative weights. Severity dominates because it is what the detection
# engineer actually asserted about this activity; asset criticality is next
# because the same event on a domain controller and on a test laptop are not
# the same event. Behavioural anomaly is weighted lowest deliberately: spec
# §17 forbids alerting on a statistical anomaly alone, and a low weight is
# how that rule is expressed in arithmetic rather than in prose.
WEIGHTS: dict[Factor, float] = {
    Factor.SEVERITY: 30.0,
    Factor.CONFIDENCE: 15.0,
    Factor.ASSET_CRITICALITY: 20.0,
    Factor.USER_RISK: 10.0,
    Factor.THREAT_INTEL: 15.0,
    Factor.MITRE_CONTEXT: 7.0,
    Factor.BEHAVIORAL_ANOMALY: 3.0,
}


# The smallest denominator the weighted mean is ever divided by. Chosen as
# the weight of a severity + confidence + asset-criticality assessment
# (30 + 15 + 20 = 65) rounded down: below that, too little is known for the
# result to be treated as a full-scale score.
MINIMUM_DENOMINATOR = 60.0


def _fingerprint(weights: dict[Factor, float]) -> str:
    payload = json.dumps(
        {
            "weights": {factor.value: weight for factor, weight in sorted(weights.items())},
            "minimum_denominator": MINIMUM_DENOMINATOR,
            "buckets": [(threshold, bucket.value) for threshold, bucket in BUCKET_BOUNDARIES],
        }
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


# Recomputed at import; `test_risk.py` asserts it still matches the value
# recorded for FORMULA_VERSION, so weights cannot drift without the version
# moving with them.
WEIGHTS_FINGERPRINT = _fingerprint(WEIGHTS)


@dataclass(frozen=True)
class FactorScore:
    """One factor's contribution, with everything needed to re-derive it."""

    factor: str
    # 0.0-1.0. Multiplied by the factor's weight to get its points.
    value: float
    weight: float
    points: float
    # False when the input was absent. An unavailable factor contributes
    # nothing AND removes its weight from the denominator (see the module
    # docstring), so it cannot silently drag a score down.
    available: bool
    # What the value was derived from, in the analyst's terms.
    reason: str
    inputs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    bucket: RiskBucket
    formula_version: str
    weights_fingerprint: str
    factors: list[FactorScore]

    @property
    def available_factors(self) -> list[FactorScore]:
        return [factor for factor in self.factors if factor.available]

    def explanation(self) -> dict[str, Any]:
        """The `risk_explanation` stored with every detection, correlation
        and (Phase 11) alert. Deliberately verbose: it has to make sense to
        a person reading it a month later, without this code in front of
        them."""
        available = self.available_factors
        return {
            "score": self.score,
            "bucket": self.bucket.value,
            "formula_version": self.formula_version,
            "weights_fingerprint": self.weights_fingerprint,
            # The denominator, spelled out, because "why is this 62 and not
            # 48?" is almost always a question about which factors had data.
            "available_weight": round(sum(factor.weight for factor in available), 2),
            "denominator": round(
                max(sum(factor.weight for factor in available), MINIMUM_DENOMINATOR), 2
            )
            if available
            else 0.0,
            "total_weight": round(sum(WEIGHTS.values()), 2),
            "factors": [asdict(factor) for factor in self.factors],
            "summary": self.summary(),
        }

    def summary(self) -> str:
        """One line an analyst reads before deciding whether to read the
        rest: the factors that actually moved the number, biggest first."""
        contributing = sorted(
            (factor for factor in self.available_factors if factor.points > 0),
            key=lambda factor: factor.points,
            reverse=True,
        )
        if not contributing:
            return f"{self.score}/100 ({self.bucket.value}): no factor contributed"
        parts = ", ".join(
            f"{factor.factor} {factor.points:.1f}pts ({factor.reason})"
            for factor in contributing[:3]
        )
        return f"{self.score}/100 ({self.bucket.value}) driven by {parts}"


def bucket_for(score: int) -> RiskBucket:
    for threshold, bucket in BUCKET_BOUNDARIES:
        if score >= threshold:
            return bucket
    return RiskBucket.LOW  # pragma: no cover - the 0 boundary catches everything
