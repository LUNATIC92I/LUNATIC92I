"""Risk engine: per-factor contributions, caps, buckets, and explainability.

Spec §10's requirement is that an analyst can see *why* a score is what it
is, so the assertions here are as much about the explanation as about the
number: a change that alters a score without altering its recorded
breakdown would be caught by the golden-file tests below.
"""

import json
from pathlib import Path

import pytest

from app.risk.engine import (
    RiskContext,
    apply_to_correlation,
    apply_to_detection,
    assess,
    context_from_correlation,
    context_from_detection,
)
from app.risk.factors import (
    TECHNIQUE_IMPACT,
    asset_criticality_factor,
    behavioral_anomaly_factor,
    confidence_factor,
    mitre_context_factor,
    severity_factor,
    threat_intel_factor,
    user_risk_factor,
)
from app.risk.model import (
    BUCKET_BOUNDARIES,
    FORMULA_VERSION,
    WEIGHTS,
    WEIGHTS_FINGERPRINT,
    Factor,
    RiskBucket,
    bucket_for,
)

GOLDEN_FILE = Path(__file__).parent / "data" / "risk_golden.json"

# The fingerprint the shipped weights must have for FORMULA_VERSION. Changing
# a weight changes the score of every future alert and makes it incomparable
# with every past one, so the version has to move with it.
EXPECTED_FINGERPRINTS = {"risk-v1": "40163da1a051d7cf"}


# ---------------------------------------------------------------------------
# The formula is versioned
# ---------------------------------------------------------------------------


def test_the_weight_table_cannot_change_without_the_version_changing() -> None:
    assert FORMULA_VERSION in EXPECTED_FINGERPRINTS, (
        "FORMULA_VERSION was bumped: add its fingerprint here and regenerate "
        "the golden file, so old and new scores stay distinguishable"
    )
    assert WEIGHTS_FINGERPRINT == EXPECTED_FINGERPRINTS[FORMULA_VERSION], (
        "the weights changed but FORMULA_VERSION did not — every stored "
        "risk_explanation would silently become unreproducible"
    )


def test_every_factor_has_a_weight() -> None:
    assert set(WEIGHTS) == set(Factor)
    assert sum(WEIGHTS.values()) == 100.0


def test_an_assessment_records_the_version_it_was_computed_under() -> None:
    assessment = assess(RiskContext(severity="high", confidence=50))
    assert assessment.formula_version == FORMULA_VERSION
    assert assessment.explanation()["weights_fingerprint"] == WEIGHTS_FINGERPRINT


# ---------------------------------------------------------------------------
# Per-factor contribution and cap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("informational", 0.0), ("low", 0.25), ("medium", 0.5), ("high", 0.75), ("critical", 1.0)],
)
def test_severity_contribution(severity: str, expected: float) -> None:
    factor = severity_factor(severity)
    assert factor.value == expected
    assert factor.points == pytest.approx(WEIGHTS[Factor.SEVERITY] * expected)
    assert severity in factor.reason


def test_confidence_contribution_is_proportional() -> None:
    assert confidence_factor(0).points == 0
    assert confidence_factor(50).points == pytest.approx(WEIGHTS[Factor.CONFIDENCE] * 0.5)
    assert confidence_factor(100).points == WEIGHTS[Factor.CONFIDENCE]


@pytest.mark.parametrize(
    ("criticality", "expected"), [("LOW", 0.25), ("MEDIUM", 0.5), ("HIGH", 0.75), ("CRITICAL", 1.0)]
)
def test_asset_criticality_contribution(criticality: str, expected: float) -> None:
    factor = asset_criticality_factor(criticality)
    assert factor.points == pytest.approx(WEIGHTS[Factor.ASSET_CRITICALITY] * expected)


def test_a_factor_cannot_exceed_its_weight() -> None:
    """The cap: out-of-range inputs (a hand-edited record, a broken feed)
    must not let one factor swamp the formula."""
    assert user_risk_factor(10_000).points == WEIGHTS[Factor.USER_RISK]
    assert confidence_factor(400).points == WEIGHTS[Factor.CONFIDENCE]
    assert behavioral_anomaly_factor({"score": 99, "confidence": 100}).points == (
        WEIGHTS[Factor.BEHAVIORAL_ANOMALY]
    )


def test_a_negative_input_cannot_subtract_risk() -> None:
    assert user_risk_factor(-500).points == 0.0
    assert behavioral_anomaly_factor({"score": -1, "confidence": 100}).points == 0.0


# ---------------------------------------------------------------------------
# Threat intel: spec §11's "a feed is not proof"
# ---------------------------------------------------------------------------


def test_a_high_confidence_malicious_indicator_scores_full() -> None:
    factor = threat_intel_factor(
        [{"value": "1.2.3.4", "classification": "malicious", "confidence": 100, "source": "feed"}]
    )
    assert factor.points == WEIGHTS[Factor.THREAT_INTEL]


def test_indicator_confidence_scales_its_contribution() -> None:
    """Spec §11: an indicator is never automatically malicious just because
    a feed said so."""
    low_confidence = threat_intel_factor(
        [{"value": "1.2.3.4", "classification": "malicious", "confidence": 40}]
    )
    assert low_confidence.points == pytest.approx(WEIGHTS[Factor.THREAT_INTEL] * 0.4)


def test_a_bare_indicator_with_no_provenance_is_treated_as_unknown() -> None:
    factor = threat_intel_factor(["1.2.3.4"])
    assert factor.value == pytest.approx(0.3)
    assert factor.points < WEIGHTS[Factor.THREAT_INTEL] / 2


def test_a_benign_indicator_adds_nothing() -> None:
    factor = threat_intel_factor([{"value": "1.2.3.4", "classification": "benign"}])
    assert factor.available is True
    assert factor.points == 0.0


def test_looking_and_finding_nothing_differs_from_not_looking() -> None:
    looked = threat_intel_factor([])
    did_not_look = threat_intel_factor(None)

    assert (looked.available, looked.points) == (True, 0.0)
    assert did_not_look.available is False


# ---------------------------------------------------------------------------
# MITRE context
# ---------------------------------------------------------------------------


def test_the_highest_impact_technique_drives_the_mitre_factor() -> None:
    factor = mitre_context_factor(["T1110.001", "T1003.001"])
    assert factor.inputs["worst"] == "T1003.001"
    assert factor.value == TECHNIQUE_IMPACT["T1003"]


def test_a_sub_technique_inherits_its_parents_impact() -> None:
    assert mitre_context_factor(["T1003.001"]).value == mitre_context_factor(["T1003"]).value


def test_an_unmapped_technique_scores_as_ordinary_not_as_zero() -> None:
    factor = mitre_context_factor(["T9999"])
    assert factor.available is True
    assert factor.value > 0


def test_no_technique_means_no_data() -> None:
    assert mitre_context_factor([]).available is False


# ---------------------------------------------------------------------------
# Behavioural anomaly: spec §17
# ---------------------------------------------------------------------------


def test_an_anomaly_alone_cannot_manufacture_a_high_score() -> None:
    """Spec §17 forbids alerting on a statistical anomaly alone; the weight
    table and the denominator floor are where that rule is enforced, not
    the prose."""
    alone = assess(RiskContext(anomaly={"score": 1.0, "confidence": 100}))
    assert alone.bucket is RiskBucket.LOW
    assert alone.score <= 5

    # ... but next to a real detection it can only nudge the number.
    with_detection = assess(RiskContext(severity="medium", confidence=50))
    nudged = assess(
        RiskContext(severity="medium", confidence=50, anomaly={"score": 1.0, "confidence": 100})
    )
    assert 0 < nudged.score - with_detection.score <= 5


def test_anomaly_confidence_scales_its_contribution() -> None:
    factor = behavioral_anomaly_factor({"score": 1.0, "confidence": 25})
    assert factor.value == pytest.approx(0.25)
    assert "25% confidence" in factor.reason


# ---------------------------------------------------------------------------
# Normalization over available factors
# ---------------------------------------------------------------------------


def test_the_denominator_has_a_floor() -> None:
    """Without it, a medium-severity detection with no context normalizes
    to 53/100 and is bucketed HIGH purely because so little was known."""
    from app.risk.model import MINIMUM_DENOMINATOR

    thin = assess(RiskContext(severity="medium", confidence=60))
    assert thin.bucket is RiskBucket.MEDIUM
    assert thin.explanation()["denominator"] == MINIMUM_DENOMINATOR
    assert thin.explanation()["available_weight"] < MINIMUM_DENOMINATOR

    # A maximal sliver can still reach the top of the scale: a critical rule
    # with nothing else known is HIGH, and confirming context takes it to
    # CRITICAL rather than the floor holding it down.
    assert assess(RiskContext(severity="critical")).bucket is RiskBucket.HIGH
    assert (
        assess(RiskContext(severity="critical", confidence=100, asset_criticality="CRITICAL")).bucket
        is RiskBucket.CRITICAL
    )


def test_a_missing_factor_does_not_drag_the_score_down() -> None:
    """The alternative — treating absent data as zero — would deflate every
    score in the platform by however many factors are not yet implemented."""
    everything_known = assess(
        RiskContext(
            severity="critical",
            confidence=100,
            asset_criticality="CRITICAL",
            user_risk_score=100,
            ioc_matches=[{"classification": "malicious", "confidence": 100}],
            mitre_attack=["T1003"],
            anomaly={"score": 1.0, "confidence": 100},
        )
    )
    assert everything_known.score == 100

    # The same detection with intel consulted and clean scores lower — the
    # absent factors did not cost it anything, the *known* zero did.
    intel_clean = assess(
        RiskContext(
            severity="critical",
            confidence=100,
            asset_criticality="CRITICAL",
            user_risk_score=100,
            ioc_matches=[],
            mitre_attack=["T1003"],
            anomaly={"score": 1.0, "confidence": 100},
        )
    )
    assert intel_clean.score < everything_known.score

    with_low_asset = assess(RiskContext(severity="critical", asset_criticality="LOW"))
    assert with_low_asset.score < assess(
        RiskContext(severity="critical", asset_criticality="CRITICAL")
    ).score, "a known-low-value asset should reduce the score"


def test_the_explanation_states_the_denominator() -> None:
    explanation = assess(RiskContext(severity="high", confidence=80)).explanation()
    assert explanation["available_weight"] == WEIGHTS[Factor.SEVERITY] + WEIGHTS[Factor.CONFIDENCE]
    assert explanation["total_weight"] == 100.0
    # The number actually divided by, so the arithmetic in the explanation
    # can be checked by hand.
    assert explanation["denominator"] >= explanation["available_weight"]


def test_an_assessment_with_no_inputs_scores_zero_and_says_so() -> None:
    assessment = assess(RiskContext())
    assert assessment.score == 0
    assert assessment.bucket is RiskBucket.LOW
    assert "no factor contributed" in assessment.summary()
    assert all(factor.available is False for factor in assessment.factors)


def test_every_factor_appears_in_the_explanation_even_when_absent() -> None:
    """An analyst must be able to see which inputs were missing, not just
    which ones counted."""
    explanation = assess(RiskContext(severity="high")).explanation()
    assert {factor["factor"] for factor in explanation["factors"]} == {f.value for f in Factor}


def test_the_explanation_is_json_serializable() -> None:
    """It is stored as JSONB and rendered in the UI; a value that cannot
    round-trip would fail at write time, in the pipeline."""
    explanation = assess(
        RiskContext(
            severity="high",
            confidence=80,
            asset_criticality="HIGH",
            ioc_matches=[{"value": "1.2.3.4", "classification": "malicious", "confidence": 90}],
            mitre_attack=["T1003"],
        )
    ).explanation()
    assert json.loads(json.dumps(explanation)) == explanation


# ---------------------------------------------------------------------------
# Buckets and their boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "bucket"),
    [
        (0, RiskBucket.LOW),
        (24, RiskBucket.LOW),
        (25, RiskBucket.MEDIUM),
        (49, RiskBucket.MEDIUM),
        (50, RiskBucket.HIGH),
        (74, RiskBucket.HIGH),
        (75, RiskBucket.CRITICAL),
        (100, RiskBucket.CRITICAL),
    ],
)
def test_bucket_boundaries(score: int, bucket: RiskBucket) -> None:
    assert bucket_for(score) is bucket


def test_the_boundaries_are_contiguous_and_cover_the_whole_range() -> None:
    thresholds = [threshold for threshold, _ in BUCKET_BOUNDARIES]
    assert thresholds == sorted(thresholds, reverse=True)
    assert thresholds[-1] == 0
    assert {bucket_for(score) for score in range(101)} == set(RiskBucket)


def test_a_realistic_critical_case_lands_in_the_critical_bucket() -> None:
    assessment = assess(
        RiskContext(
            severity="critical",
            confidence=90,
            asset_criticality="CRITICAL",
            ioc_matches=[{"value": "1.2.3.4", "classification": "malicious", "confidence": 95}],
            mitre_attack=["T1003.001"],
        )
    )
    assert assessment.bucket is RiskBucket.CRITICAL


def test_a_low_severity_detection_on_a_test_laptop_stays_low() -> None:
    assessment = assess(
        RiskContext(severity="low", confidence=30, asset_criticality="LOW", ioc_matches=[])
    )
    assert assessment.bucket is RiskBucket.LOW


# ---------------------------------------------------------------------------
# Golden files
# ---------------------------------------------------------------------------


GOLDEN_CASES: dict[str, RiskContext] = {
    "fully_populated_critical": RiskContext(
        severity="critical",
        confidence=90,
        asset_criticality="CRITICAL",
        user_risk_score=70,
        ioc_matches=[{"value": "1.2.3.4", "classification": "malicious", "confidence": 95}],
        mitre_attack=["T1003.001", "T1078"],
        anomaly={"score": 0.8, "confidence": 60},
    ),
    "detection_only": RiskContext(severity="medium", confidence=60),
    "no_inputs": RiskContext(),
    "intel_consulted_and_clean": RiskContext(
        severity="high", confidence=75, asset_criticality="MEDIUM", ioc_matches=[]
    ),
}


def test_golden_scores_and_explanations() -> None:
    """Locks the arithmetic AND its explanation. If a refactor changes a
    number, this fails and the diff shows exactly which factor moved."""
    expected = json.loads(GOLDEN_FILE.read_text())
    actual = {name: assess(context).explanation() for name, context in GOLDEN_CASES.items()}
    assert actual == expected


def test_the_golden_file_covers_every_bucket() -> None:
    expected = json.loads(GOLDEN_FILE.read_text())
    assert {case["bucket"] for case in expected.values()} >= {"LOW", "MEDIUM", "CRITICAL"}


# ---------------------------------------------------------------------------
# Reading context out of pipeline documents
# ---------------------------------------------------------------------------


def _detection(**overrides) -> dict:
    document = {
        "detection_id": "d1",
        "rule_id": "WIN-003",
        "severity": "critical",
        "confidence": 85,
        "risk_score": 90,
        "mitre_attack": ["T1003.001"],
        "evidence": {"hostname": "dc01"},
    }
    document.update(overrides)
    return document


def test_a_detection_is_scored_from_its_rule_and_its_enriched_event() -> None:
    event = {
        "asset": {"criticality": "CRITICAL"},
        "risk_context": {"user_risk_score": 80},
        "ioc_matches": [],
    }
    context = context_from_detection(_detection(), event)

    assert context.severity == "critical"
    assert context.asset_criticality == "CRITICAL"
    assert context.user_risk_score == 80
    assert context.ioc_matches == []
    assert context.enrichment_ran is True


def test_a_partially_enriched_event_does_not_claim_intel_was_consulted() -> None:
    """A provider that timed out may well have been the intel one; scoring
    it as "clean" would invent a fact."""
    event = {"ioc_matches": [], "enrichment_partial": True}
    context = context_from_detection(_detection(), event)
    assert context.enrichment_ran is False


def test_applying_risk_keeps_the_rules_own_score_separately() -> None:
    scored = apply_to_detection(_detection(), {"asset": {"criticality": "LOW"}})

    assert scored["rule_risk_score"] == 90, "the rule's static judgement was overwritten"
    assert scored["risk_score"] != 90
    assert scored["risk_bucket"] in {b.value for b in RiskBucket}
    assert scored["risk_explanation"]["factors"]


def test_asset_criticality_changes_the_computed_score() -> None:
    """The point of the factor, and the reason the inventory is
    permission-gated and audit-logged."""
    on_a_laptop = apply_to_detection(_detection(), {"asset": {"criticality": "LOW"}})
    on_a_controller = apply_to_detection(_detection(), {"asset": {"criticality": "CRITICAL"}})

    assert on_a_controller["risk_score"] > on_a_laptop["risk_score"]


def test_a_correlation_is_scored_on_the_worst_context_its_chain_touched() -> None:
    correlation = {
        "correlation_id": "CORR-001",
        "severity": "critical",
        "confidence": 85,
        "risk_score": 90,
        "mitre_attack": ["T1078"],
        "timeline": [
            {"stage": "one", "summary": {"asset": {"criticality": "LOW"}}},
            {"stage": "two", "summary": {"asset": {"criticality": "CRITICAL"}}},
        ],
    }
    context = context_from_correlation(correlation)
    assert context.asset_criticality == "CRITICAL"

    scored = apply_to_correlation(correlation)
    assert scored["risk_explanation"]["score"] == scored["risk_score"]
    assert scored["risk_bucket"] == "CRITICAL"
