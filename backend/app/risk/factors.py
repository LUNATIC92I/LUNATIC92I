"""The individual risk factors (spec §10).

Each function turns one input into a 0.0–1.0 value plus the human-readable
reason that goes into `risk_explanation`. They are deliberately small and
pure: every one of them is unit-tested on its own, and a factor that cannot
be explained in one sentence to an analyst does not belong in the formula.

Every factor can also say **"no data"**, which is different from "zero
risk". Threat intelligence arrives in Phase 9 and behavioural analytics
later; until then those factors are absent rather than scoring 0, and the
engine renormalizes over what was available (see `model.py`).
"""

from typing import Any

from app.risk.model import Factor, FactorScore, RiskBucket  # noqa: F401  (RiskBucket re-export)

SEVERITY_VALUES = {
    "informational": 0.0,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}

CRITICALITY_VALUES = {
    "LOW": 0.25,
    "MEDIUM": 0.5,
    "HIGH": 0.75,
    "CRITICAL": 1.0,
}

IOC_CLASSIFICATION_VALUES = {
    "malicious": 1.0,
    "suspicious": 0.6,
    "unknown": 0.3,
    "benign": 0.0,
}

# Impact weighting per ATT&CK technique, keyed by technique id (a
# sub-technique inherits its parent's weight). This stays a curated table
# after the Phase 10 import, for a simple reason: **ATT&CK does not publish
# a severity or impact ranking**. It describes what adversaries do, not how
# much it should worry you, so any weighting is a judgement someone has to
# make and be accountable for. What the imported catalog does give is
# validation — a test asserts every id here still exists in the real matrix,
# so this table cannot quietly reference a technique MITRE has withdrawn.
# A technique not listed scores as ordinary, never as
# unknown-and-therefore-zero.
TECHNIQUE_IMPACT: dict[str, float] = {
    "T1003": 1.0,  # OS credential dumping — one host becomes the domain
    "T1486": 1.0,  # data encrypted for impact (ransomware)
    "T1490": 0.9,  # inhibit system recovery
    "T1041": 0.9,  # exfiltration over C2
    "T1567": 0.9,  # exfiltration to web service
    "T1078": 0.8,  # valid accounts
    "T1098": 0.8,  # account manipulation
    "T1021": 0.7,  # remote services (lateral movement)
    "T1543": 0.7,  # create or modify system process (persistence)
    "T1547": 0.6,  # boot or logon autostart
    "T1053": 0.6,  # scheduled task
    "T1070": 0.6,  # indicator removal (anti-forensics)
    "T1059": 0.5,  # command and scripting interpreter
    "T1566": 0.5,  # phishing
    "T1110": 0.4,  # brute force
    "T1027": 0.4,  # obfuscated files or information
}
DEFAULT_TECHNIQUE_IMPACT = 0.4


def _clamp(value: float) -> float:
    """Every factor is capped at its weight; clamping here is what makes
    that true even when an input is out of range (a user risk score of 500,
    a hand-edited asset record)."""
    return max(0.0, min(1.0, value))


def _score(
    factor: Factor, value: float | None, reason: str, inputs: dict[str, Any]
) -> FactorScore:
    from app.risk.model import WEIGHTS

    weight = WEIGHTS[factor]
    if value is None:
        return FactorScore(
            factor=factor.value,
            value=0.0,
            weight=weight,
            points=0.0,
            available=False,
            reason=reason,
            inputs=inputs,
        )
    clamped = _clamp(value)
    return FactorScore(
        factor=factor.value,
        value=round(clamped, 4),
        weight=weight,
        points=round(weight * clamped, 4),
        available=True,
        reason=reason,
        inputs=inputs,
    )


def severity_factor(severity: str | None) -> FactorScore:
    if not severity or severity.lower() not in SEVERITY_VALUES:
        return _score(
            Factor.SEVERITY, None, "no severity on the detection", {"severity": severity}
        )
    value = SEVERITY_VALUES[severity.lower()]
    return _score(
        Factor.SEVERITY, value, f"rule severity is {severity.lower()}", {"severity": severity}
    )


def confidence_factor(confidence: int | float | None) -> FactorScore:
    if confidence is None:
        return _score(Factor.CONFIDENCE, None, "no confidence recorded", {})
    return _score(
        Factor.CONFIDENCE,
        float(confidence) / 100.0,
        f"rule confidence is {int(confidence)}%",
        {"confidence": confidence},
    )


def asset_criticality_factor(criticality: str | None) -> FactorScore:
    if not criticality or criticality.upper() not in CRITICALITY_VALUES:
        # The asset is not in the CMDB, or has no criticality set. Saying so
        # is more useful than assuming MEDIUM, which would quietly invent a
        # fact about an unknown machine.
        return _score(
            Factor.ASSET_CRITICALITY,
            None,
            "asset unknown to the inventory",
            {"criticality": criticality},
        )
    value = CRITICALITY_VALUES[criticality.upper()]
    return _score(
        Factor.ASSET_CRITICALITY,
        value,
        f"asset criticality is {criticality.upper()}",
        {"criticality": criticality.upper()},
    )


def user_risk_factor(user_risk_score: float | int | None) -> FactorScore:
    if user_risk_score is None:
        return _score(Factor.USER_RISK, None, "no user risk score available", {})
    return _score(
        Factor.USER_RISK,
        float(user_risk_score) / 100.0,
        f"user risk score is {float(user_risk_score):.0f}/100",
        {"user_risk_score": user_risk_score},
    )


def threat_intel_factor(
    ioc_matches: list[Any] | None, *, enrichment_ran: bool = True
) -> FactorScore:
    """IOC matches, weighted by classification AND confidence.

    Spec §11's hard rule is that an indicator is never automatically
    malicious just because a feed said so, so a match at 40% confidence
    contributes 40% of what the same classification would at 100%. A feed
    that has not been consulted at all is *absent*, not clean — the
    difference between "we looked and found nothing" and "we did not look".
    """
    if ioc_matches is None or not enrichment_ran:
        return _score(Factor.THREAT_INTEL, None, "threat intel not consulted", {})
    if not ioc_matches:
        return _score(Factor.THREAT_INTEL, 0.0, "no indicator matched", {"matches": 0})

    best = 0.0
    best_detail: dict[str, Any] = {}
    for match in ioc_matches:
        if isinstance(match, dict):
            classification = str(match.get("classification", "unknown")).lower()
            confidence = float(match.get("confidence", 100)) / 100.0
            detail = {
                "value": match.get("value"),
                "classification": classification,
                "confidence": match.get("confidence", 100),
                "source": match.get("source"),
            }
        else:
            # A bare indicator string carries no provenance, so it is
            # treated as unknown rather than as malicious (spec §11).
            classification, confidence = "unknown", 1.0
            detail = {"value": str(match), "classification": classification}
        value = IOC_CLASSIFICATION_VALUES.get(classification, 0.3) * _clamp(confidence)
        if value > best:
            best, best_detail = value, detail

    return _score(
        Factor.THREAT_INTEL,
        best,
        f"{len(ioc_matches)} indicator match(es), strongest "
        f"{best_detail.get('classification', 'unknown')} at "
        f"{best_detail.get('confidence', 100)}% confidence",
        {"matches": len(ioc_matches), "strongest": best_detail},
    )


def mitre_context_factor(techniques: list[str] | None) -> FactorScore:
    if not techniques:
        return _score(Factor.MITRE_CONTEXT, None, "no ATT&CK technique mapped", {})

    impacts: dict[str, float] = {}
    for technique in techniques:
        parent = technique.split(".")[0]
        impacts[technique] = TECHNIQUE_IMPACT.get(
            parent, TECHNIQUE_IMPACT.get(technique, DEFAULT_TECHNIQUE_IMPACT)
        )
    worst_technique = max(impacts, key=lambda key: impacts[key])
    return _score(
        Factor.MITRE_CONTEXT,
        impacts[worst_technique],
        f"highest-impact technique is {worst_technique}",
        {"techniques": list(techniques), "worst": worst_technique},
    )


def behavioral_anomaly_factor(anomaly: dict[str, Any] | None) -> FactorScore:
    """Spec §17: never alert on a statistical anomaly alone, and always keep
    the confidence alongside it. Both are enforced here rather than merely
    documented — the value is scaled by the detector's own confidence, and
    the factor carries the smallest weight in the table, so an anomaly can
    tip a borderline score but can never manufacture one on its own."""
    if not anomaly:
        return _score(Factor.BEHAVIORAL_ANOMALY, None, "no behavioural baseline yet", {})
    score = float(anomaly.get("score", 0.0))
    confidence = float(anomaly.get("confidence", 100)) / 100.0
    return _score(
        Factor.BEHAVIORAL_ANOMALY,
        score * _clamp(confidence),
        f"anomaly score {score:.2f} at {anomaly.get('confidence', 100)}% confidence",
        {"anomaly": anomaly},
    )
