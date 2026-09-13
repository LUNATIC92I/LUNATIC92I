# Risk scoring

Every detection and every correlation carries a computed 0–100 risk score, a
bucket, and a `risk_explanation` that reconstructs the arithmetic. Spec §10's
requirement is not the number — it is that *l'analyste doit pouvoir voir
pourquoi*. A black-box model that ranks well but cannot answer "why is this a
78?" fails this phase (`ARCHITECTURE.md` §11 records that trade-off).

## The formula

```
score = 100 × Σ(weight_i × value_i) / max(Σ weight_i for available i, 60)
```

Each factor produces a value in 0.0–1.0, is capped at its own weight, and
records the input it came from.

| Factor | Weight | Value from |
|---|---:|---|
| `severity` | 30 | rule severity: informational 0 → critical 1.0 |
| `asset_criticality` | 20 | CMDB criticality: LOW 0.25 → CRITICAL 1.0 |
| `confidence` | 15 | rule confidence / 100 |
| `threat_intel` | 15 | strongest IOC match: classification × its confidence |
| `user_risk` | 10 | user risk score / 100 |
| `mitre_context` | 7 | highest-impact ATT&CK technique in the mapping |
| `behavioral_anomaly` | 3 | anomaly score × detector confidence |

Severity dominates because it is what the detection engineer actually
asserted about this activity. Asset criticality is next because the same
event on a domain controller and on a test laptop are not the same event.

**Behavioural anomaly carries the smallest weight on purpose.** Spec §17
forbids alerting on a statistical anomaly alone; a weight of 3 out of 100 is
that rule expressed in arithmetic rather than in prose — an anomaly can tip
a borderline score, never manufacture one.

**Threat intel is scaled by the indicator's own confidence.** Spec §11's
hard rule is that an indicator is never automatically malicious because a
feed said so, so a `malicious` match at 40% confidence contributes 40% of
what the same classification would at 100%.

## Missing data is not zero risk — and not free either

Threat intel arrives in Phase 9, user risk needs UEBA, behavioural analytics
later still. Two failure modes had to be avoided at once:

- Treating an absent factor as **0** would deflate every score in the
  platform by however many factors are not yet implemented. So the
  denominator only counts factors that actually had data.
- Pure renormalization has the opposite problem: with only severity and
  confidence available, a *medium* detection at 60% confidence normalizes to
  53/100 and is bucketed HIGH, because it is scored against a 45-point scale
  rather than a 100-point one. So the denominator has a floor of 60.

Together: a maximal sliver of context can still reach the top of the scale
(a critical rule with nothing else known scores 50, HIGH), but a mid-range
factor cannot be inflated into a high score purely by the absence of
everything else.

`ioc_matches: []` after a successful enrichment means "we looked and found
nothing" and scores 0 with the factor **available**. A partial enrichment
(a provider timed out — possibly the intel one) means "we did not look" and
the factor is absent. The distinction is in `app/risk/engine.py::_intel_of`.

## Buckets

| Score | Bucket |
|---|---|
| 0–24 | LOW |
| 25–49 | MEDIUM |
| 50–74 | HIGH |
| 75–100 | CRITICAL |

Lower bound inclusive: 24 is LOW, 25 is MEDIUM. Boundaries are tested at
24/25, 49/50 and 74/75.

## The explanation

Stored on every detection and correlation as `risk_explanation`, and
rendered in the UI in Phase 14:

```json
{
  "score": 93,
  "bucket": "CRITICAL",
  "formula_version": "risk-v1",
  "weights_fingerprint": "40163da1a051d7cf",
  "available_weight": 100.0,
  "denominator": 100.0,
  "total_weight": 100.0,
  "summary": "93/100 (CRITICAL) driven by severity 30.0pts (rule severity is critical), ...",
  "factors": [
    {
      "factor": "asset_criticality",
      "value": 1.0,
      "weight": 20.0,
      "points": 20.0,
      "available": true,
      "reason": "asset criticality is CRITICAL",
      "inputs": {"criticality": "CRITICAL"}
    }
  ]
}
```

Every factor appears, including unavailable ones: an analyst has to be able
to see which inputs were *missing*, not only which ones counted. The
denominator is spelled out because "why is this 62 and not 48?" is almost
always a question about which factors had data.

The rule's own static `risk_score` is preserved as `rule_risk_score`. It is
the detection engineer's judgement about the rule; the computed score is the
judgement about this instance, and conflating the two makes both
unexplainable.

## Versioning

`FORMULA_VERSION` is recorded on every assessment. Scores computed under
different versions are not comparable, so the stored explanation is the only
way to understand an old alert's number.

`WEIGHTS_FINGERPRINT` is a hash of the weight table, the denominator floor
and the bucket boundaries. A test fails the build if any of them change
without the version changing — the same drift detection used for the RBAC
seed. Changing a weight is therefore a deliberate, versioned act, not a
one-line edit.

## Manipulating the inputs

Asset criticality is user-editable and is a direct multiplier on every score
for that machine. Someone who can quietly downgrade a domain controller to
LOW has turned down the alarm on the most valuable box in the estate without
touching a single detection rule.

So `/assets` is permission-gated (`asset:read` / `asset:write` /
`asset:delete`, and L1 analysts have read only), every mutation is
audit-logged in the same transaction as the change, and a criticality change
gets its **own** audit action — `CHANGE_ASSET_CRITICALITY` — with the before
and after values, so "who turned down the alarm on this server, and when" is
a question the audit log answers directly instead of by diffing every asset
edit. Cross-tenant edits are refused by RLS and by the API, and tested.

## Known limits

- `TECHNIQUE_IMPACT` is a small explicit table of high-impact ATT&CK
  techniques, not the full matrix; Phase 10 imports the real matrix and
  replaces it. An unlisted technique scores as ordinary (0.4), never as
  unknown-and-therefore-zero.
- `user_risk` has no producer yet — nothing computes a per-user risk score
  until UEBA exists, so the factor is absent in practice today.
- `behavioral_anomaly` likewise: the factor and its §17 safeguards are
  implemented and tested, but no detector currently emits an anomaly score.
- Scores are computed once, when the detection or correlation is produced.
  Enrichment that arrives later (an IOC feed update, an asset newly
  inventoried) does not retroactively rescore; that belongs with alert
  lifecycle in Phase 11.
