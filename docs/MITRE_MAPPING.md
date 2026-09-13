# MITRE ATT&CK coverage

What this SOC can detect, what it cannot, and how much of that is a guess.

## The catalog is imported, never hardcoded

MITRE ships several ATT&CK revisions a year: techniques are added, renamed,
deprecated and revoked. A matrix baked into source code drifts out of date
while still claiming to measure coverage — so the catalog is data, imported
from the official STIX 2.1 bundle (`enterprise-attack.json`) or any bundle
in the same shape.

```bash
# from the configured source (MITRE_ATTACK_SOURCE)
curl -sX POST localhost:8000/mitre/import -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{}'

# from a file placed in the drop directory (air-gapped installs)
curl -sX POST localhost:8000/mitre/import -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"source":"enterprise-attack.json"}'
```

The `feeds` worker re-imports automatically once the stored catalog is older
than `MITRE_CATALOG_MAX_AGE_DAYS`, and the coverage response carries
`attack_version` and `catalog_is_stale` — "73% coverage" means nothing
without saying *of what*.

Importing is `mitre:write` (admins and SOC managers) because the catalog is
global: it changes every tenant's coverage page. Each import is audit-logged
with its source and the version it brought in.

### Third-party content is validated, never trusted

The bundle is a 52MB JSON document downloaded from the internet. Everything
taken out of it is bounded (file size, object count, and every string field
capped), shape-checked (ids must match the ATT&CK id pattern; objects
missing what makes them a technique are rejected rather than stored
half-formed), and counted — `objects_rejected` is recorded on the import
row, because an import that silently drops half the matrix looks exactly
like a matrix that shrank. Non-HTTPS reference URLs and control characters
are stripped, since imported text is rendered in the UI. URL sources go
through the egress guard; file sources are confined to the drop directory.

Imports are **idempotent**: re-running one converges on the same state.
Technique→tactic links are rebuilt rather than merged, because ATT&CK moves
techniques between tactics and a merge would leave the old link inflating a
tactic the technique no longer belongs to.

## What counts as coverage

A technique is:

| Status | Meaning |
|---|---|
| `covered` | at least one **enabled or testing** rule maps to it |
| `partial` | one of its sub-techniques is covered, but the technique itself is not |
| `uncovered` | no rule maps to it |

Three deliberately conservative choices:

- **A disabled rule is not coverage.** This is the single most common way a
  coverage page overstates what a SOC can actually see.
- **A rule in `testing` is coverage.** Unlike a disabled rule it is
  evaluated on live traffic — coverage being validated, not switched off.
- **A covered sub-technique does not cover its parent.** Detecting LSASS
  dumping (T1003.001) is not detecting all of OS Credential Dumping
  (T1003), and saying otherwise tells the SOC a comfortable lie.

Revoked and deprecated techniques are excluded from the denominator by
default (`include_deprecated=true` brings them back): measuring against
entries MITRE itself withdrew inflates the gap with techniques nobody should
write a rule for.

## Mapping rules to techniques

`rule_mitre_map` is derived from each rule's own `mitre_attack` list and
refreshed **before** every coverage calculation, so a rule edited a second
ago is measured as it is now, not as it was.

A rule may claim a technique the imported catalog does not contain — a typo,
or a rule written against a newer ATT&CK than the one imported. Those are
not silently dropped: they come back in `unknown_technique_claims`, because
a false coverage claim is worse than a visible gap.

## Detections behind the numbers

Coverage from rules alone answers "could we detect this?". The other half is
"did we?" — so detections are indexed into OpenSearch (`detections-*`) as
well as published on the bus, and every technique carries a count over the
requested window plus, on the detail endpoint, its most recent detections.

Dry-run detections (from `testing` rules) are excluded from those counts:
they fire deliberately and counting them would make "we detect this" true
for a rule that never alerts.

If the detections index does not exist yet, counts come back as zeros rather
than an error — a coverage page that 500s because nothing has fired yet
would be worse than one showing the rule-derived half.

## API

| Endpoint | Permission | |
|---|---|---|
| `GET /mitre/tactics` | `mitre:read` | the imported tactics |
| `GET /mitre/techniques` | `mitre:read` | filterable by tactic; deprecated hidden by default |
| `GET /mitre/coverage` | `mitre:read` | the coverage page's data, per tactic and per technique |
| `GET /mitre/techniques/{id}` | `mitre:read` | status, covering rules, detection count, recent detections |
| `POST /mitre/import` | `mitre:write` | import or re-import the catalog |

## Risk weighting is not ATT&CK data

The risk engine weights some techniques above others
(`app/risk/factors.py::TECHNIQUE_IMPACT`). That table stays curated after
the import for a simple reason: **ATT&CK publishes no severity or impact
ranking.** It describes what adversaries do, not how much it should worry
you, so any weighting is a judgement someone has to make and own.

What the import adds is validation: a test asserts every technique id in the
table still exists in the real matrix and has not been revoked, so the
weighting cannot quietly reference something MITRE has withdrawn.

## Known limits

- Only `attack-pattern` and `x-mitre-tactic` objects are stored. Groups,
  software, campaigns, mitigations and data components are in the bundle and
  are deliberately ignored — importing objects nothing reads would be
  storage and attack surface for no benefit.
- Enterprise ATT&CK only. Mobile and ICS use the same bundle shape, so
  adding them is configuration plus a matrix column, not a redesign.
- Coverage counts rules, not rule *quality*. A rule mapped to a technique
  that would never realistically fire counts the same as a good one; that
  gap is what detection testing (and, eventually, adversary emulation)
  closes, not a coverage percentage.
