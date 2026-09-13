# Detection Engine

Rules are **data, never code**. A rule is a YAML document describing field
tests; the engine evaluates it with a fixed set of operators. There is no
`eval`, no expression language, no template rendering, and no way for a rule
— or for the log data a rule matches against — to execute anything. A SIEM
whose rule format can run code is a remote-code-execution path into the
security platform itself (`THREAT_MODEL.md` §3.4).

## Two execution shapes, one schema

The Phase 0 review found that the specification mixed single-event and
threshold semantics under one rule shape (`ARCHITECTURE.md` §1 row 4). They
are resolved as two execution paths sharing one schema:

| | streaming | windowed |
|---|---|---|
| Trigger | every normalized event, as it arrives | a scheduled pass, every `DETECTION_WINDOW_INTERVAL_SECONDS` |
| Selected by | no `window:` block | a `window:` block |
| Evaluated by | `app/detection/engine.py` in Python | `app/detection/windowed.py`, as an OpenSearch aggregation |
| Answers | "is *this event* bad?" | "is this *rate* bad?" |

A rule's `rule_type` is derived, never declared: adding `window:` makes it
windowed. The same `conditions` tree drives both, compiled to OpenSearch
query DSL for the windowed path by `app/detection/query.py`.

**Operators must mean the same thing on both paths.** Two consequences:

- negative operators compile to `must exists` + `must_not <positive>`,
  because a bare Lucene `must_not` also matches documents where the field is
  absent, while the Python evaluator does not;
- `matches` (regex) is **refused in a windowed rule at load time**. Python's
  `re` and Lucene's regexp are different languages, and a rule that matched
  differently in the two engines would be a silent detection gap. Use
  `contains` / `starts_with` / `ends_with` / `in`, or make the rule
  streaming.

## Rule format

```yaml
rule_id: AUTH-001              # ^[A-Z][A-Z0-9]*-\d{3,}$, stable across versions
name: Brute force against a single account
description: >-
  What this detects and why it matters.
severity: high                 # informational | low | medium | high | critical
confidence: 75                 # 0-100
risk_score: 65                 # 0-100
status: enabled                # enabled | disabled | testing
version: 1
author: LUNATIC-IT Detection Engineering

conditions:                    # a condition, or a group (all / any / not)
  all:
    - field: class
      operator: equals
      value: Authentication
    - field: authentication.outcome
      operator: equals
      value: failure

window:                        # present => windowed rule
  duration: 5m                 # 30s | 5m | 2h | 1d
  threshold: 5
  group_by: [user.name, source_ip]
  distinct_field: user.name    # optional: count distinct values, not events

suppress_by: [user.name, source_ip]
suppression: 30m               # hold repeat matches for this entity

exceptions:                    # optional, documented, expiring carve-outs
  - reason: the backup host fails on credential rotation
    expires_at: '2026-12-31T00:00:00Z'
    conditions:
      field: source_ip
      operator: equals
      value: 10.9.9.9

mitre_attack: [T1110, T1110.001]
false_positive_notes: >-       # required
  What benign activity looks like this, and how to tell them apart.
investigation_steps: >-        # required
  What an analyst should do, in order.
references:
  - https://attack.mitre.org/techniques/T1110/001/
```

`false_positive_notes` and `investigation_steps` are mandatory (spec §37).
An alert an analyst cannot triage is indistinguishable from noise, and the
person who understood the detection is the only one who can write them.

### Fields

`field` is a dotted path into the normalized document — the flat projections
documented in `docs/database/opensearch_indices.md` §3 (`user.name`,
`source_ip`, `process.cmd_line`, `event_code`, ...). A path that crosses a
list resolves to every element and matches if **any** of them match.

`event_code` is the *source's* own identifier (Windows event id 4625, a CEF
signature id), as a string. The document's `event_id` is this platform's own
unique id for the event and is never a rule input.

### Operators

| Operator | Notes |
|---|---|
| `equals`, `not_equals` | case-insensitive unless `case_sensitive: true`; `22` and `"22"` compare equal |
| `contains`, `not_contains`, `starts_with`, `ends_with` | substring tests |
| `matches` | regex; **streaming only** |
| `in`, `not_in` | list membership |
| `gt`, `gte`, `lt`, `lte` | numeric; a non-numeric value is a non-match, never an error |
| `exists` | `value: true` / `false`; a present-but-null field counts as absent |
| `cidr` | one network or a list; works on `ip`-typed fields |

A condition against a missing field never matches and never raises: one
malformed event must not stop a rule from evaluating the next one.

### Regex safety

Three controls, and only the third is a real bound:

1. patterns are capped at 512 characters (`schema.MAX_PATTERN_LENGTH`);
2. the subject is truncated to 8 KB before matching;
3. **each match has a wall-clock timeout** (`conditions.REGEX_TIMEOUT_SECONDS`).

Catastrophic backtracking is exponential in subject length, so neither the
pattern cap nor truncation prevents a hang — a nested quantifier can wedge
on a few dozen characters. The timeout is what keeps the worker alive, which
is why matching uses the `regex` module (the standard library's `re` cannot
be interrupted). A timed-out match is a non-match and increments
`detection_regex_timeouts_total`; any sustained value there means a rule has
effectively stopped detecting.

## Between a match and a detection

- **Exceptions** are applied after the conditions match, are counted in
  `detection_exceptions_applied_total`, and expire. In a windowed rule they
  are applied *inside* the aggregation query, so excepted events do not
  count toward the threshold; a second cheap `count` measures how many
  events each carve-out removed, so a carve-out silently eating thousands of
  events a day stays visible. An exception with an unparseable expiry is
  treated as already expired — fail towards detecting.
- **Suppression** holds repeat matches per entity (`suppress_by`, defaulting
  to a windowed rule's `group_by`) for `suppression`. Across worker replicas
  it is a Redis `SET NX EX`, so two workers cannot both fire.
- **Dry run**: a rule in `testing` status is evaluated exactly like an
  enabled one and its matches are recorded with `dry_run: true`, but they
  never become alerts. That is how a rule earns production status on real
  traffic.

## Lifecycle

The YAML files in `rules/` are the **default pack**. They are installed into
each tenant at registration (and re-runnable with
`POST /rules/install-defaults`, which never overwrites an existing rule).
After installation, PostgreSQL is authoritative: rules are per tenant, so
tuning one tenant's detection cannot affect another's.

Every change writes three things in one transaction: the rule, a new row in
the append-only `detection_rule_versions` history, and an audit entry.
Disabling a detection is one of the highest-value actions an attacker with a
foothold in the SIEM can take, so `DISABLE_DETECTION_RULE` is its own audit
action, and the version history is protected by a database trigger rather
than by convention in the service layer.

| Endpoint | Permission | |
|---|---|---|
| `GET /rules`, `GET /rules/{key}` | `rule:read` | |
| `GET /rules/{key}/versions` | `rule:read` | full previous definitions |
| `POST /rules`, `PUT /rules/{key}` | `rule:write` | creates a new version |
| `POST /rules/{key}/status` | `rule:write` | enable / disable / testing |
| `POST /rules/{key}/exceptions` | `rule:write` | reason mandatory |
| `POST /rules/test` | `rule:execute` | evaluate a candidate rule against one event; stores nothing |
| `POST /rules/install-defaults` | `rule:write` | idempotent, non-destructive |

A rule's `rule_id` cannot be changed by an update: renaming would orphan
every alert, exception and metric keyed on the old id.

## Shipped rules

| Rule | Type | ATT&CK |
|---|---|---|
| AUTH-001 Brute force against a single account | windowed | T1110.001 |
| AUTH-002 Password spraying from a single source | windowed (distinct users) | T1110.003 |
| AUTH-003 Privileged account from a non-internal address | streaming | T1078 |
| AUTH-004 Repeated account lockouts | windowed | T1110 |
| WIN-001 Encoded PowerShell command | streaming | T1059.001, T1027 |
| WIN-002 PowerShell download cradle | streaming | T1059.001, T1105 |
| WIN-003 LSASS memory dumping indicators | streaming | T1003.001 |
| WIN-004 Windows event log cleared | streaming | T1070.001 |
| WIN-005 Office application spawned a command interpreter | streaming | T1204.002 |
| WIN-006 Windows service installed | streaming | T1543.003 |

Per spec §29, every shipped rule has a positive and a negative test, and
every windowed rule additionally has exact-threshold, one-below-threshold,
out-of-window, different-user and different-source-address tests. Those run
against a real OpenSearch cluster in
`backend/app/tests/test_detection_rules_pack.py`, and a meta-test fails the
build if a rule is added to the pack without them.

## Writing a new rule

1. Write the YAML. Start with `status: testing`.
2. Check it against a real event:
   `POST /rules/test` with the rule and the event.
3. Add it to `rules/<family>/` (default pack) or `POST /rules` (one tenant).
4. Add its test set to `test_detection_rules_pack.py` — the build fails
   without it.
5. Watch `detections_total{rule_id="...",dry_run="true"}` on live traffic.
6. Promote with `POST /rules/{key}/status` → `enabled`.

## Metrics

`detections_total{rule_id,severity,dry_run}`,
`detections_suppressed_total{rule_id}`,
`detection_exceptions_applied_total{rule_id}`,
`detection_rule_errors_total{rule_id}`,
`detection_regex_timeouts_total`,
`windowed_rule_runs_total{rule_id,outcome}`,
`detection_latency_seconds`.

## Known limits

- Windowed runs overlap by design (the schedule is shorter than the window),
  so a windowed rule without `suppression` re-fires while its events remain
  in window. The loader warns; the shipped pack sets suppression everywhere.
- `cardinality` (used by `distinct_field`) is approximate above its
  precision threshold, which is set to 40,000 — exact for any realistic
  detection threshold, an estimate beyond it.
- A windowed match cites at most 10 event ids; `evidence.observed` carries
  the true count and `evidence.event_ids_truncated` says when the list is
  partial.
- Multi-event *sequences* (failed logins → success → privilege escalation)
  are correlation, not detection, and are Phase 7.
