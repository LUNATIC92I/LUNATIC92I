# Alerts

Where machine output becomes human work. A detection is a statement about
the world ("this rule matched"); an alert is a statement about the SOC
("somebody needs to look at this, and here is where they got to").

## The lifecycle

```
NEW ──► IN_PROGRESS ──► ESCALATED
 │           │              │
 └───────────┴──────────────┴──► FALSE_POSITIVE / RESOLVED ──► CLOSED
                                        │                        │
                                        └──── IN_PROGRESS ◄──────┘   (reopen)
```

`app/services/alerts.py::TRANSITIONS` is the whole truth about what may
follow what, and anything not listed is refused with a 409. A lifecycle
enforced by scattered `if` statements is one where the fifth caller invents
a sixth path, and a queue whose states are unreliable cannot be reported on
(MTTA, MTTR, false-positive rate) or trusted at a shift handover.

Reopening a closed alert is allowed, but as its own transition with its own
audit action (`REOPEN_ALERT`): new evidence on something an analyst already
dismissed is exactly the case a reviewer goes looking for.

Two timestamps are recorded when the transition happens rather than derived
later from logs: `acknowledged_at` (first move to IN_PROGRESS only — MTTA is
about first human contact, and reopening must not rewrite it) and
`closed_at`.

## Analyst tiers are enforced, not labelled

| Action | Permission | L1 | L2 / L3 | SOC manager |
|---|---|:--:|:--:|:--:|
| See the queue | `alert:read` | ✔ | ✔ | ✔ |
| Acknowledge, escalate, assign, annotate | `alert:write` | ✔ | ✔ | ✔ |
| Resolve, dismiss as false positive, close | `alert:close` | — | ✔ | ✔ |

`alert:close` exists precisely so the tier distinction lives in the
authorization layer rather than on an org chart. An L1 can pick an alert up
and push it upward; deciding it is *over* is an L2 decision.

Every status change writes an audit entry and an append-only transition row
in the same transaction as the change itself. Closures get their own audit
action per outcome (`CLOSE_ALERT_RESOLVED`, `CLOSE_ALERT_FALSE_POSITIVE`,
`CLOSE_ALERT_CLOSED`), because "who called this a false positive, and when"
is the first question asked after a missed incident.

## Deduplication

A brute-force rule firing sixty times against one account is **one alert
with sixty occurrences**, not sixty alerts. Alert fatigue is an attack
surface in its own right (THREAT_MODEL.md §3.4).

The `dedup_key` is what makes two firings "the same thing":

| Source | Key |
|---|---|
| detection | `detection:<rule>:<entity summary>` |
| correlation | `correlation:<rule>:<entity>` |

A repeat inside `ALERT_DEDUP_WINDOW_MINUTES` (default 60) folds into the
open alert: `occurrence_count` increments, `last_seen_at` moves, event ids
accumulate (bounded), and **the worst severity and risk score seen in the
episode win** — an escalating attack must not stay hidden behind the milder
firing that opened the alert. A repeat is never discarded silently;
suppression that hides the fact it happened is indistinguishable from a
detection that stopped working, which is why `occurrence_count` is on the
API response and `alerts_deduplicated_total` is a metric.

Two things deliberately start a *new* alert: a repeat after the window, and
a repeat of something already resolved. The analyst's decision was about
what they saw, not about everything that will ever look like it.

`alerts.created` is published only for genuinely new alerts, because
notifications and (Phase 15) playbooks hang off that topic and a fifty-first
occurrence must not page anyone.

## Evidence lineage

An alert cites OpenSearch document ids **by value**, never by join: the
event store is rebuildable and the alert has to survive it being reindexed
(ARCHITECTURE.md §1 row 2).

`GET /alerts/{id}/evidence` resolves those ids back to the documents:

```json
{
  "total_event_ids": 2,
  "resolved": 1,
  "missing_event_ids": ["9b1c…"],
  "documents": [{"event_id": "…", "found": true, "document": {...}}]
}
```

Ids that no longer resolve are **listed, not omitted**: "there is no
evidence" and "the evidence aged out of retention" are different findings.
The lookup is tenant-filtered in the query itself — it runs as the service
account, so that filter is the isolation boundary, and a tested consequence
is that an alert citing another tenant's event id resolves to nothing.

## What creates alerts

The `alerting` worker consumes `detections.created` and
`correlations.created`. It is a separate deployable from detection so the
queue an analyst works is not coupled to the throughput of rule evaluation.

- **Dry-run detections never become alerts.** A rule in `testing` status is
  evaluated on live traffic precisely so it can be judged without waking
  anyone.
- **`ALERT_MIN_RISK_SCORE`** (default 0) sets the floor below which a
  detection is recorded and searchable but does not become somebody's task.
  Where that line sits is a SOC staffing decision, so it is configuration.
- A correlation alert carries its **timeline** in `evidence`: the chain is
  the point of it, and an analyst opening the alert should see the sequence
  rather than go and rebuild it.

## Display ids

`ALT-2026-000123` — per tenant, per year, gapless. The counter row is locked
with `SELECT FOR UPDATE`, because two workers creating alerts in the same
instant would otherwise both read the same maximum. Each tenant counts from
one; display ids are quoted in tickets and must not leak anyone else's
volume.

## API

| Endpoint | Permission | |
|---|---|---|
| `GET /alerts` | `alert:read` | filter by status, severity, `mine=true`; ordered by risk then recency |
| `GET /alerts/counts` | `alert:read` | queue depth by status |
| `GET /alerts/{id}` | `alert:read` | full detail including `risk_explanation` |
| `POST /alerts/{id}/status` | `alert:write` / `alert:close` | depends on the target status |
| `POST /alerts/{id}/assign` | `alert:write` | `analyst_id: null` hands it back to the queue |
| `GET`/`POST /alerts/{id}/notes` | `alert:read` / `alert:write` | append-only |
| `GET /alerts/{id}/history` | `alert:read` | every transition, append-only |
| `GET /alerts/{id}/evidence` | `alert:read` | resolves event ids to documents |

## Known limits

- Notifications (email, Slack, webhook) are not implemented. `alerts.created`
  is published and is the hook they will attach to.
- Alert → incident promotion is Phase 12; an alert currently ends at CLOSED
  rather than becoming part of a case.
- Deduplication is keyed on rule and entity. Two different rules firing on
  the same entity remain two alerts, which is correct today but is exactly
  what correlation (Phase 7) and incidents (Phase 12) exist to group.
- `ALERT_MIN_RISK_SCORE` is global per deployment, not per tenant or per
  rule family.
