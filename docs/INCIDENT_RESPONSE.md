# Incident management

Where alerts become a case. An alert is one thing that fired; an incident
is what a team works — several alerts, the hosts and accounts involved, the
indicators found along the way, the tasks people are doing, and a timeline
of who did what and when.

## The workflow

```
NEW ──► TRIAGE ──► INVESTIGATION ──► CONTAINMENT ──► ERADICATION ──► RECOVERY ──► CLOSED
 │         │              │                │               │              │         │
 └─────────┴──────────────┴────────────────┴───────────────┴──────────────┘         │
                     (closable from anywhere; reopening is its own audited move) ◄───┘
```

This mirrors the NIST 800-61 lifecycle spec §14 names, and it is not a
strict pipeline: containment that turns out to have failed sends the case
back to investigation, and a case that turns out to be nothing can close
straight from NEW without being walked through five stages first. What it
is *not* is a free-for-all — jumping from NEW straight to RECOVERY is a
mistake the state machine refuses, not a shortcut it allows.
`app/services/incidents.py::TRANSITIONS` is the whole truth about what may
follow what.

Reopening a closed incident is allowed but is its own transition with its
own audit action (`REOPEN_INCIDENT`): "we thought this was over" is a thing
that happens, and hiding it helps nobody.

## Display ids

`INC-2026-000123` — unique and gapless per tenant per year, exactly like
alert ids. The counter is a small table locked with `SELECT ... FOR UPDATE`,
but locking alone does not solve concurrent creation: **the first incident
of a tenant's year has no row yet for `FOR UPDATE` to hold**, so naively
checking-then-inserting lets every concurrent creator see no row and race
to insert one, and all but the winner fail with a unique-constraint
violation. The fix is `INSERT ... ON CONFLICT DO NOTHING` to create the row
atomically (or no-op if another transaction just did), *then* the locking
`SELECT`. This exact defect was caught by this phase's own concurrency test
and was present in Phase 11's alert ids too — both are fixed the same way.

## Timeline completeness

Spec §14's acceptance criterion is explicit: **every state change produces
a timeline entry.** `app/services/incidents.py` is built around that
invariant — status changes, notes, tasks (created and updated), and every
kind of linkage (alert, asset, indicator, account) all write through
`record_timeline()`, and nothing in the API bypasses the service layer to
touch the database directly.

Completeness alone is not enough — the entries have to come back in the
order they actually happened. Postgres's `now()` is frozen at *transaction
start*, not evaluated per statement, so several timeline entries written in
one transaction (opening a case with alerts already attached, say) would
otherwise all get the identical timestamp, and the read-back order would
fall to tiebreaking on a random row id. `incident_timeline.occurred_at`
uses `clock_timestamp()` instead, which advances within a transaction, so
same-transaction entries still order correctly. This was caught by the
phase's own multi-operation timeline test.

## Linkage

An incident links to what it is about, and links are checked against the
caller's own tenant before they are created — a cross-object operation is
exactly where an unvalidated id becomes an IDOR (THREAT_MODEL.md §3.2):

| Link | Table | Cross-tenant? |
|---|---|---|
| Alert | `incident_alerts` | must belong to this tenant |
| Asset | `incident_assets` | must belong to this tenant |
| Indicator | `incident_iocs` | this tenant's own **or** a shared feed indicator |
| Account | `incident_users` | free text — the estate's account, not this platform's |

Promoting an alert **links** it rather than copying it: the alert keeps its
own lifecycle (an analyst can still work it directly), and the same
compromised host often means the same alert belongs to more than one case.

Indicators are the one exception to "must belong to this tenant": a shared,
global feed indicator has no tenant of its own, and the incident is about
*this* tenant having seen it, so linking a shared indicator is always
allowed (mirroring how `/iocs` itself treats shared rows in Phase 9).

## Evidence

An incident's evidence is not stored on the incident — it is the union of
every event id cited by every alert linked to the case, resolved back to
the documents in the event store on request
(`GET /incidents/{id}/evidence`). This rolls up naturally: link a new alert,
and its evidence is part of the case without anything being copied or
duplicated onto the incident row.

Ids that no longer resolve — usually retention aging them out — are listed
under `missing_event_ids` rather than silently omitted, the same lineage-
integrity contract Phase 11 established for alerts.

## Append-only history

`incident_timeline` and `incident_notes` reject `UPDATE` and `DELETE` at
the database level, the same pattern as the audit log and every other
append-only history table in this platform: a case record whose history can
be edited afterwards is worthless for the two things it exists for —
handing the case to the next shift, and explaining afterwards what was
known and when.

## API

| Endpoint | Permission | |
|---|---|---|
| `GET /incidents` | `incident:read` | filter by status, severity, `mine=true` |
| `GET /incidents/counts` | `incident:read` | queue depth by status |
| `POST /incidents` | `incident:write` | optionally promotes `alert_ids` at creation |
| `GET`/`PATCH /incidents/{id}` | `incident:read` / `incident:write` | |
| `POST /incidents/{id}/status` | `incident:write` | 409 on a refused transition |
| `POST /incidents/{id}/alerts`\|`assets`\|`iocs`\|`users` | `incident:write` | idempotent |
| `GET`/`POST /incidents/{id}/notes` | `incident:read` / `incident:write` | append-only |
| `GET`/`POST /incidents/{id}/tasks`, `PATCH .../tasks/{task_id}` | `incident:read` / `incident:write` | |
| `GET /incidents/{id}/timeline` | `incident:read` | every mutation, in true chronological order |
| `GET /incidents/{id}/evidence` | `incident:read` | rolled up from linked alerts |

## Known limits

- No automatic alert-to-incident promotion. Correlating several alerts into
  one case today is an analyst decision made through the API; a rule-driven
  "these alerts are probably the same incident" suggestion is future work.
- MTTD/MTTC/MTTR are recorded as timestamps (`detected_at`, `contained_at`,
  `closed_at`) but no reporting endpoint aggregates them yet — that belongs
  with the SOC overview dashboard in Phase 14.
- `incident_users` is free text with no validation against a directory:
  correct by construction (the estate's accounts are not this platform's
  users), but it means a typo'd username creates a new, unrelated entry
  rather than being caught.
