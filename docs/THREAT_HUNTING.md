# Threat Hunting

Detection rules answer questions someone already thought to ask. Hunting is
for the ones nobody wrote a rule for yet — an analyst with a hypothesis
("has this IP touched anything else?", "what did this account do
overnight?") searching `events-normalized-*` directly.

## One grammar, wherever "does this event match" is asked

A hunt's structured filters are exactly `app.detection.schema.ConditionNode`
— the same `equals`/`contains`/`cidr`/`gt`/... tree a detection or
correlation rule uses, compiled by the same, already-tested
`app.detection.query.compile_conditions`. That buys three things for free:
no `eval`, no query language handed to the client, and the same `matches`
(regex) refusal detection rules already enforce — Lucene regexp has no
per-query timeout, so a hunt cannot open the denial-of-service door the
rule engine's operator table exists to keep shut (`app/hunting/query.py`).

Every field a filter touches is checked against the normalized-event
mapping before it reaches the cluster (`GET /hunting/fields` lists the
allowlist). With `dynamic: false`, a filter on an undeclared field does not
error — it silently matches nothing, which in a hunting tool looks exactly
like "there's nothing here" instead of "you mistyped the field". Rejecting
it at request time turns that silent false negative into a fixable error.

## Free text is a bounded, escaped search — not `query_string`

`POST /hunting/search`'s `free_text` searches a fixed, reviewed field list
(`FREE_TEXT_FIELDS`) with case-insensitive wildcard/match queries, not
OpenSearch's `query_string`. Handing an analyst's search box straight to
`query_string` means the search box *is* a query-language interpreter
reachable by anyone who can search; `*`/`?` in the input are escaped so a
literal filename or address cannot expand into an unintended wildcard scan.

`source_ip`/`destination_ip` are excluded from the free-text field list:
OpenSearch rejects a `wildcard` query on an `ip`-typed field outright
("Can only use wildcard queries on keyword and text fields"), and a
substring search on an address is not a meaningful question anyway — hunt
for a specific IP with a structured `equals`/`cidr` filter instead.

## The pivot set (spec §15)

A pivot is a fixed jump an analyst makes constantly enough that it earns a
dedicated, one-call endpoint instead of a hand-built filter every time.
Each answers one of two shapes of question (`app/hunting/pivots.py`):

| Pivot | Question | Shape |
|---|---|---|
| IP → Events | What did this address do? | events, newest first |
| IP → Users | Who else used this address? | distinct values |
| User → Hosts | What machines has this account touched? | distinct values |
| Host → Processes | What has run on this host? | distinct values |
| Hash → Events | Where has this file appeared? | events, newest first |
| Domain → Events | Where has this domain/URL appeared? | events, newest first |
| User → Timeline | What did this account do, in order? | events, **oldest first** |

The "distinct values" pivots return a terms aggregation rather than a raw
event list — returning every matching event and asking the analyst to
mentally deduplicate the user/host/process column would turn a five-second
pivot into a spreadsheet exercise. User→Timeline is the one events pivot
sorted oldest-first: it is read as a narrative, not triaged like the other
three.

Every pivot filters on `tenant_id` in the query itself. Pivots run as the
service account rather than a per-user DLS-scoped credential, so this term
is the actual isolation boundary for this path (THREAT_MODEL.md §3.2), not
a convenience filter.

An address or a hash can legitimately appear in more than one field of the
normalized document (`source_ip`/`destination_ip`/`device.ip`;
`hash.md5`/`hash.sha1`/`hash.sha256`) — the algorithm is never asked for,
since an md5/sha1/sha256 value is unambiguous by length. `_term()`
centralizes the same `ip`-field case-insensitivity restriction
`app.detection.query.case_insensitive_allowed()` already enforces for
detection rules: OpenSearch 400s on `case_insensitive` for `ip`, numeric,
boolean and date fields, and this is now the third place that restriction
was hit and the second time it was fixed by sharing the one helper instead
of re-deriving it.

## Saved hunts

`POST /hunting/saved` stores the **analyst-facing query** (free text,
filters, time range — the same `HuntQuery` shape `/hunting/search` accepts)
rather than compiled OpenSearch DSL. Running a saved hunt re-validates and
re-compiles it against the current field allowlist every time
(`POST /hunting/saved/{id}/run`), so a field that stopped existing does not
silently start matching nothing, and the compiler can change without a
migration or a re-save-every-hunt maintenance chore.

## Export: capped, rate-limited, audited

A hunting tool that can return everything an analyst is scoped to see, all
at once, in a downloadable file, is also a data-exfiltration path if the
export action itself goes unwatched (THREAT_MODEL.md §3.7). `POST
/hunting/export` therefore:

- caps rows per export (`HUNT_EXPORT_MAX_ROWS`, default 10,000);
- rate-limits exports per tenant per hour (`HUNT_EXPORT_RATE_LIMIT_PER_HOUR`,
  default 20) with the same Redis fixed-window counter the ingestion
  service uses for its own quota;
- audit-logs every attempt — `EXPORT_DATA`, `result="success"` or
  `"failure"` — including a *rejected* export, so a quota hit still leaves
  a trail rather than vanishing silently.

CSV and JSON are both supported. A CSV cell is flat, so nested fields
(`user`, `process`, `hash`) are rendered as compact JSON in that column
rather than dropped — an analyst opening the file in a spreadsheet still
sees the value.

## Permissions

`hunt: read | write | execute`. There is no separate `hunt:delete` action
in the permission catalog, so deleting a saved hunt is gated on `write` —
the same choice already made for alerts and incidents.

| Action | Permission |
|---|---|
| `GET /hunting/fields`, list/get a saved hunt | `hunt:read` |
| Create, edit, delete a saved hunt | `hunt:write` |
| Search, pivot, run a saved hunt, export | `hunt:execute` |

## API

```
GET    /hunting/fields              searchable field allowlist
POST   /hunting/search              free-text and/or filtered search
GET    /hunting/saved               list this tenant's saved hunts
POST   /hunting/saved               create a saved hunt
GET    /hunting/saved/{id}          fetch one
PATCH  /hunting/saved/{id}          update name/description/query
DELETE /hunting/saved/{id}          delete
POST   /hunting/saved/{id}/run      execute a saved hunt's stored query
POST   /hunting/pivot               run one of the seven fixed pivots
POST   /hunting/export              CSV/JSON export (rate-limited, audited)
```
