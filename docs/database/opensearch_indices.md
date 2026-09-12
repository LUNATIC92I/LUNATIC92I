# LUNATIC-IT SIEM — OpenSearch Indices (Phase 0 draft)

OpenSearch is the system of record for **events only** (raw + normalized),
plus derived, rebuildable analytics indices. It is never the source of truth
for alerts/incidents/rules/users/IOCs — those live in PostgreSQL
(`docs/database/postgresql_schema.sql`) and reference OpenSearch documents by
`event_id`.

## 1. Tenant isolation strategy

Default: **shared indices with mandatory `tenant_id` field**, enforced by two
independent layers (defense in depth — see `THREAT_MODEL.md` §3.2):

1. **Application layer** — every query builder injects a `term` filter on
   `tenant_id` derived from the authenticated principal.
2. **OpenSearch Security plugin — Document Level Security (DLS)** — each
   tenant-scoped role is mapped to a DLS query
   (`{"term": {"tenant_id": "<tenant_id>"}}`) so a bug in the application
   query layer cannot leak documents across tenants.

Large/regulated tenants may opt into **index-per-tenant** later
(`events-normalized-<tenant_id>-*`) without changing the mapping — this is a
provisioning decision, not a schema change.

## 2. Index naming & ILM

Naming: `lunatic-<purpose>-<version>-<yyyy.MM.dd>` behind a write alias, so
mappings can evolve without reindexing history.

| Index pattern | Alias | Purpose | Default ILM (dev defaults, tenant-configurable) |
|---|---|---|---|
| `lunatic-events-raw-v1-*` | `events-raw-write` | Verbatim raw payload + minimal metadata, for forensic replay/reparse | hot 7d → warm 23d → delete 90d |
| `lunatic-events-normalized-v1-*` | `events-normalized-write` | OCSF-normalized, enriched, searchable events | hot 14d → warm 46d → delete 180d |
| `lunatic-detections-v1-*` | `detections-write` | Materialized rule/correlation matches for fast dashboard/timeline reads (rebuildable from PostgreSQL `alerts` + source events) | hot 30d → delete 365d |
| `lunatic-deadletter-v1-*` | `deadletter-write` | Events that failed parsing/normalization, with failure reason | hot 30d → delete 90d |

Rollover trigger: 50GB or 1 day, whichever first (tunable per tenant/volume
tier). ILM policies and retention are configurable per tenant to satisfy
differing compliance requirements — the numbers above are defaults, not caps.

## 3. Index template: `lunatic-events-normalized`

Field families follow OCSF 1.1.0 semantics; flat convenience fields (as
listed in the spec) are stored as **keyword/ip/date projections** derived
from the OCSF object, not a parallel schema (see `ARCHITECTURE.md` §1 row 6).

```json
{
  "index_patterns": ["lunatic-events-normalized-v1-*"],
  "template": {
    "settings": {
      "number_of_shards": 3,
      "number_of_replicas": 1,
      "index.lifecycle.name": "lunatic-events-normalized-policy",
      "index.lifecycle.rollover_alias": "events-normalized-write",
      "index.mapping.total_fields.limit": 2000
    },
    "mappings": {
      "dynamic": "false",
      "properties": {
        "event_id":              { "type": "keyword" },
        "timestamp":              { "type": "date" },
        "ingestion_timestamp":     { "type": "date" },
        "tenant_id":                { "type": "keyword" },
        "source":                   { "type": "keyword" },
        "source_type":               { "type": "keyword" },
        "category":                   { "type": "keyword" },
        "class":                       { "type": "keyword" },
        "severity":                     { "type": "keyword" },
        "activity":                      { "type": "keyword" },
        "actor": {
          "properties": {
            "user":     { "type": "keyword" },
            "process":   { "type": "keyword" },
            "session_id": { "type": "keyword" }
          }
        },
        "user": {
          "properties": {
            "name":   { "type": "keyword" },
            "domain":  { "type": "keyword" },
            "uid":      { "type": "keyword" }
          }
        },
        "device": {
          "properties": {
            "hostname":    { "type": "keyword" },
            "ip":           { "type": "ip" },
            "os":            { "type": "keyword" },
            "asset_id":       { "type": "keyword" }
          }
        },
        "source_ip":        { "type": "ip" },
        "destination_ip":    { "type": "ip" },
        "source_port":        { "type": "integer" },
        "destination_port":    { "type": "integer" },
        "protocol":             { "type": "keyword" },
        "hostname":              { "type": "keyword" },
        "process": {
          "properties": {
            "name":      { "type": "keyword" },
            "pid":        { "type": "integer" },
            "path":        { "type": "keyword" },
            "parent_name":  { "type": "keyword" }
          }
        },
        "command_line":       { "type": "text", "fields": { "raw": { "type": "keyword", "ignore_above": 4096 } } },
        "file": {
          "properties": {
            "name": { "type": "keyword" },
            "path":  { "type": "keyword" },
            "size":   { "type": "long" }
          }
        },
        "hash": {
          "properties": {
            "md5":    { "type": "keyword" },
            "sha1":    { "type": "keyword" },
            "sha256":   { "type": "keyword" }
          }
        },
        "domain":              { "type": "keyword" },
        "url":                  { "type": "keyword" },
        "cloud": {
          "properties": {
            "provider":  { "type": "keyword" },
            "account_id": { "type": "keyword" },
            "region":      { "type": "keyword" }
          }
        },
        "authentication": {
          "properties": {
            "method":  { "type": "keyword" },
            "outcome":  { "type": "keyword" },
            "mfa_used":  { "type": "boolean" }
          }
        },
        "mitre_techniques":     { "type": "keyword" },
        "ioc_matches":           { "type": "keyword" },
        "risk_context": {
          "properties": {
            "asset_criticality": { "type": "keyword" },
            "user_risk_score":    { "type": "float" }
          }
        },
        "enrichment_partial":     { "type": "boolean" },
        "schema_version":          { "type": "keyword" },
        "raw_event":                { "type": "object", "enabled": false },
        "normalized_event":          { "type": "object", "enabled": false }
      }
    }
  }
}
```

Notes:
- `raw_event` / `normalized_event` are stored with `"enabled": false`
  (retrievable as `_source`, not individually indexed/queried field-by-field)
  to avoid mapping explosion from heterogeneous source payloads; specific
  fields worth querying are promoted to typed top-level fields as above.
- `command_line` gets a `text` analyzer for free-text hunting plus a
  `.raw` keyword sub-field for exact-match pivots.
- `ignore_above` guards on free-form fields prevent single malformed events
  from blowing up mapping/field-data memory.

## 4. Index template: `lunatic-events-raw`

Minimal, intentionally permissive mapping (forensic archive, not meant to be
richly queried):

```json
{
  "index_patterns": ["lunatic-events-raw-v1-*"],
  "template": {
    "settings": { "number_of_shards": 2, "number_of_replicas": 1 },
    "mappings": {
      "dynamic": false,
      "properties": {
        "event_id":            { "type": "keyword" },
        "tenant_id":            { "type": "keyword" },
        "collector_id":          { "type": "keyword" },
        "source_type":            { "type": "keyword" },
        "received_at":             { "type": "date" },
        "content_hash":             { "type": "keyword" },
        "raw_payload":               { "type": "object", "enabled": false }
      }
    }
  }
}
```

## 5. Index template: `lunatic-deadletter`

```json
{
  "index_patterns": ["lunatic-deadletter-v1-*"],
  "template": {
    "mappings": {
      "dynamic": false,
      "properties": {
        "tenant_id":       { "type": "keyword" },
        "stage":            { "type": "keyword" },
        "failure_reason":    { "type": "text" },
        "failed_at":          { "type": "date" },
        "raw_payload":         { "type": "object", "enabled": false }
      }
    }
  }
}
```

## 6. Search/aggregation access patterns to optimize for

- **Threat hunting free-text + filters** (spec §15): `command_line`,
  `hostname`, `domain`, `hash.*`, `source_ip`/`destination_ip`, `severity`,
  `mitre_techniques`, date range — all covered by the keyword/ip/date fields
  above; no full reindex needed to support new filter combinations.
- **Windowed detection rules** (spec §7/§8): `date_histogram` +
  `terms`/`cardinality` aggregations bucketed by `group_by` fields
  (`user.name`, `source_ip`) over the rule's `window`.
- **Pivots** (spec §15): `IP → Events`, `User → Hosts`, etc. are terms
  aggregations / top-hits queries against the same normalized index — no
  separate graph store needed at this scale.
- **MITRE coverage page** (spec §12): aggregation over `mitre_techniques`
  joined (application-side) with the PostgreSQL `mitre_techniques` reference
  table to show covered vs. non-covered techniques.

## 7. Data lifecycle & replay

Because OpenSearch is treated as rebuildable, not authoritative: raw events
are retained long enough (`events-raw-*` ILM) to support **event replay** —
reprocessing through parsing/normalization/enrichment/detection after a rule
change or a bug fix — without needing a second archival system in Phase 0–10.
A durable archive (e.g., object storage cold tier) is a Phase 19+ HA/scale
concern, not required for initial correctness.
