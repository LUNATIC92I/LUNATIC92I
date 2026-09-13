# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 5 complete — OpenSearch event store

Phases 0–4 (architecture, repo/infra scaffolding, authentication/RBAC/
multi-tenancy, event ingestion, parsing/OCSF normalization) are done. Phase
5 lands events in the store and makes them searchable: index templates,
aliases and lifecycle policies bootstrapped in code; a failure-isolated
enrichment pipeline (asset criticality, network context) that can never
block ingestion; a bulk indexer that reports per-document rejections
instead of treating a 200 as success; and **Document-Level Security** as
the event-store half of tenant isolation, matching PostgreSQL RLS on the
relational side.

The pipeline now runs end to end — collector → ingest → parse → normalize →
enrich → indexed and queryable. Detection is Phase 6. The frontend is still
the Phase 1 placeholder. Quickstart:
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

163/163 backend tests passing against real PostgreSQL, real Redis and a
real OpenSearch cluster with the security plugin enabled. Phase 5's tests
are deliberately unmocked, because every claim it makes is a claim about
server behavior: that the mapping is actually applied (`source_ip` typed as
`ip`, so CIDR hunting works), that `dynamic: false` stores unexpected
fields without failing ingestion, that re-indexing an event id overwrites
rather than duplicates, that a bulk-rejected document is surfaced rather
than silently lost, and — the isolation claim — that a tenant's reader
issuing a `match_all` query with no filter whatsoever still sees only its
own events, and cannot write to the index at all. Ruff, mypy, Bandit, and
pip-audit all clean.

## Phase 0 deliverables

| # | Deliverable | Location |
|---|---|---|
| 1 | Spec analysis & inconsistencies | [`ARCHITECTURE.md`](ARCHITECTURE.md#1-spec-analysis--inconsistencies) |
| 2 | Final architecture | [`ARCHITECTURE.md`](ARCHITECTURE.md#2-final-architecture) |
| 3 | Threat model | [`THREAT_MODEL.md`](THREAT_MODEL.md) |
| 4 | Component diagram | [`ARCHITECTURE.md`](ARCHITECTURE.md#4-component-diagram) |
| 5 | PostgreSQL schema | [`docs/database/postgresql_schema.sql`](docs/database/postgresql_schema.sql) |
| 6 | OpenSearch indices | [`docs/database/opensearch_indices.md`](docs/database/opensearch_indices.md) |
| 7 | Service interfaces | [`ARCHITECTURE.md`](ARCHITECTURE.md#7-service-interfaces) |
| 8 | Final repository layout | [`ARCHITECTURE.md`](ARCHITECTURE.md#8-final-repository-layout) |
| 9 | Technical risks | [`docs/TECHNICAL_RISKS.md`](docs/TECHNICAL_RISKS.md) |
| 10 | Development plan (Phases 0–20) | [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) |
| 11 | Acceptance criteria per phase | [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md#acceptance-criteria-by-phase) |

## Tech stack (target)

- **Backend:** Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.x, Alembic, asyncio, httpx
- **Datastores:** PostgreSQL (system-of-record), OpenSearch (events/search/analytics), Redis (cache, streams, queues — Kafka-ready abstraction)
- **Frontend:** React, TypeScript, TailwindCSS
- **Infra:** Docker / Docker Compose → Kubernetes
- **Observability:** Prometheus, Grafana, OpenTelemetry
- **Normalization:** OCSF (Open Cybersecurity Schema Framework)

## Next step

Phase 6 — Detection Engine: the YAML rule DSL, streaming and windowed
evaluators, and the first Authentication and Windows rule families, each
with the positive/negative/boundary test set the plan requires (see
`docs/DEVELOPMENT_PLAN.md`).
