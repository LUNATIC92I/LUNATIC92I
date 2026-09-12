# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 4 complete — parsing & OCSF normalization

Phases 0–3 (architecture, repo/infra scaffolding, authentication/RBAC/
multi-tenancy, event ingestion) are done. Phase 4 adds the parsing stage: a
common parser interface with JSON, syslog (RFC 3164 + 5424), CEF, LEEF,
Windows Event XML, Apache/Nginx access log and generic `key=value` parsers,
priority-ordered format detection, and mapping into OCSF 1.1.0 with the
flat indexed projections the search layer needs. The raw payload is carried
through untouched at every step.

Normalized events currently land on `events.normalized` and stop there —
OpenSearch indexing is Phase 5, detection is Phase 6. The frontend is still
the Phase 1 placeholder. Quickstart:
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

130/130 backend tests passing against real PostgreSQL and real Redis. Phase
4 adds, per format, a positive case and a malformed case proving rejection
rather than a crash or silent junk; XXE and billion-laughs refusal on
Windows XML; a fuzz-ish sweep asserting the registry's only failure mode is
`ParserError`; proof that a crashing parser degrades to a dead-lettered
event instead of stalling the pipeline; and a contract test that fails the
build if the normalizer emits a field the OpenSearch mapping never declared
(which, under `dynamic: false`, would be silently unsearchable). Ruff,
mypy, Bandit, and pip-audit all clean.

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

Phase 5 — OpenSearch integration: index templates and ILM, the enrichment
pipeline, and Document-Level Security as the second tenant-isolation layer
on the event store (see `docs/DEVELOPMENT_PLAN.md`).
