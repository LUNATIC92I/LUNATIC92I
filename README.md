# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 3 complete — event ingestion

Phases 0–2 (architecture, repo/infra scaffolding, authentication/RBAC/
multi-tenancy) are done. Phase 3 adds the ingestion path: a common
collector interface with syslog UDP/TCP listeners and a REST gateway, the
`EventBus` abstraction over Redis Streams (Kafka-swappable, proven by an
in-memory implementation of the same interface), per-tenant rate limiting,
retry-safe deduplication, and a dead-letter path so a malformed or
oversized event is preserved and replayable rather than dropped.

Events currently land on `events.raw` and stop there — parsing/OCSF
normalization is Phase 4 and detection is Phase 6. The frontend is still
the Phase 1 placeholder. Quickstart:
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

72/72 backend tests passing against real PostgreSQL and real Redis. Beyond
the Phase 2 auth/RBAC/RLS suite, Phase 3 covers: at-least-once redelivery
of unacked messages, dead-letter routing, syslog allowlist fail-closed
behavior (an empty allowlist accepts nothing), oversized-datagram and
endless-TCP-line rejection, real-socket UDP/TCP round trips, retry
deduplication that is per-tenant rather than global, and collector API keys
that cannot be forged, replayed against another tenant, or used after
revocation. Ruff, mypy, Bandit, and pip-audit all clean.

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

Phase 4 — Normalization: parsers (JSON, syslog, CEF, LEEF, Windows Event
XML, Apache/Nginx) feeding OCSF 1.1.0 mapping (see
`docs/DEVELOPMENT_PLAN.md`).
