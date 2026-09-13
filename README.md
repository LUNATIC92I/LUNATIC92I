# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 8 complete — Risk Engine

Phases 0–7 (architecture, scaffolding, authentication/RBAC/multi-tenancy,
ingestion, OCSF normalization, event store, detection, correlation) are
done. Phase 8 scores what the pipeline produces: a versioned, explainable
weighted sum over seven factors — severity, confidence, asset criticality,
user risk, threat intel, MITRE context, behavioural anomaly — normalized to
0–100 and bucketed LOW/MEDIUM/HIGH/CRITICAL. Every detection and correlation
now carries `risk_score`, `risk_bucket` and a `risk_explanation` that
reconstructs the arithmetic factor by factor, including the factors that had
no data. Full reference: [`docs/RISK_SCORING.md`](docs/RISK_SCORING.md).

Two spec rules are enforced by the formula rather than by prose: an
indicator's contribution is scaled by *its own* confidence (§11 — a feed is
not proof), and behavioural anomaly carries the smallest weight in the table
(§17 — an anomaly can tip a borderline score, never manufacture one).

Phase 8 also adds the `/assets` API, because asset criticality is a
user-editable multiplier on every score: it is permission-gated, every
mutation is audit-logged in the same transaction, and a criticality change
gets its own audit action with before/after values.

406/406 backend tests passing against real PostgreSQL, real Redis and a real
OpenSearch cluster with the security plugin enabled — including golden-file
tests that lock each score *and* its explanation, per-factor cap tests, and
bucket boundary tests at 24/25, 49/50 and 74/75. Ruff, mypy, Bandit and
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

Phase 9 — Threat Intelligence: IOC management for all ten types in spec §11
with confidence/source/expiration history, a pluggable feed connector behind
the egress allow-list, and IOC matching wired into the enrichment pipeline
(which is what finally gives the risk engine's threat-intel factor a real
producer).
