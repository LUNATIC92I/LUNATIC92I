# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 7 complete — Correlation Engine

Phases 0–6 (architecture, scaffolding, authentication/RBAC/multi-tenancy,
ingestion, OCSF normalization, the OpenSearch event store, and the detection
engine) are done. Phase 7 adds the layer that makes a sequence mean more
than its parts: a correlation rule DSL over the same safe condition grammar,
an engine consuming both `events.normalized` and `detections.created`,
automatic timeline construction, and three shipped chains (account takeover,
credential dumping → lateral movement, document execution → persistence).

Two risks from the Phase 0 register are closed by tests rather than by
assertion:

- **Technical Risk #4 (state lost on restart).** In-flight chains live in
  Redis keyed by (tenant, rule, entity) with a TTL equal to the rule window;
  append-and-read is one Lua script so replicas cannot interleave. A test
  destroys the engine mid-chain, rebuilds it from a fresh client, and the
  chain still completes.
- **Technical Risk #5 (timestamp manipulation).** Ordering and windowing use
  an effective time — the source's clock when plausible, ingestion time when
  not. Tests back-date a stage by two days and future-date another by a
  month; both still correlate, and a genuinely old event still falls outside
  the window, so the backstop does not degrade into "everything correlates".

343/343 backend tests passing against real PostgreSQL, real Redis and a real
OpenSearch cluster with the security plugin enabled. Ruff, mypy, Bandit and
pip-audit all clean. The pipeline runs collector → ingest → parse →
normalize → enrich → index → detect → correlate. Alerts are Phase 11; the
frontend is still the Phase 1 placeholder. Quickstart:
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md); rule reference:
[`DETECTION_ENGINE.md`](DETECTION_ENGINE.md).

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

Phase 8 — Risk Engine: a versioned, explainable weighted-sum score
(severity, confidence, asset criticality, user risk, threat intel, MITRE
context, behavioural anomaly) with a `risk_explanation` an analyst can read
back (see `docs/DEVELOPMENT_PLAN.md`).
