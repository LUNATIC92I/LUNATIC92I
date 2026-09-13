# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 6 complete — Detection Engine

Phases 0–5 (architecture, repo/infra scaffolding, authentication/RBAC/
multi-tenancy, event ingestion, parsing/OCSF normalization, the OpenSearch
event store with enrichment) are done. Phase 6 makes the platform *detect*:
a declarative YAML rule DSL that cannot execute code, both execution shapes
from `ARCHITECTURE.md` §1 row 4 (a streaming evaluator per event and a
scheduled windowed aggregator for threshold rules), exceptions, suppression
and dry-run, per-tenant rule storage with an append-only version history and
audited enable/disable, and the first ten Authentication and Windows rules
enabled by default. See [`DETECTION_ENGINE.md`](DETECTION_ENGINE.md).

The pipeline now runs collector → ingest → parse → normalize → enrich →
index → **detect**, publishing to `detections.created`. Alerts are Phase 11;
correlation of multi-stage sequences is Phase 7. The frontend is still the
Phase 1 placeholder. Quickstart:
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

285/285 backend tests passing against real PostgreSQL, real Redis and a real
OpenSearch cluster with the security plugin enabled. Per spec §29 every
shipped rule carries positive and negative tests, and every windowed rule
also carries exact-threshold, one-below-threshold, out-of-window,
different-user and different-source tests — run as real aggregations against
the cluster, with a meta-test that fails the build if a rule is added
without them. Ruff, mypy, Bandit and pip-audit all clean.

Three defects the Phase 6 tests caught in Phase 6 code, all fixed: a
privileged-login rule that matched events carrying no source address at all
(`not (ip in private ranges)` is vacuously true when there is no ip); a
`case_insensitive` term query that OpenSearch rejects outright on `ip`-typed
fields, so a rule worked streaming and failed windowed; and a newly declared
mapping field that stayed unsearchable on already-created indices until
rollover.

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

Phase 7 — Correlation Engine: multi-stage attack scenarios (failed logins →
success → privilege escalation → exfiltration), Redis-persisted correlation
state that survives a worker restart, and automatic timeline construction
(see `docs/DEVELOPMENT_PLAN.md`).
