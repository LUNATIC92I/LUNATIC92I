# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 2 complete — authentication, RBAC, multi-tenancy

Phases 0–1 (architecture, repository/infra scaffolding) are done. Phase 2
adds real, tested identity infrastructure: organization (tenant)
registration, login/refresh/logout with rotating sessions, TOTP-based MFA,
Argon2id password hashing, brute-force lockout, the 10-role RBAC catalog
with a deny-by-default permission matrix, and PostgreSQL Row-Level Security
(with `FORCE ROW LEVEL SECURITY`) enforcing tenant isolation independently
of application code. No event ingestion, detection, or real dashboard yet;
see `docs/DEVELOPMENT_PLAN.md` for what each subsequent phase adds.
Quickstart: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

38/38 backend tests passing (unit: password hashing, JWT incl.
algorithm-confusion rejection, MFA/TOTP, refresh-token mechanics;
integration against a real PostgreSQL instance: full auth lifecycle,
brute-force lockout, session rotation/replay resistance, the RBAC matrix
across all 10 roles, and — the core IDOR claim — a direct test proving RLS
blocks cross-tenant reads even with no `WHERE tenant_id` filter at all, and
denies everything when no tenant context is set). Ruff, mypy, Bandit, and
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

Phase 3 — Event ingestion (see `docs/DEVELOPMENT_PLAN.md`).
