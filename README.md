# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 10 complete — MITRE ATT&CK coverage

Phases 0–9 are done (architecture, scaffolding, auth/RBAC/multi-tenancy,
ingestion, OCSF normalization, event store, detection, correlation, risk
scoring, threat intelligence). Phase 10 answers the question a SOC manager
actually asks: *what can we detect, and what can we not?*

The ATT&CK catalog is **imported, never hardcoded** — the official STIX
bundle (verified against the real v19.2 release: 15 tactics, 858 techniques,
zero rejected objects) over HTTPS through the egress guard, or from a file
for air-gapped installs, re-imported automatically once stale. Imports are
idempotent, audit-logged, and validate third-party content before storing
it: bounded sizes, shape-checked ids, stripped control characters, rejected
objects counted rather than silently dropped.

Coverage is deliberately conservative, because the alternative is a page
that flatters: a disabled rule is not coverage, a covered sub-technique does
not cover its parent (it is reported as `partial`), revoked techniques are
out of the denominator, and a rule claiming a technique the catalog lacks is
surfaced as an unknown claim rather than counted. Detections are now indexed
as well as published, so "detections per technique" and "recent detections"
come from real data — with dry-run detections excluded, since a `testing`
rule fires deliberately and never alerts. Full reference:
[`docs/MITRE_MAPPING.md`](docs/MITRE_MAPPING.md).

543/543 backend tests passing against real PostgreSQL, real Redis and a real
OpenSearch cluster with the security plugin enabled. Ruff, mypy, Bandit and
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

Phase 11 — Alerts: the full lifecycle (NEW → IN_PROGRESS → ESCALATED →
FALSE_POSITIVE/RESOLVED → CLOSED), deduplication and suppression on a
`dedup_key`, and evidence linkage back to the OpenSearch documents behind
every alert.
