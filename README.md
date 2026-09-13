# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 12 complete — Incident Management

Phases 0–11 are done (architecture, scaffolding, auth/RBAC/multi-tenancy,
ingestion, OCSF normalization, event store, detection, correlation, risk
scoring, threat intelligence, ATT&CK coverage, alerts). Phase 12 gives an
analyst a case to work in: the full NIST-800-61-shaped incident lifecycle
(NEW → TRIAGE → INVESTIGATION → CONTAINMENT → ERADICATION → RECOVERY →
CLOSED), `INC-YYYY-NNNNNN` display ids, notes, tasks, a chronological
timeline, and linkage to the alerts/assets/indicators/accounts the case is
about. Full reference: [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md).

This phase's own test suite caught two real concurrency/ordering defects
and both are fixed, one of them also in already-shipped Phase 11 code:

- **Display-id generation raced under concurrency.** `SELECT ... FOR
  UPDATE` locks nothing when the counter row doesn't exist yet, so N
  concurrent case (or alert) creators all saw no row and raced to insert
  one — all but the winner failed outright. Fixed with `INSERT ... ON
  CONFLICT DO NOTHING` before the locking `SELECT` in both `alerts.py` and
  `incidents.py`.
- **Timeline entries written in one transaction could read back in a
  random order.** Postgres's `now()` is frozen at transaction start, not
  evaluated per statement, so several entries in one transaction shared an
  identical timestamp and tie-broke on a random row id.
  `incident_timeline.occurred_at` now uses `clock_timestamp()`, which
  advances within a transaction.

677/677 backend tests passing against real PostgreSQL, real Redis and a
real OpenSearch cluster with the security plugin enabled, including the
full workflow transition matrix, concurrent-creation stress tests, timeline-
completeness checks, and the cross-tenant IDOR suite spec §12 extends from
Phase 2 to incidents. Ruff, mypy, Bandit and pip-audit all clean.

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

Phase 13 — Threat Hunting: free-text and filtered search over
`events-normalized-*` (IP/user/hostname/process/hash/domain/event
type/severity/MITRE technique), saved queries, export, and the pivot set
from spec §15 (IP → Events, IP → Users, User → Hosts, Host → Processes,
Hash → Events, Domain → Events, User → Timeline).
