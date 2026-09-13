# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 11 complete — Alerts

Phases 0–10 are done (architecture, scaffolding, auth/RBAC/multi-tenancy,
ingestion, OCSF normalization, event store, detection, correlation, risk
scoring, threat intelligence, ATT&CK coverage). Phase 11 turns machine
output into human work: detections and correlations become alerts with a
real lifecycle (NEW → IN_PROGRESS → ESCALATED → FALSE_POSITIVE/RESOLVED →
CLOSED), deduplication on a `dedup_key`, and evidence that resolves back to
the documents the alert was raised on. Full reference:
[`docs/ALERTS.md`](docs/ALERTS.md).

The analyst-tier distinction is enforced by a new `alert:close` permission
rather than written on an org chart: an L1 can acknowledge, escalate,
assign and annotate, but only L2 and above can decide an alert is over.
Every status change writes an audit entry and an append-only transition row
in the same transaction as the change, and closures are audited per outcome
— "who called this a false positive, and when" is the first question after a
missed incident.

Deduplication folds repeats into the alert they repeat (sixty brute-force
firings against one account are one alert with sixty occurrences), keeps the
worst severity and score seen in the episode so an escalating attack is not
hidden behind the milder firing that opened it, and publishes only genuinely
new alerts — a fifty-first occurrence must not page anyone.

611/611 backend tests passing against real PostgreSQL, real Redis and a real
OpenSearch cluster with the security plugin enabled, including the full
valid/invalid transition matrix, dedup window behaviour, and evidence
lineage proven against real indexed documents. Ruff, mypy, Bandit and
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

Phase 12 — Incident Management: the `NEW → TRIAGE → INVESTIGATION →
CONTAINMENT → ERADICATION → RECOVERY → CLOSED` workflow, `INC-YYYY-NNNNNN`
display ids, notes, tasks, timeline, and evidence/asset/user/IOC linkage —
the case an alert gets promoted into.
