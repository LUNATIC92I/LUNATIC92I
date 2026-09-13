# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting, with a professional SOC-analyst frontend.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: PHASE 9 complete — Threat Intelligence

Phases 0–8 (architecture, scaffolding, authentication/RBAC/multi-tenancy,
ingestion, OCSF normalization, event store, detection, correlation, risk
scoring) are done. Phase 9 gives the risk engine's threat-intel factor a
real producer: IOC management for all ten types in spec §11 with
confidence, source, tags, expiry and per-field history; pluggable feed
connectors; and indicator matching inside the enrichment pipeline, so a
detection on a known-bad address now outranks the same detection on an
unknown one. Full reference:
[`docs/THREAT_INTELLIGENCE.md`](docs/THREAT_INTELLIGENCE.md).

Spec §11's rule — *an indicator is never automatically malicious just
because a feed said so* — is enforced in four independent places: a database
constraint refusing a malicious verdict with no source, a parser that
attaches no verdict to a bare blocklist, an upsert that never upgrades a
classification on re-seeing an indicator, and the risk engine scaling each
match by its own recorded confidence.

Outbound requests now go through an egress guard (THREAT_MODEL.md §3.8):
HTTPS only, a fail-closed host allow-list, every resolved address checked
against loopback/private/link-local ranges — 169.254.169.254 included — and
redirects re-validated rather than followed. Its residual DNS-rebinding
window is documented rather than claimed closed.

499/499 backend tests passing against real PostgreSQL, real Redis and a real
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

Phase 10 — MITRE ATT&CK: an import/update mechanism for tactics, techniques
and sub-techniques (not a hardcoded table), `rule_mitre_map` populated from
the Phase 6 rules, and the coverage API — techniques covered and not
covered, detections per technique, coverage rate.
