# LUNATIC-IT SIEM

**Detect. Investigate. Respond.**

Enterprise-grade, modular, multi-tenant Security Information and Event
Management (SIEM) platform: collection → normalization (OCSF) → enrichment →
detection → correlation → risk scoring → alerting → incident response →
threat hunting → SOAR, with a professional SOC-analyst frontend, full
observability, security hardening, a benchmarked performance profile, a
Kubernetes HA deployment, and production-readiness sign-off.

This is **not** a demo. Every phase below only counts as "done" once its
tests, security review, and acceptance criteria pass — an interface existing
in the UI is never sufficient by itself.

## Status: all 20 phases complete

| Phase | What it delivered |
|---|---|
| 0 | Architecture, threat model, spec analysis (see "Phase 0 deliverables" below) |
| 1 | Repo scaffold, Docker Compose stack, CI pipeline |
| 2 | Identity, RBAC, multi-tenancy, JWT/MFA auth, row-level security |
| 3 | Ingestion: collectors, EventBus, rate limiting, dedup, DLQ |
| 4 | Format parsers + OCSF 1.1.0 normalization |
| 5 | OpenSearch event store + enrichment pipeline |
| 6 | Detection engine: rule DSL, streaming + windowed evaluators, rule packs |
| 7 | Correlation engine: multi-stage attack chains, Redis-backed state |
| 8 | Risk scoring: versioned, explainable, weighted-sum engine |
| 9 | Threat intelligence: IOC management, egress-guarded feeds |
| 10 | MITRE ATT&CK: STIX import, detection coverage mapping |
| 11 | Alerts: dedup, lifecycle state machine, evidence |
| 12 | Incident management: NIST 800-61 workflow, tasks, timeline |
| 13 | Threat hunting: search, pivots, saved hunts, audited export |
| 14 | Full React/TypeScript SOC analyst frontend + E2E tests |
| 15 | SOAR: playbook engine, approval-gated actions |
| 16 | Observability: `/health`/`/ready`/`/metrics`, tracing, dashboards |
| 17 | Security hardening: OWASP ASVS/API Top 10 audit + automated suite |
| 18 | Performance: real load-test numbers, honestly scoped |
| 19 | HA / Kubernetes: manifests, NetworkPolicies, a real chaos test |
| 20 | Production readiness: backups, runbook, final sign-off |

**851/851 backend tests passing** against real PostgreSQL, real Redis, and
a real OpenSearch cluster with the security plugin enabled — the full RBAC
matrix, cross-tenant IDOR and row-level-security suites, the automated
security regression suite (spec §30: SQLi, command injection, XSS, SSRF,
path traversal, IDOR, privilege escalation, broken auth, tenant isolation,
rate-limit bypass, JWT manipulation, replay), and every phase's own
concurrency/correctness tests. Ruff, mypy, Bandit, and pip-audit all clean.
Docker images scanned with Trivy (zero CRITICAL/HIGH findings — see
`SECURITY.md`'s sign-off checklist for what that scan actually covers).

See `SECURITY.md` for the final production-readiness sign-off and the
complete, honest list of residual risks accepted.

## Real findings, not just green checkmarks

A recurring theme worth surfacing rather than burying: several phases'
own rehearsal of "does this actually work" surfaced genuine defects that
would otherwise have shipped silently. A few examples, each fixed with a
regression test added:

- **Phase 18:** a Redis client default socket timeout silently crashed
  every worker on any 5+ second idle period — invisible to 850+ existing
  tests because none had ever let a subscribe() call sit genuinely idle.
- **Phase 19:** a chaos test that actually `SIGKILL`ed a worker mid-batch
  (50,500 real events through the real pipeline) proved the no-data-loss
  reclaim guarantee for real, and found the one thing it didn't yet cover
  at the time (Redis Sentinel failover wasn't transparent to the app —
  documented, not hidden, and since closed: `app/core/redis.py`'s
  Sentinel-aware client, verified against a real cluster with the actual
  master container killed).
- **Phase 20:** a rehearsed backup drill found that `pg_dump` with the
  application's own database role fails outright, because Row-Level
  Security is enforced even for the table owner — the correct posture
  for the app, the wrong one for a backup. Fixed with a documented,
  least-privilege backup role (`scripts/bootstrap_backup_role.sql`), not
  by weakening RLS.
- **Phase 20:** an actual Trivy scan against the real built images found
  4 CRITICAL / 39 HIGH vulnerabilities in accumulated base-image OS
  packages — fixed by pinning newer patch releases and adding a
  build-time OS security-upgrade layer, verified clean by rescanning.

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

## Documentation index

| Doc | Covers |
|---|---|
| [`SECURITY.md`](SECURITY.md) | Vulnerability disclosure, final sign-off checklist, residual risks |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | Trust boundaries, STRIDE analysis, abuse cases |
| [`docs/SECURITY_CHECKLIST.md`](docs/SECURITY_CHECKLIST.md) | ASVS/API Top 10 control-by-control tracking |
| [`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) | Health/ready/metrics, tracing, dashboards |
| [`docs/PERFORMANCE_BENCHMARK.md`](docs/PERFORMANCE_BENCHMARK.md) | The only place a throughput/latency number may be stated |
| [`docs/KUBERNETES.md`](docs/KUBERNETES.md) | HA deployment, scaling correctness, the real chaos test |
| [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md) | A rehearsed backup/restore procedure, including the RLS gotcha it found |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Platform-failure recovery (distinct from incident *management*) |
| [`docs/INCIDENT_RESPONSE.md`](docs/INCIDENT_RESPONSE.md) | The analyst-facing case workflow (Phase 12's own feature) |
| [`DETECTION_ENGINE.md`](DETECTION_ENGINE.md) | Rule DSL, streaming/windowed evaluation |
| [`docs/MITRE_MAPPING.md`](docs/MITRE_MAPPING.md) | ATT&CK coverage methodology |
| [`docs/RISK_SCORING.md`](docs/RISK_SCORING.md) | The weighted-sum risk model and its explanation output |
| [`docs/THREAT_INTELLIGENCE.md`](docs/THREAT_INTELLIGENCE.md) | IOC lifecycle, feed connectors, egress guard |
| [`docs/THREAT_HUNTING.md`](docs/THREAT_HUNTING.md) | Search, pivots, saved hunts |
| [`docs/ALERTS.md`](docs/ALERTS.md) | Dedup, lifecycle, evidence |
| [`docs/PLAYBOOKS.md`](docs/PLAYBOOKS.md) | SOAR playbook engine and shipped pack |
| [`docs/DASHBOARD.md`](docs/DASHBOARD.md) | Frontend architecture |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Local dev quickstart |
| [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) | Every phase's acceptance criteria |
| [`docs/TECHNICAL_RISKS.md`](docs/TECHNICAL_RISKS.md) | Known technical risks and their mitigations |

## Tech stack

- **Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.x, Alembic, asyncio, httpx
- **Datastores:** PostgreSQL (system-of-record, row-level security), OpenSearch (events/search/analytics), Redis Streams (EventBus — swappable for Kafka via the same abstraction)
- **Frontend:** React, TypeScript, TailwindCSS
- **Infra:** Docker Compose (single-node) and Kubernetes (`kubernetes/` — HA PostgreSQL/Redis/OpenSearch, NetworkPolicies, HPAs)
- **Observability:** Prometheus, Grafana, OpenTelemetry
- **Normalization:** OCSF (Open Cybersecurity Schema Framework) 1.1.0

## Getting started

Local development: [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
Production deployment: [`docs/KUBERNETES.md`](docs/KUBERNETES.md).
