# LUNATIC-IT SIEM — Development Plan & Acceptance Criteria (Phase 0)

Work proceeds strictly phase by phase (spec §42/43). A phase is not "done"
because its UI exists — it is done when: implemented, unit + integration
tested, tests passing, security-reviewed, acceptance criteria met, and
documented. Each phase's closeout report states: files created/modified,
features completed, tests run and their pass/fail counts, vulnerabilities
found, technical debt incurred, and next steps.

## Phase overview

| Phase | Name | Primary owner discipline(s) |
|---|---|---|
| 0 | Architecture + threat model | Principal Cybersecurity Architect |
| 1 | Repository + infrastructure | DevSecOps / Cloud Engineer |
| 2 | Authentication + RBAC + multi-tenancy | Backend Engineer / Security Engineer |
| 3 | Event ingestion | Backend Engineer / SIEM Engineer |
| 4 | Normalization (OCSF) | SIEM Engineer / Backend Engineer |
| 5 | OpenSearch integration | Database Engineer / SIEM Engineer |
| 6 | Detection Engine | Detection Engineer |
| 7 | Correlation Engine | Detection Engineer / SIEM Engineer |
| 8 | Risk Engine | Detection Engineer / Backend Engineer |
| 9 | Threat Intelligence | Threat Hunter / Backend Engineer |
| 10 | MITRE ATT&CK | Detection Engineer |
| 11 | Alerts | Backend Engineer |
| 12 | Incident Management | DFIR Engineer / Backend Engineer |
| 13 | Threat Hunting | Threat Hunter / Frontend Engineer |
| 14 | Dashboard | Frontend Engineer |
| 15 | SOAR | Security Engineer / Backend Engineer |
| 16 | Observability | SRE/Observability Engineer |
| 17 | Security hardening | Security Engineer / DevSecOps |
| 18 | Performance testing | SRE / QA Engineer |
| 19 | HA / Kubernetes | Cloud/Infrastructure Engineer |
| 20 | Production readiness | Full team |

---

## Acceptance criteria by phase

### Phase 0 — Architecture + threat model (this document set)
- [x] Spec analyzed, inconsistencies documented (`ARCHITECTURE.md` §1).
- [x] Final architecture, component diagram, data flow documented.
- [x] Threat model (STRIDE + abuse cases) documented.
- [x] PostgreSQL schema drafted.
- [x] OpenSearch index templates drafted.
- [x] Service interfaces (EventBus, rule contract, REST, enrichment, playbook action) defined.
- [x] Final repository layout defined.
- [x] Technical risk register produced.
- [x] Development plan with per-phase acceptance criteria produced (this section).
- [ ] **Explicit user validation received** before Phase 1 starts.

### Phase 1 — Repository + infrastructure
- Repository scaffolding matches `ARCHITECTURE.md` §8 exactly (empty modules with `__init__.py`, no business logic yet).
- `docker-compose.yml` brings up postgres, redis, opensearch, opensearch-dashboards, backend, frontend, prometheus, grafana with healthchecks and restart policies; `docker compose up` succeeds from a clean clone.
- Alembic initialized against an empty PostgreSQL schema (no tables yet beyond Alembic's own).
- CI skeleton (GitHub Actions): lint (Ruff) + type-check (MyPy) + `pytest` (even if the only test is a smoke test) all green on a trivial PR.
- `.env.example` present; `.env` git-ignored; secret-scanning step present in CI.
- **Tests:** `docker compose up` smoke test; CI pipeline green on a no-op change.
- **Security review:** no secrets committed; base images pinned by digest or exact tag, not `latest`.

### Phase 2 — Authentication + RBAC + multi-tenancy
- `organizations`, `users`, `roles`, `permissions`, `role_permissions`, `user_roles`, `sessions`, `api_keys` tables created via Alembic migration matching `postgresql_schema.sql` §1.
- Login/refresh/logout endpoints; Argon2id password hashing; JWT access + rotating refresh tokens; MFA enrollment/verification endpoint.
- `require_permission()` / `require_tenant_scope()` FastAPI dependencies enforced on every protected route; a route with no explicit permission check fails CI (custom lint/test rule).
- PostgreSQL RLS enabled and policy-tested on every tenant-scoped table created so far.
- **Tests:** unit tests for password hashing/JWT; RBAC test matrix (10 roles × representative endpoints); **cross-tenant IDOR tests** (user A cannot read/write org B's data) — this suite is mandatory and blocking per spec §20.
- **Security review:** JWT algorithm confusion test, brute-force/lockout test, session fixation test.

### Phase 3 — Event ingestion
- Ingestion Gateway endpoint(s) + at least 2 collectors implemented end-to-end (e.g., `SyslogCollector` UDP/TCP and a `RESTCollector`), behind the common `Collector` interface.
- `EventBus` abstraction implemented with `RedisStreamsEventBus`; `events.raw` topic populated; dead-letter path (`events.deadletter`) implemented and observable.
- Idempotency key computed and deduplication verified.
- Per-tenant rate limiting enforced at the gateway.
- **Tests:** ingestion throughput smoke test (documented number, not a claim of production capacity); duplicate-send dedup test; malformed/oversized payload → DLQ test, never a crash; collector interface unit tests.
- **Security review:** ingestion auth (API key/mTLS) cannot be bypassed; UDP source allow-listing verified.

### Phase 4 — Normalization
- Parser engine supports JSON, Syslog, CEF, LEEF, Windows Event XML, Apache, Nginx, generic auth/firewall log formats behind the common parser interface.
- OCSF 1.1.0 mapping implemented for the formats above; `raw_event` always retained; `schema_version` stamped.
- Parse failures always land in `events.deadletter` with a recorded cause; `parser_errors` metric increments.
- **Tests:** one positive fixture-based test per supported format; a malformed-input test per format proving DLQ routing (never a silent drop or crash); OCSF field-mapping snapshot tests.
- **Security review:** parser inputs are never passed to `eval`/dynamic execution; XML parsing uses an XXE-safe parser configuration.

### Phase 5 — OpenSearch integration
- Index templates from `opensearch_indices.md` applied (raw, normalized, deadletter) with ILM policies.
- Enrichment pipeline writes enriched, normalized events into `events-normalized-*`.
- OpenSearch Security DLS tenant policy configured and verified as a second isolation layer on top of app-level filtering.
- **Tests:** indexing round-trip test (ingest → parse → normalize → queryable in OpenSearch within an SLA); DLS cross-tenant query test (a Tenant-A-scoped role cannot retrieve Tenant B documents even via a crafted query).
- **Security review:** OpenSearch cluster not exposed outside the app-tier network; default demo certs/credentials rotated.

### Phase 6 — Detection Engine
- YAML rule DSL parser + validator; streaming and windowed execution paths both implemented (ARCHITECTURE.md §1 row 4).
- Rule versioning, enable/disable, dry-run, exceptions, suppression implemented.
- At least the **Authentication** and **Windows** rule families from spec §8 implemented and enabled by default (brute force, password spraying, suspicious PowerShell, encoded PowerShell, credential dumping indicators, etc.).
- **Tests:** per spec §29, each shipped rule has positive, negative, exact-threshold, out-of-window, different-user, different-IP test cases (the `BRUTE_FORCE_001` example pattern) — no rule ships without this set.
- **Security review:** a disabled/modified rule is audit-logged (THREAT_MODEL.md §3.4); rule YAML cannot achieve code execution (no `yaml.load` without `SafeLoader`, no template injection).

### Phase 7 — Correlation Engine
- Correlation rule DSL (required events, order, window, entities, score, MITRE) implemented; automatic timeline construction.
- Correlation state persisted in Redis with TTL matching rule windows (survives worker restart — Technical Risk #4).
- **Tests:** multi-stage attack scenario test (failed login → success → privilege escalation → large download → incident) reproduces the spec's example; worker-restart recovery test; out-of-order event arrival test.
- **Security review:** correlation cannot be evaded by timestamp manipulation alone (ingestion_timestamp backstop verified).

### Phase 8 — Risk Engine
- Versioned, explainable weighted-sum formula implemented (severity, confidence, asset criticality, user risk, threat intel, MITRE context, behavioral anomaly), normalized 0–100, bucketed LOW/MEDIUM/HIGH/CRITICAL.
- Every alert stores a `risk_explanation` breakdown reconstructable in the UI (spec §10 "l'analyste doit pouvoir voir pourquoi").
- **Tests:** unit tests per factor's contribution and cap; golden-file tests for known input → known score + explanation; boundary tests at 24/25, 49/50, 74/75.
- **Security review:** risk inputs that come from user-editable data (asset criticality, tags) are permission-gated and audit-logged (Technical Risk table row on manipulation).

### Phase 9 — Threat Intelligence
- IOC CRUD (all 10 types from spec §11), confidence/source/tags/expiration/history tracked; at least one pluggable feed connector implemented (interface + one real or documented-stub implementation).
- IOC matching wired into the enrichment pipeline.
- **Tests:** CRUD + expiration lifecycle tests; "a feed-sourced IOC is never auto-classified malicious without confidence/source recorded" test (spec §11 hard rule).
- **Security review:** feed connector outbound calls go through the egress allow-list (SSRF mitigation, THREAT_MODEL.md §3.8).

### Phase 10 — MITRE ATT&CK
- Tactics/techniques/sub-techniques import/update mechanism (not hardcoded) implemented; `rule_mitre_map` populated for Phase 6 rules.
- MITRE ATT&CK Coverage page data API (techniques covered/not covered, detections per technique, coverage rate, recent detections).
- **Tests:** import idempotency test (re-running an import doesn't duplicate/corrupt data); coverage calculation unit tests.
- **Security review:** import source data is validated/sanitized before storage (no blind trust of third-party content feeds).

### Phase 11 — Alerts
- Full alert lifecycle (`NEW → IN_PROGRESS → ESCALATED → FALSE_POSITIVE/RESOLVED → CLOSED`), dedup/suppression via `dedup_key`, evidence linkage to OpenSearch `event_ids`.
- **Tests:** state machine transition tests (valid/invalid transitions); dedup window tests; evidence lineage integrity test (alert always resolves back to real OpenSearch documents).
- **Security review:** alert status changes are audit-logged and permission-gated by analyst tier (L1/L2/L3 differences enforced, not just labeled).

### Phase 12 — Incident Management
- Full incident workflow (`NEW → TRIAGE → INVESTIGATION → CONTAINMENT → ERADICATION → RECOVERY → CLOSED`) with `display_id` generation (`INC-YYYY-NNNNNN`), notes, tasks, timeline, evidence, asset/user/IOC linkage.
- **Tests:** workflow transition tests; per-tenant sequential `display_id` uniqueness test under concurrency; timeline completeness test (every state change produces a timeline entry).
- **Security review:** cross-tenant incident access blocked (extends Phase 2's IDOR suite to incidents).

### Phase 13 — Threat Hunting
- Free-text + filtered search API over `events-normalized-*` (IP/user/hostname/process/hash/domain/event type/severity/MITRE technique); saved queries/hunts; export; the pivot set from spec §15 (IP→Events, IP→Users, User→Hosts, Host→Processes, Hash→Events, Domain→Events, User→Timeline).
- **Tests:** query builder unit tests per filter type; pivot correctness tests against fixture data; export format tests (CSV/JSON).
- **Security review:** hunting queries are DLS/tenant-scoped like all other OpenSearch access; export endpoints rate-limited and audit-logged (`EXPORT_DATA`).

### Phase 14 — Dashboard
- All 14 screens from spec §23 implemented against real APIs (no mocked data): SOC Overview, Alerts, Incidents, Event Explorer, Threat Hunting, MITRE ATT&CK, Threat Intelligence, Assets, Users, Detection Rules, Playbooks, Reports, Audit, Administration.
- SOC Overview metrics (events/sec, alerts, critical alerts, open incidents, risk score, top techniques/IPs/users/assets, detection performance, MTTA, MTTR, false-positive rate) computed from real data, not placeholders.
- **Tests:** frontend component tests; at least one E2E test per screen hitting the real backend in a test environment; manual browser walkthrough of the golden path (per this session's UI-testing rule) before sign-off.
- **Security review:** RBAC-driven UI hiding is confirmed to be cosmetic only — direct API calls are independently re-checked server-side (spec §19).

### Phase 15 — SOAR
- Playbook engine executing the action set from spec §18; destructive actions (`disable_user`, `isolate_host`) implemented **only** behind the approval state machine with dry-run and audit log (ARCHITECTURE.md §7.5).
- **Tests:** end-to-end playbook run test (brute force → enrich → IOC check → reputation → incident → notify); approval state machine tests including the "requester ≠ approver" dual-control constraint; dry-run-vs-execute divergence test.
- **Security review:** it is architecturally impossible to reach `execute()` on a destructive action without an `APPROVED` record — verified by a dedicated negative test, not just code review.

### Phase 16 — Observability
- `/health`, `/ready`, `/metrics` on every service; the full metric set from spec §28 exported; Prometheus scrape config + Grafana dashboards checked in; OpenTelemetry tracing across the ingestion→detection→alert path.
- **Tests:** metrics-present tests (scrape endpoint returns expected metric names); trace propagation test across at least one full pipeline hop.
- **Security review:** metrics/health endpoints do not leak sensitive data and are not exposed outside the internal network without auth.

### Phase 17 — Security hardening
- OWASP ASVS/API Security checklist applied and tracked; secure headers, strict CORS, secure cookies, TLS everywhere, rate limiting, CSRF protection where cookies are used, token rotation, session expiration all verified present (not just designed).
- **Tests:** the full automated security suite from spec §30 (SQLi, command injection, XSS, SSRF, path traversal, IDOR, privilege escalation, broken auth/authz, tenant isolation, rate-limit bypass, JWT manipulation, replay) implemented and wired to fail CI on a critical finding.
- **Security review:** this phase's own review is the automated suite's first real run; findings triaged to zero criticals before sign-off.

### Phase 18 — Performance testing
- Load test harness (e.g., k6/Locust) exercising ingestion throughput, processing latency, detection latency, query latency, alert generation latency, and API latency.
- A checked-in benchmark report is the **only** artifact allowed to state a supported events/minute figure (spec §24's "never claim without a benchmark").
- **Tests:** the load tests themselves, run in CI or a scheduled pipeline, with results archived.
- **Security review:** load testing does not use production credentials/data; synthetic data only.

### Phase 19 — HA / Kubernetes
- Kubernetes manifests (or Helm chart) for all services; PostgreSQL replication, Redis HA, OpenSearch cluster, load balancer, health checks, graceful shutdown, retry/circuit-breaker policies documented and configured.
- **Tests:** chaos/failure-injection test (kill one backend pod, one OpenSearch node, one Redis node — system degrades gracefully, no data loss for in-flight events per the DLQ guarantees from Phase 3).
- **Security review:** Kubernetes network policies restrict data-tier access to the app tier only (THREAT_MODEL.md §1).

### Phase 20 — Production readiness
- Every criterion in spec §44 checked explicitly: tests/security tests/RBAC tests/multi-tenant tests pass; load tests documented; no known-critical issue ignored; secrets externalized; structured logs; system observable; backups documented; incident-recovery runbook documented; DB migrations reproducible; Docker images scanned (Trivy); documentation set from spec §33 complete.
- **Tests:** full regression suite green; a documented, rehearsed backup-restore drill.
- **Security review:** final sign-off checklist against `SECURITY.md`, with any accepted residual risk explicitly listed (mirroring `THREAT_MODEL.md` §5).

---

## Working agreement per phase (spec §43, restated as a checklist)

For every phase: analyze → define files → implement → write tests → run
tests → fix failures → security review → verify acceptance criteria →
document → **only then** move to the next phase. Each phase's closeout
report lists: files created, files modified, features completed, tests run,
tests passed/failed, vulnerabilities found, technical debt incurred, and
next steps — matching the reporting format required by the spec.
