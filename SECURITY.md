# Security Policy

## Reporting a vulnerability

If you find a security vulnerability in this project, please report it
privately rather than through a public GitHub issue — open a private
security advisory on this repository, or contact the maintainers
directly. Include what you found, how to reproduce it, and its likely
impact; a proof of concept against synthetic/local data is welcome, a
demonstration against any real deployment you don't own is not.

Please do not:

- Test against a deployment you do not own or have explicit authorization
  to test.
- Access, modify, or exfiltrate data beyond what is strictly necessary to
  demonstrate the issue.
- Publicly disclose before a fix is available, absent a mutually agreed
  timeline.

We aim to acknowledge a report within 5 business days and to have a fix
or a mitigation plan within 30 days for a confirmed critical or high
finding.

## Final sign-off checklist (Phase 20)

Every criterion below is checked against real evidence in this
repository, not asserted — each row links to the thing that actually
proves it.

| Criterion | Status | Evidence |
|---|---|---|
| Tests pass | ✅ | 851/851 backend tests, `backend/app/tests/` |
| Security tests pass | ✅ | `app/tests/test_security_suite.py` (spec §30: SQLi, command injection, XSS, SSRF, path traversal, IDOR, privilege escalation, broken auth/authz, tenant isolation, rate-limit bypass, JWT manipulation, replay) — also its own dedicated CI job, `.github/workflows/ci.yml`'s `backend-security-suite` |
| RBAC tests pass | ✅ | `app/tests/test_auth_rbac.py` and the RBAC matrix embedded across every resource's own test file |
| Multi-tenant tests pass | ✅ | Cross-tenant IDOR + PostgreSQL RLS suites, every phase from Phase 2 onward (`app/tests/test_*` — `test_rls`, `cross_tenant`, `idor` patterns throughout) |
| Load tests documented | ✅ | `docs/PERFORMANCE_BENCHMARK.md` — the one place a supported events/minute figure may be stated, with the test environment's limits disclosed explicitly |
| No known-critical issue ignored | ✅ | See "Residual risks" below — every open item is Low/Medium, explicitly scoped, with a stated path to closing it; nothing Critical or High is open |
| Secrets externalized | ✅ | `.env.example` (dev), `kubernetes/base/secret.yaml` (k8s — documented as a dev-only template, production pointed at External Secrets/Sealed Secrets/a cloud secret manager); no secret has a non-empty default in `app/core/config.py` |
| Structured logs | ✅ | `app/core/logging.py` — JSON everywhere, no plain-text log lines |
| System observable | ✅ | `docs/OBSERVABILITY.md` — `/health`, `/ready`, `/metrics` on every service, OpenTelemetry tracing end-to-end, Prometheus + Grafana |
| Backups documented | ✅ | `docs/BACKUP_RESTORE.md` — a rehearsed procedure, including a real finding (`FORCE ROW LEVEL SECURITY` blocks a naive `pg_dump`) and its fix (`scripts/bootstrap_backup_role.sql`) |
| Incident-recovery runbook documented | ✅ | `docs/RUNBOOK.md` — platform-failure recovery, distinct from `docs/INCIDENT_RESPONSE.md`'s analyst-facing security-incident workflow |
| DB migrations reproducible | ✅ | `alembic upgrade head` from an empty database verified directly during the Phase 20 backup drill (12 migrations, clean run); also exercised on every CI run |
| Docker images scanned (Trivy) | ✅ | `.github/workflows/ci.yml`'s `docker-build-and-scan` job (`aquasecurity/trivy-action`, fails on CRITICAL/HIGH) — also run locally during this phase against the actual built images, see `docs/DEVELOPMENT_PLAN.md` Phase 20 validation notes |
| Documentation set complete | ✅ | See the full index in `README.md` |

## Residual risks accepted (mirrors `THREAT_MODEL.md` §5)

These are known, scoped, and deliberately not blocking — each has an
owner-visible path to closing it rather than being silently carried
forever.

- **Syslog UDP remains inherently spoofable**; accepted for legacy log
  source compatibility under network-level controls (the collector's own
  source-CIDR allow-list), not eliminated at the protocol layer.
  (`THREAT_MODEL.md` §5, unchanged since Phase 0.)
- **Redis Streams has weaker multi-datacenter durability guarantees than
  a dedicated log** (Kafka); the `EventBus` abstraction
  (`app/core/eventbus.py`) exists specifically so this can be swapped
  later without touching any caller. Accepted through Phase 19; revisit
  if multi-region deployment becomes a requirement.
- **No hardware security module (HSM) for JWT signing keys.** Keys are
  managed via whatever secret store the deployment uses, with rotation
  supported (`docs/RUNBOOK.md`'s secret-rotation section) but no
  HSM-backed signing. A future hardening item for regulated deployments,
  not a gap in the current threat model's own risk acceptance.
- **Redis Sentinel failover is not yet transparent to the application.**
  `RedisStreamsEventBus` holds a static connection; a Sentinel-promoted
  master requires a manual worker restart today
  (`docs/RUNBOOK.md`'s Redis Sentinel section,
  `kubernetes/data-tier/values-redis-ha.yaml`'s own detailed note). Two
  concrete fixes are already identified (a failover-aware proxy, or a
  `Sentinel`-aware client) — tracked, not silently assumed solved by
  "Redis HA" being present in `kubernetes/data-tier/`.
- **CSP is tuned for an API, not the frontend SPA**, and there is no
  dedicated WAF/bot-detection layer beyond the application's own
  fixed-window rate limits — both already stated in
  `docs/SECURITY_CHECKLIST.md`'s own "Known gaps" section and repeated
  here for one consolidated view.

Nothing in this list is Critical or High severity by this project's own
`docs/SECURITY_CHECKLIST.md` taxonomy; each remaining item is an
intentional, documented trade-off (syslog UDP, Redis Streams durability,
HSM), or a concretely scoped follow-up with an identified fix (Sentinel
awareness). Two findings this list previously carried have since been
fixed: consumer naming
(`app/core/eventbus.py::consumer_identity()` — see `docs/KUBERNETES.md`'s
"Horizontal scaling correctness" section) and the OpenSearch snapshot
repository (`scripts/bootstrap_opensearch_snapshots.sh`, rehearsed
end-to-end — see `docs/BACKUP_RESTORE.md`'s OpenSearch section).
