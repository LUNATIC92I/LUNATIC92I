# Security Hardening Checklist (Phase 17)

Tracked, not just designed: every row names the file that implements the
control and the test file that proves it holds, so "done" means verified
in this repository, not asserted in this document. Mapped against OWASP
ASVS 4.x and the OWASP API Security Top 10 (2023) — the two checklists
spec §30 draws from.

Status legend: ✅ implemented and tested · 🆕 added this phase.

## Authentication (ASVS V2, API2:2023 Broken Authentication)

| Control | Status | Implementation | Test |
|---|---|---|---|
| Passwords hashed with Argon2id, never reversible | ✅ | `app/core/security.py` (`hash_password`/`verify_password`) | `app/tests/test_security.py` |
| MFA (TOTP) available and enforceable per account | ✅ | `app/services/auth.py::enroll_mfa/confirm_mfa`; secret encrypted at rest with Fernet | `app/tests/test_auth_rbac.py` |
| Account lockout after repeated failed attempts | ✅ | `app/services/auth.py::authenticate` (`MAX_FAILED_LOGIN_ATTEMPTS`/`LOCKOUT_DURATION_MINUTES`) | `app/tests/test_security.py` |
| Per-IP rate limit on auth endpoints (login/register/refresh), independent of account lockout | 🆕 | `app/api/auth.py::_enforce_ip_rate_limit` | `app/tests/test_auth_rate_limit.py` |
| Org/account enumeration not possible from error responses | ✅ | `app/services/auth.py::authenticate` — one `InvalidCredentialsError` for bad org, bad email, or bad password alike | `app/tests/test_security.py` |
| JWT signing algorithm pinned server-side (no `alg:none` / algorithm-confusion) | ✅ | `app/core/security.py` — `jwt.decode(..., algorithms=["HS256"])`, never taken from the token itself | `app/tests/test_security.py` |
| Access tokens are short-lived and bearer-only (never in a cookie a browser auto-sends) | ✅ | `app/core/config.py::jwt_access_token_ttl_seconds` (default 900s); frontend keeps it in memory only (`docs/DASHBOARD.md`) | `app/tests/test_security.py` |

## Session Management (ASVS V3, API2:2023)

| Control | Status | Implementation | Test |
|---|---|---|---|
| Refresh token rotates on every use; reuse of an already-rotated token is rejected | ✅ | `app/services/auth.py::rotate_refresh_token` | `app/tests/test_auth_rbac.py` |
| Sessions expire server-side, not just client-side | ✅ | `SessionModel.expires_at` checked on every rotation | `app/tests/test_auth_rbac.py` |
| Refresh cookie: `HttpOnly`, `Secure` in production, `SameSite=Strict`, path-scoped to `/auth` | ✅ | `app/api/auth.py::_set_refresh_cookie` | `app/tests/test_auth_rbac.py` |
| Logout revokes the session server-side (not just clears the cookie) | ✅ | `app/services/auth.py::revoke_session` | `app/tests/test_auth_rbac.py` |
| CSRF: cross-site requests cannot carry the refresh cookie | ✅ | `SameSite=Strict` above — a CSRF token scheme would be redundant with this and was deliberately not added | `app/tests/test_auth_rbac.py` |

## Access Control (ASVS V4, API1/API3/API5:2023)

| Control | Status | Implementation | Test |
|---|---|---|---|
| Every mutating/reading route enforces RBAC server-side | ✅ | `app/auth/dependencies.py::require_permission`, applied on every router | RBAC matrix tests per phase (`test_*_api.py` across Phases 2–15) |
| RBAC-driven UI hiding is cosmetic only, never the real boundary | ✅ | spec §19; server independently re-checks every call | `app/tests/test_auth_rbac.py`, Phase 14 E2E specs |
| Tenant isolation enforced at the database layer, not just in application code | ✅ | Postgres RLS policies (`app/*/migrations`, `USING (tenant_id = current_setting('app.current_tenant_id'))`) | `test_one_tenants_*_are_invisible_to_another` in every phase's API test file |
| Cross-tenant object references (IDOR) rejected, not just filtered from lists | ✅ | every service's `get_*`/`update_*` scopes its `WHERE` on `tenant_id` and raises `NotFound` rather than `Forbidden` (indistinguishable from a missing object) | IDOR suites in `test_incidents.py`, `test_alerts_api.py`, `test_hunting_api.py`, `test_playbooks_api.py`, etc. |
| Dual control on destructive SOAR actions (requester ≠ approver) | ✅ | `app/services/playbooks.py`, DB `CHECK` constraint as defense in depth | `app/tests/test_playbooks.py` |
| Destructive action execution unreachable without a real approval record | ✅ | `app/playbooks/actions.py::DestructiveAction._verify_grant` | `test_calling_execute_directly_*` in `app/tests/test_playbooks.py` |

## Input Validation & Injection (ASVS V5, API8:2019 Injection)

| Control | Status | Implementation | Test |
|---|---|---|---|
| SQL: parameterized queries only, no string-built SQL from request data | ✅ | SQLAlchemy ORM/Core throughout; the few raw `text()` calls carry no request-supplied values | `app/tests/test_security_suite.py::TestSQLInjection` |
| Command injection: no shell/subprocess execution anywhere in the request path | ✅ | grep-verified: no `subprocess`/`os.system`/`os.popen` in `app/` | `app/tests/test_security_suite.py::TestCommandInjection` |
| XSS: API returns only `application/json`; no HTML templating of request data | ✅ | every response model is a Pydantic schema serialized as JSON | `app/tests/test_security_suite.py::TestXss` |
| Path traversal: file-drop reads confined to their configured root | ✅ | `app/threat_intel/feeds/base.py::_read_drop_file` — resolves and prefix-checks against `THREAT_INTEL_DROP_DIR` | `app/tests/test_security_suite.py::TestPathTraversal`, `app/tests/test_feeds.py` |
| XXE: hostile XML (Windows Event Log) parsed with `defusedxml`, never stdlib `ElementTree` | ✅ | `app/parsers/windows_xml.py` | `app/tests/test_parsers.py` |
| ReDoS: detection-rule regex conditions run under a hard per-match timeout | ✅ | `app/detection/conditions.py` (the `regex` package's timeout parameter) | `app/tests/test_detection_dsl.py` |
| SSRF: all outbound HTTP is egress-guarded (allowlist, private-IP refusal) | ✅ | `app/core/egress.py` (THREAT_MODEL.md §3.8) | `app/tests/test_egress.py`, `app/tests/test_security_suite.py::TestSsrf` |
| Playbooks/detection/correlation rules are data (a fixed action/operator registry), never `eval` | ✅ | `app/playbooks/schema.py`, `app/detection/schema.py` | loader tests per phase |

## Rate Limiting & Resource Consumption (API4:2023)

| Control | Status | Implementation | Test |
|---|---|---|---|
| Ingestion rate-limited per tenant | ✅ | `app/services/ingestion.py` | `app/tests/test_ingestion.py` |
| Hunt export rate-limited per tenant, capped rows, audit-logged | ✅ | `app/services/hunting.py` | `app/tests/test_hunting_api.py` |
| Auth endpoints rate-limited per IP | 🆕 | `app/api/auth.py` | `app/tests/test_auth_rate_limit.py` |
| Request payload size capped | ✅ | `app/core/config.py::ingest_max_payload_bytes` | `app/tests/test_ingestion.py` |

## Communications Security (ASVS V9)

| Control | Status | Implementation | Test |
|---|---|---|---|
| TLS terminates at the ingress/reverse proxy in front of the API (not in-process) | ✅ (deployment) | `docker-compose.yml` production overlay expects a TLS-terminating proxy; `HSTS` below tells a browser to insist on it | manual/deployment verification, out of unit-test scope |
| HSTS sent on every response | 🆕 | `app/core/security_headers.py` | `app/tests/test_security_headers.py` |
| OpenSearch connections verify TLS certificates outside development | ✅ | `app/core/opensearch.py::verify_certs=settings.opensearch_verify_certs` | `app/tests/test_opensearch.py` |
| Outbound feed fetches refuse plaintext HTTP by default | ✅ | `app/core/config.py::egress_allow_http` (default `false`) | `app/tests/test_egress.py` |

## Security Misconfiguration & Headers (ASVS V14, API7:2023)

| Control | Status | Implementation | Test |
|---|---|---|---|
| `X-Content-Type-Options: nosniff` | 🆕 | `app/core/security_headers.py` | `app/tests/test_security_headers.py` |
| `X-Frame-Options: DENY` | 🆕 | ″ | ″ |
| `Content-Security-Policy: default-src 'none'` | 🆕 | ″ | ″ |
| `Referrer-Policy: no-referrer` | 🆕 | ″ | ″ |
| `Permissions-Policy` denies geolocation/camera/microphone | 🆕 | ″ | ″ |
| CORS: explicit origin allowlist, never a wildcard with credentials | ✅ | `app/main.py`, `CORS_ALLOWED_ORIGINS` | `app/tests/test_cors.py` |
| API docs (`/docs`, `/redoc`) disabled in production | ✅ | `app/main.py::create_app` | code review (`settings.is_production`) |
| `/metrics` not reachable on the public port | 🆕 | `app/core/observability.py` (Phase 16) | `app/tests/test_health.py`, `app/tests/test_observability.py` |
| Secrets never logged or committed; `.env` gitignored, `.env.example` carries no real secret | ✅ | `.gitignore`, `.env.example` | `secret-scan` CI job (gitleaks) |

## Data Protection (ASVS V8)

| Control | Status | Implementation | Test |
|---|---|---|---|
| MFA secrets encrypted at rest (envelope encryption, Fernet) | ✅ | `app/core/security.py::encrypt_mfa_secret/decrypt_mfa_secret` | `app/tests/test_security.py` |
| Refresh tokens stored hashed, never in plaintext | ✅ | `app/services/auth.py::hash_refresh_token` | `app/tests/test_auth_rbac.py` |
| Every mutating action writes an immutable audit trail entry | ✅ | `app/audit/service.py`; `audit_logs`/`incident_timeline`/`incident_notes` are append-only at the database level | `test_incident_history_cannot_be_rewritten`, `app/tests/test_audit_api.py` |
| Tenant data never crosses tenants in bulk export | ✅ | `app/services/hunting.py::export_hunt` scopes on `tenant_id` | `app/tests/test_hunting_api.py` |

## Replay & Idempotency

| Control | Status | Implementation | Test |
|---|---|---|---|
| Ingestion dedupes retried payloads on an idempotency key | ✅ | `app/services/ingestion.py::_claim_idempotency_key` | `app/tests/test_ingestion.py` |
| A used/rotated refresh token cannot be replayed | ✅ | `rotate_refresh_token` — old session marked `revoked_at`; a stale token is rejected | `app/tests/test_security_suite.py::TestReplay` |
| A tampered/expired access token is rejected, not silently degraded | ✅ | `app/auth/dependencies.py::get_auth_context` | `app/tests/test_security_suite.py::TestJwtManipulation` |

## Automated Security Test Suite (spec §30)

`app/tests/test_security_suite.py` is the dedicated, category-organized
suite spec §30 asks for. Several of its categories re-prove protections
already covered elsewhere in this table under a name matching the spec's
own taxonomy, so a reviewer can find "the SQLi tests" without knowing
which phase originally built the underlying control:

| Category | Test class |
|---|---|
| SQL injection | `TestSQLInjection` |
| Command injection | `TestCommandInjection` |
| XSS | `TestXss` |
| SSRF | `TestSsrf` |
| Path traversal | `TestPathTraversal` |
| IDOR | `TestIdor` |
| Privilege escalation | `TestPrivilegeEscalation` |
| Broken auth/authz | `TestBrokenAuth` |
| Tenant isolation | `TestTenantIsolation` |
| Rate-limit bypass | `TestRateLimitBypass` |
| JWT manipulation | `TestJwtManipulation` |
| Replay | `TestReplay` |

CI runs this file twice on every push and pull request: once as part of
`backend-tests`' full suite, and again on its own in the dedicated
`backend-security-suite` job (`.github/workflows/ci.yml`) so the pipeline
names it explicitly rather than leaving it implicit in "the tests passed."
Either way, a finding here fails the build the same as any other test
failure — there is no separate "advisory" mode, and `docker-build-and-scan`
will not run until both jobs are green.

## Known gaps / accepted risk

- **CSP is maximally strict, not tuned for an HTML frontend.** This is
  correct for the API (it never serves HTML), but the separate frontend
  service should set its own CSP appropriate to a React SPA — out of this
  backend repository's scope.
- **TLS termination is a deployment concern**, not something the
  application process does itself; `HSTS` assumes the operator has put a
  TLS-terminating proxy in front of it, per `docker-compose.yml`'s
  production guidance.
- **No dedicated WAF/bot-detection layer.** The per-IP rate limits here are
  a coarse, fixed-window control (spec §18 already accepts the same
  trade-off for ingestion/export); a determinded distributed attacker
  rotating source IPs is out of scope for an application-layer control.
