# Cross-cutting test suites

End-to-end, load, and security test suites that span multiple services and
therefore don't belong under `backend/app/tests/` (which covers backend
unit/integration tests). This is where the following land:

- **E2E tests** (Phase 14+) — real browser flows against the running stack.
- **Load tests** (Phase 18) — the k6/Locust harness and its benchmark reports,
  per spec §24's "never claim a load without a benchmark" rule.
- **Security test suite** (Phase 17) — the automated SQLi/XSS/SSRF/IDOR/
  tenant-isolation/JWT-manipulation/etc. suite from spec §30.

Empty at Phase 1 — populated as each of those phases lands.
