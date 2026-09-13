# Dashboard

The React frontend (spec §23): 14 screens against real backend APIs — no
mocked data anywhere, including the screens whose backend doesn't exist yet.

## Authentication

The access token lives in memory only (`src/services/tokenStore.ts`) —
never `localStorage`, which an XSS payload can read just as easily as the
app can. The refresh token is the httpOnly, `SameSite=Strict` cookie the
backend already set in Phase 2 (`app/api/auth.py`); the browser holds it,
no frontend code ever touches it directly. On page load, and on any 401,
`src/services/apiClient.ts` makes exactly one silent `POST /auth/refresh`
(cookie-authenticated) and retries the original request once. Concurrent
401s share one in-flight refresh rather than each racing to rotate the
cookie.

This is also why the backend needed a **CORS policy** it never had before
(`app/main.py`, `CORS_ALLOWED_ORIGINS`): a credentialed cross-origin
request needs an explicit allowed origin — a wildcard is both rejected by
browsers for credentialed requests and a wider hole than this API needs.

## RBAC-driven UI hiding is cosmetic, not the gate

`src/components/RequirePermission.tsx` and the sidebar nav
(`src/components/AppShell.tsx`) hide screens and actions the caller's role
can't use, reading the same `resource:action` permission strings
`GET /users/me` returns (mirroring
`app.auth.dependencies.AuthenticatedUser.has_permission` so both sides ask
the question the same way). This is a UX convenience only (spec §19):
every mutation and every list endpoint is independently re-checked
server-side by `require_permission()`, so a user who forges a request past
a hidden button gets the same 403 the backend would always have given
them. One screen makes the split concrete: **Event Explorer** has no API
of its own — it browses events through the same `POST /hunting/search`
Threat Hunting uses — so it's gated on `hunt:execute`, not `event:read`;
`READ_ONLY` holds the latter but not the former, and would see a broken
screen under the more "obvious" gate.

## Backend additions this phase needed

Three small backend surfaces existed only partially or not at all before
the frontend needed them for real (not mocked) data — all reviewed and
tested to the same standard as the rest of the API, not a frontend-only
shortcut:

- **CORS** (`app/main.py`, `app/core/config.py`) — see above.
- **`GET /audit`** (`app/api/audit.py`) — every phase since Phase 2 has
  *written* to `audit_logs`; nothing before this exposed it for reading.
  Read-only by construction (no write route is defined, and the table
  itself is append-only at the database level via a trigger).
- **User administration** (`app/api/users.py`, `app/services/users.py`) —
  `GET /users` and `GET /users/me` already existed; `POST /users`,
  `PATCH /users/{id}`, and `GET /users/roles` (the fixed role catalog) are
  new, permission-gated on `user:write` (read on the roles list), and
  audit-logged (`CREATE_USER`, `UPDATE_USER`) like every other admin
  action in this codebase. A user holds exactly one role in this UI's
  model — the underlying table supports many, but nothing here assigns
  more than one, and a single-role picker keeps "who can do what" legible.

## Screens with no real backend yet: told straight, not faked

Two screens in spec §23's list have no functionality to show:

- **Playbooks** — the SOAR engine (spec §18, Phase 15) does not exist.
  The screen says so in plain language rather than rendering an invented
  playbook list or a fake run history.
- **Reports** — there is no reporting subsystem, and none is scoped for
  this phase. Rather than build one or fake one, this screen composes the
  same read APIs every other screen uses (alert/incident counts, MITRE
  coverage, asset/IOC breakdowns) into one printable summary — genuinely
  live data, just laid out differently, with a "Print / Export" button.

## SOC Overview's derived metrics

`GET /alerts/counts` and `GET /incidents/counts` are exact. MTTA, MTTR,
false-positive rate, and the "top hosts/users/IPs" lists have no dedicated
backend aggregation endpoint, so they're computed client-side
(`src/pages/SocOverviewPage.tsx`) from the same `GET /alerts` list every
other screen calls, capped at that endpoint's 500-row maximum. This is
real data, not a placeholder — exact for a small SOC's alert volume, a
documented sample (labelled "in the fetched window") for a very large one.
A future phase can replace the client-side reduction with a real backend
aggregation without changing what the screen promises.

## Testing

- **Component tests** (`vitest` + `@testing-library/react`): pure
  rendering and logic — badges, the coverage bar's proportional math, the
  `can()` permission check, RBAC-driven nav hiding (mocking `useAuth`),
  and a regression test for a real bug caught during development (see
  below).
- **E2E tests** (`playwright`, `e2e/*.spec.ts`): one real-backend test per
  screen. Each registers its own tenant via the real
  `POST /auth/register-organization` (never a fixture or a mock), logs in
  through the actual login form, and drives the golden path — creating an
  incident and walking it through its workflow, adding then deleting an
  indicator, disabling a shipped detection rule, creating and deactivating
  a user, confirming a real write shows up in the audit log. They require
  the backend and frontend dev servers already running against a
  disposable database (`scripts/dev-services.sh` +
  `docs/DEVELOPMENT.md`) — Playwright does not start either for you.
- **Manual walkthrough**: every screen was driven in a real browser via
  Playwright against the two live dev servers, screenshotted, and visually
  reviewed before sign-off (this session's UI-testing rule) — not just
  asserted programmatically.

One real bug came out of that manual pass: the pivot dropdown on Threat
Hunting rendered "IP → to → events" instead of "IP → events", because the
label formatter blanket-replaced every underscore with an arrow — which
also turned the literal word "to" in `ip_to_events` into one. Fixed in
`pivotLabel()` (`src/pages/ThreatHuntingPage.tsx`) to treat only the
`_to_` separator as the arrow, with a regression test covering every real
pivot name.
