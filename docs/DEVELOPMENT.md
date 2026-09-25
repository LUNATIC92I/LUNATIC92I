# Development quickstart

## Prerequisites

- Docker + Docker Compose v2
- Python 3.12+ (for running backend tooling outside containers)
- Node.js 20+ (for running frontend tooling outside containers)

## Run the full stack

```bash
cp .env.example .env   # then edit secrets/passwords for anything beyond a throwaway local run
docker compose up -d --build
```

Services and their host ports:

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API (docs at `/docs`) | http://localhost:8000 |
| Backend health / readiness | http://localhost:8000/health, /ready |
| Backend metrics | http://localhost:8000/metrics |
| OpenSearch | https://localhost:9200 (user `admin`, password = `OPENSEARCH_INITIAL_ADMIN_PASSWORD`) |
| OpenSearch Dashboards | http://localhost:5601 |
| Prometheus | http://localhost:9090 |
| Grafana | http://localhost:3000 (user/password from `.env`) |

Check everything is healthy:

```bash
docker compose ps
```

Tear down (add `-v` to also drop the named volumes / all data):

```bash
docker compose down
```

### Windows

Everything above is Linux-first (bash scripts, RLS-heavy Postgres, `/app/...`
paths inside containers), so run it through **Docker Desktop with the WSL2
backend** rather than native `cmd.exe`/PowerShell tooling:

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
   and enable the WSL2 engine (default on a recent install); install a WSL2
   distribution (`wsl --install`) if you don't have one.
2. Clone the repo **inside the WSL2 filesystem** (e.g. `~/LUNATIC92I`, not
   `/mnt/c/...`) — bind-mount performance and line-ending/permission
   surprises are both meaningfully worse across the Windows/Linux boundary.
3. From a WSL2 shell: the exact commands above (`cp .env.example .env`,
   `docker compose up -d --build`) work unchanged.

For a one-click launch from Windows itself (no WSL2 shell needed), double-click
**`Demarrer-LUNATIC-SIEM.bat`** at the repository root. It is the Windows
equivalent of the two commands above, and handles Docker Desktop itself —
the one real external dependency the stack has — rather than assuming it's
already there:

- **Docker not installed at all**: downloads the official Docker Desktop
  installer and launches it (its own UI, not a silent `/quiet` install —
  the EULA and any reboot/WSL2 prompt are things you approve yourself, not
  something this script hides), then continues automatically once you're
  done with it.
- **Docker installed but not running**: launches Docker Desktop and waits
  up to 2 minutes for its engine to answer before giving up with a clear
  message.
- Once Docker is ready: creates `.env` from `.env.example` on first run
  (generating a real Fernet key for `MFA_ENCRYPTION_KEY` — the one default
  that is a placeholder string rather than something directly usable — and
  leaving every other value as shipped, which is fine for a throwaway local
  run per that file's own comments), runs `docker compose up -d --build`,
  waits for `/health`, and opens the frontend in your default browser. It
  never overwrites an existing `.env`.

On its first successful run it also drops a **`LUNATIC-IT SIEM` shortcut on
the Windows Desktop** pointing back at that same launcher (idempotent — it
checks the shortcut doesn't already exist first, and a deleted shortcut is
simply recreated next run), so every run after the first is a plain
double-click on a Desktop icon with no folder to open at all. Stop the
stack with **`scripts\windows\stop.bat`** (`stop.bat -RemoveData` to also
drop the named volumes, mirroring `docker compose down -v`).

## Backend development (outside Docker)

```bash
cd backend
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

ruff check .          # lint
mypy .                # type check
bandit -r app -c pyproject.toml   # static security scan
pip-audit             # dependency vulnerability scan
```

### Running the test suite

The suite runs against real PostgreSQL and real Redis — RLS policies and
Redis Streams consumer-group semantics are the things most worth testing,
and neither survives being mocked. `scripts/dev-services.sh` starts both
and creates the dedicated test database (never point the suite at your dev
database: `_clean_tables` truncates between every test):

```bash
./scripts/dev-services.sh

cd backend
DATABASE_URL=postgresql+asyncpg://lunatic:<password>@localhost:5432/lunatic_siem_test \
MFA_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
MAX_FAILED_LOGIN_ATTEMPTS=3 \
pytest -v
```

`conftest.py` applies every Alembic migration against that database once
per test session and tears the schema down afterward, so no manual
migration step is needed.

### Alembic migrations

```bash
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
```

Every tenant-scoped table's migration must enable **and force** RLS with a
tenant-isolation policy (see the pattern in
`alembic/versions/3ed3c3c2dcfb_identity_rbac_multi_tenancy.py`) — this is
not optional per-table decoration, it's the second half of the tenant
isolation guarantee described in `THREAT_MODEL.md` §3.2.

## Frontend development (outside Docker)

```bash
cd frontend
npm ci
npm run dev          # http://localhost:5173, proxies to VITE_API_BASE_URL
npm run lint
npm run typecheck
npm run build
npm run test         # vitest: component/unit tests, no servers required

# E2E (Playwright): needs the backend AND `npm run dev` already running
# against a disposable database (see scripts/dev-services.sh) — it hits
# the real API, not a mock, and does not start either server for you.
npm run e2e
```

## Trying the auth API (Phase 2)

```bash
curl -sX POST localhost:8000/auth/register-organization -H 'content-type: application/json' -d '{
  "organization_name": "Acme", "organization_slug": "acme",
  "admin_email": "admin@acme.example.com", "admin_password": "Correct-Horse-Battery-Staple-1",
  "admin_full_name": "Admin Admin"
}'

curl -sX POST localhost:8000/auth/login -c cookies.txt -H 'content-type: application/json' -d '{
  "organization_slug": "acme", "email": "admin@acme.example.com",
  "password": "Correct-Horse-Battery-Staple-1"
}'
# -> {"access_token": "...", "token_type": "bearer", "expires_in": 900, ...}
# refresh_token is set as an httpOnly cookie, not returned in the body.

curl -s localhost:8000/users/me -H "Authorization: Bearer <access_token>"
curl -sX POST localhost:8000/auth/refresh -b cookies.txt -c cookies.txt
```

## Trying event ingestion (Phase 3)

Mint a collector key (needs `api_key:write`), then push a raw event:

```bash
curl -sX POST localhost:8000/api-keys -H "Authorization: Bearer <access_token>" \
  -H 'content-type: application/json' -d '{"name":"edge-forwarder"}'
# -> {"id": "...", "name": "edge-forwarder", "api_key": "lsk_<tenant>_<secret>"}
#    The key is shown exactly once; only its hash is stored.

curl -sX POST localhost:8000/ingest/events -H "X-API-Key: lsk_..." \
  --data-binary '<34>Oct 11 22:14:15 host sshd: Failed password for root'
# -> {"outcome": "accepted", "message_id": "1739...-0", "reason": null}
```

Re-sending the identical body returns `{"outcome": "duplicate"}` (retry
safety), an oversized body returns 202 with `dead_lettered` (preserved on
`events.raw.deadletter`, never discarded), and exceeding the tenant quota
returns 429.

The syslog listeners run as a separate worker, off by default because they
require explicit tenant + allowlist configuration:

```bash
# set SYSLOG_TENANT_ID and SYSLOG_ALLOWED_SOURCE_CIDRS in .env first
docker compose --profile syslog up -d syslog-collector
logger -n localhost -P 5514 -d "test message"
```

## Parsing and normalization (Phase 4)

The `parser` worker consumes `events.raw`, detects the format, extracts
fields, maps them to OCSF 1.1.0, and publishes to `events.normalized`.
Supported formats: JSON, syslog (RFC 3164 and 5424), CEF, LEEF, Windows
Event XML, Apache/Nginx access logs, and generic `key=value`.

```bash
docker compose up -d parser
docker compose up -d --scale parser=3 parser   # scales via one consumer group
```

Detection order matters and is deliberate: a Fortinet event arrives as CEF
inside a syslog envelope and is also full of `key=value` pairs, so the CEF
parser must claim it first or the vendor/signature/severity fields a
detection rule needs are never extracted. See `app/parsers/registry.py`.

Anything no parser can handle is dead-lettered with the reason attached and
the original bytes intact — it is never stored as an unparsed blob, which
would be a silent detection gap.

## The event store (Phase 5)

The `indexer` worker consumes `events.normalized`, enriches, and bulk-writes
to OpenSearch. It also applies the index templates and lifecycle policies at
startup, so a fresh cluster is correct before the first write rather than
inheriting a guessed dynamic mapping.

```bash
docker compose up -d indexer
curl -sk -u "admin:$OPENSEARCH_PASSWORD" \
  "https://localhost:9200/events-normalized-write/_search?pretty" \
  -H 'content-type: application/json' -d '{"query":{"match_all":{}}}'
```

Two things worth knowing when working on this:

- **The mapping is declared, not inferred** (`dynamic: false`). A field the
  normalizer emits but the mapping never declared is stored yet
  unsearchable — `test_normalization.py` fails the build if that ever
  happens, and `test_opensearch.py` asserts code and cluster agree.
- **Tenant isolation is enforced by OpenSearch**, not only by query
  builders. A single `lunatic_tenant_reader` role carries a DLS query
  substituting each user's `tenant_id` attribute, so an analyst's
  credentials cannot see another tenant's events even with an unfiltered
  `match_all` — the mirror of PostgreSQL RLS on the relational side.

Running the OpenSearch tests locally needs a real cluster with the security
plugin enabled; `scripts/dev-services.sh` starts one if `OPENSEARCH_HOME`
points at an install (default `/opt/os`), and skips it otherwise.

## Detection (Phase 6)

The `detection` worker consumes `events.normalized`, evaluates each tenant's
rules, and publishes matches to `detections.created`. It runs both execution
shapes in one process: the streaming evaluator per event, and a scheduled
pass that runs windowed (threshold) rules as OpenSearch aggregations.

```bash
docker compose up -d detection
```

Rules come from PostgreSQL and are re-read every
`DETECTION_RULE_REFRESH_SECONDS`, so enabling or disabling one takes effect
without a restart. The YAML in `rules/` is the default pack, installed into
each tenant at registration:

```bash
curl -s localhost:8000/rules -H "Authorization: Bearer <access_token>"

# try a candidate rule against one event — stores nothing
curl -sX POST localhost:8000/rules/test -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{
    "definition_yaml": "rule_id: TEST-001\nname: t\ndescription: d\nseverity: low\nconfidence: 10\nrisk_score: 10\nauthor: me\nconditions:\n  field: user.name\n  operator: equals\n  value: mallory\nfalse_positive_notes: n\ninvestigation_steps: s\n",
    "event": {"user": {"name": "mallory"}}
  }'

# take a noisy rule out of production (audit-logged, versioned)
curl -sX POST localhost:8000/rules/WIN-006/status -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"status": "testing"}'
```

Three things worth knowing when working on this:

- **A rule is data, never code.** `yaml.safe_load` only, no expression
  language, and regex matching is bounded by a per-match timeout rather than
  by hope. See [`DETECTION_ENGINE.md`](../DETECTION_ENGINE.md).
- **Both paths must mean the same thing.** A condition evaluated in Python
  and the same condition compiled to an OpenSearch query have to select the
  same events; `matches` is rejected in windowed rules precisely because it
  cannot make that guarantee.
- **Every rule change is versioned and audited** in the same transaction,
  and the history table refuses UPDATE and DELETE at the database level.

Running the detection tests needs the same real services as Phase 5 —
`scripts/dev-services.sh` starts PostgreSQL, Redis and OpenSearch; the
windowed rule tests index synthetic events and run real aggregations.

## Correlation (Phase 7)

The `correlation` worker consumes `events.normalized` **and**
`detections.created`, chains them per entity, and publishes completed chains
to `correlations.created` with a timeline attached.

```bash
docker compose up -d correlation
```

Correlation rules are the YAML in `rules/correlation/`. They are loaded at
worker start (unlike detection rules, they have no database lifecycle yet).

Everything stateful lives in Redis, keyed by (tenant, rule, entity) with a
TTL equal to the rule's window, so restarting or rescheduling the worker
does not lose an in-flight chain:

```bash
redis-cli --scan --pattern 'correlation:*' | head
redis-cli ttl 'correlation:<tenant>:CORR-001:v1:user.name=...'
```

Two behaviours to keep in mind while working on this:

- **Event time, not arrival time**, decides ordering and windows — and a
  source timestamp too far from its ingestion time is not believed at all
  (`CORRELATION_MAX_CLOCK_SKEW_SECONDS`). Timelines record which clock each
  step was judged on.
- **Completion is re-checked on every input**, so a chain can complete when
  its *first* stage finally arrives. There is no timer closing windows.

## Risk scoring and the asset inventory (Phase 8)

Detections and correlations are scored as they are produced, so the document
on `detections.created` / `correlations.created` already carries
`risk_score`, `risk_bucket` and `risk_explanation`. Nothing separate needs
to run. The formula, its weights and its versioning rules are in
[`docs/RISK_SCORING.md`](RISK_SCORING.md).

Asset criticality is one of the score's inputs, so the inventory behind it
is a security-relevant surface:

```bash
curl -sX POST localhost:8000/assets -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' \
  -d '{"asset_type":"server","hostname":"dc01","ip_address":"10.1.1.10","criticality":"CRITICAL"}'

curl -s localhost:8000/assets -H "Authorization: Bearer <token>"
```

Changing a criticality writes a `CHANGE_ASSET_CRITICALITY` audit entry with
the before and after values — its own action, so downgrades are searchable
without diffing every asset edit.

If you change a weight in `app/risk/model.py`, the build fails until
`FORMULA_VERSION` moves with it and the golden file is regenerated:

```bash
cd backend && .venv/bin/python -m pytest app/tests/test_risk.py -q
```

That is deliberate. Scores computed under different weights are not
comparable, and a stored `risk_explanation` is the only way to understand an
old alert's number.

## Threat intelligence (Phase 9)

Indicators live in PostgreSQL and are matched inside enrichment, so a
detection on a known-bad address scores higher than the same detection on an
unknown one with no extra wiring. Reference:
[`docs/THREAT_INTELLIGENCE.md`](THREAT_INTELLIGENCE.md).

```bash
# add an indicator (value canonicalized, type inferred, source required)
curl -sX POST localhost:8000/iocs -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' \
  -d '{"value":"1.2.3[.]4","classification":"malicious","confidence":90,"source":"incident-response"}'

# triage lookup: paste straight from a report, noise lines are ignored
curl -sX POST localhost:8000/iocs/match -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"values":["1.2.3[.]4","hxxp://evil[.]com/a"]}'
```

Feeds are configured as rows in `ioc_feeds` and synced by the `feeds`
worker. For local work the file-drop connector needs no network at all:

```bash
echo "203.0.113.4" > intel-drop/blocklist.txt
docker compose up -d feeds
```

Two things to know before touching this area:

- **`EGRESS_ALLOWED_HOSTS` is empty by default and the guard fails closed**,
  so an HTTP feed will be refused until its host is named. That is
  deliberate: the alternative is a SIEM that fetches whatever a config row
  tells it to.
- **Feed credentials never go in the database.** `credential_ref` names an
  environment variable; the value is read at sync time.

## MITRE ATT&CK coverage (Phase 10)

The catalog is imported rather than shipped. For a normal install the
default source is the official bundle over HTTPS — which means the egress
allow-list has to permit it:

```bash
# .env
EGRESS_ALLOWED_HOSTS=raw.githubusercontent.com

curl -sX POST localhost:8000/mitre/import -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{}'
curl -s "localhost:8000/mitre/coverage?days=30" -H "Authorization: Bearer <token>"
```

Offline (or in tests), drop the bundle in `intel-drop/` and import it by
filename. The `feeds` worker re-imports once the catalog passes
`MITRE_CATALOG_MAX_AGE_DAYS`.

Detections are indexed into `detections-*` by the indexer worker, which now
runs two consumers — events and detections — in one process. That is what
makes the per-technique counts real; without it the coverage page could only
say what rules *claim* to cover.

## Alerts (Phase 11)

The `alerting` worker turns detections and correlations into the queue an
analyst works:

```bash
docker compose up -d alerting

curl -s "localhost:8000/alerts?status=NEW" -H "Authorization: Bearer <token>"
curl -sX POST localhost:8000/alerts/<id>/status -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"status":"IN_PROGRESS"}'
curl -s localhost:8000/alerts/<id>/evidence -H "Authorization: Bearer <token>"
```

Three behaviours worth knowing before changing anything here:

- **The state machine is data** (`TRANSITIONS` in `app/services/alerts.py`).
  Add a status there or nowhere; the API returns 409 for anything the
  machine refuses.
- **Closing needs `alert:close`, triaging needs `alert:write`.** That is the
  L1/L2 split, and it is checked against the *target* status, so it cannot
  be bypassed by choosing a different endpoint.
- **Repeats fold into the open alert** within `ALERT_DEDUP_WINDOW_MINUTES`.
  If you are testing alert creation and only see one alert, check
  `occurrence_count` before assuming something was dropped.

## Incident management (Phase 12)

Cases are analyst-driven — there is no worker for this phase, unlike every
pipeline stage before it. Promoting alerts into a case, moving it through
the workflow, and linking evidence are all things a human decides to do:

```bash
# open a case, promoting alerts already in hand
curl -sX POST localhost:8000/incidents -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' \
  -d '{"title":"Suspected account takeover","severity":"critical","alert_ids":["<alert-id>"]}'

curl -sX POST localhost:8000/incidents/<id>/status -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"status":"TRIAGE"}'

curl -s localhost:8000/incidents/<id>/timeline -H "Authorization: Bearer <token>"
curl -s localhost:8000/incidents/<id>/evidence -H "Authorization: Bearer <token>"
```

Two things worth knowing before touching this area:

- **The workflow is data** (`TRANSITIONS` in `app/services/incidents.py`),
  same pattern as alerts. A 409 means the machine refused the move, not a
  bug.
- **Evidence is never stored on the incident.** `GET .../evidence` resolves
  the union of every event id cited by every *linked alert*, live, each
  time it is called — link a new alert and its evidence is part of the
  case with nothing to copy or keep in sync.

If you are adding a new kind of mutation to incidents, route it through
`app/services/incidents.py` and make sure it calls `record_timeline()` —
that is the one thing every existing test in `test_incidents.py` checks for,
and the acceptance criterion ("every state change produces a timeline
entry") depends on nothing bypassing it.

## What's here vs. what's not (Phase 12)

Phases 0–12 are done: architecture, repo/infra scaffolding,
authentication/RBAC/multi-tenancy, ingestion, parsing/OCSF normalization,
the OpenSearch event store with enrichment, the detection engine,
correlation, risk scoring, threat intelligence, ATT&CK coverage, alerts,
and incident management. The pipeline runs end to end — a syslog line or
REST payload becomes an enriched, searchable, tenant-isolated document; a
rule match becomes a detection; a sequence of those becomes a correlation;
either becomes an alert; and an analyst can promote one or more alerts into
a worked incident with its own lifecycle, tasks, and timeline.

Nothing yet lets an analyst *search* the event store directly — hunting
(Phase 13) is the free-text/filtered query API and pivot set. Notifications
are still not implemented; `alerts.created` remains the hook they will
attach to. The frontend still shows only the Phase 1 placeholder page; SOC
screens are Phase 14. See `docs/DEVELOPMENT_PLAN.md` for each phase's
acceptance criteria.
