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

## What's here vs. what's not (Phase 6)

Phases 0–6 are done: architecture, repo/infra scaffolding,
authentication/RBAC/multi-tenancy, ingestion, parsing/OCSF normalization,
the OpenSearch event store with enrichment, and the detection engine. The
pipeline runs end to end — a syslog line or REST payload becomes an
enriched, searchable, tenant-isolated document, and a rule match becomes a
detection on `detections.created`.

Nothing yet consumes those detections: correlating them into multi-stage
scenarios is Phase 7, risk scoring Phase 8, and turning them into alerts an
analyst works is Phase 11. The frontend still shows only the Phase 1
placeholder page; SOC screens are Phase 14. See
`docs/DEVELOPMENT_PLAN.md` for each phase's acceptance criteria.
