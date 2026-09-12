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

## What's here vs. what's not (Phase 4)

Phases 0–4: architecture, repo/infra scaffolding, authentication/RBAC/
multi-tenancy, event ingestion, and parsing/OCSF normalization are done.

Normalized events currently land on `events.normalized` and stop there —
nothing indexes them yet. OpenSearch indexing and enrichment are Phase 5,
detection is Phase 6. The frontend still shows only the Phase 1 placeholder
page; SOC screens are Phase 14. See `docs/DEVELOPMENT_PLAN.md` for each
phase's acceptance criteria.
