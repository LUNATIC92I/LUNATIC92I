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

The test suite exercises real PostgreSQL (RLS policies are meaningless
against SQLite or a mock), so you need a running Postgres and a dedicated
test database — never point this at your dev database, `_clean_tables`
truncates it between every test:

```bash
createdb -O lunatic lunatic_siem_test        # once
psql lunatic_siem_test -c "CREATE EXTENSION IF NOT EXISTS pgcrypto"

DATABASE_URL=postgresql+asyncpg://lunatic:<password>@localhost:5432/lunatic_siem_test \
MFA_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") \
MAX_FAILED_LOGIN_ATTEMPTS=3 \
pytest -v
```

`conftest.py` applies every Alembic migration against that database once
per test session and tears the schema down afterward, so no manual
migration step is needed beyond having the empty database and the
`pgcrypto` extension ready.

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

## What's here vs. what's not (Phase 2)

Phases 0–2: architecture, repo/infra scaffolding, and authentication/RBAC/
multi-tenancy are done. There is still no event ingestion, no detection
logic, no incidents/alerts, and no real dashboard — the frontend still
shows only the Phase 1 placeholder page (a login UI is a Phase 14
deliverable, not Phase 2's). See `docs/DEVELOPMENT_PLAN.md` for what each
subsequent phase adds and its acceptance criteria.
