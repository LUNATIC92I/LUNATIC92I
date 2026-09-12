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
pytest -v             # unit tests
bandit -r app -c pyproject.toml   # static security scan
pip-audit             # dependency vulnerability scan
```

Alembic migrations (once models exist, from Phase 2 onward):

```bash
alembic revision --autogenerate -m "describe the change"
alembic upgrade head
```

## Frontend development (outside Docker)

```bash
cd frontend
npm ci
npm run dev          # http://localhost:5173, proxies to VITE_API_BASE_URL
npm run lint
npm run typecheck
npm run build
```

## What's here vs. what's not (Phase 1)

This is repository + infrastructure scaffolding only, per
`docs/DEVELOPMENT_PLAN.md` (Phase 1). There is no authentication, no event
ingestion, no detection logic, and no real dashboard yet — the frontend
shows a placeholder page that checks backend connectivity, nothing more.
See `docs/DEVELOPMENT_PLAN.md` for what each subsequent phase adds and its
acceptance criteria.
