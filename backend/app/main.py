from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.alerts import router as alerts_router
from app.api.assets import router as assets_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.hunting import router as hunting_router
from app.api.incidents import router as incidents_router
from app.api.ingestion import router as ingestion_router
from app.api.mitre import router as mitre_router
from app.api.organizations import router as organizations_router
from app.api.playbooks import router as playbooks_router
from app.api.rules import router as rules_router
from app.api.threat_intel import router as threat_intel_router
from app.api.users import router as users_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.metrics import api_requests_total
from app.core.observability import (
    combine,
    opensearch_ready,
    postgres_ready,
    redis_ready,
    start_observability_server,
)
from app.core.tracing import configure_tracing


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    configure_tracing()
    # `/metrics` deliberately never joins the public route table below: it
    # is operational detail (event/alert/detection volume) a caller outside
    # the deployment has no business seeing (Phase 16's own review
    # criterion), so it lives only on this internal-only port, which
    # docker-compose never publishes to the host — see
    # `Settings.metrics_port` and `app/core/observability.py`.
    obs = await start_observability_server(
        get_settings().metrics_port,
        ready_check=combine(postgres_ready, redis_ready, opensearch_ready),
    )
    try:
        yield
    finally:
        obs.close()
        await obs.wait_closed()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="LUNATIC-IT SIEM API",
        version="0.1.0",
        description="Detect. Investigate. Respond.",
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
    )

    allowed_origins = [
        origin.strip() for origin in settings.cors_allowed_origins.split(",") if origin.strip()
    ]
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(users_router)
    app.include_router(organizations_router)
    app.include_router(ingestion_router)
    app.include_router(rules_router)
    app.include_router(assets_router)
    app.include_router(threat_intel_router)
    app.include_router(mitre_router)
    app.include_router(alerts_router)
    app.include_router(incidents_router)
    app.include_router(hunting_router)
    app.include_router(audit_router)
    app.include_router(playbooks_router)

    @app.middleware("http")
    async def track_requests(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        api_requests_total.labels(
            method=request.method, path=request.url.path, status=response.status_code
        ).inc()
        return response

    return app


app = create_app()
