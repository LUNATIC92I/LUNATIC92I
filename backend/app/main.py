from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest

from app.api.alerts import router as alerts_router
from app.api.assets import router as assets_router
from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.hunting import router as hunting_router
from app.api.incidents import router as incidents_router
from app.api.ingestion import router as ingestion_router
from app.api.mitre import router as mitre_router
from app.api.organizations import router as organizations_router
from app.api.rules import router as rules_router
from app.api.threat_intel import router as threat_intel_router
from app.api.users import router as users_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.metrics import api_requests_total


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    yield


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

    @app.middleware("http")
    async def track_requests(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        api_requests_total.labels(
            method=request.method, path=request.url.path, status=response.status_code
        ).inc()
        return response

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
