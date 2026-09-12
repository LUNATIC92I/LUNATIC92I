from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, Counter, generate_latest

from app.api.health import router as health_router
from app.core.config import get_settings
from app.core.logging import configure_logging

http_requests_total = Counter(
    "api_requests_total", "Total API requests", ["method", "path", "status"]
)


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

    @app.middleware("http")
    async def track_requests(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        http_requests_total.labels(
            method=request.method, path=request.url.path, status=response.status_code
        ).inc()
        return response

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
