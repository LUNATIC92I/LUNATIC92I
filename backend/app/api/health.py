import logging

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.core.db import async_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe: process is up and serving. No dependency checks —
    a slow downstream must not make Kubernetes kill a healthy process."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(response: Response) -> dict[str, str]:
    """Readiness probe: checks the app can actually reach PostgreSQL.
    Redis/OpenSearch checks are added as those clients are wired up in
    later phases."""
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        logger.exception("Readiness check failed: database unreachable")
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "reason": "database_unreachable"}
    return {"status": "ready"}
