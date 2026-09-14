import asyncio
import logging

from fastapi import APIRouter, Response, status

from app.core.observability import opensearch_ready, postgres_ready, redis_ready

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

_CHECKS = {
    "database_unreachable": postgres_ready,
    "redis_unreachable": redis_ready,
    "opensearch_unreachable": opensearch_ready,
}


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe: process is up and serving. No dependency checks —
    a slow downstream must not make Kubernetes kill a healthy process."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(response: Response) -> dict[str, str]:
    """Readiness probe: the API's three real dependencies, checked
    concurrently. Any one being unreachable makes the API unable to serve
    most of its routes, so all three gate readiness rather than just the
    database that happened to be wired up first."""
    reasons = list(_CHECKS)
    results = await asyncio.gather(*(check() for check in _CHECKS.values()))
    failures = [reason for reason, ok in zip(reasons, results, strict=True) if not ok]
    if failures:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "reason": failures[0], "reasons": ",".join(failures)}
    return {"status": "ready"}
