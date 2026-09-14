"""A tiny internal-only HTTP server for `/health`, `/ready` and `/metrics`,
shared by every worker process (spec §28/Phase 16: "these three endpoints on
every service").

Workers are bare asyncio loops, not a web framework, so this is a
hand-rolled HTTP/1.1 responder rather than a second copy of FastAPI per
process — it understands exactly three GET requests and nothing else, and
holds no state that survives past one connection.

It is deliberately never bound to a port docker-compose publishes to the
host (`Settings.metrics_port`): only Prometheus, reachable over the same
internal `app` network, ever calls this. `/metrics` in particular is
operational detail (event/alert/detection volume) a caller outside the
deployment has no business seeing — this phase's own review criterion.
"""

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable

from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest

logger = logging.getLogger(__name__)

ReadyCheck = Callable[[], Awaitable[bool]]


async def postgres_ready() -> bool:
    """Reusable readiness probe for any worker that reads/writes PostgreSQL.
    A separate short-lived session, never the worker's own — readiness must
    not depend on a session another part of the process might be holding
    open or have left in a bad state."""
    from sqlalchemy import text

    from app.core.db import async_session_factory

    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001  unreachable is "not ready", not a crash
        logger.exception("postgres readiness check failed")
        return False


async def redis_ready() -> bool:
    from app.core.redis import get_redis

    try:
        await get_redis().ping()
        return True
    except Exception:  # noqa: BLE001
        logger.exception("redis readiness check failed")
        return False


async def opensearch_ready() -> bool:
    from app.core.opensearch import get_opensearch

    try:
        return bool(await get_opensearch().ping())
    except Exception:  # noqa: BLE001
        logger.exception("opensearch readiness check failed")
        return False


def combine(*checks: ReadyCheck) -> ReadyCheck:
    """ANDs several readiness checks into one, running them concurrently so
    one slow dependency does not serialize behind another."""

    async def _combined() -> bool:
        results = await asyncio.gather(*(check() for check in checks), return_exceptions=True)
        return all(result is True for result in results)

    return _combined

_IO_TIMEOUT_SECONDS = 5.0


async def _always_ready() -> bool:
    return True


def _response(status: int, reason: str, content_type: str, body: bytes) -> bytes:
    headers = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    )
    return headers.encode("latin-1") + body


async def _handle(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ready_check: ReadyCheck
) -> None:
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=_IO_TIMEOUT_SECONDS)
        # Headers are drained and discarded — nothing here is read by path
        # or method beyond the request line, and no request carries a body.
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=_IO_TIMEOUT_SECONDS)
            if line in (b"\r\n", b""):
                break

        parts = request_line.decode("latin-1", errors="replace").split()
        path = parts[1] if len(parts) >= 2 else ""

        if path == "/health":
            # Liveness: this loop is scheduling coroutines at all. No
            # dependency checks — a slow downstream must not make an
            # orchestrator kill an otherwise-healthy process.
            writer.write(_response(200, "OK", "application/json", b'{"status":"ok"}'))
        elif path == "/ready":
            try:
                ok = await ready_check()
            except Exception:  # noqa: BLE001  an unready dependency is a 503, not a crash
                logger.exception("readiness check raised")
                ok = False
            body = b'{"status":"ready"}' if ok else b'{"status":"not_ready"}'
            reason = "OK" if ok else "Service Unavailable"
            writer.write(_response(200 if ok else 503, reason, "application/json", body))
        elif path == "/metrics":
            writer.write(_response(200, "OK", CONTENT_TYPE_LATEST, generate_latest(REGISTRY)))
        else:
            writer.write(_response(404, "Not Found", "text/plain", b"not found"))
        await writer.drain()
    except (TimeoutError, ConnectionError):
        pass  # a slow or dropped client is not this server's problem
    except Exception:  # noqa: BLE001  one bad request must never take the server down
        logger.exception("observability server request failed")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def start_observability_server(
    port: int, *, ready_check: ReadyCheck = _always_ready
) -> asyncio.base_events.Server:
    """Starts the `/health` `/ready` `/metrics` server and returns it
    already listening. Callers close it (`server.close()` then
    `await server.wait_closed()`) as part of their own shutdown sequence,
    the same as every other resource a worker owns."""
    server = await asyncio.start_server(
        lambda r, w: _handle(r, w, ready_check),
        "0.0.0.0",  # noqa: S104  # nosec B104 - internal-only by compose network placement
        port,
    )
    logger.info("observability server listening", extra={"port": port})
    return server
