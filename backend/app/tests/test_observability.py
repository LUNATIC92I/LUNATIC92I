"""The shared `/health` `/ready` `/metrics` server every worker process
runs (Phase 16, spec §28). Exercised as a real socket client rather than
through any framework test harness, since the server itself is a hand-rolled
HTTP/1.1 responder with no framework underneath it.
"""

import asyncio

import pytest

from app.core.observability import start_observability_server


async def _get(port: int, path: str) -> tuple[int, bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: test\r\n\r\n".encode())
    await writer.drain()
    raw = await asyncio.wait_for(reader.read(), timeout=5)
    writer.close()
    await writer.wait_closed()
    status_line, _, rest = raw.partition(b"\r\n")
    status = int(status_line.split(b" ")[1])
    _headers, _, body = rest.partition(b"\r\n\r\n")
    return status, body


@pytest.fixture
async def free_port() -> int:
    sock_server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = sock_server.sockets[0].getsockname()[1]
    sock_server.close()
    await sock_server.wait_closed()
    return port


async def test_health_is_always_ok(free_port: int) -> None:
    server = await start_observability_server(free_port)
    try:
        status, body = await _get(free_port, "/health")
        assert status == 200
        assert body == b'{"status":"ok"}'
    finally:
        server.close()
        await server.wait_closed()


async def test_ready_reflects_the_check_result(free_port: int) -> None:
    async def not_ready() -> bool:
        return False

    server = await start_observability_server(free_port, ready_check=not_ready)
    try:
        status, body = await _get(free_port, "/ready")
        assert status == 503
        assert body == b'{"status":"not_ready"}'
    finally:
        server.close()
        await server.wait_closed()


async def test_ready_defaults_to_true_when_no_check_is_given(free_port: int) -> None:
    server = await start_observability_server(free_port)
    try:
        status, body = await _get(free_port, "/ready")
        assert status == 200
        assert body == b'{"status":"ready"}'
    finally:
        server.close()
        await server.wait_closed()


async def test_a_raising_ready_check_is_a_503_not_a_crash(free_port: int) -> None:
    async def boom() -> bool:
        raise RuntimeError("redis is down")

    server = await start_observability_server(free_port, ready_check=boom)
    try:
        status, _body = await _get(free_port, "/ready")
        assert status == 503
        # The server itself must still answer the next request.
        status2, _ = await _get(free_port, "/health")
        assert status2 == 200
    finally:
        server.close()
        await server.wait_closed()


async def test_metrics_returns_prometheus_text_format(free_port: int) -> None:
    from app.core.metrics import api_requests_total

    api_requests_total.labels(method="GET", path="/x", status=200).inc()

    server = await start_observability_server(free_port)
    try:
        status, body = await _get(free_port, "/metrics")
        assert status == 200
        assert b"api_requests_total" in body
    finally:
        server.close()
        await server.wait_closed()


async def test_an_unknown_path_is_a_404(free_port: int) -> None:
    server = await start_observability_server(free_port)
    try:
        status, _ = await _get(free_port, "/nope")
        assert status == 404
    finally:
        server.close()
        await server.wait_closed()
