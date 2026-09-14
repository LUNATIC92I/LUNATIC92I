from httpx import AsyncClient


async def test_health_returns_ok(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_ready_returns_ready_when_every_dependency_is_reachable(client: AsyncClient) -> None:
    response = await client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


async def test_ready_is_503_when_a_dependency_is_unreachable(
    client: AsyncClient, monkeypatch
) -> None:
    import app.api.health as health_module

    async def unreachable() -> bool:
        return False

    monkeypatch.setitem(health_module._CHECKS, "redis_unreachable", unreachable)
    response = await client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "not_ready"
    assert "redis_unreachable" in body["reasons"]


async def test_metrics_is_not_exposed_on_the_public_app(client: AsyncClient) -> None:
    """`/metrics` moved to the internal-only observability port (Phase 16):
    a caller reaching the API on its normal, publicly-published port must
    never see it — operational volume (event/alert/detection counts) is not
    something the public API surface hands out. `app/tests/
    test_observability.py` proves the internal server does serve it."""
    response = await client.get("/metrics")
    assert response.status_code == 404
