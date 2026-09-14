"""Per-IP rate limiting on the auth endpoints (Phase 17, OWASP ASVS
V2.2.1) — a second, independent control on top of per-account lockout
(`app/tests/test_security.py` covers lockout itself). Limits are
monkeypatched low here so each test stays fast and deterministic; the
mechanism is the same fixed-window Redis counter the ingestion and
hunt-export rate limiters already use.
"""

from httpx import AsyncClient

from app.core.config import get_settings


async def test_login_beyond_the_per_ip_quota_is_rate_limited(
    client: AsyncClient, monkeypatch
) -> None:
    monkeypatch.setenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", "2")
    get_settings.cache_clear()

    body = {"organization_slug": "nope", "email": "a@example.com", "password": "x"}
    first = await client.post("/auth/login", json=body)
    second = await client.post("/auth/login", json=body)
    third = await client.post("/auth/login", json=body)

    # The first two are ordinary auth failures (no such org) — the quota is
    # about request volume, not about whether credentials were right.
    assert first.status_code == 401
    assert second.status_code == 401
    assert third.status_code == 429

    get_settings.cache_clear()


async def test_register_organization_beyond_the_per_ip_quota_is_rate_limited(
    client: AsyncClient, monkeypatch
) -> None:
    monkeypatch.setenv("AUTH_REGISTER_RATE_LIMIT_PER_HOUR", "2")
    get_settings.cache_clear()

    def _payload(slug: str) -> dict:
        return {
            "organization_name": f"Org {slug}",
            "organization_slug": slug,
            "admin_email": f"{slug}@example.com",
            "admin_password": "Correct-Horse-Battery-Staple-1",
            "admin_full_name": "Admin Admin",
        }

    first = await client.post("/auth/register-organization", json=_payload("ratelimit1"))
    second = await client.post("/auth/register-organization", json=_payload("ratelimit2"))
    third = await client.post("/auth/register-organization", json=_payload("ratelimit3"))

    assert first.status_code == 201
    assert second.status_code == 201
    assert third.status_code == 429

    get_settings.cache_clear()


async def test_refresh_beyond_the_per_ip_quota_is_rate_limited(
    client: AsyncClient, monkeypatch
) -> None:
    monkeypatch.setenv("AUTH_REFRESH_RATE_LIMIT_PER_MINUTE", "2")
    get_settings.cache_clear()

    first = await client.post("/auth/refresh")
    second = await client.post("/auth/refresh")
    third = await client.post("/auth/refresh")

    # No cookie on any of them — each is an ordinary 401 until the quota
    # itself is what stops the request.
    assert first.status_code == 401
    assert second.status_code == 401
    assert third.status_code == 429

    get_settings.cache_clear()


def _scraped_value(name: str, labels: str) -> float:
    from prometheus_client import REGISTRY, generate_latest

    text = generate_latest(REGISTRY).decode()
    for line in text.splitlines():
        if line.startswith(f"{name}{{{labels}}}"):
            return float(line.rsplit(" ", 1)[1])
    return 0.0


async def test_a_rate_limited_login_is_counted_in_the_metric(
    client: AsyncClient, monkeypatch
) -> None:
    before = _scraped_value("auth_rate_limited_total", 'action="login"')

    monkeypatch.setenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", "1")
    get_settings.cache_clear()
    body = {"organization_slug": "nope", "email": "a@example.com", "password": "x"}
    await client.post("/auth/login", json=body)
    await client.post("/auth/login", json=body)

    after = _scraped_value("auth_rate_limited_total", 'action="login"')
    assert after == before + 1

    get_settings.cache_clear()


async def test_the_quota_does_not_trip_ordinary_traffic(client: AsyncClient) -> None:
    """The default limits must not be so tight that a normal login-then-use
    flow ever sees a 429 — this is the regression the default values
    themselves need to keep passing."""
    org = await client.post(
        "/auth/register-organization",
        json={
            "organization_name": "Org normal",
            "organization_slug": "normalflow",
            "admin_email": "normal@example.com",
            "admin_password": "Correct-Horse-Battery-Staple-1",
            "admin_full_name": "Admin Admin",
        },
    )
    assert org.status_code == 201

    for _ in range(3):
        resp = await client.post(
            "/auth/login",
            json={
                "organization_slug": "normalflow",
                "email": "normal@example.com",
                "password": "Correct-Horse-Battery-Staple-1",
            },
        )
        assert resp.status_code == 200
