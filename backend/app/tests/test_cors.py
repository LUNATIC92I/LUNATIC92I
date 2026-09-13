"""CORS (spec §14 dashboard, THREAT_MODEL.md §3.2): the frontend authenticates
with an httpOnly refresh cookie, so an over-broad CORS policy would let any
page on the internet ride a signed-in analyst's session. Only the
configured origin may make a credentialed cross-origin request.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_the_configured_origin_is_allowed_with_credentials() -> None:
    response = client.options(
        "/organizations/me",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_an_unconfigured_origin_is_not_allowed() -> None:
    response = client.options(
        "/organizations/me",
        headers={
            "Origin": "http://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in response.headers
