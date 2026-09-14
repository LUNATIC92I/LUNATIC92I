"""Secure response headers (Phase 17, OWASP ASVS V14). Every response, on
every route — including a 404 — carries the fixed header set; there is no
route-specific opt-out.
"""

from httpx import AsyncClient

from app.core.security_headers import SECURITY_HEADERS


async def test_every_response_carries_the_full_security_header_set(client: AsyncClient) -> None:
    response = await client.get("/health")
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value


async def test_headers_are_present_even_on_a_404(client: AsyncClient) -> None:
    response = await client.get("/this-route-does-not-exist")
    assert response.status_code == 404
    for name in SECURITY_HEADERS:
        assert name in response.headers


async def test_content_security_policy_blocks_everything(client: AsyncClient) -> None:
    response = await client.get("/health")
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
