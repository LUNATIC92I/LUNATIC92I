"""The outbound egress guard (THREAT_MODEL.md §3.8).

A SIEM is a uniquely attractive SSRF target: it sits inside the management
network and it is *designed* to fetch URLs that appear in configuration and
data. These tests are the guard's specification — each one is a request that
must never leave the process.
"""

import pytest

from app.core import egress
from app.core.config import get_settings


@pytest.fixture(autouse=True)
def _clean_settings():
    """Settings are cached; every test here changes them, so the cache is
    cleared before and after."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _configure(monkeypatch, **overrides: str) -> None:
    for key, value in overrides.items():
        monkeypatch.setenv(key.upper(), value)
    get_settings.cache_clear()


def test_an_empty_allow_list_blocks_everything(monkeypatch) -> None:
    """Fail closed. A deployment that has not said where it may talk to is
    not a deployment that may talk anywhere."""
    _configure(monkeypatch, egress_allowed_hosts="")
    with pytest.raises(egress.EgressBlocked, match="allow_list_empty"):
        egress.validate_url("https://example.com/feed.txt")


def test_a_host_outside_the_allow_list_is_blocked(monkeypatch) -> None:
    _configure(monkeypatch, egress_allowed_hosts="feeds.example.com")
    with pytest.raises(egress.EgressBlocked, match="host_not_allowed"):
        egress.validate_url("https://evil.example.org/feed.txt")


def test_a_leading_dot_allows_subdomains_only(monkeypatch) -> None:
    _configure(monkeypatch, egress_allowed_hosts=".example.com")
    # A suffix match must not let "notexample.com" through.
    with pytest.raises(egress.EgressBlocked, match="host_not_allowed"):
        egress.validate_url("https://notexample.com/x")


@pytest.mark.parametrize("url", ["http://feeds.example.com/x", "ftp://feeds.example.com/x", "file:///etc/passwd", "gopher://feeds.example.com/x"])
def test_only_https_is_permitted_by_default(monkeypatch, url: str) -> None:
    _configure(monkeypatch, egress_allowed_hosts="feeds.example.com")
    with pytest.raises(egress.EgressBlocked, match="scheme"):
        egress.validate_url(url)


def test_a_url_without_a_host_is_blocked(monkeypatch) -> None:
    _configure(monkeypatch, egress_allowed_hosts="feeds.example.com")
    with pytest.raises(egress.EgressBlocked, match="host|scheme"):
        egress.validate_url("https:///feed.txt")


def test_loopback_is_blocked_even_when_allow_listed(monkeypatch) -> None:
    """The host allow-list is not the last line of defence: an allow-listed
    name whose DNS points inside is exactly the SSRF case."""
    _configure(monkeypatch, egress_allowed_hosts="localhost")
    with pytest.raises(egress.EgressBlocked, match="non_global_address"):
        egress.validate_url("https://localhost/feed.txt")


def test_the_cloud_metadata_address_is_blocked(monkeypatch) -> None:
    """169.254.169.254 is the single most valuable SSRF target in any cloud
    deployment: it hands out instance credentials."""
    _configure(monkeypatch, egress_allowed_hosts="169.254.169.254")
    with pytest.raises(egress.EgressBlocked, match="non_global_address"):
        egress.validate_url("https://169.254.169.254/latest/meta-data/")


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "0.0.0.0",  # noqa: S104  a destination to refuse, not an interface to bind
        "[::1]",
    ],
)
def test_private_and_reserved_addresses_are_blocked(monkeypatch, host: str) -> None:
    _configure(monkeypatch, egress_allowed_hosts=host.strip("[]"))
    with pytest.raises(egress.EgressBlocked, match="non_global_address"):
        egress.validate_url(f"https://{host}/x")


def test_a_public_address_passes(monkeypatch) -> None:
    _configure(monkeypatch, egress_allowed_hosts="93.184.216.34")
    target = egress.validate_url("https://93.184.216.34/feed.txt")
    assert target.addresses == ["93.184.216.34"]


def test_the_private_escape_hatch_is_off_by_default_and_explicit(monkeypatch) -> None:
    """The setting exists for local development. Its default must be secure,
    and turning it on must be a deliberate act — hence this test, which
    fails if the default ever flips."""
    _configure(monkeypatch, egress_allowed_hosts="127.0.0.1")
    assert get_settings().egress_allow_private_destinations is False
    with pytest.raises(egress.EgressBlocked):
        egress.validate_url("https://127.0.0.1/x")

    _configure(
        monkeypatch, egress_allowed_hosts="127.0.0.1", egress_allow_private_destinations="true"
    )
    assert egress.validate_url("https://127.0.0.1/x").host == "127.0.0.1"


def test_an_unresolvable_host_is_blocked_not_attempted(monkeypatch) -> None:
    _configure(monkeypatch, egress_allowed_hosts="does-not-exist.invalid")
    with pytest.raises(egress.EgressBlocked, match="dns_failure"):
        egress.validate_url("https://does-not-exist.invalid/x")


async def test_a_blocked_url_never_reaches_the_network(monkeypatch) -> None:
    """The guard runs before any client is constructed: if this ever
    regressed, the request would be made and only then judged."""
    _configure(monkeypatch, egress_allowed_hosts="feeds.example.com")

    import httpx

    def _explode(*args, **kwargs):
        raise AssertionError("an HTTP client was created for a blocked URL")

    monkeypatch.setattr(httpx, "AsyncClient", _explode)
    with pytest.raises(egress.EgressBlocked):
        await egress.fetch("https://evil.example.org/x")
