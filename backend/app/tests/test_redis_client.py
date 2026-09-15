"""app/core/redis.py::build_redis_client — the Sentinel-awareness fix.

The actual failover-following behavior (a Sentinel-managed master
promotion, the same client continuing to serve requests against the new
master with no restart) was verified directly against a real local
Redis + Sentinel cluster during development: a genuine master container
was SIGKILLed mid-poll, and the client recovered automatically after one
transient connection error, once Sentinel's own detection window
elapsed — data written both before and after the kill was confirmed
present on the promoted replica. That kind of live, multi-container
failover isn't something a unit test can reproduce; what these tests
cover is the half that *can* be verified in-process: URL parsing, and
that configuration correctly selects one connection strategy over the
other.
"""

import redis.asyncio as aioredis
from redis.asyncio.sentinel import SentinelConnectionPool

from app.core.config import get_settings
from app.core.redis import _parse_sentinel_hosts, build_redis_client


def test_parse_sentinel_hosts_uses_the_default_port_when_omitted() -> None:
    assert _parse_sentinel_hosts("sentinel1,sentinel2:26380") == [
        ("sentinel1", 26379),
        ("sentinel2", 26380),
    ]


def test_parse_sentinel_hosts_ignores_blank_entries() -> None:
    assert _parse_sentinel_hosts(" sentinel1:26379 , , sentinel2:26379") == [
        ("sentinel1", 26379),
        ("sentinel2", 26379),
    ]


def test_without_sentinel_configured_uses_a_plain_url_connection(
    monkeypatch,
) -> None:
    """Unchanged prior behavior — local dev, docker-compose's single Redis
    node, and the test suite all rely on this path."""
    monkeypatch.setattr(get_settings(), "redis_sentinel_hosts", "", raising=False)
    client = build_redis_client("redis://localhost:6379/0")
    assert isinstance(client.connection_pool, aioredis.ConnectionPool)
    assert not isinstance(client.connection_pool, SentinelConnectionPool)


def test_with_sentinel_configured_it_takes_priority_over_any_url(
    monkeypatch,
) -> None:
    """Sentinel configuration is a deployment-wide switch: once set, it
    wins even over an explicit redis_url passed by the caller (see
    build_redis_client's own docstring for why a mixed deployment would
    defeat the point)."""
    settings = get_settings()
    monkeypatch.setattr(settings, "redis_sentinel_hosts", "sentinel1:26379,sentinel2:26379", raising=False)
    monkeypatch.setattr(settings, "redis_sentinel_service_name", "mymaster", raising=False)
    client = build_redis_client("redis://this-should-be-ignored:6379/0")
    assert isinstance(client.connection_pool, SentinelConnectionPool)


def test_sentinel_mode_still_authenticates_with_the_url_password(
    monkeypatch,
) -> None:
    """Bitnami's redis chart (kubernetes/data-tier/values-redis-ha.yaml)
    protects both the data nodes and the Sentinel processes themselves
    with a password — Sentinel mode must keep authenticating, not just
    keep following the master."""
    settings = get_settings()
    monkeypatch.setattr(settings, "redis_sentinel_hosts", "sentinel1:26379", raising=False)
    client = build_redis_client("redis://:s3cret@this-host-is-irrelevant:6379/0")
    assert client.connection_pool.connection_kwargs.get("password") == "s3cret"
