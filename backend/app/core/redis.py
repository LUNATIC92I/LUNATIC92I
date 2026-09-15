"""Shared Redis client.

Distinct from the EventBus (which happens to be Redis-backed today): this is
Redis used *as* Redis — rate-limit counters, idempotency claims, and the
correlation-window state Phase 7 will add. Keeping the two separate means
moving the bus to Kafka later does not disturb any of this.
"""

from functools import lru_cache
from urllib.parse import urlparse

import redis.asyncio as aioredis
from redis.asyncio.sentinel import Sentinel

from app.core.config import get_settings


def _parse_sentinel_hosts(raw: str) -> list[tuple[str, int]]:
    hosts: list[tuple[str, int]] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        host, _, port = entry.partition(":")
        hosts.append((host, int(port) if port else 26379))
    return hosts


def build_redis_client(
    redis_url: str | None = None, *, socket_timeout: float | None = None
) -> aioredis.Redis:
    """Builds a Redis client, transparently following a Sentinel-managed
    failover when Sentinel is configured (`REDIS_SENTINEL_HOSTS`) instead
    of holding a static connection to whichever node was master when the
    process started.

    A static `redis://` connection (what every client in this codebase
    used exclusively before this function existed) has no way to learn
    that Sentinel promoted a different node — it keeps addressing the old
    master and simply fails once that node is gone. `Sentinel.master_for()`
    re-resolves the current master's address on every command via a
    separate connection to the Sentinel processes themselves, so a
    replica promotion is followed automatically, not just detected: the
    caller's existing client object keeps working across the failover
    with no restart (verified directly: a real local Sentinel cluster,
    the actual master container killed, the same client continuing to
    serve requests against the promoted replica within Sentinel's own
    detection window).

    Sentinel configuration is a deployment-wide switch, not a per-call
    choice: when `REDIS_SENTINEL_HOSTS` is set, it takes priority over
    any `redis_url` passed in, because a caller half-connected via
    Sentinel and half via a static URL would defeat the point — every
    Redis client in one deployment should agree on how it finds the
    master. `redis_url` remains the only thing that matters when
    Sentinel isn't configured, which is unchanged prior behavior for
    local dev, docker-compose's single Redis node, and the test suite.
    """
    settings = get_settings()
    if settings.redis_sentinel_hosts:
        # The password lives in redis_url (e.g. "redis://:secret@host:port/0")
        # even in Sentinel mode — it is still the credential Redis itself
        # authenticates with, Sentinel or not. Bitnami's redis chart (used
        # in kubernetes/data-tier/values-redis-ha.yaml) protects both the
        # data nodes and the Sentinel processes with the same password by
        # default, so the one value covers both `sentinel_kwargs` (the
        # connections to the Sentinel processes themselves) and the
        # connection to whichever node master_for() resolves to.
        password = urlparse(redis_url or settings.redis_url).password
        # redis-py's Sentinel class predates precise typing for its
        # **connection_kwargs pass-through; the constructor call and
        # master_for()'s return type are both genuinely untyped here,
        # not a mistake on this file's part.
        sentinel = Sentinel(  # type: ignore[no-untyped-call]
            _parse_sentinel_hosts(settings.redis_sentinel_hosts),
            sentinel_kwargs={"password": password} if password else None,
            decode_responses=False,
            socket_timeout=socket_timeout,
            password=password,
        )
        master: aioredis.Redis = sentinel.master_for(
            settings.redis_sentinel_service_name,
            decode_responses=False,
            socket_timeout=socket_timeout,
            password=password,
        )
        return master
    kwargs: dict[str, object] = {"decode_responses": False}
    if socket_timeout is not None:
        kwargs["socket_timeout"] = socket_timeout
    return aioredis.from_url(redis_url or settings.redis_url, **kwargs)


@lru_cache
def get_redis() -> aioredis.Redis:
    return build_redis_client()
