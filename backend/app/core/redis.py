"""Shared Redis client.

Distinct from the EventBus (which happens to be Redis-backed today): this is
Redis used *as* Redis — rate-limit counters, idempotency claims, and the
correlation-window state Phase 7 will add. Keeping the two separate means
moving the bus to Kafka later does not disturb any of this.
"""

from functools import lru_cache

import redis.asyncio as aioredis

from app.core.config import get_settings


@lru_cache
def get_redis() -> aioredis.Redis:
    return aioredis.from_url(get_settings().redis_url, decode_responses=False)
