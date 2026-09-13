"""Correlation state: the in-flight windows, held outside the worker.

Technical Risk #4 in `docs/TECHNICAL_RISKS.md` is that a correlation engine
keeping its half-finished chains in process memory loses them on every
restart and every deploy — and a missed multi-stage detection looks exactly
like nothing having happened. So state lives in Redis, keyed by
(tenant, rule, entity), with a TTL equal to the rule's window: a restart
resumes from durable state, and an abandoned chain expires by itself rather
than being cleaned up by code that might not run.

Two properties the implementation has to get right:

- **Append-and-read is one atomic operation.** Two workers processing two
  stages of the same chain concurrently must both see a consistent view, or
  a chain completes in neither of them. The Redis implementation is a single
  Lua script (RPUSH + LTRIM + EXPIRE + LRANGE) rather than a read-modify-
  write from the client.
- **A key is bounded.** One noisy entity must not be able to grow a list
  forever; the oldest hits are trimmed, which is visible in the metric
  rather than silent, because a trimmed chain can no longer be reconstructed
  in full for the timeline.
"""

import abc
import json
import logging
from dataclasses import asdict, dataclass
from typing import Any

from app.core import metrics

logger = logging.getLogger(__name__)

# Per (rule, entity). Generous for any real chain; a rule that hits this is
# matching far too broadly, which the metric surfaces.
DEFAULT_MAX_HITS = 500


@dataclass(frozen=True)
class StageHit:
    """One input that matched one stage of one rule, for one entity."""

    stage: str
    # The time used for windowing and ordering. Equal to the source's own
    # timestamp unless that was implausible, in which case it is the
    # ingestion time — see `engine.effective_time`.
    occurred_at_ms: int
    claimed_at_ms: int
    ingested_at_ms: int
    time_source: str  # "event" | "ingestion"
    kind: str  # "event" | "detection"
    event_id: str
    summary: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str | bytes) -> "StageHit":
        data = json.loads(raw)
        return cls(**data)


class CorrelationStateStore(abc.ABC):
    @abc.abstractmethod
    async def append(
        self, key: str, hit: StageHit, *, ttl_seconds: int, max_hits: int = DEFAULT_MAX_HITS
    ) -> list[StageHit]:
        """Records `hit` and returns every hit currently held for `key`,
        oldest first. Atomic: concurrent callers each see their own write."""

    @abc.abstractmethod
    async def read(self, key: str) -> list[StageHit]:
        """Everything held for `key`. For inspection and tests — the engine
        uses the list `append` returns, so it never needs a second round
        trip that could see a different state."""

    @abc.abstractmethod
    async def clear(self, key: str) -> None: ...


class InMemoryCorrelationStateStore(CorrelationStateStore):
    """A test double and single-process fallback. Explicitly NOT what the
    worker runs on: everything in here dies with the process, which is the
    failure mode Technical Risk #4 is about."""

    def __init__(self) -> None:
        self._hits: dict[str, list[StageHit]] = {}

    async def append(
        self, key: str, hit: StageHit, *, ttl_seconds: int, max_hits: int = DEFAULT_MAX_HITS
    ) -> list[StageHit]:
        held = self._hits.setdefault(key, [])
        held.append(hit)
        if len(held) > max_hits:
            del held[: len(held) - max_hits]
            metrics.correlation_state_trimmed_total.inc()
        return list(held)

    async def read(self, key: str) -> list[StageHit]:
        return list(self._hits.get(key, []))

    async def clear(self, key: str) -> None:
        self._hits.pop(key, None)


_APPEND_SCRIPT = """
redis.call('RPUSH', KEYS[1], ARGV[1])
local length = redis.call('LLEN', KEYS[1])
local max_hits = tonumber(ARGV[2])
local trimmed = 0
if length > max_hits then
    redis.call('LTRIM', KEYS[1], length - max_hits, -1)
    trimmed = length - max_hits
end
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
return {trimmed, unpack(redis.call('LRANGE', KEYS[1], 0, -1))}
"""


class RedisCorrelationStateStore(CorrelationStateStore):
    """The deployable implementation.

    The TTL is refreshed on every append, which is the behaviour a sliding
    window wants: a chain that keeps receiving activity stays alive, and one
    that goes quiet for a full window expires on its own.
    """

    def __init__(self, redis: Any, prefix: str = "correlation:") -> None:
        self._redis = redis
        self._prefix = prefix
        self._script = redis.register_script(_APPEND_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._prefix}{key}"

    async def append(
        self, key: str, hit: StageHit, *, ttl_seconds: int, max_hits: int = DEFAULT_MAX_HITS
    ) -> list[StageHit]:
        response = await self._script(
            keys=[self._key(key)],
            args=[hit.to_json(), str(max_hits), str(max(1, ttl_seconds))],
        )
        trimmed, *raw_hits = response
        if int(trimmed):
            # Loud: past this point the timeline for that entity is no
            # longer complete, which an analyst reading it must be able to
            # find out from somewhere.
            metrics.correlation_state_trimmed_total.inc(int(trimmed))
            logger.warning(
                "correlation state trimmed; the rule is matching too broadly",
                extra={"key": key, "dropped": int(trimmed)},
            )
        return [StageHit.from_json(raw) for raw in raw_hits]

    async def read(self, key: str) -> list[StageHit]:
        raw_hits = await self._redis.lrange(self._key(key), 0, -1)
        return [StageHit.from_json(raw) for raw in raw_hits]

    async def clear(self, key: str) -> None:
        await self._redis.delete(self._key(key))
