"""Correlation engine: chains, state, and the two evasions worth caring about.

The properties under test are the ones that separate a correlation engine
from a `for` loop over recent events: it must survive its own restart, it
must not care what order the network delivered things in, and it must not be
steerable by whatever timestamp an attacker chose to write into a log line.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.redis import get_redis
from app.correlation.engine import (
    CorrelationEngine,
    detection_input,
    effective_time,
    event_input,
)
from app.correlation.loader import parse_correlation_rule
from app.correlation.state import (
    InMemoryCorrelationStateStore,
    RedisCorrelationStateStore,
    StageHit,
)
from app.detection.engine import InMemorySuppressionStore
from app.detection.loader import RuleLoadError

BASE_TIME = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)

_HEAD = """
correlation_id: TEST-001
name: Two-step chain
description: A minimal ordered chain for tests.
severity: high
confidence: 70
risk_score: 80
status: enabled
author: tests
window: 30m
correlate_by:
  - user.name
ordered: true
stages:
"""

_STAGE_ONE = """  - name: first
    conditions:
      field: activity
      operator: equals
      value: step_one
"""

_STAGE_TWO = """  - name: second
    conditions:
      field: activity
      operator: equals
      value: step_two
"""

_TAIL = """false_positive_notes: none
investigation_steps: none
"""


def _chain(stages: str | None = None, *, tail: str = "") -> str:
    """Assembles a rule document. Built from pieces rather than patched with
    string replacement so a test that changes the stage list cannot
    accidentally produce YAML that is invalid for an unrelated reason."""
    return _HEAD + (stages if stages is not None else _STAGE_ONE + _STAGE_TWO) + _TAIL + tail


CHAIN = _chain()


def _engine(rule_yaml: str = CHAIN, *, state=None, suppression=None) -> CorrelationEngine:
    return CorrelationEngine(
        [parse_correlation_rule(rule_yaml)],
        state=state or InMemoryCorrelationStateStore(),
        suppression=suppression,
    )


def _event(
    activity: str,
    *,
    tenant: str,
    user: str = "alice",
    at: datetime | None = None,
    ingested_at: datetime | None = None,
    **extra,
) -> dict:
    occurred = at or BASE_TIME
    ingested = ingested_at or occurred
    document = {
        "event_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "timestamp": occurred.isoformat(),
        "ingestion_timestamp": ingested.isoformat(),
        "activity": activity,
        "user": {"name": user},
    }
    document.update(extra)
    return document


async def _feed(engine: CorrelationEngine, document: dict) -> list:
    correlation_input = event_input(document)
    assert correlation_input is not None
    return await engine.process(correlation_input)


# ---------------------------------------------------------------------------
# Chain completion
# ---------------------------------------------------------------------------


async def test_a_chain_fires_only_when_every_required_stage_has_happened() -> None:
    engine, tenant = _engine(), str(uuid.uuid4())

    assert await _feed(engine, _event("step_one", tenant=tenant)) == []
    matches = await _feed(
        engine, _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=1))
    )

    assert len(matches) == 1
    match = matches[0]
    assert match.correlation_id == "TEST-001"
    assert match.entity == {"user.name": "alice"}
    assert match.stages_matched == ["first", "second"]
    assert match.span_seconds == 60
    assert len(match.event_ids) == 2


async def test_a_partial_chain_never_fires() -> None:
    engine, tenant = _engine(), str(uuid.uuid4())
    for _ in range(5):
        assert await _feed(engine, _event("step_one", tenant=tenant)) == []


async def test_stages_out_of_order_do_not_complete_an_ordered_chain() -> None:
    """Step two before step one is not the chain this rule describes."""
    engine, tenant = _engine(), str(uuid.uuid4())

    assert await _feed(engine, _event("step_two", tenant=tenant)) == []
    assert (
        await _feed(
            engine, _event("step_one", tenant=tenant, at=BASE_TIME + timedelta(minutes=1))
        )
        == []
    )


async def test_an_unordered_chain_accepts_either_order() -> None:
    engine = _engine(CHAIN.replace("ordered: true", "ordered: false"))
    tenant = str(uuid.uuid4())

    assert await _feed(engine, _event("step_two", tenant=tenant)) == []
    matches = await _feed(
        engine, _event("step_one", tenant=tenant, at=BASE_TIME + timedelta(minutes=1))
    )
    assert len(matches) == 1


async def test_arrival_order_does_not_decide_ordering(monkeypatch) -> None:
    """The out-of-order delivery case: a backlogged collector delivers the
    later stage first, but the chain is judged on event time and still
    completes."""
    engine, tenant = _engine(), str(uuid.uuid4())

    # step_two happened at 12:05 but arrives first; step_one happened at
    # 12:00 and arrives second.
    later = _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=5))
    earlier = _event("step_one", tenant=tenant, at=BASE_TIME)

    assert await _feed(engine, later) == []
    matches = await _feed(engine, earlier)

    assert len(matches) == 1
    assert [entry["stage"] for entry in matches[0].timeline] == ["first", "second"]


async def test_stages_outside_the_window_do_not_chain() -> None:
    engine, tenant = _engine(), str(uuid.uuid4())

    assert await _feed(engine, _event("step_one", tenant=tenant)) == []
    assert (
        await _feed(
            engine, _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=31))
        )
        == []
    )


async def test_the_chain_is_per_entity() -> None:
    """Two users each doing half of the chain is not one attack."""
    engine, tenant = _engine(), str(uuid.uuid4())

    assert await _feed(engine, _event("step_one", tenant=tenant, user="alice")) == []
    assert await _feed(engine, _event("step_two", tenant=tenant, user="bob")) == []


async def test_the_chain_is_per_tenant() -> None:
    engine = _engine()
    tenant_a, tenant_b = str(uuid.uuid4()), str(uuid.uuid4())

    assert await _feed(engine, _event("step_one", tenant=tenant_a)) == []
    assert await _feed(engine, _event("step_two", tenant=tenant_b)) == []


async def test_an_input_missing_the_entity_field_is_not_correlated() -> None:
    engine, tenant = _engine(), str(uuid.uuid4())
    anonymous = _event("step_one", tenant=tenant)
    del anonymous["user"]

    assert await _feed(engine, anonymous) == []
    # ... and it did not silently join anyone else's chain either.
    assert await _feed(engine, _event("step_two", tenant=tenant)) == []


async def test_min_count_requires_repetition() -> None:
    repeated_first = _STAGE_ONE.replace(
        "  - name: first\n", "  - name: first\n    min_count: 3\n"
    )
    engine = _engine(_chain(repeated_first + _STAGE_TWO))
    tenant = str(uuid.uuid4())

    for minute in range(2):
        assert (
            await _feed(
                engine, _event("step_one", tenant=tenant, at=BASE_TIME + timedelta(minutes=minute))
            )
            == []
        )
    assert (
        await _feed(engine, _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=3)))
        == []
    ), "the chain completed with too few first-stage hits"

    await _feed(engine, _event("step_one", tenant=tenant, at=BASE_TIME + timedelta(minutes=4)))
    matches = await _feed(
        engine, _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=5))
    )
    assert len(matches) == 1


async def test_an_optional_stage_enriches_the_timeline_without_gating() -> None:
    optional_stage = """  - name: extra
    required: false
    conditions:
      field: activity
      operator: equals
      value: step_three
"""
    engine = _engine(_chain(_STAGE_ONE + _STAGE_TWO + optional_stage))
    tenant = str(uuid.uuid4())

    await _feed(engine, _event("step_three", tenant=tenant))
    assert await _feed(engine, _event("step_one", tenant=tenant)) == []
    matches = await _feed(
        engine, _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=1))
    )

    assert len(matches) == 1
    assert "extra" in {entry["stage"] for entry in matches[0].timeline}
    assert "extra" not in matches[0].stages_matched


async def test_suppression_stops_a_completed_chain_re_firing() -> None:
    """Without it, every further input for that entity re-completes the
    chain for as long as its window holds."""
    engine = _engine(_chain(tail="suppression: 1h\n"), suppression=InMemorySuppressionStore())
    tenant = str(uuid.uuid4())

    await _feed(engine, _event("step_one", tenant=tenant))
    assert len(await _feed(engine, _event("step_two", tenant=tenant))) == 1
    assert await _feed(engine, _event("step_two", tenant=tenant)) == []


async def test_a_disabled_rule_is_not_evaluated() -> None:
    engine = _engine(CHAIN.replace("status: enabled", "status: disabled"))
    assert engine.rules == []


# ---------------------------------------------------------------------------
# The timeline
# ---------------------------------------------------------------------------


async def test_the_timeline_is_built_automatically_and_in_time_order() -> None:
    engine, tenant = _engine(), str(uuid.uuid4())
    await _feed(engine, _event("step_one", tenant=tenant, source_ip="203.0.113.9"))
    matches = await _feed(
        engine,
        _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=2), hostname="web01"),
    )

    timeline = matches[0].timeline
    assert [entry["stage"] for entry in timeline] == ["first", "second"]
    assert timeline[0]["time"] < timeline[1]["time"]
    assert timeline[0]["summary"]["source_ip"] == "203.0.113.9"
    assert timeline[1]["summary"]["hostname"] == "web01"
    assert all(entry["time_source"] == "event" for entry in timeline)
    assert matches[0].first_seen == timeline[0]["time"]
    assert matches[0].last_seen == timeline[-1]["time"]


# ---------------------------------------------------------------------------
# Timestamp manipulation (Technical Risk #5)
# ---------------------------------------------------------------------------


def test_a_plausible_timestamp_is_believed() -> None:
    claimed = int(BASE_TIME.timestamp() * 1000)
    ingested = claimed + 60_000
    assert effective_time(claimed, ingested, max_skew_seconds=900) == (claimed, "event")


def test_an_implausible_timestamp_falls_back_to_ingestion_time() -> None:
    ingested = int(BASE_TIME.timestamp() * 1000)
    for claimed in (ingested - 2 * 86_400_000, ingested + 2 * 86_400_000):
        resolved, source = effective_time(claimed, ingested, max_skew_seconds=900)
        assert (resolved, source) == (ingested, "ingestion")


async def test_backdating_an_event_does_not_evade_the_correlation_window() -> None:
    """The evasion this defeats: stamp the second stage two days earlier so
    it falls outside the window, and the chain never closes."""
    engine, tenant = _engine(), str(uuid.uuid4())

    await _feed(engine, _event("step_one", tenant=tenant))
    forged = _event(
        "step_two",
        tenant=tenant,
        at=BASE_TIME - timedelta(days=2),  # what the log line claims
        ingested_at=BASE_TIME + timedelta(minutes=1),  # when we actually received it
    )
    matches = await _feed(engine, forged)

    assert len(matches) == 1, "a forged timestamp evaded the correlation"
    forged_entry = matches[0].timeline[-1]
    assert forged_entry["time_source"] == "ingestion"
    # The claimed time is still recorded: an analyst must be able to see
    # that the source lied, not just that we overrode it.
    assert forged_entry["claimed_time"].startswith("2026-09-11")


async def test_future_dating_an_event_does_not_evade_it_either() -> None:
    engine, tenant = _engine(), str(uuid.uuid4())
    await _feed(engine, _event("step_one", tenant=tenant))

    matches = await _feed(
        engine,
        _event(
            "step_two",
            tenant=tenant,
            at=BASE_TIME + timedelta(days=30),
            ingested_at=BASE_TIME + timedelta(minutes=1),
        ),
    )
    assert len(matches) == 1


async def test_a_genuinely_old_event_still_falls_outside_the_window() -> None:
    """The backstop must not turn into "everything correlates": an event
    that really did happen (and was ingested) long ago stays out."""
    engine, tenant = _engine(), str(uuid.uuid4())
    old = BASE_TIME - timedelta(days=2)

    await _feed(engine, _event("step_one", tenant=tenant, at=old, ingested_at=old))
    assert await _feed(engine, _event("step_two", tenant=tenant)) == []


# ---------------------------------------------------------------------------
# State: durability across a restart (Technical Risk #4)
# ---------------------------------------------------------------------------


@pytest.fixture
def redis_state() -> RedisCorrelationStateStore:
    return RedisCorrelationStateStore(get_redis(), prefix=f"test-correlation:{uuid.uuid4()}:")


async def test_state_survives_the_engine_being_destroyed_and_rebuilt(
    redis_state: RedisCorrelationStateStore,
) -> None:
    """The restart-recovery test Technical Risk #4 asks for: everything the
    engine knows lives in Redis, so a new engine picks the chain up exactly
    where the old one left off."""
    tenant = str(uuid.uuid4())

    before_restart = _engine(state=redis_state)
    assert await _feed(before_restart, _event("step_one", tenant=tenant)) == []
    del before_restart

    # A brand-new engine object with a brand-new store client: nothing
    # in-process carries over.
    after_restart = _engine(
        state=RedisCorrelationStateStore(get_redis(), prefix=redis_state._prefix)
    )
    matches = await _feed(
        after_restart, _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=1))
    )

    assert len(matches) == 1, "the in-flight chain was lost on restart"
    assert len(matches[0].timeline) == 2


async def test_two_workers_sharing_state_complete_one_chain(
    redis_state: RedisCorrelationStateStore,
) -> None:
    """Append-and-read is atomic, so a chain split across replicas still
    completes — in exactly one of them."""
    tenant = str(uuid.uuid4())
    worker_a = _engine(state=redis_state, suppression=InMemorySuppressionStore())
    worker_b = _engine(
        state=RedisCorrelationStateStore(get_redis(), prefix=redis_state._prefix),
        suppression=InMemorySuppressionStore(),
    )

    assert await _feed(worker_a, _event("step_one", tenant=tenant)) == []
    matches = await _feed(
        worker_b, _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=1))
    )
    assert len(matches) == 1


async def test_redis_state_expires_with_the_rule_window(
    redis_state: RedisCorrelationStateStore,
) -> None:
    """The TTL is what stops abandoned chains accumulating forever; it is
    set from the rule's own window, not guessed."""
    key = f"ttl-probe-{uuid.uuid4()}"
    await redis_state.append(
        key,
        StageHit(
            stage="first",
            occurred_at_ms=0,
            claimed_at_ms=0,
            ingested_at_ms=0,
            time_source="event",
            kind="event",
            event_id="e1",
            summary={},
        ),
        ttl_seconds=1800,
    )

    ttl = await get_redis().ttl(f"{redis_state._prefix}{key}")
    assert 0 < ttl <= 1800


async def test_state_is_capped_per_entity(redis_state: RedisCorrelationStateStore) -> None:
    """One noisy entity must not be able to grow a key without bound."""
    key = f"cap-probe-{uuid.uuid4()}"

    def _hit(index: int) -> StageHit:
        return StageHit(
            stage="first",
            occurred_at_ms=index,
            claimed_at_ms=index,
            ingested_at_ms=index,
            time_source="event",
            kind="event",
            event_id=f"e{index}",
            summary={},
        )

    for index in range(12):
        held = await redis_state.append(key, _hit(index), ttl_seconds=60, max_hits=10)

    assert len(held) == 10
    assert [hit.event_id for hit in held][0] == "e2", "the oldest hits should be the ones dropped"


# ---------------------------------------------------------------------------
# Detections as chain inputs
# ---------------------------------------------------------------------------


def _detection(rule_id: str, *, tenant: str, user: str = "alice", at: datetime | None = None) -> dict:
    moment = (at or BASE_TIME).isoformat()
    return {
        "detection_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "rule_id": rule_id,
        "rule_name": rule_id,
        "severity": "high",
        "confidence": 70,
        "risk_score": 60,
        "mitre_attack": ["T1110"],
        "event_ids": [str(uuid.uuid4())],
        "entity": {"user.name": user},
        "matched_at": moment,
        "dry_run": False,
        "evidence": {"timestamp": moment, "source_ip": "203.0.113.5"},
    }


async def test_a_detection_can_be_a_stage() -> None:
    detection_stage = """  - name: first
    matches: detection
    conditions:
      field: detection.rule_id
      operator: equals
      value: AUTH-001
"""
    engine = _engine(_chain(detection_stage + _STAGE_TWO))
    tenant = str(uuid.uuid4())

    detection = detection_input(_detection("AUTH-001", tenant=tenant))
    assert detection is not None
    assert await engine.process(detection) == []

    matches = await _feed(
        engine, _event("step_two", tenant=tenant, at=BASE_TIME + timedelta(minutes=1))
    )
    assert len(matches) == 1
    assert matches[0].timeline[0]["kind"] == "detection"
    assert matches[0].timeline[0]["summary"]["detection_rule"] == "AUTH-001"


def test_a_dry_run_detection_is_never_a_chain_input() -> None:
    """A rule in `testing` status must not be able to drive an alerting
    correlation, or "testing" would not mean what it says."""
    dry = _detection("AUTH-001", tenant=str(uuid.uuid4()))
    dry["dry_run"] = True
    assert detection_input(dry) is None


def test_a_windowed_detections_bucket_key_resolves_as_an_entity() -> None:
    """A windowed detection carries its entity only as a dotted bucket key;
    it has to become a real nested field or the chain never keys on it."""
    detection = _detection("AUTH-001", tenant="t")
    detection["evidence"] = {"observed": 5}
    resolved = detection_input(detection)
    assert resolved is not None
    assert resolved.document["user"]["name"] == "alice"


# ---------------------------------------------------------------------------
# Schema and loading
# ---------------------------------------------------------------------------


def test_a_rule_with_one_required_stage_is_refused() -> None:
    """That is a detection rule wearing a correlation rule's clothes, and it
    would fire on every single input."""
    optional_second = _STAGE_TWO.replace(
        "  - name: second\n", "  - name: second\n    required: false\n"
    )
    with pytest.raises(RuleLoadError, match="two required stages"):
        parse_correlation_rule(_chain(_STAGE_ONE + optional_second))


def test_duplicate_stage_names_are_refused() -> None:
    with pytest.raises(RuleLoadError, match="unique"):
        parse_correlation_rule(CHAIN.replace("name: second", "name: first"))


def test_an_unbounded_window_is_refused() -> None:
    with pytest.raises(RuleLoadError, match="maximum"):
        parse_correlation_rule(CHAIN.replace("window: 30m", "window: 7d"))


def test_yaml_code_execution_is_refused() -> None:
    with pytest.raises(RuleLoadError):
        parse_correlation_rule('!!python/object/apply:os.system ["echo pwned"]')


def test_an_unknown_key_is_refused() -> None:
    with pytest.raises(RuleLoadError):
        parse_correlation_rule(CHAIN + "windo: 5m\n")
