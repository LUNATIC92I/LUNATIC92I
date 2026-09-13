"""Streaming engine behaviour: what happens between "the conditions matched"
and "a detection was emitted".

Each of these is a control that exists because of a specific failure mode —
alert fatigue, undocumented carve-outs, a new rule enabled straight onto
production traffic, one broken rule blinding the rest — so each gets a test
that would fail if the control were quietly removed.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.detection.engine import (
    InMemorySuppressionStore,
    StreamingEngine,
    entity_key,
    matching_exception,
)
from app.detection.loader import parse_rule
from app.detection.schema import DetectionRule, RuleStatus

BASE_RULE = """
rule_id: TEST-100
name: Failed logon
description: Any failed authentication.
severity: high
confidence: 70
risk_score: 60
status: enabled
author: tests
conditions:
  all:
    - field: class
      operator: equals
      value: Authentication
    - field: authentication.outcome
      operator: equals
      value: failure
false_positive_notes: none
investigation_steps: none
"""


def _rule(extra: str = "", **overrides) -> DetectionRule:
    rule = parse_rule(BASE_RULE + extra)
    return rule.model_copy(update=overrides) if overrides else rule


def _event(event_id: str = "e1", **overrides) -> dict:
    document = {
        "event_id": event_id,
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "class": "Authentication",
        "authentication": {"outcome": "failure"},
        "user": {"name": "alice"},
        "source_ip": "10.1.1.5",
        "hostname": "web01",
    }
    document.update(overrides)
    return document


async def test_a_matching_event_produces_a_detection_with_its_rule_metadata() -> None:
    engine = StreamingEngine([_rule()])
    matches = await engine.evaluate(_event())

    assert len(matches) == 1
    match = matches[0]
    assert match.rule_id == "TEST-100"
    assert match.severity == "high"
    assert match.confidence == 70
    assert match.risk_score == 60
    assert match.event_ids == ["e1"]
    assert match.dry_run is False
    # Evidence travels with the detection so an analyst does not have to go
    # back to the event store to see why it fired.
    assert match.evidence["user"] == {"name": "alice"}


async def test_a_non_matching_event_produces_nothing() -> None:
    engine = StreamingEngine([_rule()])
    assert await engine.evaluate(_event(authentication={"outcome": "success"})) == []


async def test_a_disabled_rule_is_never_evaluated() -> None:
    engine = StreamingEngine([_rule(status=RuleStatus.DISABLED)])
    assert engine.rules == []
    assert await engine.evaluate(_event()) == []


async def test_a_testing_rule_matches_but_is_marked_dry_run() -> None:
    """How a new rule earns production status: evaluated on real traffic,
    recorded, but never turned into an alert."""
    engine = StreamingEngine([_rule(status=RuleStatus.TESTING)])
    matches = await engine.evaluate(_event())

    assert len(matches) == 1
    assert matches[0].dry_run is True


async def test_windowed_rules_are_not_silently_run_by_the_streaming_engine() -> None:
    windowed = _rule("window:\n  duration: 5m\n  threshold: 5\n  group_by: [user.name]\n")
    engine = StreamingEngine([windowed])

    assert engine.rules == [], "a threshold rule must not fire on a single event"
    assert await engine.evaluate(_event()) == []


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


EXCEPTION_YAML = """exceptions:
  - reason: svc-backup authenticates from the backup host and fails on rotation
    conditions:
      all:
        - field: user.name
          operator: equals
          value: svc-backup
        - field: source_ip
          operator: equals
          value: 10.9.9.9
"""


async def test_an_active_exception_suppresses_the_match() -> None:
    engine = StreamingEngine([_rule(EXCEPTION_YAML)])
    excepted = _event(user={"name": "svc-backup"}, source_ip="10.9.9.9")

    assert await engine.evaluate(excepted) == []


async def test_an_exception_only_covers_what_it_describes() -> None:
    """The narrowness of a carve-out is the point: the same account from a
    different host is not covered."""
    engine = StreamingEngine([_rule(EXCEPTION_YAML)])
    elsewhere = _event(user={"name": "svc-backup"}, source_ip="203.0.113.7")

    assert len(await engine.evaluate(elsewhere)) == 1


async def test_an_expired_exception_stops_applying() -> None:
    past = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    rule = _rule(EXCEPTION_YAML + f"    expires_at: '{past}'\n")
    engine = StreamingEngine([rule])

    assert len(await engine.evaluate(_event(user={"name": "svc-backup"}, source_ip="10.9.9.9"))) == 1


async def test_an_unexpired_exception_still_applies() -> None:
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    rule = _rule(EXCEPTION_YAML + f"    expires_at: '{future}'\n")

    assert matching_exception(rule, _event(user={"name": "svc-backup"}, source_ip="10.9.9.9"))


async def test_an_unparseable_expiry_is_treated_as_expired() -> None:
    """Fail towards detecting: a carve-out nobody can date must not keep
    silently removing coverage."""
    rule = _rule(EXCEPTION_YAML + "    expires_at: 'whenever'\n")
    engine = StreamingEngine([rule])

    assert len(await engine.evaluate(_event(user={"name": "svc-backup"}, source_ip="10.9.9.9"))) == 1


def test_an_exception_without_a_reason_cannot_be_written() -> None:
    with pytest.raises(ValueError):
        parse_rule(
            BASE_RULE
            + "exceptions:\n  - conditions:\n      field: user.name\n"
            "        operator: equals\n        value: svc\n"
        )


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------


SUPPRESSED = "suppression: 30m\nsuppress_by:\n  - user.name\n  - source_ip\n"


async def test_suppression_holds_repeat_matches_for_the_same_entity() -> None:
    engine = StreamingEngine([_rule(SUPPRESSED)], suppression=InMemorySuppressionStore())

    assert len(await engine.evaluate(_event("e1"))) == 1
    assert await engine.evaluate(_event("e2")) == [], "the same entity fired twice"


async def test_suppression_is_per_entity_not_per_rule() -> None:
    """The failure this prevents: one noisy account hiding every other
    account's brute force."""
    engine = StreamingEngine([_rule(SUPPRESSED)], suppression=InMemorySuppressionStore())

    assert len(await engine.evaluate(_event("e1", user={"name": "alice"}))) == 1
    assert len(await engine.evaluate(_event("e2", user={"name": "bob"}))) == 1
    assert len(await engine.evaluate(_event("e3", source_ip="203.0.113.5"))) == 1


async def test_suppression_expires() -> None:
    engine = StreamingEngine(
        [_rule("suppression: 1s\nsuppress_by:\n  - user.name\n")],
        suppression=InMemorySuppressionStore(),
    )
    assert len(await engine.evaluate(_event("e1"))) == 1
    assert await engine.evaluate(_event("e2")) == []

    # Rather than sleeping, expire the claim the way time would.
    store = InMemorySuppressionStore()
    assert await store.claim("k", 1) is True
    store._until["k"] = 0.0
    assert await store.claim("k", 1) is True


async def test_a_rule_without_suppression_fires_every_time() -> None:
    engine = StreamingEngine([_rule()])
    assert len(await engine.evaluate(_event("e1"))) == 1
    assert len(await engine.evaluate(_event("e2"))) == 1


def test_the_suppression_entity_is_read_from_the_event() -> None:
    rule = _rule(SUPPRESSED)
    assert entity_key(rule, _event()) == {"user.name": "alice", "source_ip": "10.1.1.5"}
    # A missing entity field is recorded as None rather than dropped, so two
    # different "unknown" entities cannot collide into one suppression key
    # with a populated one.
    assert entity_key(rule, {"user": {"name": "alice"}})["source_ip"] is None


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


async def test_one_failing_rule_does_not_stop_the_others() -> None:
    broken = _rule().model_copy(update={"rule_id": "TEST-999"})
    # Force a failure deep inside evaluation without touching the engine.
    object.__setattr__(broken, "conditions", None)

    engine = StreamingEngine([broken, _rule()])
    matches = await engine.evaluate(_event())

    assert [match.rule_id for match in matches] == ["TEST-100"]


async def test_rules_can_be_swapped_without_losing_suppression_state() -> None:
    """A rule refresh must not re-open every suppression window; otherwise a
    worker refreshing every minute would re-alert every minute."""
    engine = StreamingEngine([_rule(SUPPRESSED)], suppression=InMemorySuppressionStore())
    assert len(await engine.evaluate(_event("e1"))) == 1

    engine.replace_rules([_rule(SUPPRESSED)])
    assert await engine.evaluate(_event("e2")) == []
