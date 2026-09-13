"""The shipped correlation pack, exercised as whole attack scenarios.

Every rule gets the full chain (it fires), the chain minus one required
stage (it does not), the chain out of order (it does not, for ordered
rules), and the chain spread beyond the window (it does not). The first of
these reproduces the multi-stage example from spec §9 — failed logins, a
successful login, privilege escalation, bulk download — end to end through
the real shipped rule, not a fixture written for the test.
"""

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.correlation.engine import CorrelationEngine, detection_input, event_input
from app.correlation.loader import load_correlation_rules
from app.correlation.schema import CorrelationRule
from app.correlation.state import InMemoryCorrelationStateStore
from app.detection.engine import InMemorySuppressionStore

RULES_ROOT = Path(__file__).resolve().parents[3] / "rules"
RULES: dict[str, CorrelationRule] = {
    rule.correlation_id: rule for rule in load_correlation_rules(RULES_ROOT).rules
}

T0 = datetime(2026, 9, 13, 9, 0, tzinfo=UTC)


def _engine(correlation_id: str) -> CorrelationEngine:
    return CorrelationEngine(
        [RULES[correlation_id]],
        state=InMemoryCorrelationStateStore(),
        suppression=InMemorySuppressionStore(),
    )


def _event(tenant: str, *, minutes: float, **fields: Any) -> dict[str, Any]:
    moment = (T0 + timedelta(minutes=minutes)).isoformat()
    return {
        "event_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "timestamp": moment,
        "ingestion_timestamp": moment,
        **fields,
    }


def _detection(
    tenant: str, *, rule_id: str, minutes: float, entity: dict[str, Any], **evidence: Any
) -> dict[str, Any]:
    moment = (T0 + timedelta(minutes=minutes)).isoformat()
    return {
        "detection_id": str(uuid.uuid4()),
        "tenant_id": tenant,
        "rule_id": rule_id,
        "rule_name": rule_id,
        "severity": "high",
        "confidence": 80,
        "risk_score": 70,
        "mitre_attack": [],
        "event_ids": [str(uuid.uuid4())],
        "entity": entity,
        "matched_at": moment,
        "dry_run": False,
        "evidence": {"timestamp": moment, **evidence},
    }


async def _play(engine: CorrelationEngine, inputs: list[dict[str, Any]]) -> list:
    """Feeds a scenario in the given order and returns everything it fired."""
    fired = []
    for document in inputs:
        resolved = (
            detection_input(document)
            if "detection_id" in document
            else event_input(document)
        )
        assert resolved is not None, document
        fired.extend(await engine.process(resolved))
    return fired


# ---------------------------------------------------------------------------
# CORR-001 — the spec §9 scenario
# ---------------------------------------------------------------------------


def _takeover_chain(tenant: str, *, user: str = "alice", spread: float = 1.0) -> list[dict]:
    """Failed logins -> successful login -> privilege escalation -> bulk
    download, exactly the sequence spec §9 describes."""
    return [
        _detection(
            tenant,
            rule_id="AUTH-001",
            minutes=0,
            entity={"user.name": user, "source_ip": "203.0.113.5"},
            source_ip="203.0.113.5",
        ),
        _event(
            tenant,
            minutes=spread,
            **{
                "class": "Authentication",
                "authentication": {"outcome": "success"},
                "user": {"name": user},
                "source_ip": "203.0.113.5",
            },
        ),
        _event(
            tenant,
            minutes=spread * 2,
            event_code="4728",
            user={"name": user},
            hostname="dc01",
        ),
        _event(
            tenant,
            minutes=spread * 3,
            user={"name": user},
            file={"name": "customers.csv", "size": 750_000_000},
        ),
    ]


async def test_corr_001_account_takeover_fires_on_the_full_chain() -> None:
    tenant = str(uuid.uuid4())
    fired = await _play(_engine("CORR-001"), _takeover_chain(tenant))

    assert len(fired) == 1, "the spec §9 scenario did not correlate"
    match = fired[0]
    assert match.correlation_id == "CORR-001"
    assert match.severity == "critical"
    assert match.entity == {"user.name": "alice"}
    assert match.stages_matched == ["brute_force", "successful_login", "privilege_escalation"]
    # The chain closes at the privilege change, before the download: waiting
    # for exfiltration to call a takeover a takeover means alerting after
    # the damage. The bulk read arrives a minute later and is suppressed,
    # so it reaches the analyst as evidence on the alert (Phase 11) rather
    # than as a second correlation.
    assert [entry["stage"] for entry in match.timeline] == [
        "brute_force",
        "successful_login",
        "privilege_escalation",
    ]
    assert match.span_seconds == 120


async def test_corr_001_carries_an_optional_stage_that_arrived_in_time() -> None:
    """When the bulk read happens *before* the privilege change, it is in
    the timeline the analyst first sees."""
    tenant = str(uuid.uuid4())
    chain = _takeover_chain(tenant)
    early_download = {
        **chain[3],
        "timestamp": (T0 + timedelta(seconds=90)).isoformat(),
        "ingestion_timestamp": (T0 + timedelta(seconds=90)).isoformat(),
    }
    fired = await _play(_engine("CORR-001"), [chain[0], chain[1], early_download, chain[2]])

    assert len(fired) == 1
    assert "bulk_data_access" in {entry["stage"] for entry in fired[0].timeline}
    assert "bulk_data_access" not in fired[0].stages_matched


async def test_corr_001_fires_before_any_data_is_taken() -> None:
    tenant = str(uuid.uuid4())
    fired = await _play(_engine("CORR-001"), _takeover_chain(tenant)[:3])
    assert len(fired) == 1


async def test_corr_001_does_not_fire_without_the_privilege_change() -> None:
    tenant = str(uuid.uuid4())
    chain = _takeover_chain(tenant)
    assert await _play(_engine("CORR-001"), [chain[0], chain[1], chain[3]]) == []


async def test_corr_001_does_not_fire_without_the_successful_login() -> None:
    tenant = str(uuid.uuid4())
    chain = _takeover_chain(tenant)
    assert await _play(_engine("CORR-001"), [chain[0], chain[2]]) == []


async def test_corr_001_does_not_fire_out_of_order() -> None:
    """A privilege change *before* the brute force is a different story —
    most likely an administrator doing their job."""
    tenant = str(uuid.uuid4())
    chain = _takeover_chain(tenant)
    reversed_times = [
        {**chain[2], "timestamp": T0.isoformat(), "ingestion_timestamp": T0.isoformat()},
        chain[0],
        {
            **chain[1],
            "timestamp": (T0 + timedelta(minutes=5)).isoformat(),
            "ingestion_timestamp": (T0 + timedelta(minutes=5)).isoformat(),
        },
    ]
    assert await _play(_engine("CORR-001"), reversed_times) == []


async def test_corr_001_does_not_fire_when_the_chain_is_spread_beyond_its_window() -> None:
    tenant = str(uuid.uuid4())
    # 20 minutes between each stage: every pair is close, the chain is not.
    assert await _play(_engine("CORR-001"), _takeover_chain(tenant, spread=20)) == []


async def test_corr_001_does_not_chain_two_different_accounts() -> None:
    tenant = str(uuid.uuid4())
    alice = _takeover_chain(tenant, user="alice")
    bob = _takeover_chain(tenant, user="bob")
    # Alice was brute-forced; Bob legitimately logged in and got a group.
    assert await _play(_engine("CORR-001"), [alice[0], bob[1], bob[2]]) == []


async def test_corr_001_ignores_a_dry_run_detection() -> None:
    tenant = str(uuid.uuid4())
    chain = _takeover_chain(tenant)
    chain[0]["dry_run"] = True
    engine = _engine("CORR-001")

    fired = []
    for document in chain:
        resolved = (
            detection_input(document) if "detection_id" in document else event_input(document)
        )
        if resolved is None:
            continue
        fired.extend(await engine.process(resolved))
    assert fired == []


# ---------------------------------------------------------------------------
# CORR-002 — credential dumping then lateral movement
# ---------------------------------------------------------------------------


def _dumping_chain(tenant: str, *, host: str = "srv01", spread: float = 5.0) -> list[dict]:
    return [
        _detection(
            tenant,
            rule_id="WIN-003",
            minutes=0,
            entity={"hostname": host},
            hostname=host,
        ),
        _event(tenant, minutes=spread, event_code="7045", hostname=host),
    ]


async def test_corr_002_fires_on_dumping_then_service_installation() -> None:
    tenant = str(uuid.uuid4())
    fired = await _play(_engine("CORR-002"), _dumping_chain(tenant))

    assert len(fired) == 1
    assert fired[0].entity == {"hostname": "srv01"}
    assert fired[0].risk_score == 95


async def test_corr_002_also_accepts_a_remote_logon_as_the_second_stage() -> None:
    tenant = str(uuid.uuid4())
    chain = _dumping_chain(tenant)
    chain[1] = _event(
        tenant,
        minutes=5,
        event_code="4624",
        hostname="srv01",
        authentication={"outcome": "success", "logon_type": "3"},
    )
    assert len(await _play(_engine("CORR-002"), chain)) == 1


async def test_corr_002_does_not_fire_on_an_interactive_logon() -> None:
    """Logon type 2 is someone at the keyboard, not the lateral movement
    this rule is about."""
    tenant = str(uuid.uuid4())
    chain = _dumping_chain(tenant)
    chain[1] = _event(
        tenant,
        minutes=5,
        event_code="4624",
        hostname="srv01",
        authentication={"outcome": "success", "logon_type": "2"},
    )
    assert await _play(_engine("CORR-002"), chain) == []


async def test_corr_002_does_not_chain_across_hosts() -> None:
    tenant = str(uuid.uuid4())
    chain = _dumping_chain(tenant)
    chain[1] = _event(tenant, minutes=5, event_code="7045", hostname="unrelated-host")
    assert await _play(_engine("CORR-002"), chain) == []


async def test_corr_002_does_not_fire_beyond_its_window() -> None:
    tenant = str(uuid.uuid4())
    assert await _play(_engine("CORR-002"), _dumping_chain(tenant, spread=90)) == []


# ---------------------------------------------------------------------------
# CORR-003 — document execution then persistence
# ---------------------------------------------------------------------------


def _phishing_chain(tenant: str, *, host: str = "wks42", spread: float = 2.0) -> list[dict]:
    return [
        _detection(tenant, rule_id="WIN-005", minutes=0, entity={"hostname": host}, hostname=host),
        _detection(
            tenant, rule_id="WIN-002", minutes=spread, entity={"hostname": host}, hostname=host
        ),
        _event(
            tenant,
            minutes=spread * 2,
            hostname=host,
            command_line="schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc minute",
        ),
    ]


async def test_corr_003_fires_on_document_to_payload_to_persistence() -> None:
    tenant = str(uuid.uuid4())
    fired = await _play(_engine("CORR-003"), _phishing_chain(tenant))

    assert len(fired) == 1
    assert fired[0].stages_matched == [
        "document_spawned_interpreter",
        "payload_staging",
        "persistence",
    ]
    assert set(fired[0].mitre_attack) >= {"T1566", "T1547.001"}


async def test_corr_003_does_not_fire_on_the_document_alone() -> None:
    tenant = str(uuid.uuid4())
    assert await _play(_engine("CORR-003"), _phishing_chain(tenant)[:2]) == []


async def test_corr_003_does_not_fire_when_persistence_precedes_the_document() -> None:
    tenant = str(uuid.uuid4())
    chain = _phishing_chain(tenant)
    early_persistence = {
        **chain[2],
        "timestamp": (T0 - timedelta(minutes=5)).isoformat(),
        "ingestion_timestamp": (T0 - timedelta(minutes=5)).isoformat(),
    }
    assert await _play(_engine("CORR-003"), [early_persistence, chain[0], chain[1]]) == []


# ---------------------------------------------------------------------------
# Pack hygiene
# ---------------------------------------------------------------------------


def test_the_shipped_correlation_pack_loads_cleanly() -> None:
    result = load_correlation_rules(RULES_ROOT)
    assert result.errors == []
    assert result.warnings == []
    assert len(result.rules) >= 3


def test_every_shipped_correlation_rule_is_documented_and_enabled() -> None:
    for rule in RULES.values():
        assert rule.status.value == "enabled", rule.correlation_id
        assert rule.false_positive_notes.strip(), rule.correlation_id
        assert rule.investigation_steps.strip(), rule.correlation_id
        assert rule.mitre_attack, rule.correlation_id
        assert rule.references, rule.correlation_id
        # Without suppression a completed chain re-fires on every further
        # input for that entity until its window rolls off.
        assert rule.suppression is not None, rule.correlation_id


def test_every_shipped_correlation_rule_has_a_scenario_test() -> None:
    tested = Path(__file__).read_text()
    for correlation_id in RULES:
        assert correlation_id.lower().replace("-", "_") in tested, correlation_id


def test_detection_rules_referenced_by_the_pack_actually_exist() -> None:
    """A stage keyed on a detection rule id that no longer ships is a chain
    that can never complete — and nothing else would notice."""
    from app.detection.loader import load_rules

    shipped = {rule.rule_id for rule in load_rules(RULES_ROOT).rules}
    referenced: set[str] = set()

    def walk(node: Any) -> None:
        group = getattr(node, "all_of", None) or getattr(node, "any_of", None)
        if group:
            for child in group:
                walk(child)
            return
        if getattr(node, "not_of", None) is not None:
            walk(node.not_of)
            return
        if getattr(node, "field_path", None) == "detection.rule_id":
            value = node.value
            referenced.update(value if isinstance(value, list) else [value])

    for rule in RULES.values():
        for stage in rule.stages:
            walk(stage.conditions)

    assert referenced, "no correlation stage references a detection rule"
    assert referenced <= shipped, f"unknown detection rules referenced: {referenced - shipped}"
