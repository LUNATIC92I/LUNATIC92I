"""Pivot correctness (spec §15) against a real OpenSearch cluster.

A pivot is a claim about an aggregation or a sorted search — the same
reason `test_detection_rules_pack.py`'s windowed cases run against a real
cluster rather than a fake: asserting behaviour against a fake client would
only test the fake. Every pivot here is also checked for tenant isolation,
since pivots run as the service account (THREAT_MODEL.md §3.2) and a
cross-tenant leak in an aggregation is easy to miss in a superficial test.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.opensearch import get_opensearch
from app.hunting.pivots import UnknownPivot, run_pivot
from app.services.index_management import NORMALIZED_ALIAS, bootstrap_indices


@pytest.fixture(scope="session", autouse=True)
async def _bootstrap() -> None:
    await bootstrap_indices(get_opensearch())


async def _index(*documents: dict[str, Any]) -> None:
    client = get_opensearch()
    operations: list[dict[str, Any]] = []
    for document in documents:
        operations.append({"index": {"_index": NORMALIZED_ALIAS, "_id": document["event_id"]}})
        operations.append(document)
    response = await client.bulk(body=operations, refresh=True)
    assert not response["errors"], response


def _event(tenant_id: str, **overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "class": "network",
        "severity": "medium",
        "hostname": "host-a",
    }
    document.update(overrides)
    return document


async def test_ip_to_events_finds_both_source_and_destination_matches() -> None:
    tenant = str(uuid.uuid4())
    ip = "10.9.9.9"
    await _index(
        _event(tenant, source_ip=ip, hostname="host-a"),
        _event(tenant, destination_ip=ip, hostname="host-b"),
        _event(tenant, source_ip="10.9.9.10", hostname="host-c"),
    )
    result = await run_pivot(get_opensearch(), "ip_to_events", tenant, ip)
    assert result.total == 2
    assert {e["hostname"] for e in result.events} == {"host-a", "host-b"}


async def test_ip_to_events_is_newest_first() -> None:
    tenant = str(uuid.uuid4())
    ip = "10.9.9.11"
    await _index(
        _event(tenant, source_ip=ip, hostname="older", timestamp="2026-01-01T00:00:00+00:00"),
        _event(tenant, source_ip=ip, hostname="newer", timestamp="2026-01-02T00:00:00+00:00"),
    )
    result = await run_pivot(get_opensearch(), "ip_to_events", tenant, ip)
    assert [e["hostname"] for e in result.events] == ["newer", "older"]


async def test_ip_to_users_returns_distinct_users_not_raw_events() -> None:
    tenant = str(uuid.uuid4())
    ip = "10.9.9.12"
    await _index(
        _event(tenant, source_ip=ip, user={"name": "alice"}),
        _event(tenant, source_ip=ip, user={"name": "alice"}),
        _event(tenant, destination_ip=ip, user={"name": "bob"}),
    )
    result = await run_pivot(get_opensearch(), "ip_to_users", tenant, ip)
    assert result.result_type == "values"
    by_value = {v.value: v.count for v in result.values}
    assert by_value == {"alice": 2, "bob": 1}


async def test_ip_pivots_accept_case_insensitive_ipv6_without_400ing() -> None:
    # Regression test: an earlier version of _term() hardcoded
    # `case_insensitive: True` on every field including `ip`-typed ones,
    # which OpenSearch rejects outright (400). This exercises the exact
    # code path that broke.
    tenant = str(uuid.uuid4())
    await _index(_event(tenant, source_ip="10.9.9.13", hostname="host-z"))
    result = await run_pivot(get_opensearch(), "ip_to_events", tenant, "10.9.9.13")
    assert result.total == 1


async def test_user_to_hosts() -> None:
    tenant = str(uuid.uuid4())
    await _index(
        _event(tenant, user={"name": "carol"}, hostname="ws-1"),
        _event(tenant, user={"name": "carol"}, hostname="ws-2"),
        _event(tenant, user={"name": "dave"}, hostname="ws-3"),
    )
    result = await run_pivot(get_opensearch(), "user_to_hosts", tenant, "carol")
    assert {v.value for v in result.values} == {"ws-1", "ws-2"}


async def test_host_to_processes() -> None:
    tenant = str(uuid.uuid4())
    await _index(
        _event(tenant, hostname="dc01", process={"name": "cmd.exe"}),
        _event(tenant, hostname="dc01", process={"name": "powershell.exe"}),
        _event(tenant, hostname="dc02", process={"name": "notepad.exe"}),
    )
    result = await run_pivot(get_opensearch(), "host_to_processes", tenant, "dc01")
    assert {v.value for v in result.values} == {"cmd.exe", "powershell.exe"}


async def test_hash_to_events_matches_regardless_of_algorithm() -> None:
    tenant = str(uuid.uuid4())
    digest = "d41d8cd98f00b204e9800998ecf8427e"
    await _index(
        _event(tenant, hash={"md5": digest}, hostname="a"),
        _event(tenant, hash={"sha1": "unrelated"}, hostname="b"),
    )
    result = await run_pivot(get_opensearch(), "hash_to_events", tenant, digest)
    assert result.total == 1
    assert result.events[0]["hostname"] == "a"


async def test_domain_to_events_matches_exact_domain_and_url_substring() -> None:
    tenant = str(uuid.uuid4())
    await _index(
        _event(tenant, domain="evil.example.com", hostname="a"),
        _event(tenant, url="http://evil.example.com/payload", hostname="b"),
        _event(tenant, domain="benign.example.com", hostname="c"),
    )
    result = await run_pivot(get_opensearch(), "domain_to_events", tenant, "evil.example.com")
    assert {e["hostname"] for e in result.events} == {"a", "b"}


async def test_user_to_timeline_is_oldest_first() -> None:
    tenant = str(uuid.uuid4())
    await _index(
        _event(tenant, user={"name": "erin"}, hostname="second", timestamp="2026-02-02T00:00:00+00:00"),
        _event(tenant, user={"name": "erin"}, hostname="first", timestamp="2026-02-01T00:00:00+00:00"),
    )
    result = await run_pivot(get_opensearch(), "user_to_timeline", tenant, "erin")
    assert [e["hostname"] for e in result.events] == ["first", "second"]


async def test_pivots_are_tenant_scoped() -> None:
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    ip = "10.9.9.99"
    await _index(
        _event(tenant_a, source_ip=ip, hostname="a-host"),
        _event(tenant_b, source_ip=ip, hostname="b-host"),
    )
    result = await run_pivot(get_opensearch(), "ip_to_events", tenant_a, ip)
    assert result.total == 1
    assert result.events[0]["hostname"] == "a-host"


async def test_an_unknown_pivot_name_is_refused() -> None:
    with pytest.raises(UnknownPivot):
        await run_pivot(get_opensearch(), "not_a_pivot", str(uuid.uuid4()), "x")


async def test_an_empty_pivot_value_is_refused() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        await run_pivot(get_opensearch(), "ip_to_events", str(uuid.uuid4()), "   ")


async def test_a_pivot_with_no_matches_returns_an_empty_result_not_an_error() -> None:
    result = await run_pivot(get_opensearch(), "ip_to_events", str(uuid.uuid4()), "203.0.113.1")
    assert result.total == 0
    assert result.events == []
