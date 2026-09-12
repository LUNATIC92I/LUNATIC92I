import asyncio
import uuid

import pytest

from app.collectors.base import Collector, RawIngestEvent
from app.collectors.rest import RestCollector
from app.collectors.syslog import SyslogTCPCollector, SyslogUDPCollector, _SourceAllowlist


class _FakeIngest:
    def __init__(self) -> None:
        self.events: list[RawIngestEvent] = []

    async def __call__(self, event: RawIngestEvent) -> None:
        self.events.append(event)


def test_content_hash_and_idempotency_key_are_deterministic() -> None:
    tenant_id = uuid.uuid4()
    collector = RestCollector(collector_id="c1")

    first = collector.build_event(tenant_id=tenant_id, raw_payload=b"same bytes")
    second = collector.build_event(tenant_id=tenant_id, raw_payload=b"same bytes")

    assert first.content_hash == second.content_hash
    assert first.idempotency_key == second.idempotency_key


def test_idempotency_key_differs_across_tenants_for_identical_payloads() -> None:
    """Two tenants sending byte-identical logs is normal (same appliance
    model, same message). They must never deduplicate against each other."""
    collector = RestCollector(collector_id="c1")
    a = collector.build_event(tenant_id=uuid.uuid4(), raw_payload=b"kernel: oom")
    b = collector.build_event(tenant_id=uuid.uuid4(), raw_payload=b"kernel: oom")

    assert a.idempotency_key != b.idempotency_key


def test_different_payloads_produce_different_keys() -> None:
    collector = RestCollector(collector_id="c1")
    tenant_id = uuid.uuid4()
    a = collector.build_event(tenant_id=tenant_id, raw_payload=b"payload-a")
    b = collector.build_event(tenant_id=tenant_id, raw_payload=b"payload-b")

    assert a.idempotency_key != b.idempotency_key


def test_collectors_share_the_common_interface() -> None:
    assert issubclass(RestCollector, Collector)
    assert issubclass(SyslogUDPCollector, Collector)
    assert issubclass(SyslogTCPCollector, Collector)
    assert {RestCollector.source_type, SyslogUDPCollector.source_type, SyslogTCPCollector.source_type} == {
        "rest",
        "syslog_udp",
        "syslog_tcp",
    }


# ---------------------------------------------------------------------------
# Source allowlist (THREAT_MODEL.md §3.1 — unauthenticated syslog transport)
# ---------------------------------------------------------------------------


def test_empty_allowlist_denies_everything() -> None:
    """Fail closed. A misconfigured collector must accept nothing, not
    everything — the opposite default would silently expose a tenant's event
    stream to any host that can reach the port."""
    allowlist = _SourceAllowlist([])
    assert not allowlist.allows("10.0.0.1")
    assert not allowlist.allows("127.0.0.1")


def test_allowlist_matches_cidr_and_rejects_outsiders() -> None:
    allowlist = _SourceAllowlist(["10.0.0.0/8", "192.168.1.5/32"])
    assert allowlist.allows("10.4.5.6")
    assert allowlist.allows("192.168.1.5")
    assert not allowlist.allows("192.168.1.6")
    assert not allowlist.allows("8.8.8.8")
    assert not allowlist.allows(None)
    assert not allowlist.allows("not-an-ip")


# ---------------------------------------------------------------------------
# Syslog UDP
# ---------------------------------------------------------------------------


async def test_udp_collector_ingests_allowlisted_datagram() -> None:
    ingest = _FakeIngest()
    collector = SyslogUDPCollector(
        collector_id="syslog-udp",
        tenant_id=uuid.uuid4(),
        ingest=ingest,
        allowed_source_cidrs=["10.0.0.0/8"],
    )

    await collector.handle_datagram(b"<34>Oct 11 22:14:15 host su: failed", "10.1.2.3")

    assert len(ingest.events) == 1
    assert ingest.events[0].raw_payload == b"<34>Oct 11 22:14:15 host su: failed"
    assert ingest.events[0].source_ip == "10.1.2.3"
    assert ingest.events[0].source_type == "syslog_udp"


async def test_udp_collector_rejects_non_allowlisted_source() -> None:
    ingest = _FakeIngest()
    collector = SyslogUDPCollector(
        collector_id="syslog-udp",
        tenant_id=uuid.uuid4(),
        ingest=ingest,
        allowed_source_cidrs=["10.0.0.0/8"],
    )

    await collector.handle_datagram(b"spoofed", "203.0.113.9")

    assert ingest.events == []


async def test_udp_collector_rejects_oversized_datagram() -> None:
    ingest = _FakeIngest()
    collector = SyslogUDPCollector(
        collector_id="syslog-udp",
        tenant_id=uuid.uuid4(),
        ingest=ingest,
        allowed_source_cidrs=["10.0.0.0/8"],
        max_payload_bytes=100,
    )

    await collector.handle_datagram(b"x" * 101, "10.1.2.3")

    assert ingest.events == []


async def test_udp_collector_end_to_end_over_a_real_socket() -> None:
    ingest = _FakeIngest()
    collector = SyslogUDPCollector(
        collector_id="syslog-udp",
        tenant_id=uuid.uuid4(),
        ingest=ingest,
        allowed_source_cidrs=["127.0.0.0/8"],
        host="127.0.0.1",
        port=0,  # ask the OS for a free port
    )
    await collector.start()
    assert collector._transport is not None
    port = collector._transport.get_extra_info("sockname")[1]

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port)
    )
    try:
        transport.sendto(b"<13>real datagram")
        for _ in range(50):
            if ingest.events:
                break
            await asyncio.sleep(0.02)
    finally:
        transport.close()
        await collector.stop()

    assert [event.raw_payload for event in ingest.events] == [b"<13>real datagram"]


# ---------------------------------------------------------------------------
# Syslog TCP
# ---------------------------------------------------------------------------


@pytest.fixture
async def tcp_collector():
    ingest = _FakeIngest()
    collector = SyslogTCPCollector(
        collector_id="syslog-tcp",
        tenant_id=uuid.uuid4(),
        ingest=ingest,
        allowed_source_cidrs=["127.0.0.0/8"],
        host="127.0.0.1",
        port=0,
        max_payload_bytes=1024,
    )
    await collector.start()
    yield collector, ingest
    await collector.stop()


async def test_tcp_collector_splits_newline_delimited_events(tcp_collector) -> None:
    collector, ingest = tcp_collector
    port = collector._server.sockets[0].getsockname()[1]

    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"first message\nsecond message\n")
    await writer.drain()
    writer.close()
    await writer.wait_closed()

    for _ in range(50):
        if len(ingest.events) >= 2:
            break
        await asyncio.sleep(0.02)

    assert [event.raw_payload for event in ingest.events] == [b"first message", b"second message"]


async def test_tcp_collector_drops_connection_streaming_an_endless_line(tcp_collector) -> None:
    """A peer that never sends a newline must not be buffered into an OOM
    (THREAT_MODEL.md §3.1 DoS)."""
    collector, ingest = tcp_collector
    port = collector._server.sockets[0].getsockname()[1]

    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"x" * 4096)  # 4x the configured cap, no newline
        await writer.drain()
        await asyncio.sleep(0.2)
    except (ConnectionResetError, BrokenPipeError):
        pass  # the collector closing on us is the expected outcome
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass

    assert ingest.events == []
