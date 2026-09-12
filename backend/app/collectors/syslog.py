"""Syslog collectors (UDP and TCP), spec §5.

Syslog over UDP is unauthenticated and trivially spoofable — a fact of the
protocol, not something this code can fix (THREAT_MODEL.md §3.1 / §5). It is
supported because real estates still emit it, and it is contained by:

- a per-tenant source-IP allowlist that **fails closed** (an empty allowlist
  accepts nothing, rather than everything),
- a hard payload size cap, so one oversized datagram or an endless TCP line
  cannot exhaust worker memory,
- never parsing or evaluating the payload here — bytes go to the pipeline
  verbatim.

TLS syslog is the recommended production transport; that collector arrives
with the rest of the source integrations in later phases.
"""

import asyncio
import ipaddress
import logging
import uuid
from collections.abc import Awaitable, Callable
from typing import ClassVar

from app.collectors.base import ListenerCollector, RawIngestEvent

logger = logging.getLogger(__name__)

IngestCallback = Callable[[RawIngestEvent], Awaitable[object]]

DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024


class _SourceAllowlist:
    """Fails closed: no configured networks means no accepted sources."""

    def __init__(self, cidrs: list[str]) -> None:
        self._networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]

    def allows(self, source_ip: str | None) -> bool:
        if source_ip is None or not self._networks:
            return False
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return any(address in network for network in self._networks)


class _SyslogDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: "SyslogUDPCollector") -> None:
        self._collector = collector

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        # Fire-and-forget: a slow pipeline must never block the socket read
        # loop, or the kernel receive buffer overflows and datagrams vanish.
        task = asyncio.create_task(self._collector.handle_datagram(data, addr[0]))
        self._collector.track(task)


class SyslogUDPCollector(ListenerCollector):
    source_type: ClassVar[str] = "syslog_udp"

    def __init__(
        self,
        *,
        collector_id: str,
        tenant_id: uuid.UUID,
        ingest: IngestCallback,
        allowed_source_cidrs: list[str],
        # Binding all interfaces is intended: a collector exists to receive
        # from the network, and the security boundary here is the source-IP
        # allowlist above, not the bind address. Override per deployment
        # where a single interface is known.
        host: str = "0.0.0.0",  # noqa: S104  # nosec B104
        port: int = 5514,
        max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
    ) -> None:
        super().__init__(collector_id)
        self._tenant_id = tenant_id
        self._ingest = ingest
        self._allowlist = _SourceAllowlist(allowed_source_cidrs)
        self._host = host
        self._port = port
        self._max_payload_bytes = max_payload_bytes
        self._transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[object]] = set()

    def track(self, task: asyncio.Task[object]) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def handle_datagram(self, data: bytes, source_ip: str) -> None:
        if not self._allowlist.allows(source_ip):
            logger.warning(
                "rejected syslog datagram from non-allowlisted source",
                extra={"source_ip": source_ip, "collector_id": self.collector_id},
            )
            return
        if len(data) > self._max_payload_bytes:
            logger.warning(
                "rejected oversized syslog datagram",
                extra={"source_ip": source_ip, "size": len(data)},
            )
            return
        event = self.build_event(
            tenant_id=self._tenant_id, raw_payload=data, source_ip=source_ip
        )
        await self._ingest(event)

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _SyslogDatagramProtocol(self),
            local_addr=(self._host, self._port),
        )
        self._transport = transport
        logger.info("syslog UDP collector listening", extra={"port": self._port})

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()


class SyslogTCPCollector(ListenerCollector):
    source_type: ClassVar[str] = "syslog_tcp"

    def __init__(
        self,
        *,
        collector_id: str,
        tenant_id: uuid.UUID,
        ingest: IngestCallback,
        allowed_source_cidrs: list[str],
        # Binding all interfaces is intended: a collector exists to receive
        # from the network, and the security boundary here is the source-IP
        # allowlist above, not the bind address. Override per deployment
        # where a single interface is known.
        host: str = "0.0.0.0",  # noqa: S104  # nosec B104
        port: int = 5514,
        max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
    ) -> None:
        super().__init__(collector_id)
        self._tenant_id = tenant_id
        self._ingest = ingest
        self._allowlist = _SourceAllowlist(allowed_source_cidrs)
        self._host = host
        self._port = port
        self._max_payload_bytes = max_payload_bytes
        self._server: asyncio.Server | None = None

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else None
        try:
            if not self._allowlist.allows(source_ip):
                logger.warning(
                    "rejected syslog TCP connection from non-allowlisted source",
                    extra={"source_ip": source_ip},
                )
                return
            while True:
                try:
                    line = await reader.readuntil(b"\n")
                except asyncio.IncompleteReadError as exc:
                    line = exc.partial  # peer closed mid-line; keep what we got
                    if not line:
                        return
                except (asyncio.LimitOverrunError, ValueError):
                    # A peer streaming an endless line without a newline: drop
                    # the connection rather than buffering it into an OOM.
                    logger.warning(
                        "syslog TCP line exceeded size cap; closing connection",
                        extra={"source_ip": source_ip},
                    )
                    return

                payload = line.rstrip(b"\r\n")
                if payload:
                    event = self.build_event(
                        tenant_id=self._tenant_id, raw_payload=payload, source_ip=source_ip
                    )
                    await self._ingest(event)
                if reader.at_eof():
                    return
        finally:
            writer.close()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self.handle_client, self._host, self._port, limit=self._max_payload_bytes
        )
        logger.info("syslog TCP collector listening", extra={"port": self._port})

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
