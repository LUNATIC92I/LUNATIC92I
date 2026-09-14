"""Syslog collector worker — a deployable process separate from the API
(ARCHITECTURE.md §3: the ingestion hot path never shares a failure domain
with the request/response API).

Run with:  python -m app.workers.syslog_collector

Configuration comes from the environment (12-factor). Because syslog is an
unauthenticated transport, a listener is bound to exactly one tenant and one
source-IP allowlist, both explicitly configured — there is no way to run
this "for all tenants" and let the payload decide who it belongs to, which
is precisely the spoofing risk THREAT_MODEL.md §3.1 describes.
"""

import asyncio
import logging
import signal
import uuid

from app.collectors.syslog import SyslogTCPCollector, SyslogUDPCollector
from app.core.config import get_settings
from app.core.eventbus import get_event_bus
from app.core.logging import configure_logging
from app.core.observability import redis_ready, start_observability_server
from app.core.redis import get_redis
from app.core.tracing import configure_tracing
from app.services.ingestion import IngestionService

logger = logging.getLogger(__name__)


async def run() -> None:
    configure_logging()
    configure_tracing()
    settings = get_settings()

    if not settings.syslog_tenant_id:
        raise RuntimeError("SYSLOG_TENANT_ID must be set to run the syslog collector worker")
    if not settings.syslog_allowed_source_cidrs:
        raise RuntimeError(
            "SYSLOG_ALLOWED_SOURCE_CIDRS must list the sources permitted to send syslog. "
            "It is intentionally required: an empty allowlist accepts nothing."
        )

    tenant_id = uuid.UUID(settings.syslog_tenant_id)
    allowed = [
        cidr.strip() for cidr in settings.syslog_allowed_source_cidrs.split(",") if cidr.strip()
    ]
    ingestion = IngestionService(bus=get_event_bus(), redis=get_redis())

    collectors = [
        SyslogUDPCollector(
            collector_id="syslog-udp",
            tenant_id=tenant_id,
            ingest=ingestion.ingest,
            allowed_source_cidrs=allowed,
            port=settings.syslog_udp_port,
        ),
        SyslogTCPCollector(
            collector_id="syslog-tcp",
            tenant_id=tenant_id,
            ingest=ingestion.ingest,
            allowed_source_cidrs=allowed,
            port=settings.syslog_tcp_port,
        ),
    ]

    for collector in collectors:
        await collector.start()
    obs = await start_observability_server(settings.metrics_port, ready_check=redis_ready)

    stop_requested = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_requested.set)

    logger.info("syslog collector worker running", extra={"tenant_id": str(tenant_id)})
    await stop_requested.wait()

    # Graceful shutdown (spec §25): stop accepting new data before exiting so
    # in-flight events finish rather than dying with the process.
    logger.info("shutting down syslog collector worker")
    for collector in collectors:
        await collector.stop()
    obs.close()
    await obs.wait_closed()


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
