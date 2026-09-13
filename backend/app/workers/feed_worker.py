"""Threat-intelligence feed worker.

Run with:  python -m app.workers.feed_worker

Separate from the pipeline workers on purpose: a feed sync is a long,
network-bound, failure-prone operation, and it must never be able to stall
event processing. Its worst failure mode is stale intelligence, which the
metrics and the feed's own `last_sync_status` make visible.
"""

import asyncio
import contextlib
import logging
import signal

from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import async_session_factory
from app.core.logging import configure_logging
from app.models.identity import Organization
from app.services.feeds import sync_shared_feeds, sync_tenant_feeds

logger = logging.getLogger(__name__)


async def sync_once() -> int:
    outcomes = list(await sync_shared_feeds())

    async with async_session_factory() as db:
        stmt = select(Organization.id).where(Organization.is_active.is_(True))
        tenants = list((await db.execute(stmt)).scalars())

    for tenant_id in tenants:
        try:
            outcomes.extend(await sync_tenant_feeds(tenant_id))
        except Exception:  # noqa: BLE001  one tenant's feeds are not the others'
            logger.exception("tenant feed sync failed", extra={"tenant_id": str(tenant_id)})

    failures = [outcome for outcome in outcomes if not outcome.ok]
    logger.info(
        "feed sync pass complete",
        extra={"feeds": len(outcomes), "failed": len(failures)},
    )
    return len(outcomes)


async def run() -> None:
    configure_logging()
    interval = get_settings().threat_intel_feed_interval_seconds

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    logger.info("feed worker running", extra={"interval_seconds": interval})
    while not stop.is_set():
        try:
            await sync_once()
        except Exception:  # noqa: BLE001  the loop must outlive any single pass
            logger.exception("feed sync pass failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval)
    logger.info("feed worker stopped")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
