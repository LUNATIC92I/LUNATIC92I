"""External-data worker: threat-intelligence feeds and the ATT&CK catalog.

Run with:  python -m app.workers.feed_worker

Separate from the pipeline workers on purpose: both jobs are long,
network-bound and failure-prone, and neither must be able to stall event
processing. Their worst failure mode is stale data, which the metrics, the
feed's own `last_sync_status` and the coverage page's `catalog_is_stale`
flag all make visible rather than silent.
"""

import asyncio
import contextlib
import logging
import signal

from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import async_session_factory
from app.core.logging import configure_logging
from app.mitre.importer import ImportError_, load_bundle, parse_bundle
from app.models.identity import Organization
from app.services.feeds import sync_shared_feeds, sync_tenant_feeds
from app.services.mitre import import_bundle, stale_import

logger = logging.getLogger(__name__)


async def refresh_attack_catalog() -> bool:
    """Re-imports ATT&CK when the stored catalog has aged out.

    MITRE ships several revisions a year, so a coverage page measured
    against a matrix from last year is measuring the wrong thing. The import
    is idempotent, so the only cost of running it again is the download.
    """
    settings = get_settings()
    if not settings.mitre_attack_source:
        return False

    async with async_session_factory() as db:
        if not await stale_import(db, max_age_days=settings.mitre_catalog_max_age_days):
            return False

    try:
        payload, source = await load_bundle(settings.mitre_attack_source)
        bundle = parse_bundle(payload)
    except ImportError_ as exc:
        # Loud, not fatal: an unreachable or malformed catalog leaves the
        # previous one in place, which is the safe degradation.
        logger.warning("attack catalog refresh failed", extra={"error": str(exc)})
        return False

    async with async_session_factory() as db:
        await import_bundle(db, bundle=bundle, source=source)
        await db.commit()
    logger.info("attack catalog refreshed", extra={"attack_version": bundle.attack_version})
    return True


async def sync_once() -> int:
    try:
        await refresh_attack_catalog()
    except Exception:  # noqa: BLE001  intel feeds must still run
        logger.exception("attack catalog refresh raised")

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
