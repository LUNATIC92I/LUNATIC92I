"""Feed synchronization.

A sync is: read what the source publishes, write it as indicators, and
record what happened on the feed row. The last part is not bookkeeping —
`last_synced_at` and `last_sync_status` are how an operator finds out that
their intelligence stopped updating three weeks ago. A feed that fails is
counted (`ioc_feed_sync_failures_total`) and recorded, never swallowed:
silently stale intel looks exactly like a quiet week.

Failures are isolated per feed. One source returning garbage, timing out, or
being refused by the egress guard must not stop the others from updating.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import metrics
from app.core.config import get_settings
from app.core.db import intel_sync_session, tenant_scoped_session
from app.models.threat_intel import IocFeed
from app.services.threat_intel import upsert_from_feed
from app.threat_intel.feeds.base import FeedError, build_connector

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SyncOutcome:
    feed: str
    ok: bool
    created: int = 0
    updated: int = 0
    skipped: int = 0
    error: str | None = None


async def sync_feed(db: AsyncSession, feed: IocFeed) -> SyncOutcome:
    settings = get_settings()
    try:
        connector = build_connector(
            connector_type=feed.connector_type,
            name=feed.name,
            config=dict(feed.config or {}),
            credential_ref=feed.credential_ref,
        )
        indicators = await connector.fetch()
    except FeedError as exc:
        return await _record_failure(db, feed, str(exc), reason="feed_error")
    except Exception as exc:  # noqa: BLE001  a connector bug must not stop the others
        logger.exception("feed connector raised", extra={"feed": feed.name})
        return await _record_failure(db, feed, f"connector error: {exc}", reason="connector_bug")

    counts = await upsert_from_feed(
        db,
        tenant_id=feed.tenant_id,
        source=feed.name,
        indicators=indicators,
        default_ttl_days=settings.threat_intel_default_ttl_days,
    )
    feed.last_synced_at = datetime.now(UTC)
    feed.last_sync_status = (
        f"ok: {counts['created']} new, {counts['updated']} refreshed, "
        f"{counts['skipped']} unparseable"
    )
    logger.info("feed synced", extra={"feed": feed.name, **counts})
    return SyncOutcome(
        feed=feed.name,
        ok=True,
        created=counts["created"],
        updated=counts["updated"],
        skipped=counts["skipped"],
    )


async def _record_failure(
    db: AsyncSession, feed: IocFeed, message: str, *, reason: str
) -> SyncOutcome:
    metrics.ioc_feed_sync_failures_total.labels(source=feed.name, reason=reason).inc()
    feed.last_synced_at = datetime.now(UTC)
    # Truncated: a connector can produce a very long error, and this column
    # is read by a human in a list view.
    feed.last_sync_status = f"failed: {message}"[:500]
    logger.warning("feed sync failed", extra={"feed": feed.name, "error": message})
    return SyncOutcome(feed=feed.name, ok=False, error=message)


async def sync_shared_feeds() -> list[SyncOutcome]:
    """Syncs the feeds that belong to no tenant, in the one session allowed
    to write shared indicators."""
    async with intel_sync_session() as db:
        stmt = select(IocFeed).where(IocFeed.tenant_id.is_(None), IocFeed.is_enabled.is_(True))
        feeds = list((await db.execute(stmt)).scalars())
        outcomes = [await sync_feed(db, feed) for feed in feeds]
        await db.commit()
    return outcomes


async def sync_tenant_feeds(tenant_id: uuid.UUID) -> list[SyncOutcome]:
    async with tenant_scoped_session(tenant_id) as db:
        stmt = select(IocFeed).where(IocFeed.tenant_id == tenant_id, IocFeed.is_enabled.is_(True))
        feeds = list((await db.execute(stmt)).scalars())
        outcomes = [await sync_feed(db, feed) for feed in feeds]
        await db.commit()
    return outcomes
