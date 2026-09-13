"""Indicator lifecycle: create, amend, expire, and record who changed what.

Spec §11's hard rule governs this whole module: **an indicator is never
automatically malicious just because it came from a feed**. That is enforced
in three places rather than asserted once —

1. the database refuses a malicious/suspicious row with no source
   (`ck_iocs_source_required`);
2. a feed sync may only write the classification and confidence the feed
   itself asserted, defaulting to `unknown`/50 when it asserts nothing
   (`upsert_from_feed`);
3. the risk engine scales an indicator's contribution by that recorded
   confidence (Phase 8), so a low-confidence feed claim moves a score a
   little and a high-confidence analyst judgement moves it a lot.

Expiry is not a background job. Every read path filters on `expires_at`, so
an indicator stops matching the moment it lapses even if nothing has swept
the table — a sweeper that fails silently would otherwise keep stale
intelligence alive, which is how a SOC ends up chasing an IP that was
reassigned to a CDN six months ago.
"""

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.core import metrics
from app.models.threat_intel import Ioc, IocHistory
from app.threat_intel.normalize import canonicalize

# Feed-sourced indicators expire unless the feed says otherwise. Intel is
# perishable and a feed that stops publishing an indicator is making a
# statement; without a default TTL the platform would accumulate claims
# nobody stands behind any more.
DEFAULT_FEED_TTL_DAYS = 30

# Fields whose change is worth a history row of its own.
TRACKED_FIELDS = ("classification", "confidence", "source", "expires_at", "tags", "description")


class IocNotFound(LookupError):
    pass


@dataclass(frozen=True)
class FeedIndicator:
    """One indicator as a feed asserts it.

    `classification` and `confidence` are optional on purpose: a feed that
    publishes a bare list of addresses is asserting "I saw this", not "this
    is malicious", and the difference has to survive into the database.
    """

    value: str
    ioc_type: str | None = None
    classification: str | None = None
    confidence: int | None = None
    description: str | None = None
    tags: Sequence[str] = ()
    expires_at: datetime | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _not_expired() -> Any:
    return or_(Ioc.expires_at.is_(None), Ioc.expires_at > _now())


def _visible_to(tenant_id: uuid.UUID | None) -> Any:
    """A tenant sees its own indicators and the shared feed ones. RLS
    enforces the same thing at the database; this keeps the SQL honest
    about intent and works for the sync path, which has no tenant."""
    if tenant_id is None:
        return Ioc.tenant_id.is_(None)
    return or_(Ioc.tenant_id == tenant_id, Ioc.tenant_id.is_(None))


async def list_iocs(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    ioc_type: str | None = None,
    include_expired: bool = False,
    limit: int = 200,
) -> list[Ioc]:
    stmt = select(Ioc).where(_visible_to(tenant_id))
    if ioc_type:
        stmt = stmt.where(Ioc.ioc_type == ioc_type)
    if not include_expired:
        stmt = stmt.where(_not_expired())
    stmt = stmt.order_by(Ioc.last_seen.desc()).limit(limit)
    return list((await db.execute(stmt)).scalars())


async def get_ioc(db: AsyncSession, tenant_id: uuid.UUID, ioc_id: uuid.UUID) -> Ioc:
    stmt = select(Ioc).where(Ioc.id == ioc_id, _visible_to(tenant_id))
    ioc = (await db.execute(stmt)).scalar_one_or_none()
    if ioc is None:
        raise IocNotFound(str(ioc_id))
    return ioc


async def create_ioc(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    value: str,
    ioc_type: str | None,
    classification: str,
    confidence: int,
    source: str,
    description: str | None,
    tags: Sequence[str],
    expires_at: datetime | None,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> Ioc:
    canonical, resolved_type = canonicalize(value, ioc_type)

    ioc = Ioc(
        tenant_id=tenant_id,
        ioc_type=resolved_type,
        value=canonical,
        classification=classification,
        confidence=confidence,
        source=source,
        description=description,
        tags=list(tags),
        expires_at=expires_at,
        created_by=actor_id,
    )
    db.add(ioc)
    await db.flush()
    await db.refresh(ioc)

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="CREATE_IOC",
        object_type="ioc",
        object_id=str(ioc.id),
        after_state={
            "value": canonical,
            "type": resolved_type,
            "classification": classification,
            "confidence": confidence,
            "source": source,
        },
        result="success",
    )
    return ioc


async def update_ioc(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    ioc_id: uuid.UUID,
    values: dict[str, Any],
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> Ioc:
    ioc = await get_ioc(db, tenant_id, ioc_id)
    if ioc.tenant_id is None:
        # A shared feed indicator is not this tenant's to edit; RLS would
        # refuse the write anyway, but a clear error beats a silent no-op.
        raise IocNotFound(str(ioc_id))

    before = {field: getattr(ioc, field) for field in TRACKED_FIELDS}
    for key, value in values.items():
        setattr(ioc, key, value)
    await db.flush()
    await db.refresh(ioc)

    for field in TRACKED_FIELDS:
        old, new = before[field], getattr(ioc, field)
        if old == new:
            continue
        db.add(
            IocHistory(
                ioc_id=ioc.id,
                tenant_id=ioc.tenant_id,
                changed_field=field,
                old_value=None if old is None else str(old),
                new_value=None if new is None else str(new),
                changed_by=actor_id,
            )
        )

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        # Its own action: reclassifying an indicator changes what fires and
        # how hard, so "who called this benign" must be directly searchable.
        action=(
            "RECLASSIFY_IOC"
            if before["classification"] != ioc.classification
            else "UPDATE_IOC"
        ),
        object_type="ioc",
        object_id=str(ioc.id),
        before_state={key: str(value) for key, value in before.items()},
        after_state={field: str(getattr(ioc, field)) for field in TRACKED_FIELDS},
        result="success",
    )
    return ioc


async def delete_ioc(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    ioc_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> None:
    ioc = await get_ioc(db, tenant_id, ioc_id)
    if ioc.tenant_id is None:
        raise IocNotFound(str(ioc_id))
    before = {"value": ioc.value, "type": ioc.ioc_type, "source": ioc.source}
    await db.delete(ioc)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="DELETE_IOC",
        object_type="ioc",
        object_id=str(ioc_id),
        before_state=before,
        result="success",
    )


async def history_for(
    db: AsyncSession, tenant_id: uuid.UUID, ioc_id: uuid.UUID
) -> list[IocHistory]:
    await get_ioc(db, tenant_id, ioc_id)  # 404s for another tenant's indicator
    stmt = (
        select(IocHistory)
        .where(IocHistory.ioc_id == ioc_id)
        .order_by(IocHistory.changed_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


async def match(
    db: AsyncSession, tenant_id: uuid.UUID | None, observables: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """Looks up canonicalized observables and returns the matches, each
    carrying its provenance.

    One query for the whole event rather than one per observable: this runs
    on the ingestion hot path, and the shape of this call is what decides
    whether intel matching is free or is the pipeline's bottleneck.
    """
    pairs = [(ioc_type, value) for ioc_type, values in observables.items() for value in values]
    if not pairs:
        return []

    stmt = select(Ioc).where(
        tuple_(Ioc.ioc_type, Ioc.value).in_(pairs),
        _visible_to(tenant_id),
        _not_expired(),
    )
    rows = list((await db.execute(stmt)).scalars())

    return [
        {
            "value": row.value,
            "type": row.ioc_type,
            # Both travel with the match because the risk engine scales the
            # contribution by them (Phase 8) and an analyst needs to know
            # who is making the claim.
            "classification": row.classification,
            "confidence": row.confidence,
            "source": row.source,
            "tags": list(row.tags),
            "ioc_id": str(row.id),
            "shared": row.tenant_id is None,
        }
        for row in rows
    ]


async def upsert_from_feed(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | None,
    source: str,
    indicators: Iterable[FeedIndicator],
    default_ttl_days: int = DEFAULT_FEED_TTL_DAYS,
) -> dict[str, int]:
    """Writes a feed's indicators, refreshing what already exists.

    A feed may only assert what it actually publishes: an indicator arriving
    with no classification is stored as `unknown` at confidence 50, never
    promoted to malicious (spec §11). Re-seeing an indicator refreshes
    `last_seen` and its expiry — that is how "the feed still stands behind
    this" is recorded — but never silently raises its classification.
    """
    now = _now()
    created = updated = skipped = 0

    for indicator in indicators:
        try:
            canonical, resolved_type = canonicalize(indicator.value, indicator.ioc_type)
        except ValueError:
            skipped += 1
            continue

        stmt = select(Ioc).where(
            Ioc.tenant_id.is_(None) if tenant_id is None else Ioc.tenant_id == tenant_id,
            Ioc.ioc_type == resolved_type,
            Ioc.value == canonical,
            Ioc.source == source,
        )
        existing = (await db.execute(stmt)).scalar_one_or_none()
        expires_at = indicator.expires_at or now + timedelta(days=default_ttl_days)

        if existing is None:
            db.add(
                Ioc(
                    tenant_id=tenant_id,
                    ioc_type=resolved_type,
                    value=canonical,
                    # Defaults chosen so an unqualified feed entry can never
                    # look like a confident malicious verdict.
                    classification=indicator.classification or "unknown",
                    confidence=indicator.confidence if indicator.confidence is not None else 50,
                    source=source,
                    description=indicator.description,
                    tags=list(indicator.tags),
                    first_seen=now,
                    last_seen=now,
                    expires_at=expires_at,
                )
            )
            created += 1
        else:
            existing.last_seen = now
            existing.expires_at = expires_at
            if indicator.classification:
                existing.classification = indicator.classification
            if indicator.confidence is not None:
                existing.confidence = indicator.confidence
            if indicator.tags:
                existing.tags = sorted({*existing.tags, *indicator.tags})
            updated += 1

    await db.flush()
    metrics.ioc_feed_indicators_total.labels(source=source, outcome="created").inc(created)
    metrics.ioc_feed_indicators_total.labels(source=source, outcome="updated").inc(updated)
    metrics.ioc_feed_indicators_total.labels(source=source, outcome="skipped").inc(skipped)
    return {"created": created, "updated": updated, "skipped": skipped}


async def purge_expired(db: AsyncSession, *, older_than_days: int = 90) -> int:
    """Removes indicators that lapsed a long time ago.

    Deliberately separate from expiry: expiry stops an indicator matching
    immediately (every read filters on it), while this only reclaims space
    afterwards. A purge that fails therefore degrades storage, never
    detection correctness.
    """
    cutoff = _now() - timedelta(days=older_than_days)
    stmt = delete(Ioc).where(and_(Ioc.expires_at.is_not(None), Ioc.expires_at < cutoff))
    result = await db.execute(stmt)
    # `rowcount` is on the DBAPI cursor result; SQLAlchemy's typing does not
    # expose it on the generic Result, hence the narrow cast rather than a
    # blanket ignore.
    return int(getattr(result, "rowcount", 0) or 0)


async def count_active(db: AsyncSession, tenant_id: uuid.UUID | None) -> int:
    stmt = select(func.count()).select_from(Ioc).where(_visible_to(tenant_id), _not_expired())
    return int((await db.execute(stmt)).scalar_one())
