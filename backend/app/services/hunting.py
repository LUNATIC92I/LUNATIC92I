"""Threat hunting orchestration (spec §15): search execution, saved-hunt
CRUD, and export.

Search and pivots run as the service account against `events-normalized-*`
(THREAT_MODEL.md §3.2), so the `tenant_id` term `app.hunting.query.build_query`
and `app.hunting.pivots` compile in is the isolation boundary for this path —
the same trust model the detection and correlation engines already use.

Export is the one action here with a materially different risk: a hunting
tool that can return everything an analyst is scoped to see, all at once, in
a downloadable file, is also a data-exfiltration path if that action itself
goes unwatched (THREAT_MODEL.md §3.7). It is therefore capped in size,
rate-limited per tenant, and audit-logged (`EXPORT_DATA`) — the same review
item the ingestion service's rate limiter and the asset service's audit
trail both exist to satisfy elsewhere.
"""

import csv
import io
import json
import time
import uuid
from typing import Any

import redis.asyncio as aioredis
from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import NotFoundError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.core.config import get_settings
from app.core.metrics import hunt_exports_total, hunt_searches_total
from app.hunting.pivots import EVENT_FIELDS
from app.hunting.query import build_query
from app.models.hunting import SavedHunt
from app.schemas.hunting import ExportRequest, HuntQuery
from app.services.index_management import NORMALIZED_ALIAS


class SavedHuntNotFound(LookupError):
    pass


class ExportRateLimited(Exception):
    pass


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


async def execute_search(
    client: AsyncOpenSearch,
    *,
    tenant_id: uuid.UUID,
    query: HuntQuery,
    limit: int,
) -> tuple[int, list[dict[str, Any]]]:
    """Runs a hunt query and returns `(total, events)`. `total` is the
    cluster's full match count, which can exceed `len(events)` — the
    response tells an analyst there is more, rather than silently
    truncating."""
    body = {
        "size": limit,
        "query": build_query(
            tenant_id=str(tenant_id),
            free_text=query.free_text,
            filters=query.filters,
            since=query.since,
            until=query.until,
        ),
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": list(EVENT_FIELDS),
    }
    hunt_searches_total.inc()
    try:
        response = await client.search(index=NORMALIZED_ALIAS, body=body)
    except NotFoundError:
        return 0, []

    hits = response.get("hits", {})
    total = int(hits.get("total", {}).get("value", 0))
    events = [hit["_source"] for hit in hits.get("hits", [])]
    return total, events


# ---------------------------------------------------------------------------
# Saved hunts
# ---------------------------------------------------------------------------


async def list_saved_hunts(db: AsyncSession, tenant_id: uuid.UUID) -> list[SavedHunt]:
    stmt = (
        select(SavedHunt)
        .where(SavedHunt.tenant_id == tenant_id)
        .order_by(SavedHunt.name)
    )
    return list((await db.execute(stmt)).scalars())


async def get_saved_hunt(db: AsyncSession, tenant_id: uuid.UUID, hunt_id: uuid.UUID) -> SavedHunt:
    stmt = select(SavedHunt).where(SavedHunt.tenant_id == tenant_id, SavedHunt.id == hunt_id)
    hunt = (await db.execute(stmt)).scalar_one_or_none()
    if hunt is None:
        raise SavedHuntNotFound(str(hunt_id))
    return hunt


async def create_saved_hunt(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    name: str,
    description: str | None,
    query: HuntQuery,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> SavedHunt:
    hunt = SavedHunt(
        tenant_id=tenant_id,
        name=name,
        description=description,
        query=query.model_dump(mode="json", by_alias=True),
        created_by=actor_id,
    )
    db.add(hunt)
    await db.flush()
    await db.refresh(hunt)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="CREATE_SAVED_HUNT",
        object_type="saved_hunt",
        object_id=str(hunt.id),
        after_state={"name": name, "query": hunt.query},
        result="success",
    )
    return hunt


async def update_saved_hunt(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    hunt_id: uuid.UUID,
    name: str | None,
    description: str | None,
    query: HuntQuery | None,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> SavedHunt:
    hunt = await get_saved_hunt(db, tenant_id, hunt_id)
    before = {"name": hunt.name, "description": hunt.description, "query": hunt.query}
    if name is not None:
        hunt.name = name
    if description is not None:
        hunt.description = description
    if query is not None:
        hunt.query = query.model_dump(mode="json", by_alias=True)
    await db.flush()
    await db.refresh(hunt)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="UPDATE_SAVED_HUNT",
        object_type="saved_hunt",
        object_id=str(hunt.id),
        before_state=before,
        after_state={"name": hunt.name, "description": hunt.description, "query": hunt.query},
        result="success",
    )
    return hunt


async def delete_saved_hunt(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    hunt_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> None:
    hunt = await get_saved_hunt(db, tenant_id, hunt_id)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="DELETE_SAVED_HUNT",
        object_type="saved_hunt",
        object_id=str(hunt.id),
        before_state={"name": hunt.name, "query": hunt.query},
        result="success",
    )
    await db.delete(hunt)
    await db.flush()


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


async def _within_export_rate_limit(redis: aioredis.Redis, tenant_id: uuid.UUID) -> bool:
    # Fixed-window counter, same shape as the ingestion rate limiter
    # (app/services/ingestion.py::_within_rate_limit) — simple and
    # predictable, at the cost of allowing up to 2x the quota across a
    # window boundary, which is an acceptable trade for a coarse
    # anti-exfiltration control on an infrequent action.
    window = int(time.time() // 3600)
    key = f"hunt:export:ratelimit:{tenant_id}:{window}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 7200)
    limit = get_settings().hunt_export_rate_limit_per_hour
    return bool(count <= limit)


def _rows_to_csv(events: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(EVENT_FIELDS), extrasaction="ignore")
    writer.writeheader()
    for event in events:
        # Nested fields (user, process, hash) are objects; a CSV cell is
        # flat, so they are rendered as compact JSON rather than dropped —
        # an analyst opening the file in a spreadsheet still sees the value,
        # just not exploded into extra columns.
        row = {
            field: (
                _compact_json(event[field])
                if isinstance(event.get(field), dict | list)
                else event.get(field, "")
            )
            for field in EVENT_FIELDS
        }
        writer.writerow(row)
    return buffer.getvalue()


def _compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)


async def export_hunt(
    db: AsyncSession,
    redis: aioredis.Redis,
    client: AsyncOpenSearch,
    *,
    tenant_id: uuid.UUID,
    request: ExportRequest,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> tuple[str, str]:
    """Returns `(content, content_type)`. Raises `ExportRateLimited` if the
    tenant's hourly export quota is spent — checked and audit-logged before
    the search even runs, so a rejected export still leaves a trail. Like
    every other service in this codebase, this does not commit; the caller
    commits once, in the API layer, whichever branch is taken."""
    settings = get_settings()
    if not await _within_export_rate_limit(redis, tenant_id):
        hunt_exports_total.labels(format=request.format, outcome="rate_limited").inc()
        await record_audit_event(
            db,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_ip=actor_ip,
            action="EXPORT_DATA",
            object_type="hunt_export",
            result="failure",
            after_state={"reason": "rate_limited", "format": request.format},
        )
        raise ExportRateLimited(
            f"export quota of {settings.hunt_export_rate_limit_per_hour}/hour exceeded"
        )

    max_rows = min(request.max_rows or settings.hunt_export_max_rows, settings.hunt_export_max_rows)
    total, events = await execute_search(
        client,
        tenant_id=tenant_id,
        query=HuntQuery(
            free_text=request.free_text,
            filters=request.filters,
            since=request.since,
            until=request.until,
        ),
        limit=max_rows,
    )

    hunt_exports_total.labels(format=request.format, outcome="success").inc()
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="EXPORT_DATA",
        object_type="hunt_export",
        result="success",
        after_state={
            "format": request.format,
            "rows_exported": len(events),
            "total_matched": total,
        },
    )

    if request.format == "csv":
        return _rows_to_csv(events), "text/csv"

    return json.dumps({"total": total, "events": events}, default=str), "application/json"
