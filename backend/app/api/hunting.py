"""Threat hunting API (spec §15 `/hunting`).

`hunt:read` sees saved hunts and the field allowlist; `hunt:execute` runs a
search, a pivot, a saved hunt, or an export; `hunt:write` creates, edits or
deletes a saved hunt. There is no separate `hunt:delete` action in the
permission catalog (app/auth/permissions.py), so deleting a saved hunt is
gated on `write` — the same choice already made for alerts and incidents.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.auth.dependencies import AuthContext, require_permission
from app.core.opensearch import get_opensearch
from app.core.redis import get_redis
from app.hunting.pivots import UnknownPivot, run_pivot
from app.hunting.query import InvalidHuntQuery, compile_filters, known_fields
from app.models.hunting import SavedHunt
from app.schemas.hunting import (
    ExportRequest,
    HuntFieldsResponse,
    HuntQuery,
    HuntSearchRequest,
    HuntSearchResponse,
    PivotRequest,
    PivotResponse,
    PivotValueCount,
    SavedHuntCreate,
    SavedHuntPublic,
    SavedHuntUpdate,
)
from app.services import hunting as service

router = APIRouter(prefix="/hunting", tags=["hunting"])


def _hunt_uuid(hunt_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(hunt_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "saved hunt not found") from exc


def _public(hunt: SavedHunt) -> SavedHuntPublic:
    return SavedHuntPublic(
        id=str(hunt.id),
        name=hunt.name,
        description=hunt.description,
        query=hunt.query,
        created_by=str(hunt.created_by) if hunt.created_by else None,
        created_at=hunt.created_at,
        updated_at=hunt.updated_at,
    )


def _validate_query(query: HuntQuery) -> None:
    """Raises 422 for a filter tree the query builder would otherwise
    refuse (unknown field, unsupported operator) — checked up front so a
    saved hunt's *contents* are validated at save time, not only when it is
    later run. Compiling and discarding the result is cheap and reuses the
    query builder's own checks instead of restating them here."""
    if query.filters is not None:
        try:
            compile_filters(query.filters)
        except InvalidHuntQuery as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@router.get("/fields", response_model=HuntFieldsResponse)
async def list_fields(
    ctx: AuthContext = Depends(require_permission("hunt", "read")),
) -> HuntFieldsResponse:
    return HuntFieldsResponse(fields=sorted(known_fields()))


@router.post("/search", response_model=HuntSearchResponse)
async def search(
    payload: HuntSearchRequest,
    ctx: AuthContext = Depends(require_permission("hunt", "execute")),
) -> HuntSearchResponse:
    _validate_query(payload)
    client = get_opensearch()
    total, events = await service.execute_search(
        client, tenant_id=ctx.user.tenant_id, query=payload, limit=payload.limit
    )
    return HuntSearchResponse(total=total, events=events)


@router.get("/saved", response_model=list[SavedHuntPublic])
async def list_saved(
    ctx: AuthContext = Depends(require_permission("hunt", "read")),
) -> list[SavedHuntPublic]:
    rows = await service.list_saved_hunts(ctx.db, ctx.user.tenant_id)
    return [_public(row) for row in rows]


@router.post("/saved", response_model=SavedHuntPublic, status_code=status.HTTP_201_CREATED)
async def create_saved(
    payload: SavedHuntCreate,
    ctx: AuthContext = Depends(require_permission("hunt", "write")),
) -> SavedHuntPublic:
    _validate_query(payload.query)
    hunt = await service.create_saved_hunt(
        ctx.db,
        tenant_id=ctx.user.tenant_id,
        name=payload.name,
        description=payload.description,
        query=payload.query,
        actor_id=ctx.user.id,
    )
    await ctx.db.commit()
    return _public(hunt)


@router.get("/saved/{hunt_id}", response_model=SavedHuntPublic)
async def get_saved(
    hunt_id: str,
    ctx: AuthContext = Depends(require_permission("hunt", "read")),
) -> SavedHuntPublic:
    try:
        hunt = await service.get_saved_hunt(ctx.db, ctx.user.tenant_id, _hunt_uuid(hunt_id))
    except service.SavedHuntNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "saved hunt not found") from exc
    return _public(hunt)


@router.patch("/saved/{hunt_id}", response_model=SavedHuntPublic)
async def update_saved(
    hunt_id: str,
    payload: SavedHuntUpdate,
    ctx: AuthContext = Depends(require_permission("hunt", "write")),
) -> SavedHuntPublic:
    if payload.query is not None:
        _validate_query(payload.query)
    try:
        hunt = await service.update_saved_hunt(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            hunt_id=_hunt_uuid(hunt_id),
            name=payload.name,
            description=payload.description,
            query=payload.query,
            actor_id=ctx.user.id,
        )
    except service.SavedHuntNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "saved hunt not found") from exc
    await ctx.db.commit()
    return _public(hunt)


@router.delete("/saved/{hunt_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_saved(
    hunt_id: str,
    ctx: AuthContext = Depends(require_permission("hunt", "write")),
) -> None:
    try:
        await service.delete_saved_hunt(
            ctx.db, tenant_id=ctx.user.tenant_id, hunt_id=_hunt_uuid(hunt_id), actor_id=ctx.user.id
        )
    except service.SavedHuntNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "saved hunt not found") from exc
    await ctx.db.commit()


@router.post("/saved/{hunt_id}/run", response_model=HuntSearchResponse)
async def run_saved(
    hunt_id: str,
    limit: int = 100,
    ctx: AuthContext = Depends(require_permission("hunt", "execute")),
) -> HuntSearchResponse:
    try:
        hunt = await service.get_saved_hunt(ctx.db, ctx.user.tenant_id, _hunt_uuid(hunt_id))
    except service.SavedHuntNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "saved hunt not found") from exc

    query = HuntQuery.model_validate(hunt.query)
    _validate_query(query)
    client = get_opensearch()
    total, events = await service.execute_search(
        client, tenant_id=ctx.user.tenant_id, query=query, limit=max(1, min(limit, 1000))
    )
    return HuntSearchResponse(total=total, events=events)


@router.post("/pivot", response_model=PivotResponse)
async def pivot(
    payload: PivotRequest,
    ctx: AuthContext = Depends(require_permission("hunt", "execute")),
) -> PivotResponse:
    client = get_opensearch()
    try:
        result = await run_pivot(
            client, payload.pivot, str(ctx.user.tenant_id), payload.value, limit=payload.limit
        )
    except UnknownPivot as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return PivotResponse(
        pivot=result.pivot,
        result_type=result.result_type,
        total=result.total,
        events=result.events,
        values=[PivotValueCount(value=v.value, count=v.count) for v in result.values],
    )


@router.post("/export")
async def export(
    payload: ExportRequest,
    ctx: AuthContext = Depends(require_permission("hunt", "execute")),
) -> Response:
    _validate_query(payload)
    client = get_opensearch()
    redis = get_redis()
    try:
        content, content_type = await service.export_hunt(
            ctx.db,
            redis,
            client,
            tenant_id=ctx.user.tenant_id,
            request=payload,
            actor_id=ctx.user.id,
        )
    except service.ExportRateLimited as exc:
        await ctx.db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(exc)) from exc
    await ctx.db.commit()
    extension = "csv" if payload.format == "csv" else "json"
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="hunt-export.{extension}"'},
    )
