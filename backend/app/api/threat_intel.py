"""Threat intelligence API (spec §22 `/iocs`).

Writes are permission-gated and audit-logged, and reclassification gets its
own audit action: an indicator's classification and confidence decide
whether an alert fires and how hard (Phase 8's risk factor reads both), so
downgrading one is as consequential as disabling a detection rule.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.auth.dependencies import AuthContext, require_permission
from app.models.threat_intel import Ioc
from app.schemas.threat_intel import (
    IocCreate,
    IocHistoryPublic,
    IocMatchRequest,
    IocMatchResult,
    IocPublic,
    IocUpdate,
)
from app.services import threat_intel as service
from app.threat_intel.normalize import InvalidIndicator, canonicalize

router = APIRouter(prefix="/iocs", tags=["threat-intelligence"])


def _public(ioc: Ioc) -> IocPublic:
    expires_at = ioc.expires_at
    return IocPublic(
        id=str(ioc.id),
        ioc_type=ioc.ioc_type,
        value=ioc.value,
        classification=ioc.classification,
        confidence=ioc.confidence,
        source=ioc.source,
        description=ioc.description,
        tags=list(ioc.tags),
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        expires_at=expires_at,
        is_expired=expires_at is not None and expires_at <= datetime.now(UTC),
        shared=ioc.tenant_id is None,
    )


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _ioc_uuid(ioc_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(ioc_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found") from exc


@router.get("", response_model=list[IocPublic])
async def list_iocs(
    ioc_type: str | None = Query(default=None),
    include_expired: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1000),
    ctx: AuthContext = Depends(require_permission("ioc", "read")),
) -> list[IocPublic]:
    rows = await service.list_iocs(
        ctx.db,
        ctx.user.tenant_id,
        ioc_type=ioc_type,
        include_expired=include_expired,
        limit=limit,
    )
    return [_public(row) for row in rows]


@router.get("/{ioc_id}", response_model=IocPublic)
async def get_ioc(
    ioc_id: str,
    ctx: AuthContext = Depends(require_permission("ioc", "read")),
) -> IocPublic:
    try:
        ioc = await service.get_ioc(ctx.db, ctx.user.tenant_id, _ioc_uuid(ioc_id))
    except service.IocNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found") from exc
    return _public(ioc)


@router.post("", response_model=IocPublic, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    payload: IocCreate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("ioc", "write")),
) -> IocPublic:
    try:
        ioc = await service.create_ioc(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            value=payload.value,
            ioc_type=payload.ioc_type,
            classification=payload.classification,
            confidence=payload.confidence,
            source=payload.source,
            description=payload.description,
            tags=payload.tags,
            expires_at=payload.expires_at,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except InvalidIndicator as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await ctx.db.commit()
    return _public(ioc)


@router.patch("/{ioc_id}", response_model=IocPublic)
async def update_ioc(
    ioc_id: str,
    payload: IocUpdate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("ioc", "write")),
) -> IocPublic:
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no fields to update")
    try:
        ioc = await service.update_ioc(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            ioc_id=_ioc_uuid(ioc_id),
            values=values,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.IocNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found") from exc
    await ctx.db.commit()
    return _public(ioc)


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(
    ioc_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("ioc", "delete")),
) -> None:
    try:
        await service.delete_ioc(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            ioc_id=_ioc_uuid(ioc_id),
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.IocNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found") from exc
    await ctx.db.commit()


@router.get("/{ioc_id}/history", response_model=list[IocHistoryPublic])
async def ioc_history(
    ioc_id: str,
    ctx: AuthContext = Depends(require_permission("ioc", "read")),
) -> list[IocHistoryPublic]:
    try:
        rows = await service.history_for(ctx.db, ctx.user.tenant_id, _ioc_uuid(ioc_id))
    except service.IocNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "indicator not found") from exc
    return [
        IocHistoryPublic(
            changed_field=row.changed_field,
            old_value=row.old_value,
            new_value=row.new_value,
            changed_by=str(row.changed_by) if row.changed_by else None,
            changed_at=row.changed_at,
        )
        for row in rows
    ]


@router.post("/match", response_model=list[IocMatchResult])
async def match_values(
    payload: IocMatchRequest,
    ctx: AuthContext = Depends(require_permission("ioc", "read")),
) -> list[IocMatchResult]:
    """Triage lookup: "are any of these known?". Values are canonicalized
    exactly as stored values are, so a defanged paste from a report
    (`1.2.3[.]4`) matches without the analyst having to clean it up."""
    observables: dict[str, list[str]] = {}
    for raw in payload.values:
        try:
            canonical, ioc_type = canonicalize(raw)
        except InvalidIndicator:
            # An unparseable value simply matches nothing; failing the whole
            # request because one line of a pasted list was noise would make
            # the endpoint useless for its actual use.
            continue
        observables.setdefault(ioc_type, []).append(canonical)

    matches = await service.match(ctx.db, ctx.user.tenant_id, observables)
    return [IocMatchResult(**item) for item in matches]
