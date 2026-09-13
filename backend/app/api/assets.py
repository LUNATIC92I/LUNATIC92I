"""Asset inventory API (spec §16, §22 `/assets`).

Read is separated from write, and both from delete, because this inventory
feeds the risk engine: an analyst needs to see an asset's criticality to
understand a score, but changing it changes every future score for that
machine. Every mutation is audit-logged by the service layer inside the
same transaction as the change.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth.dependencies import AuthContext, require_permission
from app.models.assets import Asset
from app.schemas.assets import AssetCreate, AssetPublic, AssetUpdate
from app.services import assets as service

router = APIRouter(prefix="/assets", tags=["assets"])


def _public(asset: Asset) -> AssetPublic:
    return AssetPublic(
        id=str(asset.id),
        asset_type=asset.asset_type,
        hostname=asset.hostname,
        ip_address=str(asset.ip_address) if asset.ip_address else None,
        mac_address=str(asset.mac_address) if asset.mac_address else None,
        os=asset.os,
        owner=asset.owner,
        department=asset.department,
        criticality=asset.criticality,
        environment=asset.environment,
        tags=list(asset.tags),
        is_active=asset.is_active,
        last_seen_at=asset.last_seen_at,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
    )


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _asset_uuid(asset_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(asset_id)
    except ValueError as exc:
        # 404 rather than 422: a malformed id and an id belonging to another
        # tenant must be indistinguishable from outside (THREAT_MODEL.md §3.2).
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found") from exc


@router.get("", response_model=list[AssetPublic])
async def list_assets(
    ctx: AuthContext = Depends(require_permission("asset", "read")),
) -> list[AssetPublic]:
    return [_public(asset) for asset in await service.list_assets(ctx.db, ctx.user.tenant_id)]


@router.get("/{asset_id}", response_model=AssetPublic)
async def get_asset(
    asset_id: str,
    ctx: AuthContext = Depends(require_permission("asset", "read")),
) -> AssetPublic:
    try:
        asset = await service.get_asset(ctx.db, ctx.user.tenant_id, _asset_uuid(asset_id))
    except service.AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found") from exc
    return _public(asset)


@router.post("", response_model=AssetPublic, status_code=status.HTTP_201_CREATED)
async def create_asset(
    payload: AssetCreate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset", "write")),
) -> AssetPublic:
    asset = await service.create_asset(
        ctx.db,
        tenant_id=ctx.user.tenant_id,
        values=payload.model_dump(),
        actor_id=ctx.user.id,
        actor_ip=_client_ip(request),
    )
    await ctx.db.commit()
    return _public(asset)


@router.patch("/{asset_id}", response_model=AssetPublic)
async def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset", "write")),
) -> AssetPublic:
    values = payload.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no fields to update")
    try:
        asset = await service.update_asset(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            asset_id=_asset_uuid(asset_id),
            values=values,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found") from exc
    await ctx.db.commit()
    return _public(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("asset", "delete")),
) -> None:
    try:
        await service.delete_asset(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            asset_id=_asset_uuid(asset_id),
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found") from exc
    await ctx.db.commit()
