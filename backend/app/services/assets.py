"""Asset inventory (spec §16), and the audit trail over it.

Every write here is audit-logged in the same transaction as the change,
because asset criticality is a risk-score input: someone who can quietly
downgrade the domain controller to LOW has turned down the alarm on the
most valuable machine in the estate without touching a single detection
rule (`docs/TECHNICAL_RISKS.md`, risk-input manipulation). The audit entry
records the before and after so that change is recoverable and attributable.
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.models.assets import Asset

# Fields whose change is worth recording in full. Kept explicit rather than
# dumping the whole row: an audit entry is read by a person.
_AUDITED_FIELDS = ("hostname", "criticality", "environment", "owner", "tags", "is_active")


class AssetNotFound(LookupError):
    pass


def _snapshot(asset: Asset) -> dict[str, Any]:
    return {field: getattr(asset, field) for field in _AUDITED_FIELDS}


async def list_assets(db: AsyncSession, tenant_id: uuid.UUID) -> list[Asset]:
    stmt = (
        select(Asset).where(Asset.tenant_id == tenant_id).order_by(Asset.hostname, Asset.created_at)
    )
    return list((await db.execute(stmt)).scalars())


async def get_asset(db: AsyncSession, tenant_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
    stmt = select(Asset).where(Asset.tenant_id == tenant_id, Asset.id == asset_id)
    asset = (await db.execute(stmt)).scalar_one_or_none()
    if asset is None:
        raise AssetNotFound(str(asset_id))
    return asset


async def create_asset(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    values: dict[str, Any],
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> Asset:
    asset = Asset(tenant_id=tenant_id, **values)
    db.add(asset)
    await db.flush()
    # Refreshed inside the tenant-scoped transaction, while the RLS GUC is
    # still set: created_at/updated_at are server defaults, and letting the
    # response serializer trigger a lazy load after the commit would run
    # that query with no tenant context and fail (the same interaction
    # documented in app/core/db.py).
    await db.refresh(asset)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="CREATE_ASSET",
        object_type="asset",
        object_id=str(asset.id),
        after_state=_snapshot(asset),
        result="success",
    )
    return asset


async def update_asset(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    values: dict[str, Any],
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> Asset:
    asset = await get_asset(db, tenant_id, asset_id)
    before = _snapshot(asset)

    for key, value in values.items():
        setattr(asset, key, value)

    await db.flush()
    await db.refresh(asset)
    after = _snapshot(asset)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        # Criticality changes get their own action so "who turned down the
        # alarm on this server, and when" is a question the audit log can
        # answer directly instead of by diffing every asset edit.
        action=(
            "CHANGE_ASSET_CRITICALITY"
            if before["criticality"] != after["criticality"]
            else "UPDATE_ASSET"
        ),
        object_type="asset",
        object_id=str(asset.id),
        before_state=before,
        after_state=after,
        result="success",
    )
    return asset


async def delete_asset(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    asset_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> None:
    asset = await get_asset(db, tenant_id, asset_id)
    before = _snapshot(asset)
    await db.delete(asset)
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="DELETE_ASSET",
        object_type="asset",
        object_id=str(asset_id),
        before_state=before,
        result="success",
    )
