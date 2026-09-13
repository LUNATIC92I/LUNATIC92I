"""Concrete enrichment providers (spec §5 pipeline step, Phase 5).

Scope note: threat-intel/IOC matching is Phase 9 and UEBA user-risk is
Phase 17 — both plug in here as additional providers with no change to the
pipeline. What ships now is the enrichment that has a real data source
today: the asset inventory built in Phase 2's schema, and network context
derivable from the event itself.
"""

import ipaddress
import uuid
from typing import Any, ClassVar

from sqlalchemy import or_, select

from app.core.db import tenant_scoped_session
from app.enrichment.base import EnrichmentProvider, EnrichmentResult
from app.models.assets import Asset


class NetworkContextProvider(EnrichmentProvider):
    """Derives context from the event's own addresses — no external calls,
    so it cannot fail or be slow.

    Public/private classification is genuinely useful signal: "internal host
    talked to internal host" and "internal host talked to the internet" are
    different detections, and later phases (beaconing, exfiltration) key off
    exactly this distinction.
    """

    name: ClassVar[str] = "network_context"

    async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
        geo: dict[str, Any] = {}
        source_private = _is_private(document.get("source_ip"))
        destination_private = _is_private(document.get("destination_ip"))
        if source_private is not None:
            geo["source_is_private"] = source_private
        if destination_private is not None:
            geo["destination_is_private"] = destination_private
        return EnrichmentResult(fields={"geo": geo} if geo else {})


class AssetContextProvider(EnrichmentProvider):
    """Attaches the asset's criticality and environment from the CMDB.

    This is the input the Risk Engine (Phase 8) weights most heavily: the
    same failed login means something different on a developer laptop and on
    a domain controller. Matching is by hostname first, then source IP.
    """

    name: ClassVar[str] = "asset_context"

    async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
        tenant_id = document.get("tenant_id")
        hostname = document.get("hostname")
        source_ip = document.get("source_ip")
        if not tenant_id or not (hostname or source_ip):
            return EnrichmentResult()

        conditions = []
        if hostname:
            conditions.append(Asset.hostname == hostname)
        if source_ip:
            conditions.append(Asset.ip_address == source_ip)

        async with tenant_scoped_session(uuid.UUID(str(tenant_id))) as db:
            asset = await db.scalar(select(Asset).where(or_(*conditions)).limit(1))
            if asset is None:
                return EnrichmentResult()
            return EnrichmentResult(
                fields={
                    "asset": {
                        "id": str(asset.id),
                        "criticality": asset.criticality,
                        "environment": asset.environment,
                        "owner": asset.owner,
                    },
                    "device": {"asset_id": str(asset.id)},
                    "risk_context": {"asset_criticality": asset.criticality},
                }
            )


def _is_private(value: Any) -> bool | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return address.is_private or address.is_loopback or address.is_link_local
