"""Concrete enrichment providers (spec §5 pipeline step).

Scope note: UEBA user-risk is a later phase and plugs in here as one more
provider with no change to the pipeline. What ships today: network context
derived from the event itself (Phase 5), the asset inventory (Phase 5, and
the highest-weighted risk input), and indicator matching against the threat
intelligence set (Phase 9).
"""

import ipaddress
import uuid
from typing import Any, ClassVar

from sqlalchemy import or_, select

from app.core import metrics
from app.core.db import tenant_scoped_session
from app.enrichment.base import EnrichmentProvider, EnrichmentResult
from app.models.assets import Asset
from app.services.threat_intel import match as match_indicators
from app.threat_intel.normalize import observables_from_event


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


class IocMatchProvider(EnrichmentProvider):
    """Matches the event's observables against the indicator set (spec §11).

    What it writes is deliberately not a boolean. Each match carries its
    classification, its confidence and its source, because the risk engine
    scales an indicator's contribution by that confidence (Phase 8) and an
    analyst has to be able to see who is making the claim — a 40%-confidence
    hit from a bulk blocklist and a 95%-confidence hit from incident
    response are not the same finding.

    A single query per event covers every observable; expired indicators are
    filtered in that query, so an indicator stops matching the moment it
    lapses rather than when some sweeper next runs.
    """

    name: ClassVar[str] = "ioc_match"

    async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
        tenant_id = document.get("tenant_id")
        if not tenant_id:
            return EnrichmentResult()

        observables = observables_from_event(document)
        if not observables:
            return EnrichmentResult()

        async with tenant_scoped_session(uuid.UUID(str(tenant_id))) as db:
            matches = await match_indicators(db, uuid.UUID(str(tenant_id)), observables)

        # An empty list is a real result, not an absent one: "we looked and
        # found nothing" is what lets the risk engine score the threat-intel
        # factor as available-and-zero instead of unknown (Phase 8).
        if not matches:
            return EnrichmentResult(fields={"ioc_matches": []})

        worst = max(matches, key=lambda item: _CLASSIFICATION_RANK.get(item["classification"], 0))
        metrics.ioc_matches_total.labels(classification=worst["classification"]).inc()
        return EnrichmentResult(
            fields={
                "ioc_matches": matches,
                "risk_context": {"ioc_classification": worst["classification"]},
            }
        )


_CLASSIFICATION_RANK = {"benign": 0, "unknown": 1, "suspicious": 2, "malicious": 3}


def _is_private(value: Any) -> bool | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return address.is_private or address.is_loopback or address.is_link_local
