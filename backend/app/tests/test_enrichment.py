"""Enrichment pipeline tests.

The behavior that matters is not "does enrichment add fields" — it is
"does a broken enrichment source stop events reaching the SOC". Every test
below is about the second question.
"""

import asyncio
import uuid
from typing import Any, ClassVar

from sqlalchemy import select

from app.core.db import async_session_factory, tenant_scoped_session
from app.enrichment.base import EnrichmentPipeline, EnrichmentProvider, EnrichmentResult
from app.enrichment.providers import AssetContextProvider, NetworkContextProvider
from app.models.assets import Asset
from app.models.identity import Organization


class _Working(EnrichmentProvider):
    name: ClassVar[str] = "working"

    async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
        return EnrichmentResult(fields={"added": "yes"})


class _Exploding(EnrichmentProvider):
    name: ClassVar[str] = "exploding"

    async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
        raise RuntimeError("upstream enrichment service is down")


class _Hanging(EnrichmentProvider):
    name: ClassVar[str] = "hanging"

    async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
        await asyncio.sleep(30)
        return EnrichmentResult(fields={"never": "arrives"})


async def test_a_failing_provider_does_not_lose_the_event() -> None:
    pipeline = EnrichmentPipeline((_Exploding(), _Working()))

    enriched = await pipeline.enrich({"event_id": "e1"})

    assert enriched["event_id"] == "e1"  # the event survives
    assert enriched["added"] == "yes"  # the healthy provider still contributed
    assert enriched["enrichment_partial"] is True
    assert enriched["enrichment_errors"] == ["exploding"]


async def test_a_hanging_provider_is_timed_out_rather_than_blocking_ingestion() -> None:
    """A slow enrichment source must degrade one field, not stall the
    pipeline — visibility matters most exactly when something is wrong."""
    pipeline = EnrichmentPipeline((_Hanging(), _Working()), timeout_seconds=0.05)

    started = asyncio.get_running_loop().time()
    enriched = await pipeline.enrich({"event_id": "e1"})
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 5.0, "pipeline waited for the hanging provider"
    assert enriched["added"] == "yes"
    assert enriched["enrichment_errors"] == ["hanging"]


async def test_healthy_pipeline_does_not_mark_events_partial() -> None:
    enriched = await EnrichmentPipeline((_Working(),)).enrich({"event_id": "e1"})

    assert "enrichment_partial" not in enriched
    assert "enrichment_errors" not in enriched


async def test_providers_run_concurrently_not_serially() -> None:
    """Latency must be the slowest provider, not the sum of all of them."""

    class _Slow(EnrichmentProvider):
        name: ClassVar[str] = "slow"

        async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
            await asyncio.sleep(0.1)
            return EnrichmentResult(fields={})

    pipeline = EnrichmentPipeline(tuple(_Slow() for _ in range(5)), timeout_seconds=5)

    started = asyncio.get_running_loop().time()
    await pipeline.enrich({"event_id": "e1"})
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 0.4, f"5 x 100ms providers took {elapsed:.2f}s — they ran serially"


async def test_nested_fields_from_two_providers_merge_instead_of_clobbering() -> None:
    class _A(EnrichmentProvider):
        name: ClassVar[str] = "a"

        async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
            return EnrichmentResult(fields={"asset": {"id": "asset-1"}})

    class _B(EnrichmentProvider):
        name: ClassVar[str] = "b"

        async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
            return EnrichmentResult(fields={"asset": {"criticality": "HIGH"}})

    enriched = await EnrichmentPipeline((_A(), _B())).enrich({"event_id": "e1"})

    assert enriched["asset"] == {"id": "asset-1", "criticality": "HIGH"}


# ---------------------------------------------------------------------------
# Concrete providers
# ---------------------------------------------------------------------------


async def test_network_context_classifies_private_and_public_addresses() -> None:
    result = await NetworkContextProvider().enrich(
        {"source_ip": "10.1.1.5", "destination_ip": "8.8.8.8"}
    )

    assert result.fields["geo"] == {"source_is_private": True, "destination_is_private": False}


async def test_network_context_is_silent_when_there_are_no_addresses() -> None:
    assert (await NetworkContextProvider().enrich({"event_id": "e1"})).fields == {}


async def _create_org_and_asset(**asset_kwargs: Any) -> uuid.UUID:
    async with async_session_factory() as db:
        org = Organization(name="Acme", slug=f"acme-{uuid.uuid4().hex[:8]}")
        db.add(org)
        await db.commit()
        tenant_id = org.id

    async with tenant_scoped_session(tenant_id) as db:
        db.add(Asset(tenant_id=tenant_id, **asset_kwargs))
        await db.commit()
    return tenant_id


async def test_asset_context_attaches_criticality_by_hostname() -> None:
    """Asset criticality is the Risk Engine's heaviest input: the same failed
    login means something different on a laptop and a domain controller."""
    tenant_id = await _create_org_and_asset(
        asset_type="server",
        hostname="dc01",
        criticality="CRITICAL",
        environment="production",
        owner="platform-team",
    )

    result = await AssetContextProvider().enrich(
        {"tenant_id": str(tenant_id), "hostname": "dc01"}
    )

    assert result.fields["asset"]["criticality"] == "CRITICAL"
    assert result.fields["asset"]["environment"] == "production"
    assert result.fields["risk_context"]["asset_criticality"] == "CRITICAL"
    assert result.fields["device"]["asset_id"] == result.fields["asset"]["id"]


async def test_asset_context_matches_on_source_ip_when_hostname_is_absent() -> None:
    tenant_id = await _create_org_and_asset(
        asset_type="endpoint", ip_address="10.1.1.50", criticality="LOW"
    )

    result = await AssetContextProvider().enrich(
        {"tenant_id": str(tenant_id), "source_ip": "10.1.1.50"}
    )

    assert result.fields["asset"]["criticality"] == "LOW"


async def test_asset_context_never_returns_another_tenants_asset() -> None:
    """An unknown host is normal; an unknown host wrongly labelled CRITICAL
    because another tenant owns that hostname would corrupt risk scoring
    across tenants."""
    other_tenant = await _create_org_and_asset(
        asset_type="server", hostname="shared-name", criticality="CRITICAL"
    )
    async with async_session_factory() as db:
        org = Organization(name="Globex", slug=f"globex-{uuid.uuid4().hex[:8]}")
        db.add(org)
        await db.commit()
        my_tenant = org.id

    result = await AssetContextProvider().enrich(
        {"tenant_id": str(my_tenant), "hostname": "shared-name"}
    )

    assert result.fields == {}
    # The other tenant's asset does exist — this is isolation, not absence.
    async with tenant_scoped_session(other_tenant) as db:
        assert await db.scalar(select(Asset).where(Asset.hostname == "shared-name")) is not None


async def test_asset_context_is_silent_for_unknown_hosts() -> None:
    tenant_id = await _create_org_and_asset(asset_type="server", hostname="known-host")

    result = await AssetContextProvider().enrich(
        {"tenant_id": str(tenant_id), "hostname": "never-seen-before"}
    )

    assert result.fields == {}
