import time
import uuid

import pytest
from httpx import AsyncClient

from app.collectors.rest import RestCollector
from app.core.eventbus import TOPIC_EVENTS_RAW, InMemoryEventBus
from app.core.redis import get_redis
from app.services.ingestion import IngestionService, IngestOutcome

_COLLECTOR = RestCollector(collector_id="test-collector")


def _event(tenant_id: uuid.UUID, payload: bytes):
    return _COLLECTOR.build_event(tenant_id=tenant_id, raw_payload=payload)


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


@pytest.fixture
def ingestion(bus: InMemoryEventBus) -> IngestionService:
    return IngestionService(bus=bus, redis=get_redis(), max_payload_bytes=1024)


async def test_accepts_and_publishes_event(
    ingestion: IngestionService, bus: InMemoryEventBus
) -> None:
    result = await ingestion.ingest(_event(uuid.uuid4(), b"a log line"))

    assert result.outcome is IngestOutcome.ACCEPTED
    [published] = await bus.peek(TOPIC_EVENTS_RAW)
    assert published.payload == b"a log line"
    assert published.headers["source_type"] == "rest"
    assert published.headers["content_hash"]


async def test_duplicate_event_is_deduplicated(
    ingestion: IngestionService, bus: InMemoryEventBus
) -> None:
    """A collector retrying after a network timeout must not double-count."""
    tenant_id = uuid.uuid4()
    first = await ingestion.ingest(_event(tenant_id, b"identical payload"))
    second = await ingestion.ingest(_event(tenant_id, b"identical payload"))

    assert first.outcome is IngestOutcome.ACCEPTED
    assert second.outcome is IngestOutcome.DUPLICATE
    assert len(await bus.peek(TOPIC_EVENTS_RAW)) == 1


async def test_identical_payloads_from_different_tenants_both_ingest(
    ingestion: IngestionService, bus: InMemoryEventBus
) -> None:
    await ingestion.ingest(_event(uuid.uuid4(), b"kernel: out of memory"))
    result = await ingestion.ingest(_event(uuid.uuid4(), b"kernel: out of memory"))

    assert result.outcome is IngestOutcome.ACCEPTED
    assert len(await bus.peek(TOPIC_EVENTS_RAW)) == 2


async def test_oversized_payload_is_dead_lettered_not_dropped(
    ingestion: IngestionService, bus: InMemoryEventBus
) -> None:
    result = await ingestion.ingest(_event(uuid.uuid4(), b"x" * 2048))

    assert result.outcome is IngestOutcome.DEAD_LETTERED
    assert await bus.peek(TOPIC_EVENTS_RAW) == []

    [dead] = await bus.peek(f"{TOPIC_EVENTS_RAW}.deadletter")
    assert dead.payload == b"x" * 2048  # the event itself is preserved, not discarded
    assert dead.headers["dead_letter_reason"] == "payload_too_large"


async def test_empty_payload_is_dead_lettered(
    ingestion: IngestionService, bus: InMemoryEventBus
) -> None:
    result = await ingestion.ingest(_event(uuid.uuid4(), b""))

    assert result.outcome is IngestOutcome.DEAD_LETTERED
    [dead] = await bus.peek(f"{TOPIC_EVENTS_RAW}.deadletter")
    assert dead.headers["dead_letter_reason"] == "empty_payload"


async def test_rate_limit_rejects_beyond_quota(bus: InMemoryEventBus) -> None:
    ingestion = IngestionService(bus=bus, redis=get_redis(), rate_limit_per_minute=3)
    tenant_id = uuid.uuid4()

    outcomes = [
        (await ingestion.ingest(_event(tenant_id, f"line {i}".encode()))).outcome for i in range(5)
    ]

    assert outcomes[:3] == [IngestOutcome.ACCEPTED] * 3
    assert outcomes[3:] == [IngestOutcome.RATE_LIMITED] * 2


async def test_rate_limit_is_per_tenant_not_global(bus: InMemoryEventBus) -> None:
    """One noisy tenant must not consume another tenant's quota
    (THREAT_MODEL.md §3.1)."""
    ingestion = IngestionService(bus=bus, redis=get_redis(), rate_limit_per_minute=2)
    noisy, quiet = uuid.uuid4(), uuid.uuid4()

    for i in range(4):
        await ingestion.ingest(_event(noisy, f"noise {i}".encode()))

    result = await ingestion.ingest(_event(quiet, b"a quiet tenant's log"))
    assert result.outcome is IngestOutcome.ACCEPTED


async def test_bus_failure_is_dead_lettered_and_does_not_poison_dedup(
    bus: InMemoryEventBus,
) -> None:
    """If publishing fails, the event must be dead-lettered AND its dedup
    claim released — otherwise a later retry of the same event would be
    silently swallowed as a 'duplicate' of something never ingested."""

    class _FailingBus(InMemoryEventBus):
        fail = True

        async def publish(self, topic: str, message):
            if self.fail and topic == TOPIC_EVENTS_RAW:
                raise RuntimeError("bus unavailable")
            return await super().publish(topic, message)

    failing_bus = _FailingBus()
    ingestion = IngestionService(bus=failing_bus, redis=get_redis())
    tenant_id = uuid.uuid4()

    first = await ingestion.ingest(_event(tenant_id, b"important event"))
    assert first.outcome is IngestOutcome.DEAD_LETTERED

    failing_bus.fail = False
    retry = await ingestion.ingest(_event(tenant_id, b"important event"))
    assert retry.outcome is IngestOutcome.ACCEPTED


async def test_ingestion_throughput_smoke(bus: InMemoryEventBus) -> None:
    """A smoke test, NOT a capacity claim (spec §24 forbids claiming a
    supported load without a real benchmark). It exists to catch an
    accidental order-of-magnitude regression in the hot path; the real
    numbers come from the Phase 18 load-test report.
    """
    ingestion = IngestionService(bus=bus, redis=get_redis(), rate_limit_per_minute=1_000_000)
    tenant_id = uuid.uuid4()
    events = [_event(tenant_id, f"event number {i}".encode()) for i in range(500)]

    started = time.perf_counter()
    for event in events:
        await ingestion.ingest(event)
    elapsed = time.perf_counter() - started

    assert len(await bus.peek(TOPIC_EVENTS_RAW, count=1000)) == 500
    # Deliberately loose: this asserts "not catastrophically slow", nothing more.
    assert elapsed < 30.0, f"500 events took {elapsed:.2f}s"


# ---------------------------------------------------------------------------
# Gateway API (authentication is the security boundary here)
# ---------------------------------------------------------------------------


async def _register_and_login(client: AsyncClient, slug: str = "acme") -> str:
    await client.post(
        "/auth/register-organization",
        json={
            "organization_name": "Acme",
            "organization_slug": slug,
            "admin_email": "admin@example.com",
            "admin_password": "Correct-Horse-Battery-Staple-1",
            "admin_full_name": "Admin",
        },
    )
    resp = await client.post(
        "/auth/login",
        json={
            "organization_slug": slug,
            "email": "admin@example.com",
            "password": "Correct-Horse-Battery-Staple-1",
        },
    )
    return str(resp.json()["access_token"])


async def test_ingest_requires_an_api_key(client: AsyncClient) -> None:
    resp = await client.post("/ingest/events", content=b"some log")
    assert resp.status_code == 401


async def test_ingest_rejects_a_forged_api_key(client: AsyncClient) -> None:
    forged = f"lsk_{uuid.uuid4()}_totally-made-up-key-value"
    resp = await client.post("/ingest/events", content=b"some log", headers={"X-API-Key": forged})
    assert resp.status_code == 401


async def test_ingest_rejects_a_malformed_api_key(client: AsyncClient) -> None:
    resp = await client.post(
        "/ingest/events", content=b"some log", headers={"X-API-Key": "not-a-key"}
    )
    assert resp.status_code == 401


async def test_end_to_end_key_issuance_then_ingest(client: AsyncClient) -> None:
    token = await _register_and_login(client)

    created = await client.post(
        "/api-keys", json={"name": "edge-forwarder"}, headers={"Authorization": f"Bearer {token}"}
    )
    assert created.status_code == 201, created.text
    api_key = created.json()["api_key"]

    ingested = await client.post(
        "/ingest/events",
        content=b"<34>Oct 11 22:14:15 host sshd: Failed password for root",
        headers={"X-API-Key": api_key},
    )
    assert ingested.status_code == 200, ingested.text
    assert ingested.json()["outcome"] == "accepted"


async def test_api_key_cannot_be_replayed_against_another_tenant(client: AsyncClient) -> None:
    """The tenant id in a key's prefix is routing information, not a claim
    to be trusted: swapping it must not let tenant A's key write into
    tenant B, because the stored hash covers the whole key string."""
    from sqlalchemy import select

    from app.core.db import async_session_factory
    from app.models.identity import Organization

    token = await _register_and_login(client, slug="acme")
    created = await client.post(
        "/api-keys", json={"name": "acme-forwarder"}, headers={"Authorization": f"Bearer {token}"}
    )
    acme_key = created.json()["api_key"]

    await client.post(
        "/auth/register-organization",
        json={
            "organization_name": "Globex",
            "organization_slug": "globex",
            "admin_email": "admin@globex.example.com",
            "admin_password": "Correct-Horse-Battery-Staple-1",
            "admin_full_name": "Admin",
        },
    )
    async with async_session_factory() as db:
        globex_id = await db.scalar(select(Organization.id).where(Organization.slug == "globex"))

    _prefix, _old_tenant, secret = acme_key.split("_", 2)
    repointed = f"lsk_{globex_id}_{secret}"

    resp = await client.post(
        "/ingest/events", content=b"cross-tenant attempt", headers={"X-API-Key": repointed}
    )
    assert resp.status_code == 401


async def test_revoked_api_key_is_rejected(client: AsyncClient) -> None:
    from datetime import UTC, datetime

    from sqlalchemy import select

    from app.core.db import async_session_factory, tenant_scoped_session
    from app.models.identity import ApiKey, Organization

    token = await _register_and_login(client)
    created = await client.post(
        "/api-keys", json={"name": "doomed"}, headers={"Authorization": f"Bearer {token}"}
    )
    api_key = created.json()["api_key"]

    async with async_session_factory() as db:
        tenant_id = await db.scalar(select(Organization.id).where(Organization.slug == "acme"))
    async with tenant_scoped_session(tenant_id) as db:
        row = await db.scalar(select(ApiKey).where(ApiKey.tenant_id == tenant_id))
        row.revoked_at = datetime.now(UTC)
        await db.commit()

    resp = await client.post(
        "/ingest/events", content=b"after revocation", headers={"X-API-Key": api_key}
    )
    assert resp.status_code == 401


async def test_issuing_an_api_key_requires_permission(client: AsyncClient) -> None:
    """A READ_ONLY analyst must not be able to mint a credential that can
    push events into the tenant."""
    from app.tests.test_auth_rbac import _create_user_with_role, _login

    register = await client.post(
        "/auth/register-organization",
        json={
            "organization_name": "Acme",
            "organization_slug": "acme",
            "admin_email": "admin@example.com",
            "admin_password": "Correct-Horse-Battery-Staple-1",
            "admin_full_name": "Admin",
        },
    )
    tenant_id = uuid.UUID(register.json()["organization_id"])
    await _create_user_with_role(
        tenant_id=tenant_id, email="readonly@example.com", role_name="READ_ONLY"
    )
    token = await _login(client, slug="acme", email="readonly@example.com")

    resp = await client.post(
        "/api-keys", json={"name": "sneaky"}, headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403
