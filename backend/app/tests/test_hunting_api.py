"""The hunting API (spec §15 `/hunting`): search, saved hunts, pivots, and
export — RBAC-gated like every other route, DLS/tenant-scoped like every
other OpenSearch-backed one, and with export additionally rate-limited and
audit-logged (`EXPORT_DATA`, THREAT_MODEL.md §3.7's exfiltration concern).
"""

import csv
import io
import json
import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import tenant_scoped_session
from app.core.opensearch import get_opensearch
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.identity import Role, User, UserRole
from app.services.index_management import NORMALIZED_ALIAS, bootstrap_indices


async def _register(client: AsyncClient, slug: str, email: str = "admin@example.com") -> dict:
    resp = await client.post(
        "/auth/register-organization",
        json={
            "organization_name": f"Org {slug}",
            "organization_slug": slug,
            "admin_email": email,
            "admin_password": "Correct-Horse-Battery-Staple-1",
            "admin_full_name": "Admin Admin",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _login(client: AsyncClient, slug: str, email: str = "admin@example.com") -> dict:
    resp = await client.post(
        "/auth/login",
        json={"organization_slug": slug, "email": email, "password": "Correct-Horse-Battery-Staple-1"},
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def _user_with_role(tenant_id: uuid.UUID, email: str, role_name: str) -> uuid.UUID:
    async with tenant_scoped_session(tenant_id) as db:
        role = await db.scalar(select(Role).where(Role.name == role_name))
        assert role is not None
        user = User(
            tenant_id=tenant_id,
            email=email,
            password_hash=hash_password("Correct-Horse-Battery-Staple-1"),
            full_name="Test User",
        )
        db.add(user)
        await db.flush()
        db.add(UserRole(user_id=user.id, role_id=role.id, tenant_id=tenant_id))
        await db.commit()
        return user.id


async def _index_event(tenant_id: str, **overrides: object) -> str:
    client = get_opensearch()
    await bootstrap_indices(client)
    event_id = str(uuid.uuid4())
    document = {
        "event_id": event_id,
        "tenant_id": tenant_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "class": "network",
        "severity": "medium",
        "hostname": "host-a",
    }
    document.update(overrides)
    await client.index(index=NORMALIZED_ALIAS, id=event_id, body=document, refresh=True)
    return event_id


@pytest.fixture
async def tenant(client: AsyncClient):
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    return tenant_id, headers


@pytest.fixture(autouse=True)
def _clean_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


async def test_free_text_search_finds_a_matching_event(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), user={"name": "carol"})

    resp = await client.post("/hunting/search", headers=headers, json={"free_text": "carol"})
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


async def test_structured_filter_search(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), source_ip="10.4.4.4")

    resp = await client.post(
        "/hunting/search",
        headers=headers,
        json={"filters": {"field": "source_ip", "operator": "equals", "value": "10.4.4.4"}},
    )
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


async def test_an_unknown_field_in_a_filter_is_a_422(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/hunting/search",
        headers=headers,
        json={"filters": {"field": "not_a_field", "operator": "equals", "value": "x"}},
    )
    assert resp.status_code == 422


async def test_the_matches_operator_is_refused_in_a_hunt(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/hunting/search",
        headers=headers,
        json={"filters": {"field": "hostname", "operator": "matches", "value": ".*"}},
    )
    assert resp.status_code == 422


async def test_a_query_with_neither_free_text_nor_filters_is_rejected(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    resp = await client.post("/hunting/search", headers=headers, json={})
    assert resp.status_code == 422


async def test_hunting_fields_lists_the_searchable_allowlist(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.get("/hunting/fields", headers=headers)
    assert resp.status_code == 200
    assert "hostname" in resp.json()["fields"]


# ---------------------------------------------------------------------------
# Saved hunts
# ---------------------------------------------------------------------------


async def test_saved_hunt_crud_round_trip(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant

    created = await client.post(
        "/hunting/saved",
        headers=headers,
        json={"name": "Carol hunt", "description": "carol activity", "query": {"free_text": "carol"}},
    )
    assert created.status_code == 201
    hunt_id = created.json()["id"]

    listed = await client.get("/hunting/saved", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1

    fetched = await client.get(f"/hunting/saved/{hunt_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "Carol hunt"

    updated = await client.patch(
        f"/hunting/saved/{hunt_id}", headers=headers, json={"name": "Carol hunt v2"}
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Carol hunt v2"
    # The query is untouched by a name-only patch.
    assert updated.json()["query"]["free_text"] == "carol"

    deleted = await client.delete(f"/hunting/saved/{hunt_id}", headers=headers)
    assert deleted.status_code == 204

    gone = await client.get(f"/hunting/saved/{hunt_id}", headers=headers)
    assert gone.status_code == 404


async def test_saving_a_hunt_with_an_invalid_filter_is_refused_at_save_time(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/hunting/saved",
        headers=headers,
        json={
            "name": "bad hunt",
            "query": {"filters": {"field": "not_a_field", "operator": "equals", "value": "x"}},
        },
    )
    assert resp.status_code == 422


async def test_running_a_saved_hunt_executes_its_stored_query(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), hostname="dc01")
    created = await client.post(
        "/hunting/saved",
        headers=headers,
        json={
            "name": "dc01 hunt",
            "query": {"filters": {"field": "hostname", "operator": "equals", "value": "dc01"}},
        },
    )
    hunt_id = created.json()["id"]

    resp = await client.post(f"/hunting/saved/{hunt_id}/run", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


async def test_a_malformed_saved_hunt_id_is_indistinguishable_from_missing(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    assert (await client.get("/hunting/saved/not-a-uuid", headers=headers)).status_code == 404


# ---------------------------------------------------------------------------
# Pivots
# ---------------------------------------------------------------------------


async def test_pivot_endpoint_returns_matching_events(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), source_ip="10.7.7.7")

    resp = await client.post(
        "/hunting/pivot", headers=headers, json={"pivot": "ip_to_events", "value": "10.7.7.7"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result_type"] == "events"
    assert body["total"] == 1


async def test_pivot_endpoint_returns_distinct_values(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), source_ip="10.7.7.8", user={"name": "gina"})

    resp = await client.post(
        "/hunting/pivot", headers=headers, json={"pivot": "ip_to_users", "value": "10.7.7.8"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result_type"] == "values"
    assert body["values"] == [{"value": "gina", "count": 1}]


async def test_an_unknown_pivot_name_is_a_422(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/hunting/pivot", headers=headers, json={"pivot": "not_a_real_pivot", "value": "x"}
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Export: formats, rate limiting, audit trail
# ---------------------------------------------------------------------------


async def test_csv_export_has_a_header_row_and_one_row_per_event(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), user={"name": "hank"}, hostname="host-h")

    resp = await client.post(
        "/hunting/export", headers=headers, json={"free_text": "hank", "format": "csv"}
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(resp.text)))
    assert len(rows) == 1
    assert rows[0]["hostname"] == "host-h"
    # Nested fields are flattened to JSON, not silently dropped.
    assert json.loads(rows[0]["user"]) == {"name": "hank"}


async def test_json_export_carries_total_and_events(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), user={"name": "irene"})

    resp = await client.post(
        "/hunting/export", headers=headers, json={"free_text": "irene", "format": "json"}
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert body["total"] == 1
    assert body["events"][0]["user"]["name"] == "irene"


async def test_export_beyond_the_hourly_quota_is_rate_limited(
    client: AsyncClient, tenant, monkeypatch
) -> None:
    tenant_id, headers = tenant
    monkeypatch.setenv("HUNT_EXPORT_RATE_LIMIT_PER_HOUR", "1")
    get_settings.cache_clear()
    await _index_event(str(tenant_id), user={"name": "jack"})

    first = await client.post(
        "/hunting/export", headers=headers, json={"free_text": "jack", "format": "json"}
    )
    assert first.status_code == 200

    second = await client.post(
        "/hunting/export", headers=headers, json={"free_text": "jack", "format": "json"}
    )
    assert second.status_code == 429


async def test_every_export_is_audit_logged_including_rejections(
    client: AsyncClient, tenant, monkeypatch
) -> None:
    tenant_id, headers = tenant
    monkeypatch.setenv("HUNT_EXPORT_RATE_LIMIT_PER_HOUR", "1")
    get_settings.cache_clear()
    await _index_event(str(tenant_id), user={"name": "kate"})

    await client.post("/hunting/export", headers=headers, json={"free_text": "kate", "format": "csv"})
    await client.post("/hunting/export", headers=headers, json={"free_text": "kate", "format": "csv"})

    async with tenant_scoped_session(tenant_id) as db:
        rows = (
            await db.execute(
                select(AuditLog.result).where(AuditLog.action == "EXPORT_DATA")
            )
        ).scalars().all()
    assert sorted(rows) == ["failure", "success"]


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


async def test_a_read_only_role_can_read_but_not_execute_or_write(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    await _user_with_role(tenant_id, "ro@example.com", "READ_ONLY")
    read_only = await _login(client, "acme", "ro@example.com")

    assert (await client.get("/hunting/fields", headers=read_only)).status_code == 200
    assert (
        await client.post("/hunting/search", headers=read_only, json={"free_text": "x"})
    ).status_code == 403
    assert (
        await client.post(
            "/hunting/saved", headers=read_only, json={"name": "x", "query": {"free_text": "x"}}
        )
    ).status_code == 403
    assert (
        await client.post(
            "/hunting/pivot", headers=read_only, json={"pivot": "ip_to_events", "value": "1.2.3.4"}
        )
    ).status_code == 403
    assert (
        await client.post("/hunting/export", headers=read_only, json={"free_text": "x"})
    ).status_code == 403


async def test_a_soc_analyst_l1_can_search_and_read_but_not_manage_saved_hunts(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), user={"name": "liam"})
    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    assert (
        await client.post("/hunting/search", headers=l1, json={"free_text": "liam"})
    ).status_code == 200
    assert (
        await client.post(
            "/hunting/saved", headers=l1, json={"name": "x", "query": {"free_text": "x"}}
        )
    ).status_code == 403


async def test_a_role_with_no_hunt_permission_is_forbidden_everywhere(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    await _user_with_role(tenant_id, "auditor@example.com", "AUDITOR")
    auditor = await _login(client, "acme", "auditor@example.com")

    assert (await client.get("/hunting/fields", headers=auditor)).status_code == 403
    assert (await client.get("/hunting/saved", headers=auditor)).status_code == 403


async def test_an_unauthenticated_caller_reaches_nothing(client: AsyncClient) -> None:
    assert (await client.get("/hunting/fields")).status_code == 401
    assert (await client.post("/hunting/search", json={"free_text": "x"})).status_code == 401


# ---------------------------------------------------------------------------
# Cross-tenant isolation
# ---------------------------------------------------------------------------


async def test_one_tenants_saved_hunts_are_invisible_to_another(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    created = await client.post(
        "/hunting/saved", headers=headers, json={"name": "mine", "query": {"free_text": "x"}}
    )
    hunt_id = created.json()["id"]

    await _register(client, "globex", "b@example.com")
    other = await _login(client, "globex", "b@example.com")

    assert (await client.get("/hunting/saved", headers=other)).json() == []
    assert (await client.get(f"/hunting/saved/{hunt_id}", headers=other)).status_code == 404
    assert (
        await client.patch(f"/hunting/saved/{hunt_id}", headers=other, json={"name": "y"})
    ).status_code == 404
    assert (await client.delete(f"/hunting/saved/{hunt_id}", headers=other)).status_code == 404
    assert (await client.post(f"/hunting/saved/{hunt_id}/run", headers=other)).status_code == 404


async def test_search_and_pivots_never_return_another_tenants_events(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    await _index_event(str(tenant_id), source_ip="10.8.8.8", user={"name": "mona"})

    org2 = await _register(client, "initech", "c@example.com")
    headers2 = await _login(client, "initech", "c@example.com")
    await _index_event(org2["organization_id"], source_ip="10.8.8.8", user={"name": "mona"})

    resp = await client.post(
        "/hunting/pivot", headers=headers, json={"pivot": "ip_to_events", "value": "10.8.8.8"}
    )
    assert resp.json()["total"] == 1

    resp2 = await client.post(
        "/hunting/pivot", headers=headers2, json={"pivot": "ip_to_events", "value": "10.8.8.8"}
    )
    assert resp2.json()["total"] == 1
