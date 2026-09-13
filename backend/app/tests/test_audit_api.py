"""The audit log read API: every write elsewhere in the platform lands here,
so this is checked against a real write (asset creation) rather than
seeded rows directly — the same "does the whole path work" standard the
evidence-lineage tests elsewhere in this suite hold themselves to.
"""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import tenant_scoped_session
from app.core.security import hash_password
from app.models.identity import Role, User, UserRole


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


@pytest.fixture
async def tenant(client: AsyncClient):
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    return tenant_id, headers


async def test_a_real_write_shows_up_in_the_audit_log(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    created = await client.post(
        "/assets",
        headers=headers,
        json={"asset_type": "server", "hostname": "audit-test-host", "criticality": "HIGH"},
    )
    assert created.status_code == 201
    asset_id = created.json()["id"]

    resp = await client.get("/audit", headers=headers)
    assert resp.status_code == 200
    entries = resp.json()
    match = next((e for e in entries if e["object_id"] == asset_id), None)
    assert match is not None
    assert match["action"] == "CREATE_ASSET"
    assert match["object_type"] == "asset"
    assert match["result"] == "success"


async def test_filtering_by_action(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    await client.post(
        "/assets", headers=headers, json={"asset_type": "server", "hostname": "h1", "criticality": "LOW"}
    )

    resp = await client.get("/audit", headers=headers, params={"action": "CREATE_ASSET"})
    assert resp.status_code == 200
    assert all(e["action"] == "CREATE_ASSET" for e in resp.json())
    assert len(resp.json()) >= 1


async def test_a_role_without_audit_permission_is_forbidden(client: AsyncClient, tenant) -> None:
    tenant_id, _headers = tenant
    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")
    assert (await client.get("/audit", headers=l1)).status_code == 403


async def test_an_auditor_can_read(client: AsyncClient, tenant) -> None:
    tenant_id, _headers = tenant
    await _user_with_role(tenant_id, "auditor@example.com", "AUDITOR")
    auditor = await _login(client, "acme", "auditor@example.com")
    assert (await client.get("/audit", headers=auditor)).status_code == 200


async def test_one_tenants_audit_log_is_invisible_to_another(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    await client.post(
        "/assets", headers=headers, json={"asset_type": "server", "hostname": "secret-host", "criticality": "LOW"}
    )

    await _register(client, "globex", "b@example.com")
    other = await _login(client, "globex", "b@example.com")

    entries = (await client.get("/audit", headers=other)).json()
    assert all(e.get("object_id") != "secret-host" for e in entries)
    hostnames = [
        (e.get("after_state") or {}).get("hostname") for e in entries if e.get("after_state")
    ]
    assert "secret-host" not in hostnames
