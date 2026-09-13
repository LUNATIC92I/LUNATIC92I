"""User management (Administration screen): create, update (deactivate,
reassign role), the role catalog, RBAC gating, and cross-tenant IDOR — the
same suite shape every other admin-capable resource in this codebase gets.
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


async def test_role_catalog_is_the_fixed_role_set(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.get("/users/roles", headers=headers)
    assert resp.status_code == 200
    assert "SOC_ANALYST_L1" in resp.json()["roles"]
    assert "READ_ONLY" in resp.json()["roles"]


async def test_creating_a_user_with_a_role(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/users",
        headers=headers,
        json={
            "email": "newanalyst@example.com",
            "full_name": "New Analyst",
            "password": "Correct-Horse-Battery-Staple-2",
            "role": "SOC_ANALYST_L1",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["email"] == "newanalyst@example.com"
    assert body["roles"] == ["SOC_ANALYST_L1"]
    assert body["is_active"] is True

    # The new account can actually log in.
    login = await client.post(
        "/auth/login",
        json={
            "organization_slug": "acme",
            "email": "newanalyst@example.com",
            "password": "Correct-Horse-Battery-Staple-2",
        },
    )
    assert login.status_code == 200


async def test_duplicate_email_is_refused(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    payload = {
        "email": "dupe@example.com",
        "full_name": "Dupe",
        "password": "Correct-Horse-Battery-Staple-3",
        "role": "READ_ONLY",
    }
    first = await client.post("/users", headers=headers, json=payload)
    assert first.status_code == 201
    second = await client.post("/users", headers=headers, json=payload)
    assert second.status_code == 409


async def test_an_unknown_role_is_rejected(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/users",
        headers=headers,
        json={
            "email": "x@example.com",
            "full_name": "X",
            "password": "Correct-Horse-Battery-Staple-4",
            "role": "NOT_A_REAL_ROLE",
        },
    )
    assert resp.status_code == 422


async def test_updating_a_users_active_status_and_role(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    user_id = await _user_with_role(tenant_id, "toupdate@example.com", "READ_ONLY")

    resp = await client.patch(
        f"/users/{user_id}", headers=headers, json={"is_active": False, "role": "SOC_ANALYST_L2"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["is_active"] is False
    assert body["roles"] == ["SOC_ANALYST_L2"]


async def test_an_empty_update_is_rejected(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    user_id = await _user_with_role(tenant_id, "empty@example.com", "READ_ONLY")
    resp = await client.patch(f"/users/{user_id}", headers=headers, json={})
    assert resp.status_code == 422


async def test_a_malformed_user_id_is_indistinguishable_from_missing(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    resp = await client.patch("/users/not-a-uuid", headers=headers, json={"is_active": False})
    assert resp.status_code == 404


async def test_an_auditor_can_list_but_not_write(client: AsyncClient, tenant) -> None:
    # AUDITOR holds `user:read` but not `user:write` (app/auth/permissions.py)
    # — the role built specifically to see everything and change nothing.
    tenant_id, headers = tenant
    await _user_with_role(tenant_id, "auditor@example.com", "AUDITOR")
    auditor = await _login(client, "acme", "auditor@example.com")

    assert (await client.get("/users", headers=auditor)).status_code == 200
    assert (
        await client.post(
            "/users",
            headers=auditor,
            json={
                "email": "blocked@example.com",
                "full_name": "Blocked",
                "password": "Correct-Horse-Battery-Staple-5",
                "role": "READ_ONLY",
            },
        )
    ).status_code == 403


async def test_one_tenants_users_are_invisible_and_unreachable_from_another(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    user_id = await _user_with_role(tenant_id, "acmeuser@example.com", "READ_ONLY")

    await _register(client, "globex", "b@example.com")
    other = await _login(client, "globex", "b@example.com")

    listed = await client.get("/users", headers=other)
    assert all(u["id"] != str(user_id) for u in listed.json())

    assert (
        await client.patch(f"/users/{user_id}", headers=other, json={"is_active": False})
    ).status_code == 404
