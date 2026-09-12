import uuid

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import select, text

from app.core.db import async_session_factory, tenant_scoped_session
from app.core.security import hash_password
from app.models.identity import Organization, Role, User, UserRole


async def _register_org(client: AsyncClient, *, slug: str, email: str = "admin@example.com") -> dict:
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


async def _login(
    client: AsyncClient, *, slug: str, email: str, password: str = "Correct-Horse-Battery-Staple-1"
) -> str:
    resp = await client.post(
        "/auth/login", json={"organization_slug": slug, "email": email, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return str(resp.json()["access_token"])


async def _create_user_with_role(*, tenant_id: uuid.UUID, email: str, role_name: str) -> None:
    async with tenant_scoped_session(tenant_id) as db:
        role = await db.scalar(select(Role).where(Role.name == role_name))
        assert role is not None, f"role {role_name} missing from seed data"
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


def _auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Registration / login / session lifecycle
# ---------------------------------------------------------------------------


async def test_register_login_and_me(client: AsyncClient) -> None:
    await _register_org(client, slug="acme")
    token = await _login(client, slug="acme", email="admin@example.com")

    resp = await client.get("/users/me", headers=_auth_header(token))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["email"] == "admin@example.com"
    assert "ORG_ADMIN" in body["roles"]
    assert "user:write" in body["permissions"]


async def test_duplicate_organization_slug_rejected(client: AsyncClient) -> None:
    await _register_org(client, slug="acme")
    resp = await client.post(
        "/auth/register-organization",
        json={
            "organization_name": "Another Acme",
            "organization_slug": "acme",
            "admin_email": "other@example.com",
            "admin_password": "Correct-Horse-Battery-Staple-1",
            "admin_full_name": "Other Admin",
        },
    )
    assert resp.status_code == 409


async def test_login_wrong_password_rejected(client: AsyncClient) -> None:
    await _register_org(client, slug="acme")
    resp = await client.post(
        "/auth/login",
        json={"organization_slug": "acme", "email": "admin@example.com", "password": "wrong-password"},
    )
    assert resp.status_code == 401


async def test_login_unknown_organization_gives_generic_error(client: AsyncClient) -> None:
    """Must not leak whether an org slug exists via a different error shape."""
    resp = await client.post(
        "/auth/login",
        json={"organization_slug": "does-not-exist", "email": "x@example.com", "password": "whatever12345"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid credentials"


async def test_brute_force_lockout(client: AsyncClient) -> None:
    """MAX_FAILED_LOGIN_ATTEMPTS=3 is set in conftest for fast tests."""
    await _register_org(client, slug="acme")

    for _ in range(3):
        resp = await client.post(
            "/auth/login",
            json={"organization_slug": "acme", "email": "admin@example.com", "password": "wrong"},
        )
        assert resp.status_code == 401

    # Fourth attempt (even with the CORRECT password) must be locked out.
    resp = await client.post(
        "/auth/login",
        json={
            "organization_slug": "acme",
            "email": "admin@example.com",
            "password": "Correct-Horse-Battery-Staple-1",
        },
    )
    assert resp.status_code == 423
    assert "Retry-After" in resp.headers


async def test_refresh_token_rotation_invalidates_old_token(client: AsyncClient) -> None:
    await _register_org(client, slug="acme")
    await _login(client, slug="acme", email="admin@example.com")
    old_cookie = client.cookies.get("refresh_token")
    assert old_cookie is not None

    resp = await client.post("/auth/refresh")
    assert resp.status_code == 200
    new_cookie = client.cookies.get("refresh_token")
    assert new_cookie is not None
    assert new_cookie != old_cookie

    # Reusing the now-rotated-away old token must fail (session-fixation /
    # replay resistance — THREAT_MODEL.md §3.3).
    client.cookies.set("refresh_token", old_cookie)
    resp = await client.post("/auth/refresh")
    assert resp.status_code == 401


async def test_logout_revokes_refresh_token(client: AsyncClient) -> None:
    await _register_org(client, slug="acme")
    await _login(client, slug="acme", email="admin@example.com")

    resp = await client.post("/auth/logout")
    assert resp.status_code == 204

    resp = await client.post("/auth/refresh")
    assert resp.status_code == 401


async def test_unauthenticated_request_is_401_not_403(client: AsyncClient) -> None:
    resp = await client.get("/users/me")
    assert resp.status_code == 401


async def test_expired_or_garbage_bearer_token_is_401(client: AsyncClient) -> None:
    resp = await client.get("/users/me", headers=_auth_header("not-a-real-token"))
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# MFA
# ---------------------------------------------------------------------------


async def test_mfa_enroll_verify_and_login(client: AsyncClient) -> None:
    await _register_org(client, slug="acme")
    token = await _login(client, slug="acme", email="admin@example.com")

    resp = await client.post("/auth/mfa/enroll", headers=_auth_header(token))
    assert resp.status_code == 200
    secret = resp.json()["secret"]

    code = pyotp.TOTP(secret).now()
    resp = await client.post("/auth/mfa/verify", json={"code": code}, headers=_auth_header(token))
    assert resp.status_code == 204

    # Password alone is no longer enough once MFA is enabled.
    resp = await client.post(
        "/auth/login",
        json={
            "organization_slug": "acme",
            "email": "admin@example.com",
            "password": "Correct-Horse-Battery-Staple-1",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"]["mfa_required"] is True

    code = pyotp.TOTP(secret).now()
    resp = await client.post(
        "/auth/login",
        json={
            "organization_slug": "acme",
            "email": "admin@example.com",
            "password": "Correct-Horse-Battery-Staple-1",
            "mfa_code": code,
        },
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# RBAC matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role_name", "expect_can_list_users"),
    [
        ("SUPER_ADMIN", True),
        ("ORG_ADMIN", True),
        ("SOC_MANAGER", True),
        ("SOC_ANALYST_L1", False),
        ("SOC_ANALYST_L2", False),
        ("SOC_ANALYST_L3", False),
        ("THREAT_HUNTER", False),
        ("DFIR_ANALYST", False),
        ("AUDITOR", True),  # auditors have read-only access to users by design
        ("READ_ONLY", False),
    ],
)
async def test_rbac_matrix_users_list(
    client: AsyncClient, role_name: str, expect_can_list_users: bool
) -> None:
    org = await _register_org(client, slug="acme")
    tenant_id = uuid.UUID(org["organization_id"])
    email = f"{role_name.lower()}@example.com"
    await _create_user_with_role(tenant_id=tenant_id, email=email, role_name=role_name)

    token = await _login(client, slug="acme", email=email)
    resp = await client.get("/users", headers=_auth_header(token))

    if expect_can_list_users:
        assert resp.status_code == 200, resp.text
    else:
        assert resp.status_code == 403, resp.text


async def test_permission_change_takes_effect_without_new_login(client: AsyncClient) -> None:
    """Permissions are re-derived from the DB every request (never cached
    in the token) — revoking a role must take effect on the very next
    request with the same still-valid access token."""
    org = await _register_org(client, slug="acme")
    tenant_id = uuid.UUID(org["organization_id"])
    await _create_user_with_role(tenant_id=tenant_id, email="analyst@example.com", role_name="SOC_MANAGER")
    token = await _login(client, slug="acme", email="analyst@example.com")

    resp = await client.get("/users", headers=_auth_header(token))
    assert resp.status_code == 200

    async with tenant_scoped_session(tenant_id) as db:
        await db.execute(
            text("DELETE FROM user_roles WHERE user_id = (SELECT id FROM users WHERE email = :email)"),
            {"email": "analyst@example.com"},
        )
        await db.commit()

    resp = await client.get("/users", headers=_auth_header(token))
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Multi-tenant isolation / IDOR
# ---------------------------------------------------------------------------


async def test_users_list_never_leaks_across_tenants(client: AsyncClient) -> None:
    await _register_org(client, slug="acme", email="admin@acme.example.com")
    await _register_org(client, slug="globex", email="admin@globex.example.com")

    token_acme = await _login(client, slug="acme", email="admin@acme.example.com")
    token_globex = await _login(client, slug="globex", email="admin@globex.example.com")

    resp = await client.get("/users", headers=_auth_header(token_acme))
    acme_emails = {u["email"] for u in resp.json()}
    resp = await client.get("/users", headers=_auth_header(token_globex))
    globex_emails = {u["email"] for u in resp.json()}

    assert acme_emails == {"admin@acme.example.com"}
    assert globex_emails == {"admin@globex.example.com"}


async def test_organization_me_never_leaks_another_tenant(client: AsyncClient) -> None:
    await _register_org(client, slug="acme", email="admin@acme.example.com")
    await _register_org(client, slug="globex", email="admin@globex.example.com")

    token_acme = await _login(client, slug="acme", email="admin@acme.example.com")
    resp = await client.get("/organizations/me", headers=_auth_header(token_acme))
    assert resp.status_code == 200
    assert resp.json()["slug"] == "acme"


async def test_row_level_security_blocks_cross_tenant_read_even_without_app_filter() -> None:
    """The real defense-in-depth claim: even a query with NO tenant_id
    filter at all must not be able to see another tenant's rows, because
    PostgreSQL's FORCE ROW LEVEL SECURITY enforces it independently of
    whatever the application code remembered to type (THREAT_MODEL.md
    §3.2)."""
    async with async_session_factory() as db:
        org_a = Organization(name="Org A", slug="rls-org-a")
        org_b = Organization(name="Org B", slug="rls-org-b")
        db.add_all([org_a, org_b])
        await db.commit()
        await db.refresh(org_a)
        await db.refresh(org_b)

    async with tenant_scoped_session(org_a.id) as db:
        db.add(User(tenant_id=org_a.id, email="a@example.com", password_hash="x", full_name="A"))
        await db.commit()

    async with tenant_scoped_session(org_b.id) as db:
        db.add(User(tenant_id=org_b.id, email="b@example.com", password_hash="x", full_name="B"))
        await db.commit()

    async with tenant_scoped_session(org_a.id) as db:
        # Deliberately no WHERE clause on tenant_id — RLS alone must filter this.
        rows = (await db.execute(select(User))).scalars().all()
        emails = {u.email for u in rows}

    assert emails == {"a@example.com"}


async def test_row_level_security_denies_all_rows_without_tenant_context() -> None:
    """Fail-closed: with no `app.current_tenant_id` set at all, a
    tenant-scoped table must return zero rows, not everything."""
    async with async_session_factory() as db:
        org = Organization(name="Org C", slug="rls-org-c")
        db.add(org)
        await db.commit()
        await db.refresh(org)

    async with tenant_scoped_session(org.id) as db:
        db.add(User(tenant_id=org.id, email="c@example.com", password_hash="x", full_name="C"))
        await db.commit()

    async with async_session_factory() as db:  # no tenant GUC set at all
        rows = (await db.execute(select(User))).scalars().all()
        assert rows == []
