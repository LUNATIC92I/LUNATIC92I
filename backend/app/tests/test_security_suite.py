"""The dedicated, category-organized security test suite spec §30 calls
for (Phase 17). Several categories re-prove protections that already have
deep, dedicated coverage elsewhere in this codebase (tenant isolation and
IDOR especially, exercised per-phase in every `test_*_api.py`); this file
exists so a reviewer — or CI — can find "the SQLi tests" / "the SSRF
tests" / etc. under the name spec §30 uses, in one place, rather than
having to know which phase originally built the underlying control.
See docs/SECURITY_CHECKLIST.md for the full control-to-test mapping.

Every test here runs through the real API (or the real, non-mocked
service/security primitives it calls), never a simulation of the attack —
a finding in this file is a finding a real request could reproduce.
"""

import time
import uuid

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.config import get_settings
from app.core.db import tenant_scoped_session
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
    from app.core.security import hash_password

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


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------


class TestSQLInjection:
    """SQLAlchemy's parameterized queries throughout mean an injection
    payload is just a string that matches nothing — not a syntax break."""

    async def test_login_email_field_rejects_injection_before_it_ever_reaches_the_database(
        self, client: AsyncClient
    ) -> None:
        """Two independent layers, both proven here: Pydantic's `EmailStr`
        refuses the payload as not-an-email (422) before the query layer
        ever sees it; `test_hunting_free_text_search_...` below proves the
        second layer (parameterization) for a field that *is* free text."""
        await _register(client, "sqli-login")
        resp = await client.post(
            "/auth/login",
            json={
                "organization_slug": "sqli-login",
                "email": "' OR '1'='1",
                "password": "anything",
            },
        )
        assert resp.status_code == 422

    async def test_hunting_free_text_search_treats_injection_as_a_literal_string(
        self, client: AsyncClient
    ) -> None:
        org = await _register(client, "sqli-hunt")
        headers = await _login(client, "sqli-hunt")
        resp = await client.post(
            "/hunting/search",
            headers=headers,
            json={"free_text": "'; DROP TABLE organizations; --"},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

        # The table survived: proven by the org still being usable.
        still_there = await client.post(
            "/auth/login",
            json={
                "organization_slug": "sqli-hunt",
                "email": "admin@example.com",
                "password": "Correct-Horse-Battery-Staple-1",
            },
        )
        assert still_there.status_code == 200
        _ = org


# ---------------------------------------------------------------------------
# Command injection
# ---------------------------------------------------------------------------


class TestCommandInjection:
    def test_no_shell_execution_anywhere_in_the_application(self) -> None:
        """A structural regression guard rather than a per-endpoint probe:
        this codebase has no legitimate reason to shell out, ever (spec
        §30). If a future change introduces `subprocess`/`os.system`, this
        fails loudly instead of shipping a new command-injection surface
        silently."""
        import pathlib
        import re

        app_root = pathlib.Path(__file__).resolve().parents[1]
        offenders = []
        pattern = re.compile(r"\b(subprocess|os\.system|os\.popen)\b")
        for path in app_root.rglob("*.py"):
            if "tests" in path.parts:
                continue
            if pattern.search(path.read_text(encoding="utf-8", errors="ignore")):
                offenders.append(str(path))
        assert offenders == []


# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------


class TestXss:
    """A pure JSON API cannot reflect a payload into an executable HTML
    context by definition — but that guarantee is only as good as "every
    response really is JSON," which this proves directly rather than by
    inspecting route decorators."""

    async def test_a_script_payload_in_an_incident_title_is_never_executed(
        self, client: AsyncClient
    ) -> None:
        _org = await _register(client, "xss-incident")
        headers = await _login(client, "xss-incident")
        payload = "<script>alert(document.cookie)</script>"

        resp = await client.post(
            "/incidents",
            headers=headers,
            json={"title": payload, "description": "d", "severity": "low"},
        )
        assert resp.status_code == 201
        assert resp.headers["content-type"].startswith("application/json")
        # Stored and returned verbatim as data, inside a JSON string — never
        # unescaped into a response a browser would parse as markup.
        assert resp.json()["title"] == payload

    async def test_the_response_content_type_is_never_html(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert "text/html" not in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------


class TestSsrf:
    """The full guard (allow-list, private-IP refusal, redirect
    re-validation) has its own exhaustive suite in test_egress.py; these
    two are the headline cases spec §30 names by name."""

    def test_the_cloud_metadata_address_is_refused(self, monkeypatch) -> None:
        from app.core import egress
        from app.core.config import get_settings

        monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "169.254.169.254")
        get_settings.cache_clear()
        try:
            with pytest.raises(egress.EgressBlocked, match="non_global_address"):
                egress.validate_url("https://169.254.169.254/latest/meta-data/")
        finally:
            get_settings.cache_clear()

    def test_an_unlisted_host_is_refused_even_over_https(self, monkeypatch) -> None:
        from app.core import egress
        from app.core.config import get_settings

        monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "an-allowed-host.example.com")
        get_settings.cache_clear()
        try:
            with pytest.raises(egress.EgressBlocked, match="host_not_allowed"):
                egress.validate_url("https://not-an-allowed-host.example.net/feed")
        finally:
            get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_a_drop_feed_cannot_escape_its_configured_directory(self, tmp_path, monkeypatch) -> None:
        from app.core.config import get_settings
        from app.threat_intel.feeds.base import FeedError, _read_drop_file

        drop_dir = tmp_path / "intel-drop"
        drop_dir.mkdir()
        (tmp_path / "secret.txt").write_text("outside the drop directory")

        monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(drop_dir))
        get_settings.cache_clear()
        try:
            with pytest.raises(FeedError, match="resolves outside"):
                _read_drop_file("../secret.txt")
        finally:
            get_settings.cache_clear()


# ---------------------------------------------------------------------------
# IDOR
# ---------------------------------------------------------------------------


class TestIdor:
    """Consolidated cross-tenant object-reference checks across the
    platform's core objects. Each domain's own test file (test_incidents.py,
    test_alerts_api.py, test_playbooks_api.py, ...) covers this in more
    depth for that domain specifically."""

    async def test_an_incident_id_from_another_tenant_is_a_404_not_a_403(
        self, client: AsyncClient
    ) -> None:
        _org_a = await _register(client, "idor-a")
        headers_a = await _login(client, "idor-a")
        created = await client.post(
            "/incidents",
            headers=headers_a,
            json={"title": "tenant a's incident", "description": "d", "severity": "low"},
        )
        incident_id = created.json()["id"]

        await _register(client, "idor-b", "b@example.com")
        headers_b = await _login(client, "idor-b", "b@example.com")

        resp = await client.get(f"/incidents/{incident_id}", headers=headers_b)
        # 404, not 403: existence of another tenant's object is not
        # revealed by a different status code (THREAT_MODEL.md §3.2).
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------


class TestPrivilegeEscalation:
    async def test_a_soc_manager_cannot_grant_org_admin_to_a_new_user(
        self, client: AsyncClient
    ) -> None:
        org = await _register(client, "privesc-create")
        tenant_id = uuid.UUID(org["organization_id"])
        await _user_with_role(tenant_id, "manager@example.com", "SOC_MANAGER")
        manager = await _login(client, "privesc-create", "manager@example.com")

        resp = await client.post(
            "/users",
            headers=manager,
            json={
                "email": "newadmin@example.com",
                "full_name": "New Admin",
                "password": "Correct-Horse-Battery-Staple-1",
                "role": "ORG_ADMIN",
            },
        )
        assert resp.status_code == 403

    async def test_a_soc_manager_cannot_promote_an_existing_user_to_org_admin(
        self, client: AsyncClient
    ) -> None:
        org = await _register(client, "privesc-update")
        tenant_id = uuid.UUID(org["organization_id"])
        await _user_with_role(tenant_id, "manager2@example.com", "SOC_MANAGER")
        target_id = await _user_with_role(tenant_id, "target@example.com", "READ_ONLY")
        manager = await _login(client, "privesc-update", "manager2@example.com")

        resp = await client.patch(
            f"/users/{target_id}", headers=manager, json={"role": "ORG_ADMIN"}
        )
        assert resp.status_code == 403

    async def test_an_org_admin_can_still_grant_org_admin(self, client: AsyncClient) -> None:
        """The fix is a check on the actor, not a blanket ban — the
        legitimate case must keep working."""
        await _register(client, "privesc-legit")
        admin = await _login(client, "privesc-legit")

        resp = await client.post(
            "/users",
            headers=admin,
            json={
                "email": "seconadmin@example.com",
                "full_name": "Second Admin",
                "password": "Correct-Horse-Battery-Staple-1",
                "role": "ORG_ADMIN",
            },
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Broken authentication/authorization
# ---------------------------------------------------------------------------


class TestBrokenAuth:
    async def test_no_bearer_token_is_401(self, client: AsyncClient) -> None:
        assert (await client.get("/incidents")).status_code == 401

    async def test_a_malformed_bearer_token_is_401_not_500(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/incidents", headers={"Authorization": "Bearer not-a-real-token"}
        )
        assert resp.status_code == 401

    async def test_a_deactivated_users_still_valid_token_is_rejected(
        self, client: AsyncClient
    ) -> None:
        org = await _register(client, "deactivated")
        tenant_id = uuid.UUID(org["organization_id"])
        headers = await _login(client, "deactivated")

        async with tenant_scoped_session(tenant_id) as db:
            user = await db.scalar(select(User).where(User.email == "admin@example.com"))
            assert user is not None
            user.is_active = False
            await db.commit()

        resp = await client.get("/incidents", headers=headers)
        assert resp.status_code == 401

    async def test_a_permission_the_role_lacks_is_403_not_a_silent_empty_result(
        self, client: AsyncClient
    ) -> None:
        org = await _register(client, "noperm")
        tenant_id = uuid.UUID(org["organization_id"])
        await _user_with_role(tenant_id, "auditor@example.com", "AUDITOR")
        auditor = await _login(client, "noperm", "auditor@example.com")

        resp = await client.post(
            "/incidents",
            headers=auditor,
            json={"title": "x", "description": "d", "severity": "low"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    async def test_a_session_with_no_tenant_context_sees_no_rows(self) -> None:
        """`users` (like every per-tenant data table) carries an RLS policy
        keyed on `app.current_tenant_id`; a session that never set it — the
        default for any connection outside `tenant_scoped_session` — must
        see nothing, not an empty-because-filtered result but a real,
        database-level "this session has no tenant" state. (`organizations`
        itself is deliberately not RLS-scoped this way: `services/auth.py`
        looks a slug up before it has any tenant context to set.)"""
        from app.core.db import async_session_factory
        from app.core.security import hash_password
        from app.models.identity import Organization

        async with async_session_factory() as db:
            org = Organization(name="rls-check", slug=f"rls-{uuid.uuid4().hex[:8]}")
            db.add(org)
            await db.commit()
            org_id = org.id

        async with tenant_scoped_session(org_id) as db:
            db.add(
                User(
                    tenant_id=org_id,
                    email="rls-check@example.com",
                    password_hash=hash_password("x"),
                    full_name="RLS Check",
                )
            )
            await db.commit()

        async with async_session_factory() as db:
            rows = list(
                (await db.execute(select(User).where(User.tenant_id == org_id))).scalars()
            )
        assert rows == []

    async def test_one_tenants_users_are_invisible_to_another(self, client: AsyncClient) -> None:
        await _register(client, "tenant-iso-a")
        headers_a = await _login(client, "tenant-iso-a")
        await _register(client, "tenant-iso-b", "b@example.com")
        headers_b = await _login(client, "tenant-iso-b", "b@example.com")

        users_a = {u["email"] for u in (await client.get("/users", headers=headers_a)).json()}
        users_b = {u["email"] for u in (await client.get("/users", headers=headers_b)).json()}
        assert users_a.isdisjoint(users_b)


# ---------------------------------------------------------------------------
# Rate-limit bypass
# ---------------------------------------------------------------------------


class TestRateLimitBypass:
    async def test_a_spoofed_x_forwarded_for_header_does_not_reset_the_quota(
        self, client: AsyncClient, monkeypatch
    ) -> None:
        """The rate limiter keys on the real TCP peer address
        (`request.client.host`), never a client-supplied header — otherwise
        every request could claim a fresh quota just by sending a different
        `X-Forwarded-For` value."""
        monkeypatch.setenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", "1")
        get_settings.cache_clear()
        body = {"organization_slug": "nope", "email": "a@example.com", "password": "x"}

        first = await client.post(
            "/auth/login", json=body, headers={"X-Forwarded-For": "1.2.3.4"}
        )
        second = await client.post(
            "/auth/login", json=body, headers={"X-Forwarded-For": "5.6.7.8"}
        )
        assert first.status_code == 401
        assert second.status_code == 429

        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# JWT manipulation
# ---------------------------------------------------------------------------


class TestJwtManipulation:
    """`app/tests/test_security.py` proves `decode_access_token()` itself
    rejects these at the function level; these prove the same through the
    real HTTP dependency chain a request actually goes through."""

    async def test_a_token_signed_with_a_different_key_is_rejected(
        self, client: AsyncClient
    ) -> None:
        forged = jwt.encode(
            {"sub": str(uuid.uuid4()), "tenant_id": str(uuid.uuid4()), "typ": "access"},
            key="attacker-controlled-key",
            algorithm="HS256",
        )
        resp = await client.get("/incidents", headers={"Authorization": f"Bearer {forged}"})
        assert resp.status_code == 401

    async def test_a_token_claiming_someone_elses_tenant_is_still_bound_by_its_own_signature(
        self, client: AsyncClient
    ) -> None:
        """An attacker cannot simply edit the `tenant_id` claim of their own
        token to point at a different tenant — doing so invalidates the
        signature, since the signature covers the whole payload."""
        org_a = await _register(client, "jwt-tenant-a")
        org_b = await _register(client, "jwt-tenant-b", "b@example.com")
        headers = await _login(client, "jwt-tenant-a")
        token = headers["Authorization"].removeprefix("Bearer ")

        header_b64, payload_b64, signature_b64 = token.split(".")
        import base64
        import json

        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
        payload["tenant_id"] = org_b["organization_id"]
        tampered_payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        )
        tampered_token = f"{header_b64}.{tampered_payload_b64}.{signature_b64}"

        resp = await client.get(
            "/incidents", headers={"Authorization": f"Bearer {tampered_token}"}
        )
        assert resp.status_code == 401
        _ = org_a

    async def test_an_expired_access_token_is_rejected_through_the_real_dependency(
        self, client: AsyncClient
    ) -> None:
        settings = get_settings()
        expired = jwt.encode(
            {
                "sub": str(uuid.uuid4()),
                "tenant_id": str(uuid.uuid4()),
                "typ": "access",
                "iat": int(time.time()) - 3600,
                "exp": int(time.time()) - 60,
            },
            settings.jwt_secret_key,
            algorithm="HS256",
        )
        resp = await client.get("/incidents", headers={"Authorization": f"Bearer {expired}"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


class TestReplay:
    async def test_a_rotated_refresh_token_cannot_be_reused(self, client: AsyncClient) -> None:
        await _register(client, "replay-refresh")
        login = await client.post(
            "/auth/login",
            json={
                "organization_slug": "replay-refresh",
                "email": "admin@example.com",
                "password": "Correct-Horse-Battery-Staple-1",
            },
        )
        assert login.status_code == 200
        old_cookie = client.cookies.get("refresh_token")
        assert old_cookie

        first_refresh = await client.post("/auth/refresh")
        assert first_refresh.status_code == 200

        # Replay the original (now-rotated) refresh token explicitly.
        client.cookies.set("refresh_token", old_cookie)
        replay = await client.post("/auth/refresh")
        assert replay.status_code == 401

    async def test_replaying_the_same_raw_event_through_the_real_api_is_deduplicated(
        self, client: AsyncClient
    ) -> None:
        """`test_ingestion.py` covers dedup in depth at the service layer;
        this is the one proof it also holds through the real HTTP path a
        collector actually uses — API key auth included."""
        await _register(client, "replay-ingest")
        admin = await _login(client, "replay-ingest")

        key_resp = await client.post(
            "/api-keys", headers=admin, json={"name": "replay-test-collector"}
        )
        assert key_resp.status_code == 201, key_resp.text
        api_key = key_resp.json()["api_key"]

        first = await client.post(
            "/ingest/events",
            headers={"X-API-Key": api_key},
            content=b"identical raw event for replay test",
        )
        second = await client.post(
            "/ingest/events",
            headers={"X-API-Key": api_key},
            content=b"identical raw event for replay test",
        )
        assert first.json()["outcome"] == "accepted"
        assert second.json()["outcome"] == "duplicate"
