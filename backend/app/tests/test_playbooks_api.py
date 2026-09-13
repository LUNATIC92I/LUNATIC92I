"""The SOAR playbooks API (spec §18 `/playbooks`): CRUD, run orchestration,
and the approval workflow, RBAC-gated like every other route and isolated
per tenant like every other object in this platform.

Route ordering gets its own tests: `/playbooks/runs`, `/playbooks/approvals`
and `/playbooks/install-defaults` are declared ahead of the generic
`/playbooks/{key}` specifically so a request for one of those literal paths
is never captured by `{key}` instead — a regression there would surface as
a 404 with a body from the wrong handler, not a crash, so it needs its own
assertion rather than relying on other tests to notice.
"""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import tenant_scoped_session
from app.core.security import hash_password
from app.models.alerts import Alert
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


async def _plain_user(tenant_id: uuid.UUID, email: str) -> uuid.UUID:
    async with tenant_scoped_session(tenant_id) as db:
        user = User(
            tenant_id=tenant_id,
            email=email,
            password_hash=hash_password("x"),
            full_name="Victim",
        )
        db.add(user)
        await db.commit()
        return user.id


async def _alert(tenant_id: uuid.UUID, **overrides) -> uuid.UUID:
    kwargs = {
        "tenant_id": tenant_id,
        "display_id": f"ALT-{uuid.uuid4().hex[:8]}",
        "title": "Repeated failed logins",
        "description": "d",
        "severity": "high",
        "confidence": 70,
        "risk_score": 60,
        "dedup_key": str(uuid.uuid4()),
    }
    kwargs.update(overrides)
    async with tenant_scoped_session(tenant_id) as db:
        alert = Alert(**kwargs)
        db.add(alert)
        await db.commit()
        return alert.id


@pytest.fixture
async def tenant(client: AsyncClient):
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    return tenant_id, headers


def _steps(*actions: str) -> list[dict]:
    return [{"action": action} for action in actions]


# ---------------------------------------------------------------------------
# CRUD and route ordering
# ---------------------------------------------------------------------------


async def test_the_shipped_pack_is_installed_at_registration(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.get("/playbooks", headers=headers)
    assert resp.status_code == 200
    assert sorted(p["key"] for p in resp.json()) == ["PB-001", "PB-002", "PB-003"]


async def test_creating_and_reading_a_playbook_round_trips(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    created = await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-950", "name": "Custom", "trigger_type": "manual", "steps": _steps("enrich_ip")},
    )
    assert created.status_code == 201, created.text
    assert created.json()["key"] == "PB-950"

    fetched = await client.get("/playbooks/PB-950", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["name"] == "Custom"


async def test_creating_a_playbook_with_a_duplicate_key_is_a_409(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    payload = {"key": "PB-951", "name": "X", "steps": _steps("enrich_ip")}
    first = await client.post("/playbooks", headers=headers, json=payload)
    assert first.status_code == 201
    second = await client.post("/playbooks", headers=headers, json=payload)
    assert second.status_code == 409


async def test_an_unknown_playbook_key_is_a_404(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.get("/playbooks/PB-999", headers=headers)
    assert resp.status_code == 404


async def test_a_step_naming_an_unregistered_action_is_a_422(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-952", "name": "Bad", "steps": _steps("not_a_real_action")},
    )
    assert resp.status_code == 422


async def test_install_defaults_is_idempotent_over_the_api(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    # Already installed at registration; a second call installs nothing new.
    resp = await client.post("/playbooks/install-defaults", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["installed"] == []


async def test_runs_approvals_and_install_defaults_are_not_shadowed_by_the_key_route(
    client: AsyncClient, tenant
) -> None:
    """The literal sub-paths must resolve to their own handlers, never to
    `GET /playbooks/{key}` with `key="runs"` (which would 404 as a missing
    playbook rather than 200 with a list)."""
    _tenant_id, headers = tenant
    assert (await client.get("/playbooks/runs", headers=headers)).status_code == 200
    assert (await client.get("/playbooks/approvals", headers=headers)).status_code == 200
    assert isinstance((await client.get("/playbooks/runs", headers=headers)).json(), list)
    assert isinstance((await client.get("/playbooks/approvals", headers=headers)).json(), list)


# ---------------------------------------------------------------------------
# Running a playbook: dry run vs execute, non-destructive completion
# ---------------------------------------------------------------------------


async def test_dry_running_a_non_destructive_playbook_previews_and_completes(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    alert_id = await _alert(tenant_id, source_ip="198.51.100.20")
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-960", "name": "Enrich only", "steps": _steps("enrich_ip")},
    )

    resp = await client.post(
        "/playbooks/PB-960/run",
        headers=headers,
        json={"dry_run": True, "alert_id": str(alert_id)},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["dry_run"] is True
    assert body["results"][0]["kind"] == "preview"


async def test_executing_the_same_playbook_produces_a_result_not_a_preview(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    alert_id = await _alert(tenant_id, source_ip="198.51.100.21")
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-961", "name": "Enrich only", "steps": _steps("enrich_ip")},
    )

    resp = await client.post(
        "/playbooks/PB-961/run",
        headers=headers,
        json={"dry_run": False, "alert_id": str(alert_id)},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "COMPLETED"
    assert body["results"][0]["kind"] == "result"


async def test_running_with_an_alert_from_another_tenant_is_refused(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    other = await _register(client, "otherorg", "z@example.com")
    foreign_alert_id = await _alert(uuid.UUID(other["organization_id"]))
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-962", "name": "X", "steps": _steps("enrich_ip")},
    )

    resp = await client.post(
        "/playbooks/PB-962/run",
        headers=headers,
        json={"dry_run": False, "alert_id": str(foreign_alert_id)},
    )
    assert resp.status_code == 422


async def test_running_a_nonexistent_playbook_is_a_404(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post("/playbooks/PB-999/run", headers=headers, json={"dry_run": True})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Destructive playbooks: halt, approve, reject, dual control
# ---------------------------------------------------------------------------


async def test_a_destructive_playbook_halts_awaiting_approval(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _plain_user(tenant_id, "victim@example.com")
    alert_id = await _alert(tenant_id, affected_user="victim@example.com")
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-970", "name": "Disable", "steps": _steps("disable_user")},
    )

    resp = await client.post(
        "/playbooks/PB-970/run",
        headers=headers,
        json={"dry_run": False, "alert_id": str(alert_id)},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "AWAITING_APPROVAL"

    pending = await client.get("/playbooks/approvals", headers=headers)
    assert pending.status_code == 200
    assert len(pending.json()) == 1
    assert pending.json()[0]["action_name"] == "disable_user"
    assert pending.json()[0]["status"] == "PENDING_APPROVAL"


async def test_the_requester_cannot_approve_their_own_request(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _plain_user(tenant_id, "victim2@example.com")
    alert_id = await _alert(tenant_id, affected_user="victim2@example.com")
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-971", "name": "Disable", "steps": _steps("disable_user")},
    )
    await client.post(
        "/playbooks/PB-971/run", headers=headers, json={"dry_run": False, "alert_id": str(alert_id)}
    )
    approval_id = (await client.get("/playbooks/approvals", headers=headers)).json()[0]["id"]

    resp = await client.post(f"/playbooks/approvals/{approval_id}/approve", headers=headers)
    assert resp.status_code == 403


async def test_a_second_approver_can_approve_and_the_run_completes(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    await _plain_user(tenant_id, "victim3@example.com")
    alert_id = await _alert(tenant_id, affected_user="victim3@example.com")
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-972", "name": "Disable", "steps": _steps("disable_user")},
    )
    await client.post(
        "/playbooks/PB-972/run", headers=headers, json={"dry_run": False, "alert_id": str(alert_id)}
    )
    approval_id = (await client.get("/playbooks/approvals", headers=headers)).json()[0]["id"]

    await _user_with_role(tenant_id, "approver@example.com", "SOC_MANAGER")
    approver_headers = await _login(client, "acme", "approver@example.com")

    resp = await client.post(
        f"/playbooks/approvals/{approval_id}/approve", headers=approver_headers
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "COMPLETED"

    async with tenant_scoped_session(tenant_id) as db:
        victim = await db.scalar(select(User).where(User.email == "victim3@example.com"))
    assert victim is not None and victim.is_active is False


async def test_rejecting_halts_the_run_and_requires_a_reason(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _plain_user(tenant_id, "victim4@example.com")
    alert_id = await _alert(tenant_id, affected_user="victim4@example.com")
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-973", "name": "Disable", "steps": _steps("disable_user")},
    )
    await client.post(
        "/playbooks/PB-973/run", headers=headers, json={"dry_run": False, "alert_id": str(alert_id)}
    )
    approval_id = (await client.get("/playbooks/approvals", headers=headers)).json()[0]["id"]

    await _user_with_role(tenant_id, "rejector@example.com", "SOC_MANAGER")
    rejector_headers = await _login(client, "acme", "rejector@example.com")

    missing_reason = await client.post(
        f"/playbooks/approvals/{approval_id}/reject", headers=rejector_headers, json={"reason": ""}
    )
    assert missing_reason.status_code == 422

    resp = await client.post(
        f"/playbooks/approvals/{approval_id}/reject",
        headers=rejector_headers,
        json={"reason": "not authorized right now"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "REJECTED"

    async with tenant_scoped_session(tenant_id) as db:
        victim = await db.scalar(select(User).where(User.email == "victim4@example.com"))
    assert victim is not None and victim.is_active is True


async def test_approving_an_unknown_approval_id_is_a_404(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(f"/playbooks/approvals/{uuid.uuid4()}/approve", headers=headers)
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


async def test_read_only_can_read_but_not_write_run_or_approve(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _user_with_role(tenant_id, "ro@example.com", "READ_ONLY")
    ro = await _login(client, "acme", "ro@example.com")

    assert (await client.get("/playbooks", headers=ro)).status_code == 200
    assert (
        await client.post(
            "/playbooks", headers=ro, json={"key": "PB-980", "name": "x", "steps": _steps("enrich_ip")}
        )
    ).status_code == 403
    assert (await client.post("/playbooks/PB-001/run", headers=ro, json={"dry_run": True})).status_code == 403
    assert (await client.get("/playbooks/approvals", headers=ro)).status_code == 403
    assert (await client.post("/playbooks/install-defaults", headers=ro)).status_code == 403


async def test_soc_analyst_l2_can_execute_but_not_write_or_approve(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    alert_id = await _alert(tenant_id, source_ip="198.51.100.30")
    await _user_with_role(tenant_id, "l2@example.com", "SOC_ANALYST_L2")
    l2 = await _login(client, "acme", "l2@example.com")

    assert (
        await client.post(
            "/playbooks/PB-001/run", headers=l2, json={"dry_run": True, "alert_id": str(alert_id)}
        )
    ).status_code == 200
    assert (
        await client.post(
            "/playbooks", headers=l2, json={"key": "PB-981", "name": "x", "steps": _steps("enrich_ip")}
        )
    ).status_code == 403
    assert (await client.get("/playbooks/approvals", headers=l2)).status_code == 403


async def test_a_role_with_no_playbook_permission_is_forbidden(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _user_with_role(tenant_id, "hunter@example.com", "THREAT_HUNTER")
    hunter = await _login(client, "acme", "hunter@example.com")

    assert (await client.get("/playbooks", headers=hunter)).status_code == 403


async def test_an_unauthenticated_caller_reaches_nothing(client: AsyncClient) -> None:
    assert (await client.get("/playbooks")).status_code == 401
    assert (await client.get("/playbooks/runs")).status_code == 401
    assert (await client.get("/playbooks/approvals")).status_code == 401


# ---------------------------------------------------------------------------
# Cross-tenant isolation
# ---------------------------------------------------------------------------


async def test_one_tenants_playbooks_are_invisible_to_another(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-990", "name": "mine", "steps": _steps("enrich_ip")},
    )

    other = await _register(client, "globex", "b@example.com")
    other_headers = await _login(client, "globex", "b@example.com")

    assert (await client.get("/playbooks/PB-990", headers=other_headers)).status_code == 404
    keys = {p["key"] for p in (await client.get("/playbooks", headers=other_headers)).json()}
    assert "PB-990" not in keys
    _ = other  # organization created only to obtain isolated headers


async def test_a_run_from_another_tenant_is_invisible(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    alert_id = await _alert(tenant_id, source_ip="198.51.100.40")
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-991", "name": "x", "steps": _steps("enrich_ip")},
    )
    run = await client.post(
        "/playbooks/PB-991/run", headers=headers, json={"dry_run": True, "alert_id": str(alert_id)}
    )
    run_id = run.json()["id"]

    await _register(client, "initech", "c@example.com")
    other_headers = await _login(client, "initech", "c@example.com")

    assert (await client.get(f"/playbooks/runs/{run_id}", headers=other_headers)).status_code == 404


async def test_an_approval_from_another_tenant_cannot_be_decided(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    await _plain_user(tenant_id, "victim5@example.com")
    alert_id = await _alert(tenant_id, affected_user="victim5@example.com")
    await client.post(
        "/playbooks",
        headers=headers,
        json={"key": "PB-992", "name": "Disable", "steps": _steps("disable_user")},
    )
    await client.post(
        "/playbooks/PB-992/run", headers=headers, json={"dry_run": False, "alert_id": str(alert_id)}
    )
    approval_id = (await client.get("/playbooks/approvals", headers=headers)).json()[0]["id"]

    other = await _register(client, "umbrella", "d@example.com")
    await _user_with_role(uuid.UUID(other["organization_id"]), "e@example.com", "SOC_MANAGER")
    foreign_approver = await _login(client, "umbrella", "e@example.com")

    resp = await client.post(
        f"/playbooks/approvals/{approval_id}/approve", headers=foreign_approver
    )
    assert resp.status_code == 404
