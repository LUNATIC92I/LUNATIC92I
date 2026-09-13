"""Asset inventory API — the permission-gated, audit-logged risk input.

Asset criticality is a multiplier on every risk score computed for that
machine, so this endpoint is not ordinary CRUD: someone who can quietly
downgrade a domain controller to LOW has turned down the alarm on the most
valuable box in the estate without touching a detection rule. The Phase 8
security review item is exactly that, and these are its tests.
"""

import uuid

from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import tenant_scoped_session
from app.core.security import hash_password
from app.models.assets import Asset
from app.models.audit import AuditLog
from app.models.identity import Role, User, UserRole
from app.risk.engine import apply_to_detection

SERVER = {
    "asset_type": "server",
    "hostname": "dc01",
    "ip_address": "10.1.1.10",
    "criticality": "CRITICAL",
    "environment": "production",
    "owner": "infrastructure",
    "tags": ["domain-controller"],
}


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
        json={
            "organization_slug": slug,
            "email": email,
            "password": "Correct-Horse-Battery-Staple-1",
        },
    )
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def _user_with_role(tenant_id: uuid.UUID, email: str, role_name: str) -> None:
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


async def _audit_actions(tenant_id: uuid.UUID) -> list[str]:
    async with tenant_scoped_session(tenant_id) as db:
        rows = await db.execute(select(AuditLog.action).order_by(AuditLog.occurred_at))
        return list(rows.scalars())


async def test_create_read_update_and_delete(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")

    created = await client.post("/assets", headers=headers, json=SERVER)
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]
    assert created.json()["criticality"] == "CRITICAL"
    assert created.json()["tags"] == ["domain-controller"]

    listed = await client.get("/assets", headers=headers)
    assert [asset["hostname"] for asset in listed.json()] == ["dc01"]

    updated = await client.patch(
        f"/assets/{asset_id}", headers=headers, json={"owner": "platform"}
    )
    assert updated.json()["owner"] == "platform"
    assert updated.json()["criticality"] == "CRITICAL", "an unrelated edit changed criticality"

    deleted = await client.delete(f"/assets/{asset_id}", headers=headers)
    assert deleted.status_code == 204
    assert (await client.get(f"/assets/{asset_id}", headers=headers)).status_code == 404


async def test_criticality_changes_are_audited_under_their_own_action(
    client: AsyncClient,
) -> None:
    """"Who turned down the alarm on this server, and when" has to be a
    question the audit log answers directly."""
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    headers = await _login(client, "acme")

    asset_id = (await client.post("/assets", headers=headers, json=SERVER)).json()["id"]
    await client.patch(f"/assets/{asset_id}", headers=headers, json={"criticality": "LOW"})

    actions = await _audit_actions(tenant_id)
    assert "CREATE_ASSET" in actions
    assert "CHANGE_ASSET_CRITICALITY" in actions

    async with tenant_scoped_session(tenant_id) as db:
        entry = await db.scalar(
            select(AuditLog).where(AuditLog.action == "CHANGE_ASSET_CRITICALITY")
        )
    assert entry is not None
    assert entry.before_state["criticality"] == "CRITICAL"
    assert entry.after_state["criticality"] == "LOW"
    assert entry.object_id == asset_id


async def test_an_ordinary_edit_is_audited_as_an_update(client: AsyncClient) -> None:
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    headers = await _login(client, "acme")

    asset_id = (await client.post("/assets", headers=headers, json=SERVER)).json()["id"]
    await client.patch(f"/assets/{asset_id}", headers=headers, json={"department": "IT"})

    actions = await _audit_actions(tenant_id)
    assert "UPDATE_ASSET" in actions
    assert "CHANGE_ASSET_CRITICALITY" not in actions


async def test_deleting_an_asset_records_what_it_was(client: AsyncClient) -> None:
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    headers = await _login(client, "acme")

    asset_id = (await client.post("/assets", headers=headers, json=SERVER)).json()["id"]
    await client.delete(f"/assets/{asset_id}", headers=headers)

    async with tenant_scoped_session(tenant_id) as db:
        entry = await db.scalar(select(AuditLog).where(AuditLog.action == "DELETE_ASSET"))
    assert entry is not None
    assert entry.before_state["hostname"] == "dc01"
    assert entry.before_state["criticality"] == "CRITICAL"


async def test_criticality_is_a_fixed_vocabulary(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")

    resp = await client.post("/assets", headers=headers, json={**SERVER, "criticality": "SUPREME"})
    assert resp.status_code == 422

    resp = await client.post("/assets", headers=headers, json={**SERVER, "asset_type": "toaster"})
    assert resp.status_code == 422


async def test_criticality_is_normalized_to_upper_case(client: AsyncClient) -> None:
    """A lower-case 'critical' that stored as-is would silently score as an
    unknown asset (the risk factor matches on the canonical form)."""
    await _register(client, "acme")
    headers = await _login(client, "acme")

    created = await client.post("/assets", headers=headers, json={**SERVER, "criticality": "high"})
    assert created.json()["criticality"] == "HIGH"


async def test_an_empty_patch_is_rejected(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")
    asset_id = (await client.post("/assets", headers=headers, json=SERVER)).json()["id"]

    assert (await client.patch(f"/assets/{asset_id}", headers=headers, json={})).status_code == 400


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


async def test_an_analyst_can_read_but_not_edit_the_inventory(client: AsyncClient) -> None:
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    admin = await _login(client, "acme")
    asset_id = (await client.post("/assets", headers=admin, json=SERVER)).json()["id"]

    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    assert (await client.get("/assets", headers=l1)).status_code == 200
    assert (await client.post("/assets", headers=l1, json=SERVER)).status_code == 403
    assert (
        await client.patch(f"/assets/{asset_id}", headers=l1, json={"criticality": "LOW"})
    ).status_code == 403
    assert (await client.delete(f"/assets/{asset_id}", headers=l1)).status_code == 403


async def test_an_l3_analyst_can_edit_but_not_delete(client: AsyncClient) -> None:
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    admin = await _login(client, "acme")
    asset_id = (await client.post("/assets", headers=admin, json=SERVER)).json()["id"]

    await _user_with_role(tenant_id, "l3@example.com", "SOC_ANALYST_L3")
    l3 = await _login(client, "acme", "l3@example.com")

    assert (
        await client.patch(f"/assets/{asset_id}", headers=l3, json={"criticality": "HIGH"})
    ).status_code == 200
    assert (await client.delete(f"/assets/{asset_id}", headers=l3)).status_code == 403


async def test_an_unauthenticated_caller_reaches_nothing(client: AsyncClient) -> None:
    assert (await client.get("/assets")).status_code == 401
    assert (await client.post("/assets", json=SERVER)).status_code == 401


async def test_one_tenants_assets_are_invisible_to_another(client: AsyncClient) -> None:
    await _register(client, "acme", "a@example.com")
    await _register(client, "globex", "b@example.com")
    headers_a = await _login(client, "acme", "a@example.com")
    headers_b = await _login(client, "globex", "b@example.com")

    asset_id = (await client.post("/assets", headers=headers_a, json=SERVER)).json()["id"]

    assert (await client.get("/assets", headers=headers_b)).json() == []
    assert (await client.get(f"/assets/{asset_id}", headers=headers_b)).status_code == 404
    # The interesting one: B must not be able to downgrade A's domain
    # controller and quietly lower every alert about it.
    assert (
        await client.patch(f"/assets/{asset_id}", headers=headers_b, json={"criticality": "LOW"})
    ).status_code == 404
    assert (await client.delete(f"/assets/{asset_id}", headers=headers_b)).status_code == 404

    still_critical = await client.get(f"/assets/{asset_id}", headers=headers_a)
    assert still_critical.json()["criticality"] == "CRITICAL"


async def test_a_malformed_asset_id_is_indistinguishable_from_a_missing_one(
    client: AsyncClient,
) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")
    assert (await client.get("/assets/not-a-uuid", headers=headers)).status_code == 404


# ---------------------------------------------------------------------------
# The inventory is a risk input
# ---------------------------------------------------------------------------


async def test_the_inventory_criticality_is_what_the_risk_engine_reads(
    client: AsyncClient,
) -> None:
    """Closes the loop: the value stored through this API is the value the
    score is computed from, so an unaudited path to it would be an unaudited
    path to every future alert's priority."""
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    headers = await _login(client, "acme")
    asset_id = (await client.post("/assets", headers=headers, json=SERVER)).json()["id"]

    async with tenant_scoped_session(tenant_id) as db:
        asset = await db.get(Asset, uuid.UUID(asset_id))
        assert asset is not None
        enriched_event = {"asset": {"criticality": asset.criticality}}

    detection = {
        "detection_id": "d1",
        "rule_id": "WIN-003",
        "severity": "high",
        "confidence": 80,
        "risk_score": 70,
        "mitre_attack": ["T1003"],
        "evidence": {},
    }
    as_critical = apply_to_detection(detection, enriched_event)

    await client.patch(f"/assets/{asset_id}", headers=headers, json={"criticality": "LOW"})
    async with tenant_scoped_session(tenant_id) as db:
        asset = await db.get(Asset, uuid.UUID(asset_id))
        assert asset is not None
        downgraded_event = {"asset": {"criticality": asset.criticality}}

    as_low = apply_to_detection(detection, downgraded_event)

    assert as_critical["risk_score"] > as_low["risk_score"]
    assert "CHANGE_ASSET_CRITICALITY" in await _audit_actions(tenant_id)
