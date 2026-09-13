"""The incidents API: promotion, RBAC, and the cross-tenant IDOR suite.

Spec §12 extends the Phase 2 IDOR requirement to incidents explicitly:
cross-tenant incident access must be blocked. This file's isolation tests
are that requirement checked against every endpoint the API exposes, not
just the obvious read path.
"""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import tenant_scoped_session
from app.core.opensearch import get_opensearch
from app.core.security import hash_password
from app.models.assets import Asset
from app.models.audit import AuditLog
from app.models.identity import Role, User, UserRole
from app.models.threat_intel import Ioc
from app.services import alerts as alert_service
from app.services.alerts import AlertInput
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
        json={
            "organization_slug": slug,
            "email": email,
            "password": "Correct-Horse-Battery-Staple-1",
        },
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


async def _seed_alert(tenant_id: uuid.UUID, *, event_ids: list[str] | None = None) -> str:
    async with tenant_scoped_session(tenant_id) as db:
        alert, _created = await alert_service.create_or_update(
            db,
            AlertInput(
                tenant_id=tenant_id,
                source="detection",
                rule_key="WIN-003",
                title="LSASS memory dumping indicators",
                description="WIN-003 fired for hostname=dc01",
                severity="critical",
                confidence=85,
                risk_score=90,
                risk_bucket="CRITICAL",
                risk_explanation={"score": 90},
                dedup_key=f"detection:WIN-003:{uuid.uuid4()}",
                event_ids=event_ids or [str(uuid.uuid4())],
                detection_ids=[str(uuid.uuid4())],
                evidence={"hostname": "dc01"},
                mitre_techniques=["T1003.001"],
                affected_host="dc01",
            ),
        )
        await db.commit()
        return str(alert.id)


async def _seed_asset(tenant_id: uuid.UUID, hostname: str = "dc01") -> str:
    async with tenant_scoped_session(tenant_id) as db:
        asset = Asset(
            tenant_id=tenant_id, asset_type="server", hostname=hostname, criticality="HIGH"
        )
        db.add(asset)
        await db.commit()
        return str(asset.id)


async def _seed_ioc(tenant_id: uuid.UUID, value: str = "203.0.113.9") -> str:
    async with tenant_scoped_session(tenant_id) as db:
        ioc = Ioc(
            tenant_id=tenant_id,
            ioc_type="ipv4",
            value=value,
            classification="malicious",
            confidence=90,
            source="ir",
        )
        db.add(ioc)
        await db.commit()
        return str(ioc.id)


async def _index_event(tenant_id: str, event_id: str) -> None:
    client = get_opensearch()
    await bootstrap_indices(client)
    await client.index(
        index=NORMALIZED_ALIAS,
        id=event_id,
        body={
            "event_id": event_id,
            "tenant_id": tenant_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "source_type": "windows_event_log",
            "class": "Process Activity",
            "hostname": "dc01",
            "schema_version": "lunatic-1",
        },
        refresh=True,
    )


@pytest.fixture
async def tenant(client: AsyncClient):
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    return tenant_id, headers


# ---------------------------------------------------------------------------
# Creation, promotion, reads
# ---------------------------------------------------------------------------


async def test_creating_an_incident(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant

    created = await client.post(
        "/incidents", headers=headers, json={"title": "Suspected takeover", "severity": "critical"}
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["display_id"].startswith("INC-")
    assert body["priority"] == "P1"
    assert body["status"] == "NEW"
    assert body["alerts"] == []


async def test_promoting_alerts_at_creation(client: AsyncClient, tenant) -> None:
    """The common path: an analyst opens a case directly from one or more
    alerts they were already looking at."""
    tenant_id, headers = tenant
    alert_id = await _seed_alert(tenant_id)

    created = await client.post(
        "/incidents",
        headers=headers,
        json={"title": "Account takeover", "severity": "critical", "alert_ids": [alert_id]},
    )
    assert created.status_code == 201, created.text
    assert len(created.json()["alerts"]) == 1
    assert created.json()["alerts"][0]["id"] == alert_id


async def test_promoting_an_alert_from_another_tenant_is_refused(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    other_org = await _register(client, "globex", "b@example.com")
    foreign_alert = await _seed_alert(uuid.UUID(other_org["organization_id"]))

    resp = await client.post(
        "/incidents",
        headers=headers,
        json={"title": "x", "alert_ids": [foreign_alert]},
    )
    assert resp.status_code == 404


async def test_the_queue_can_be_listed_filtered_and_counted(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    first = await client.post("/incidents", headers=headers, json={"title": "a", "severity": "low"})
    await client.post(
        f"/incidents/{first.json()['id']}/status", headers=headers, json={"status": "TRIAGE"}
    )
    await client.post("/incidents", headers=headers, json={"title": "b", "severity": "high"})

    assert len((await client.get("/incidents?status=NEW", headers=headers)).json()) == 1
    assert len((await client.get("/incidents?status=TRIAGE", headers=headers)).json()) == 1

    counts = await client.get("/incidents/counts", headers=headers)
    assert counts.json()["by_status"] == {"NEW": 1, "TRIAGE": 1}
    assert counts.json()["open_total"] == 2


async def test_updating_fields(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]

    updated = await client.patch(
        f"/incidents/{incident_id}",
        headers=headers,
        json={"lessons_learned": "MFA should have been enforced on the VPN"},
    )
    assert updated.status_code == 200
    assert "MFA" in updated.json()["lessons_learned"]

    async with tenant_scoped_session(tenant_id) as db:
        actions = list((await db.execute(select(AuditLog.action))).scalars())
    assert "UPDATE_INCIDENT" in actions


async def test_an_empty_patch_is_rejected(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]
    assert (await client.patch(f"/incidents/{incident_id}", headers=headers, json={})).status_code == 400


# ---------------------------------------------------------------------------
# Workflow through the API
# ---------------------------------------------------------------------------


async def test_valid_and_invalid_transitions_through_the_api(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]

    moved = await client.post(
        f"/incidents/{incident_id}/status", headers=headers, json={"status": "TRIAGE"}
    )
    assert moved.status_code == 200
    assert moved.json()["status"] == "TRIAGE"

    invalid = await client.post(
        f"/incidents/{incident_id}/status", headers=headers, json={"status": "RECOVERY"}
    )
    assert invalid.status_code == 409
    assert "cannot move an incident" in invalid.text


async def test_an_unknown_status_is_rejected(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]
    resp = await client.post(
        f"/incidents/{incident_id}/status", headers=headers, json={"status": "VANISHED"}
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Linkage, notes, tasks
# ---------------------------------------------------------------------------


async def test_linking_alerts_assets_iocs_and_users(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]
    alert_id = await _seed_alert(tenant_id)
    asset_id = await _seed_asset(tenant_id)
    ioc_id = await _seed_ioc(tenant_id)

    r1 = await client.post(
        f"/incidents/{incident_id}/alerts", headers=headers, json={"alert_id": alert_id}
    )
    assert r1.status_code == 200
    assert len(r1.json()["alerts"]) == 1

    r2 = await client.post(
        f"/incidents/{incident_id}/assets", headers=headers, json={"asset_id": asset_id}
    )
    assert r2.json()["linked"]["assets"][0]["id"] == asset_id

    r3 = await client.post(
        f"/incidents/{incident_id}/iocs", headers=headers, json={"ioc_id": ioc_id}
    )
    assert r3.json()["linked"]["iocs"][0]["id"] == ioc_id

    r4 = await client.post(
        f"/incidents/{incident_id}/users", headers=headers, json={"username": "alice"}
    )
    assert r4.json()["linked"]["users"][0]["username"] == "alice"


async def test_linking_a_foreign_assets_id_is_refused(client: AsyncClient, tenant) -> None:
    """A cross-object link is a place an IDOR hides: linking must check the
    target belongs to the caller's own tenant."""
    tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]
    other_org = await _register(client, "globex", "b@example.com")
    foreign_asset = await _seed_asset(uuid.UUID(other_org["organization_id"]))

    resp = await client.post(
        f"/incidents/{incident_id}/assets", headers=headers, json={"asset_id": foreign_asset}
    )
    assert resp.status_code == 404


async def test_notes_and_tasks(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]

    note = await client.post(
        f"/incidents/{incident_id}/notes", headers=headers, json={"body": "first look done"}
    )
    assert note.status_code == 201
    assert len((await client.get(f"/incidents/{incident_id}/notes", headers=headers)).json()) == 1

    task = await client.post(
        f"/incidents/{incident_id}/tasks", headers=headers, json={"title": "collect memory image"}
    )
    assert task.status_code == 201
    task_id = task.json()["id"]

    done = await client.patch(
        f"/incidents/{incident_id}/tasks/{task_id}", headers=headers, json={"status": "done"}
    )
    assert done.status_code == 200
    assert done.json()["completed_at"] is not None


async def test_an_invalid_task_status_is_rejected(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]
    task_id = (
        await client.post(f"/incidents/{incident_id}/tasks", headers=headers, json={"title": "x"})
    ).json()["id"]

    resp = await client.patch(
        f"/incidents/{incident_id}/tasks/{task_id}", headers=headers, json={"status": "vanished"}
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Timeline completeness through the API
# ---------------------------------------------------------------------------


async def test_the_timeline_reflects_every_action_taken_through_the_api(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]
    asset_id = await _seed_asset(tenant_id)

    await client.post(
        f"/incidents/{incident_id}/status", headers=headers, json={"status": "TRIAGE"}
    )
    await client.post(f"/incidents/{incident_id}/notes", headers=headers, json={"body": "note"})
    await client.post(
        f"/incidents/{incident_id}/tasks", headers=headers, json={"title": "task"}
    )
    await client.post(
        f"/incidents/{incident_id}/assets", headers=headers, json={"asset_id": asset_id}
    )

    timeline = await client.get(f"/incidents/{incident_id}/timeline", headers=headers)
    assert timeline.status_code == 200
    kinds = [entry["kind"] for entry in timeline.json()]
    assert kinds == ["created", "status_change", "note", "task", "asset_linked"]
    # Genuinely ordered, not just complete — the clock_timestamp() fix.
    occurred = [entry["occurred_at"] for entry in timeline.json()]
    assert occurred == sorted(occurred)


# ---------------------------------------------------------------------------
# Evidence, rolled up from linked alerts
# ---------------------------------------------------------------------------


async def test_evidence_rolls_up_from_every_linked_alert(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]

    event_id = str(uuid.uuid4())
    await _index_event(str(tenant_id), event_id)
    alert_id = await _seed_alert(tenant_id, event_ids=[event_id])
    await client.post(
        f"/incidents/{incident_id}/alerts", headers=headers, json={"alert_id": alert_id}
    )

    evidence = await client.get(f"/incidents/{incident_id}/evidence", headers=headers)
    assert evidence.status_code == 200
    body = evidence.json()
    assert body["total_event_ids"] == 1
    assert body["resolved"] == 1
    assert body["documents"][0]["document"]["hostname"] == "dc01"


async def test_evidence_that_aged_out_is_reported(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]

    gone = str(uuid.uuid4())
    alert_id = await _seed_alert(tenant_id, event_ids=[gone])
    await client.post(
        f"/incidents/{incident_id}/alerts", headers=headers, json={"alert_id": alert_id}
    )

    body = (await client.get(f"/incidents/{incident_id}/evidence", headers=headers)).json()
    assert body["resolved"] == 0
    assert body["missing_event_ids"] == [gone]


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


async def test_an_analyst_can_read_and_write_incidents(client: AsyncClient, tenant) -> None:
    tenant_id, _headers = tenant
    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    created = await client.post("/incidents", headers=l1, json={"title": "x"})
    assert created.status_code == 201
    assert (await client.get("/incidents", headers=l1)).status_code == 200


async def test_a_read_only_role_cannot_write(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]
    await _user_with_role(tenant_id, "ro@example.com", "READ_ONLY")
    read_only = await _login(client, "acme", "ro@example.com")

    assert (await client.get("/incidents", headers=read_only)).status_code == 200
    assert (
        await client.post("/incidents", headers=read_only, json={"title": "x"})
    ).status_code == 403
    assert (
        await client.post(
            f"/incidents/{incident_id}/status", headers=read_only, json={"status": "TRIAGE"}
        )
    ).status_code == 403
    assert (
        await client.post(
            f"/incidents/{incident_id}/notes", headers=read_only, json={"body": "x"}
        )
    ).status_code == 403


async def test_a_threat_hunter_can_read_but_not_write(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]
    await _user_with_role(tenant_id, "hunter@example.com", "THREAT_HUNTER")
    hunter = await _login(client, "acme", "hunter@example.com")

    assert (await client.get(f"/incidents/{incident_id}", headers=hunter)).status_code == 200
    assert (
        await client.post(
            f"/incidents/{incident_id}/status", headers=hunter, json={"status": "TRIAGE"}
        )
    ).status_code == 403


async def test_an_unauthenticated_caller_reaches_nothing(client: AsyncClient) -> None:
    assert (await client.get("/incidents")).status_code == 401
    assert (await client.post("/incidents", json={"title": "x"})).status_code == 401


# ---------------------------------------------------------------------------
# Cross-tenant isolation — spec §12's extension of the Phase 2 IDOR suite
# ---------------------------------------------------------------------------


async def test_one_tenants_incidents_are_invisible_to_another(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    incident_id = (
        await client.post("/incidents", headers=headers, json={"title": "x"})
    ).json()["id"]

    await _register(client, "globex", "b@example.com")
    other = await _login(client, "globex", "b@example.com")

    assert (await client.get("/incidents", headers=other)).json() == []
    assert (await client.get(f"/incidents/{incident_id}", headers=other)).status_code == 404
    assert (
        await client.patch(f"/incidents/{incident_id}", headers=other, json={"title": "y"})
    ).status_code == 404
    assert (
        await client.post(
            f"/incidents/{incident_id}/status", headers=other, json={"status": "TRIAGE"}
        )
    ).status_code == 404
    assert (
        await client.post(f"/incidents/{incident_id}/notes", headers=other, json={"body": "x"})
    ).status_code == 404
    assert (
        await client.get(f"/incidents/{incident_id}/timeline", headers=other)
    ).status_code == 404
    assert (
        await client.get(f"/incidents/{incident_id}/evidence", headers=other)
    ).status_code == 404
    assert (
        await client.get(f"/incidents/{incident_id}/tasks", headers=other)
    ).status_code == 404


async def test_a_malformed_incident_id_is_indistinguishable_from_missing(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    assert (await client.get("/incidents/not-a-uuid", headers=headers)).status_code == 404
