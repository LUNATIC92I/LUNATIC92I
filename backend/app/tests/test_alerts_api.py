"""The alerts API: analyst tiers, audit, and evidence lineage.

The phase's security review item is that the L1/L2/L3 distinction is
*enforced*, not labelled — so most of this file is about who may do what,
and the rest is about an alert being able to prove what it was raised on.
"""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import tenant_scoped_session
from app.core.opensearch import get_opensearch
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.identity import Role, User, UserRole
from app.services import alerts as service
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
        alert, _created = await service.create_or_update(
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
                risk_explanation={"score": 90, "factors": []},
                dedup_key=f"detection:WIN-003:hostname=dc01:{uuid.uuid4()}",
                event_ids=event_ids or [str(uuid.uuid4())],
                detection_ids=[str(uuid.uuid4())],
                evidence={"hostname": "dc01"},
                mitre_techniques=["T1003.001"],
                affected_host="dc01",
            ),
        )
        await db.commit()
        return str(alert.id)


@pytest.fixture
async def tenant(client: AsyncClient):
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    alert_id = await _seed_alert(tenant_id)
    return tenant_id, headers, alert_id


# ---------------------------------------------------------------------------
# Reading the queue
# ---------------------------------------------------------------------------


async def test_the_queue_shows_the_alert_with_its_context(client: AsyncClient, tenant) -> None:
    _tenant_id, headers, alert_id = tenant

    listed = await client.get("/alerts", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["display_id"].startswith("ALT-")

    detail = await client.get(f"/alerts/{alert_id}", headers=headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["severity"] == "critical"
    assert body["mitre_techniques"] == ["T1003.001"]
    # The score's reasoning travels with the alert (Phase 8).
    assert body["risk_explanation"]["score"] == 90
    assert body["event_ids"]


async def test_the_queue_can_be_filtered_and_counted(client: AsyncClient, tenant) -> None:
    _tenant_id, headers, alert_id = tenant
    await client.post(f"/alerts/{alert_id}/status", headers=headers, json={"status": "IN_PROGRESS"})

    assert (await client.get("/alerts?status=NEW", headers=headers)).json() == []
    assert len((await client.get("/alerts?status=IN_PROGRESS", headers=headers)).json()) == 1

    counts = await client.get("/alerts/counts", headers=headers)
    assert counts.json()["by_status"] == {"IN_PROGRESS": 1}
    assert counts.json()["open_total"] == 1


async def test_an_unknown_alert_is_a_404(client: AsyncClient, tenant) -> None:
    _tenant_id, headers, _alert_id = tenant
    assert (await client.get(f"/alerts/{uuid.uuid4()}", headers=headers)).status_code == 404
    assert (await client.get("/alerts/not-a-uuid", headers=headers)).status_code == 404


# ---------------------------------------------------------------------------
# Lifecycle through the API
# ---------------------------------------------------------------------------


async def test_triage_moves_the_alert_and_records_who_did_it(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers, alert_id = tenant

    moved = await client.post(
        f"/alerts/{alert_id}/status", headers=headers, json={"status": "IN_PROGRESS"}
    )
    assert moved.status_code == 200
    assert moved.json()["status"] == "IN_PROGRESS"
    assert moved.json()["acknowledged_at"] is not None
    # Picking an alert up takes ownership: an unassigned in-progress alert
    # is how work falls between two analysts.
    assert moved.json()["analyst_id"] is not None

    history = await client.get(f"/alerts/{alert_id}/history", headers=headers)
    assert [row["to_status"] for row in history.json()] == ["NEW", "IN_PROGRESS"]

    async with tenant_scoped_session(tenant_id) as db:
        actions = list((await db.execute(select(AuditLog.action))).scalars())
    assert "ALERT_IN_PROGRESS" in actions


async def test_an_invalid_transition_is_a_conflict_not_a_crash(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers, alert_id = tenant
    await client.post(
        f"/alerts/{alert_id}/status", headers=headers, json={"status": "FALSE_POSITIVE"}
    )

    resp = await client.post(
        f"/alerts/{alert_id}/status", headers=headers, json={"status": "RESOLVED"}
    )
    assert resp.status_code == 409
    assert "cannot move an alert from FALSE_POSITIVE" in resp.text


async def test_an_unknown_status_is_rejected(client: AsyncClient, tenant) -> None:
    _tenant_id, headers, alert_id = tenant
    resp = await client.post(
        f"/alerts/{alert_id}/status", headers=headers, json={"status": "MAYBE"}
    )
    assert resp.status_code == 422


async def test_closing_records_the_resolution_and_is_audited(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers, alert_id = tenant

    closed = await client.post(
        f"/alerts/{alert_id}/status",
        headers=headers,
        json={"status": "FALSE_POSITIVE", "note": "authorised crash-dump collection, case 4711"},
    )
    assert closed.status_code == 200
    assert closed.json()["closed_at"] is not None
    assert "4711" in closed.json()["resolution_note"]

    async with tenant_scoped_session(tenant_id) as db:
        actions = list((await db.execute(select(AuditLog.action))).scalars())
    assert "CLOSE_ALERT_FALSE_POSITIVE" in actions


async def test_reopening_is_its_own_audited_action(client: AsyncClient, tenant) -> None:
    """New evidence on something already dismissed is exactly what a
    reviewer goes looking for."""
    tenant_id, headers, alert_id = tenant
    await client.post(
        f"/alerts/{alert_id}/status", headers=headers, json={"status": "FALSE_POSITIVE"}
    )
    reopened = await client.post(
        f"/alerts/{alert_id}/status", headers=headers, json={"status": "IN_PROGRESS"}
    )
    assert reopened.status_code == 200

    async with tenant_scoped_session(tenant_id) as db:
        actions = list((await db.execute(select(AuditLog.action))).scalars())
    assert "REOPEN_ALERT" in actions


async def test_assigning_and_unassigning_is_audited(client: AsyncClient, tenant) -> None:
    tenant_id, headers, alert_id = tenant
    analyst_id = await _user_with_role(tenant_id, "l2@example.com", "SOC_ANALYST_L2")

    assigned = await client.post(
        f"/alerts/{alert_id}/assign", headers=headers, json={"analyst_id": str(analyst_id)}
    )
    assert assigned.json()["analyst_id"] == str(analyst_id)

    unassigned = await client.post(
        f"/alerts/{alert_id}/assign", headers=headers, json={"analyst_id": None}
    )
    assert unassigned.json()["analyst_id"] is None

    async with tenant_scoped_session(tenant_id) as db:
        actions = list((await db.execute(select(AuditLog.action))).scalars())
    assert actions.count("ASSIGN_ALERT") == 2


async def test_notes_are_recorded_against_the_alert(client: AsyncClient, tenant) -> None:
    _tenant_id, headers, alert_id = tenant

    created = await client.post(
        f"/alerts/{alert_id}/notes",
        headers=headers,
        json={"body": "confirmed with the platform team: no change window covers this"},
    )
    assert created.status_code == 201

    notes = await client.get(f"/alerts/{alert_id}/notes", headers=headers)
    assert len(notes.json()) == 1
    assert notes.json()[0]["author_id"] is not None


# ---------------------------------------------------------------------------
# Analyst tiers — the security review item
# ---------------------------------------------------------------------------


async def test_an_l1_analyst_can_triage_and_escalate(client: AsyncClient, tenant) -> None:
    tenant_id, _headers, alert_id = tenant
    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    assert (await client.get("/alerts", headers=l1)).status_code == 200
    assert (
        await client.post(f"/alerts/{alert_id}/status", headers=l1, json={"status": "IN_PROGRESS"})
    ).status_code == 200
    assert (
        await client.post(f"/alerts/{alert_id}/status", headers=l1, json={"status": "ESCALATED"})
    ).status_code == 200
    assert (
        await client.post(f"/alerts/{alert_id}/notes", headers=l1, json={"body": "escalating"})
    ).status_code == 201


@pytest.mark.parametrize("closing_status", ["RESOLVED", "FALSE_POSITIVE", "CLOSED"])
async def test_an_l1_analyst_cannot_end_the_work(
    client: AsyncClient, tenant, closing_status: str
) -> None:
    """The tier distinction, enforced by the authorization layer rather than
    written on an org chart: an L1 can pick an alert up, only L2 and above
    can decide it is over."""
    tenant_id, _headers, alert_id = tenant
    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    resp = await client.post(
        f"/alerts/{alert_id}/status", headers=l1, json={"status": closing_status}
    )
    assert resp.status_code == 403
    assert "alert:close" in resp.text


async def test_an_l2_analyst_can_close(client: AsyncClient, tenant) -> None:
    tenant_id, _headers, alert_id = tenant
    await _user_with_role(tenant_id, "l2@example.com", "SOC_ANALYST_L2")
    l2 = await _login(client, "acme", "l2@example.com")

    resp = await client.post(
        f"/alerts/{alert_id}/status", headers=l2, json={"status": "RESOLVED"}
    )
    assert resp.status_code == 200


async def test_a_read_only_role_cannot_touch_anything(client: AsyncClient, tenant) -> None:
    tenant_id, _headers, alert_id = tenant
    await _user_with_role(tenant_id, "ro@example.com", "READ_ONLY")
    read_only = await _login(client, "acme", "ro@example.com")

    assert (await client.get("/alerts", headers=read_only)).status_code == 200
    assert (
        await client.post(
            f"/alerts/{alert_id}/status", headers=read_only, json={"status": "IN_PROGRESS"}
        )
    ).status_code == 403
    assert (
        await client.post(f"/alerts/{alert_id}/notes", headers=read_only, json={"body": "hi"})
    ).status_code == 403
    assert (
        await client.post(
            f"/alerts/{alert_id}/assign", headers=read_only, json={"analyst_id": None}
        )
    ).status_code == 403


async def test_a_threat_hunter_can_read_but_not_triage(client: AsyncClient, tenant) -> None:
    tenant_id, _headers, alert_id = tenant
    await _user_with_role(tenant_id, "hunter@example.com", "THREAT_HUNTER")
    hunter = await _login(client, "acme", "hunter@example.com")

    assert (await client.get(f"/alerts/{alert_id}", headers=hunter)).status_code == 200
    assert (
        await client.post(
            f"/alerts/{alert_id}/status", headers=hunter, json={"status": "IN_PROGRESS"}
        )
    ).status_code == 403


async def test_an_unauthenticated_caller_reaches_nothing(client: AsyncClient) -> None:
    assert (await client.get("/alerts")).status_code == 401
    assert (
        await client.post(f"/alerts/{uuid.uuid4()}/status", json={"status": "CLOSED"})
    ).status_code == 401


async def test_one_tenants_alerts_are_invisible_to_another(client: AsyncClient, tenant) -> None:
    _tenant_id, _headers, alert_id = tenant
    await _register(client, "globex", "b@example.com")
    other = await _login(client, "globex", "b@example.com")

    assert (await client.get("/alerts", headers=other)).json() == []
    assert (await client.get(f"/alerts/{alert_id}", headers=other)).status_code == 404
    assert (
        await client.post(f"/alerts/{alert_id}/status", headers=other, json={"status": "CLOSED"})
    ).status_code == 404
    assert (await client.get(f"/alerts/{alert_id}/evidence", headers=other)).status_code == 404


# ---------------------------------------------------------------------------
# Evidence lineage
# ---------------------------------------------------------------------------


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
            "command_line": "rundll32.exe comsvcs.dll, MiniDump 624 lsass.dmp full",
            "schema_version": "lunatic-1",
        },
        refresh=True,
    )


async def test_an_alert_resolves_back_to_the_events_behind_it(client: AsyncClient) -> None:
    """Evidence lineage integrity: an alert must always be able to show the
    documents it was raised on."""
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])

    event_id = str(uuid.uuid4())
    await _index_event(str(tenant_id), event_id)
    alert_id = await _seed_alert(tenant_id, event_ids=[event_id])

    evidence = await client.get(f"/alerts/{alert_id}/evidence", headers=headers)
    assert evidence.status_code == 200
    body = evidence.json()

    assert body["total_event_ids"] == 1
    assert body["resolved"] == 1
    assert body["missing_event_ids"] == []
    assert body["documents"][0]["found"] is True
    assert body["documents"][0]["document"]["hostname"] == "dc01"


async def test_evidence_that_aged_out_is_reported_not_hidden(client: AsyncClient) -> None:
    """"No evidence" and "the evidence expired" are different findings."""
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])

    present, gone = str(uuid.uuid4()), str(uuid.uuid4())
    await _index_event(str(tenant_id), present)
    alert_id = await _seed_alert(tenant_id, event_ids=[present, gone])

    body = (await client.get(f"/alerts/{alert_id}/evidence", headers=headers)).json()

    assert body["total_event_ids"] == 2
    assert body["resolved"] == 1
    assert body["missing_event_ids"] == [gone]


async def test_evidence_cannot_reach_another_tenants_events(client: AsyncClient) -> None:
    """An alert citing an id belonging to someone else must resolve to
    nothing: the tenant filter here is the isolation boundary, since this
    query runs as the service account."""
    org_a = await _register(client, "acme", "a@example.com")
    org_b = await _register(client, "globex", "b@example.com")
    headers_a = await _login(client, "acme", "a@example.com")

    foreign_event = str(uuid.uuid4())
    await _index_event(org_b["organization_id"], foreign_event)
    alert_id = await _seed_alert(uuid.UUID(org_a["organization_id"]), event_ids=[foreign_event])

    body = (await client.get(f"/alerts/{alert_id}/evidence", headers=headers_a)).json()

    assert body["resolved"] == 0
    assert body["missing_event_ids"] == [foreign_event]
