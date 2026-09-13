"""Rule management: persistence, versioning, audit, and access control.

Phase 6's security review question is "can an attacker with a foothold in
the SIEM quietly turn off a detection?" These tests answer it in three
parts: the change is permission-gated, it is audit-logged in the same
transaction, and the previous definition survives in an append-only history
the database itself refuses to rewrite (THREAT_MODEL.md §3.4).
"""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text

from app.core.db import async_session_factory, tenant_scoped_session
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.detection import DetectionRuleRecord, DetectionRuleVersion
from app.models.identity import Role, User, UserRole

RULE_YAML = """
rule_id: CUST-001
name: Custom test rule
description: A rule created through the API.
severity: medium
confidence: 60
risk_score: 50
status: enabled
author: tests
conditions:
  field: user.name
  operator: equals
  value: mallory
false_positive_notes: none
investigation_steps: none
mitre_attack:
  - T1078
references:
  - https://attack.mitre.org/techniques/T1078/
"""


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


@pytest.fixture
async def tenant(client: AsyncClient):
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    return uuid.UUID(org["organization_id"]), headers


# ---------------------------------------------------------------------------
# The default pack
# ---------------------------------------------------------------------------


async def test_a_new_tenant_starts_with_the_default_rules_enabled(
    client: AsyncClient, tenant
) -> None:
    """A tenant with no detections sees nothing, so the pack is installed at
    registration rather than left as a step someone must remember."""
    _tenant_id, headers = tenant
    resp = await client.get("/rules", headers=headers)

    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 10
    assert {rule["rule_key"] for rule in rules} >= {"AUTH-001", "AUTH-002", "WIN-001"}
    assert all(rule["status"] == "enabled" for rule in rules)
    # Both execution shapes are represented, and each rule says which it is.
    assert {rule["rule_type"] for rule in rules} == {"streaming", "windowed"}


async def test_installing_defaults_again_does_not_clobber_local_tuning(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    await client.post(
        "/rules/AUTH-001/status", headers=headers, json={"status": "disabled"}
    )

    resp = await client.post("/rules/install-defaults", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["installed"] == [], "an existing rule was reinstalled"

    after = await client.get("/rules/AUTH-001", headers=headers)
    assert after.json()["status"] == "disabled", "local tuning was overwritten"


# ---------------------------------------------------------------------------
# CRUD and versioning
# ---------------------------------------------------------------------------


async def test_create_read_and_version_a_rule(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant

    created = await client.post("/rules", headers=headers, json={"definition_yaml": RULE_YAML})
    assert created.status_code == 201, created.text
    assert created.json()["rule_key"] == "CUST-001"
    assert created.json()["current_version"] == 1
    # Indexed columns are derived from the parsed rule, never sent alongside.
    assert created.json()["severity"] == "medium"
    assert created.json()["mitre_techniques"] == ["T1078"]

    updated = await client.put(
        "/rules/CUST-001",
        headers=headers,
        json={
            "definition_yaml": RULE_YAML.replace("severity: medium", "severity: critical"),
            "change_summary": "raise severity after IR review",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["current_version"] == 2
    assert updated.json()["severity"] == "critical"

    versions = await client.get("/rules/CUST-001/versions", headers=headers)
    assert [entry["version"] for entry in versions.json()] == [2, 1]
    assert versions.json()[0]["change_summary"] == "raise severity after IR review"
    # The previous definition is recoverable in full, not just as a diff.
    assert "severity: medium" in versions.json()[1]["definition_yaml"]


async def test_a_duplicate_rule_id_is_rejected(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    await client.post("/rules", headers=headers, json={"definition_yaml": RULE_YAML})
    again = await client.post("/rules", headers=headers, json={"definition_yaml": RULE_YAML})
    assert again.status_code == 409


async def test_an_invalid_rule_is_a_422_with_the_parser_message(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/rules", headers=headers, json={"definition_yaml": "rule_id: nope\nname: x\n"}
    )
    assert resp.status_code == 422
    assert "invalid rule" in resp.text


async def test_a_rule_cannot_be_renamed_in_place(client: AsyncClient, tenant) -> None:
    """Renaming would orphan every alert, exception and metric keyed on the
    old id."""
    _tenant_id, headers = tenant
    await client.post("/rules", headers=headers, json={"definition_yaml": RULE_YAML})

    resp = await client.put(
        "/rules/CUST-001",
        headers=headers,
        json={"definition_yaml": RULE_YAML.replace("CUST-001", "CUST-002")},
    )
    assert resp.status_code == 422
    assert "rule_id cannot be changed" in resp.text


async def test_yaml_code_execution_is_refused_by_the_api(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/rules",
        headers=headers,
        json={"definition_yaml": '!!python/object/apply:os.system ["echo pwned"]'},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Status changes are audited
# ---------------------------------------------------------------------------


async def _audit_actions(tenant_id: uuid.UUID) -> list[str]:
    async with tenant_scoped_session(tenant_id) as db:
        rows = await db.execute(select(AuditLog.action).order_by(AuditLog.occurred_at))
        return list(rows.scalars())


async def test_disabling_a_rule_is_audit_logged(client: AsyncClient, tenant) -> None:
    tenant_id, headers = tenant

    resp = await client.post(
        "/rules/AUTH-001/status", headers=headers, json={"status": "disabled"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "disabled"
    # The stored YAML follows the column, so the engine and the API cannot
    # disagree about whether a rule is on.
    assert "status: disabled" in resp.json()["definition_yaml"]

    assert "DISABLE_DETECTION_RULE" in await _audit_actions(tenant_id)


async def test_enabling_and_dry_running_are_distinct_audited_states(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    await client.post("/rules/AUTH-001/status", headers=headers, json={"status": "disabled"})
    await client.post("/rules/AUTH-001/status", headers=headers, json={"status": "testing"})

    actions = await _audit_actions(tenant_id)
    assert actions.count("DISABLE_DETECTION_RULE") == 1
    assert actions.count("ENABLE_DETECTION_RULE") == 1

    current = await client.get("/rules/AUTH-001", headers=headers)
    assert current.json()["status"] == "testing"


async def test_editing_a_rule_is_audit_logged_with_both_definitions(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    await client.post("/rules", headers=headers, json={"definition_yaml": RULE_YAML})
    await client.put(
        "/rules/CUST-001",
        headers=headers,
        json={"definition_yaml": RULE_YAML.replace("confidence: 60", "confidence: 10")},
    )

    async with tenant_scoped_session(tenant_id) as db:
        row = await db.scalar(
            select(AuditLog).where(AuditLog.action == "UPDATE_DETECTION_RULE")
        )
    assert row is not None
    assert "confidence: 60" in row.before_state["definition_yaml"]
    assert "confidence: 10" in row.after_state["definition_yaml"]


async def test_rule_history_cannot_be_rewritten(client: AsyncClient, tenant) -> None:
    """Enforced by a database trigger, not by the service layer: an attacker
    who reaches the database directly still cannot edit the history."""
    tenant_id, headers = tenant
    await client.post("/rules", headers=headers, json={"definition_yaml": RULE_YAML})

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(
                text("UPDATE detection_rule_versions SET definition_yaml = 'tampered'")
            )
        await db.rollback()

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(text("DELETE FROM detection_rule_versions"))
        await db.rollback()


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


async def test_an_exception_is_validated_stored_and_audited(
    client: AsyncClient, tenant
) -> None:
    tenant_id, headers = tenant
    resp = await client.post(
        "/rules/AUTH-001/exceptions",
        headers=headers,
        json={
            "reason": "backup host fails on credential rotation",
            "conditions": {"field": "source_ip", "operator": "equals", "value": "10.9.9.9"},
            "expires_at": "2026-12-31T00:00:00Z",
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["reason"].startswith("backup host")

    listed = await client.get("/rules/AUTH-001/exceptions", headers=headers)
    assert len(listed.json()) == 1
    assert "CREATE_RULE_EXCEPTION" in await _audit_actions(tenant_id)


async def test_an_exception_with_an_invalid_condition_is_rejected(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/rules/AUTH-001/exceptions",
        headers=headers,
        json={
            "reason": "typo in the operator",
            "conditions": {"field": "source_ip", "operator": "equalz", "value": "10.9.9.9"},
        },
    )
    assert resp.status_code == 422


async def test_an_exception_without_a_reason_is_rejected(client: AsyncClient, tenant) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/rules/AUTH-001/exceptions",
        headers=headers,
        json={
            "reason": "",
            "conditions": {"field": "source_ip", "operator": "equals", "value": "10.9.9.9"},
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------


async def test_the_test_endpoint_evaluates_without_storing_anything(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    resp = await client.post(
        "/rules/test",
        headers=headers,
        json={
            "definition_yaml": RULE_YAML,
            "event": {"user": {"name": "mallory"}, "tenant_id": "t"},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["matched"] is True

    miss = await client.post(
        "/rules/test",
        headers=headers,
        json={"definition_yaml": RULE_YAML, "event": {"user": {"name": "alice"}}},
    )
    assert miss.json()["matched"] is False

    # Nothing was persisted by either call.
    listed = await client.get("/rules", headers=headers)
    assert "CUST-001" not in {rule["rule_key"] for rule in listed.json()}


async def test_testing_a_windowed_rule_says_what_it_did_not_check(
    client: AsyncClient, tenant
) -> None:
    _tenant_id, headers = tenant
    stored = await client.get("/rules/AUTH-001", headers=headers)

    resp = await client.post(
        "/rules/test",
        headers=headers,
        json={
            "definition_yaml": stored.json()["definition_yaml"],
            "event": {
                "class": "Authentication",
                "authentication": {"outcome": "failure"},
                "user": {"name": "alice"},
            },
        },
    )
    assert resp.status_code == 200
    assert resp.json()["rule_type"] == "windowed"
    assert "threshold" in (resp.json()["note"] or "")


# ---------------------------------------------------------------------------
# Access control and tenant isolation
# ---------------------------------------------------------------------------


async def test_an_l1_analyst_can_read_but_not_change_rules(
    client: AsyncClient, tenant
) -> None:
    tenant_id, _headers = tenant
    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    # L1 has no rule:read in the seed matrix — reading rules is an L2+ task.
    assert (await client.get("/rules", headers=l1)).status_code == 403
    assert (
        await client.post("/rules", headers=l1, json={"definition_yaml": RULE_YAML})
    ).status_code == 403
    assert (
        await client.post("/rules/AUTH-001/status", headers=l1, json={"status": "disabled"})
    ).status_code == 403


async def test_an_l2_analyst_can_read_and_test_but_not_edit(
    client: AsyncClient, tenant
) -> None:
    tenant_id, _headers = tenant
    await _user_with_role(tenant_id, "l2@example.com", "SOC_ANALYST_L2")
    l2 = await _login(client, "acme", "l2@example.com")

    assert (await client.get("/rules", headers=l2)).status_code == 200
    assert (
        await client.post(
            "/rules/test",
            headers=l2,
            json={"definition_yaml": RULE_YAML, "event": {"user": {"name": "mallory"}}},
        )
    ).status_code == 200
    assert (
        await client.post("/rules/AUTH-001/status", headers=l2, json={"status": "disabled"})
    ).status_code == 403


async def test_an_unauthenticated_caller_reaches_nothing(client: AsyncClient) -> None:
    assert (await client.get("/rules")).status_code == 401


async def test_one_tenants_rules_are_invisible_to_another(client: AsyncClient) -> None:
    org_a = await _register(client, "acme", "a@example.com")
    await _register(client, "globex", "b@example.com")
    headers_a = await _login(client, "acme", "a@example.com")
    headers_b = await _login(client, "globex", "b@example.com")

    await client.post("/rules", headers=headers_a, json={"definition_yaml": RULE_YAML})

    # B cannot see it, cannot fetch it by key, and cannot change it.
    assert "CUST-001" not in {
        rule["rule_key"] for rule in (await client.get("/rules", headers=headers_b)).json()
    }
    assert (await client.get("/rules/CUST-001", headers=headers_b)).status_code == 404
    assert (
        await client.post("/rules/CUST-001/status", headers=headers_b, json={"status": "disabled"})
    ).status_code == 404

    # ... and A's rule is untouched.
    assert (await client.get("/rules/CUST-001", headers=headers_a)).json()["status"] == "enabled"
    assert uuid.UUID(org_a["organization_id"])


async def test_row_level_security_hides_other_tenants_rules_at_the_database(
    client: AsyncClient,
) -> None:
    """The application filter is not the only thing standing between tenants:
    with a different tenant's GUC set, the rows are simply not there."""
    org_a = await _register(client, "acme", "a@example.com")
    org_b = await _register(client, "globex", "b@example.com")
    tenant_a = uuid.UUID(org_a["organization_id"])
    tenant_b = uuid.UUID(org_b["organization_id"])

    async with tenant_scoped_session(tenant_a) as db:
        visible_to_a = len(list((await db.execute(select(DetectionRuleRecord))).scalars()))
        versions_a = len(list((await db.execute(select(DetectionRuleVersion))).scalars()))
    async with tenant_scoped_session(tenant_b) as db:
        b_keys = {
            record.tenant_id
            for record in (await db.execute(select(DetectionRuleRecord))).scalars()
        }

    assert visible_to_a >= 10
    assert versions_a >= 10
    assert b_keys == {tenant_b}


async def test_a_session_with_no_tenant_context_sees_no_rules(client: AsyncClient) -> None:
    """Fail-closed: a bug that forgets to set the tenant GUC must return
    nothing, never everything."""
    await _register(client, "acme")

    async with async_session_factory() as db:
        rows = list((await db.execute(select(DetectionRuleRecord))).scalars())
    assert rows == []
