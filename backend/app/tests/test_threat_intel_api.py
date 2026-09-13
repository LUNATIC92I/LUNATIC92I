"""The /iocs API and IOC matching inside enrichment.

Two things are being proved: that indicator management is gated and audited
like the risk input it is, and that a stored indicator actually reaches the
event pipeline and, through it, the risk score.
"""

import uuid
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy import select

from app.core.db import tenant_scoped_session
from app.core.security import hash_password
from app.enrichment.providers import IocMatchProvider
from app.models.audit import AuditLog
from app.models.identity import Role, User, UserRole
from app.risk.engine import apply_to_detection

INDICATOR = {
    "value": "203.0.113.77",
    "classification": "malicious",
    "confidence": 90,
    "source": "incident-response",
    "description": "C2 from INC-2026-000123",
    "tags": ["c2"],
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


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


async def test_create_list_and_delete_an_indicator(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")

    created = await client.post("/iocs", headers=headers, json=INDICATOR)
    assert created.status_code == 201, created.text
    assert created.json()["ioc_type"] == "ipv4"
    assert created.json()["shared"] is False
    ioc_id = created.json()["id"]

    listed = await client.get("/iocs", headers=headers)
    assert [row["value"] for row in listed.json()] == ["203.0.113.77"]

    assert (await client.delete(f"/iocs/{ioc_id}", headers=headers)).status_code == 204
    assert (await client.get(f"/iocs/{ioc_id}", headers=headers)).status_code == 404


async def test_a_defanged_value_is_stored_canonically(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")

    created = await client.post(
        "/iocs", headers=headers, json={**INDICATOR, "value": "hxxp://EVIL.test[.]com/a"}
    )
    assert created.status_code == 201
    assert created.json()["value"] == "http://evil.test.com/a"
    assert created.json()["ioc_type"] == "url"


async def test_an_unusable_value_is_rejected_with_a_reason(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")

    resp = await client.post("/iocs", headers=headers, json={**INDICATOR, "value": "not a thing"})
    assert resp.status_code == 422
    assert "indicator type" in resp.text


async def test_source_is_required(client: AsyncClient) -> None:
    """Spec §11 at the API: every claim names who is making it."""
    await _register(client, "acme")
    headers = await _login(client, "acme")

    payload = {key: value for key, value in INDICATOR.items() if key != "source"}
    assert (await client.post("/iocs", headers=headers, json=payload)).status_code == 422
    assert (
        await client.post("/iocs", headers=headers, json={**INDICATOR, "source": ""})
    ).status_code == 422


async def test_reclassification_is_audited_under_its_own_action(client: AsyncClient) -> None:
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    headers = await _login(client, "acme")
    ioc_id = (await client.post("/iocs", headers=headers, json=INDICATOR)).json()["id"]

    resp = await client.patch(
        f"/iocs/{ioc_id}", headers=headers, json={"classification": "benign", "confidence": 5}
    )
    assert resp.status_code == 200
    assert resp.json()["classification"] == "benign"

    actions = await _audit_actions(tenant_id)
    assert "CREATE_IOC" in actions
    assert "RECLASSIFY_IOC" in actions


async def test_the_history_endpoint_shows_what_changed(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")
    ioc_id = (await client.post("/iocs", headers=headers, json=INDICATOR)).json()["id"]
    await client.patch(f"/iocs/{ioc_id}", headers=headers, json={"confidence": 20})

    history = await client.get(f"/iocs/{ioc_id}/history", headers=headers)
    assert history.status_code == 200
    changed = {row["changed_field"]: (row["old_value"], row["new_value"]) for row in history.json()}
    assert changed["confidence"] == ("90", "20")


async def test_an_expired_indicator_is_hidden_unless_asked_for(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")
    expired = {
        **INDICATOR,
        "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
    }
    await client.post("/iocs", headers=headers, json=expired)

    assert (await client.get("/iocs", headers=headers)).json() == []
    with_expired = await client.get("/iocs?include_expired=true", headers=headers)
    assert len(with_expired.json()) == 1
    assert with_expired.json()[0]["is_expired"] is True


async def test_the_match_endpoint_accepts_a_pasted_defanged_list(client: AsyncClient) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post("/iocs", headers=headers, json=INDICATOR)

    resp = await client.post(
        "/iocs/match",
        headers=headers,
        # As pasted out of a report: defanged, with a line of noise.
        json={"values": ["203.0.113[.]77", "not an indicator", "8.8.8.8"]},
    )
    assert resp.status_code == 200
    assert [row["value"] for row in resp.json()] == ["203.0.113.77"]
    assert resp.json()[0]["confidence"] == 90


# ---------------------------------------------------------------------------
# Access control and isolation
# ---------------------------------------------------------------------------


async def test_an_l1_analyst_can_read_but_not_write(client: AsyncClient) -> None:
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    admin = await _login(client, "acme")
    ioc_id = (await client.post("/iocs", headers=admin, json=INDICATOR)).json()["id"]

    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    assert (await client.get("/iocs", headers=l1)).status_code == 200
    assert (await client.post("/iocs", headers=l1, json=INDICATOR)).status_code == 403
    assert (
        await client.patch(f"/iocs/{ioc_id}", headers=l1, json={"classification": "benign"})
    ).status_code == 403
    assert (await client.delete(f"/iocs/{ioc_id}", headers=l1)).status_code == 403


async def test_an_unauthenticated_caller_reaches_nothing(client: AsyncClient) -> None:
    assert (await client.get("/iocs")).status_code == 401
    assert (await client.post("/iocs/match", json={"values": ["8.8.8.8"]})).status_code == 401


async def test_one_tenants_indicators_are_invisible_to_another(client: AsyncClient) -> None:
    await _register(client, "acme", "a@example.com")
    await _register(client, "globex", "b@example.com")
    headers_a = await _login(client, "acme", "a@example.com")
    headers_b = await _login(client, "globex", "b@example.com")

    ioc_id = (await client.post("/iocs", headers=headers_a, json=INDICATOR)).json()["id"]

    assert (await client.get("/iocs", headers=headers_b)).json() == []
    assert (await client.get(f"/iocs/{ioc_id}", headers=headers_b)).status_code == 404
    assert (
        await client.patch(f"/iocs/{ioc_id}", headers=headers_b, json={"classification": "benign"})
    ).status_code == 404
    assert (
        await client.post("/iocs/match", headers=headers_b, json={"values": ["203.0.113.77"]})
    ).json() == []


# ---------------------------------------------------------------------------
# Matching inside the pipeline, and its effect on risk
# ---------------------------------------------------------------------------


async def test_the_enrichment_provider_attaches_matches_with_their_provenance(
    client: AsyncClient,
) -> None:
    org = await _register(client, "acme")
    tenant_id = org["organization_id"]
    headers = await _login(client, "acme")
    await client.post("/iocs", headers=headers, json=INDICATOR)

    result = await IocMatchProvider().enrich(
        {"tenant_id": tenant_id, "source_ip": "203.0.113.77", "hostname": "web01"}
    )

    matches = result.fields["ioc_matches"]
    assert len(matches) == 1
    assert matches[0]["classification"] == "malicious"
    assert matches[0]["confidence"] == 90
    assert matches[0]["source"] == "incident-response"
    assert result.fields["risk_context"]["ioc_classification"] == "malicious"


async def test_an_event_with_no_match_records_that_intel_was_consulted(
    client: AsyncClient,
) -> None:
    """"We looked and found nothing" is different from "we did not look":
    the risk engine scores the first as available-and-zero and the second as
    unknown (Phase 8)."""
    org = await _register(client, "acme")

    result = await IocMatchProvider().enrich(
        {"tenant_id": org["organization_id"], "source_ip": "8.8.8.8"}
    )
    assert result.fields == {"ioc_matches": []}


async def test_an_event_with_no_observables_is_left_alone(client: AsyncClient) -> None:
    org = await _register(client, "acme")
    result = await IocMatchProvider().enrich(
        {"tenant_id": org["organization_id"], "hostname": "web01"}
    )
    assert result.fields == {}


async def test_an_expired_indicator_no_longer_enriches(client: AsyncClient) -> None:
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post(
        "/iocs",
        headers=headers,
        json={
            **INDICATOR,
            "value": "203.0.113.78",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
    )

    result = await IocMatchProvider().enrich(
        {"tenant_id": org["organization_id"], "source_ip": "203.0.113.78"}
    )
    assert result.fields["ioc_matches"] == []


async def test_a_high_confidence_match_raises_the_risk_score(client: AsyncClient) -> None:
    """The Phase 9 → Phase 8 loop: intelligence is only worth storing if it
    changes what the SOC sees first."""
    org = await _register(client, "acme")
    tenant_id = org["organization_id"]
    headers = await _login(client, "acme")
    await client.post("/iocs", headers=headers, json=INDICATOR)

    detection = {
        "detection_id": "d1",
        "rule_id": "AUTH-003",
        "severity": "high",
        "confidence": 70,
        "risk_score": 60,
        "mitre_attack": ["T1078"],
        "evidence": {},
    }

    matched_event = (
        await IocMatchProvider().enrich({"tenant_id": tenant_id, "source_ip": "203.0.113.77"})
    ).fields
    clean_event = (
        await IocMatchProvider().enrich({"tenant_id": tenant_id, "source_ip": "8.8.8.8"})
    ).fields

    with_match = apply_to_detection(detection, matched_event)
    without_match = apply_to_detection(detection, clean_event)

    assert with_match["risk_score"] > without_match["risk_score"]
    factors = {factor["factor"]: factor for factor in with_match["risk_explanation"]["factors"]}
    assert factors["threat_intel"]["available"] is True
    assert "malicious" in factors["threat_intel"]["reason"]


async def test_a_low_confidence_feed_hit_moves_the_score_less(client: AsyncClient) -> None:
    """Spec §11's rule, visible end to end: the same classification at 30%
    confidence is worth less than at 90%."""
    org = await _register(client, "acme")
    tenant_id = org["organization_id"]
    headers = await _login(client, "acme")
    await client.post(
        "/iocs",
        headers=headers,
        json={**INDICATOR, "value": "203.0.113.79", "confidence": 30, "source": "bulk-feed"},
    )
    await client.post(
        "/iocs", headers=headers, json={**INDICATOR, "value": "203.0.113.80", "confidence": 95}
    )

    detection = {
        "detection_id": "d1",
        "rule_id": "AUTH-003",
        "severity": "high",
        "confidence": 70,
        "risk_score": 60,
        "mitre_attack": ["T1078"],
        "evidence": {},
    }
    low = apply_to_detection(
        detection,
        (await IocMatchProvider().enrich({"tenant_id": tenant_id, "source_ip": "203.0.113.79"})).fields,
    )
    high = apply_to_detection(
        detection,
        (await IocMatchProvider().enrich({"tenant_id": tenant_id, "source_ip": "203.0.113.80"})).fields,
    )

    assert low["risk_score"] < high["risk_score"]
