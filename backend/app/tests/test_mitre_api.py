"""The /mitre API and the detections that make its numbers real.

Coverage is only useful if it reflects the rules a tenant actually has and
the detections those rules actually produced — so this file exercises the
whole loop: import the catalog, ship rules, index a detection, read the
coverage page.
"""

import json
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
from app.services.index_management import DETECTION_ALIAS, bootstrap_indices
from app.tests.test_mitre import BUNDLE


@pytest.fixture
async def catalog(tmp_path, monkeypatch):
    """Puts a bundle in the drop directory and points the importer at it —
    the offline path, so tests never depend on MITRE's servers."""
    from app.core.config import get_settings

    (tmp_path / "attack.json").write_text(json.dumps(BUNDLE))
    monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(tmp_path))
    monkeypatch.setenv("MITRE_ATTACK_SOURCE", "attack.json")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


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


async def _index_detection(tenant_id: str, *, technique: str, dry_run: bool = False) -> None:
    client = get_opensearch()
    await bootstrap_indices(client)
    await client.index(
        index=DETECTION_ALIAS,
        id=str(uuid.uuid4()),
        body={
            "detection_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "rule_id": "WIN-003",
            "rule_name": "LSASS dumping",
            "severity": "critical",
            "risk_score": 90,
            "risk_bucket": "CRITICAL",
            "mitre_attack": [technique],
            "entity_summary": "hostname=dc01",
            "matched_at": datetime.now(UTC).isoformat(),
            "dry_run": dry_run,
            "event_ids": [str(uuid.uuid4())],
        },
        refresh=True,
    )


# ---------------------------------------------------------------------------
# Import through the API
# ---------------------------------------------------------------------------


async def test_importing_the_catalog_is_audited_and_idempotent(
    client: AsyncClient, catalog
) -> None:
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    headers = await _login(client, "acme")

    first = await client.post("/mitre/import", headers=headers, json={})
    assert first.status_code == 200, first.text
    assert first.json()["attack_version"] == "19.2"
    assert first.json()["techniques_imported"] == 4
    assert first.json()["objects_rejected"] == 2

    second = await client.post("/mitre/import", headers=headers, json={})
    assert second.json()["techniques_imported"] == 4

    techniques = await client.get("/mitre/techniques", headers=headers)
    # Four imported, one revoked and hidden by default.
    assert len(techniques.json()) == 3

    async with tenant_scoped_session(tenant_id) as db:
        actions = list((await db.execute(select(AuditLog.action))).scalars())
    assert actions.count("IMPORT_MITRE_ATTACK") == 2


async def test_an_unreadable_source_is_a_422_not_a_500(client: AsyncClient, catalog) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")

    resp = await client.post("/mitre/import", headers=headers, json={"source": "missing.json"})
    assert resp.status_code == 422
    assert "does not exist" in resp.text


async def test_importing_requires_mitre_write(client: AsyncClient, catalog) -> None:
    """The catalog is global: importing it changes every tenant's coverage
    page, so it is an administrative action."""
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    assert (await client.post("/mitre/import", headers=l1, json={})).status_code == 403


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


async def test_the_shipped_rule_pack_produces_real_coverage(client: AsyncClient, catalog) -> None:
    """The Phase 6 rules map onto the catalog without anyone editing a
    mapping table by hand."""
    await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post("/mitre/import", headers=headers, json={})

    coverage = await client.get("/mitre/coverage", headers=headers)
    assert coverage.status_code == 200
    body = coverage.json()

    assert body["attack_version"] == "19.2"
    assert body["total_techniques"] == 3
    # WIN-003 ships mapped to T1003 and T1003.001, WIN-004 to T1070.
    covered = {item["technique_id"] for item in body["techniques"] if item["status"] == "covered"}
    assert {"T1003", "T1003.001", "T1070"} <= covered
    assert body["coverage_rate"] == 100.0

    by_id = {item["technique_id"]: item for item in body["techniques"]}
    assert "WIN-003" in by_id["T1003.001"]["rule_keys"]


async def test_techniques_the_rules_claim_but_the_catalog_lacks_are_surfaced(
    client: AsyncClient, catalog
) -> None:
    """The shipped rules reference far more of ATT&CK than this miniature
    test bundle contains, which is exactly the "rule written against a newer
    matrix" case the field exists for."""
    await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post("/mitre/import", headers=headers, json={})

    body = (await client.get("/mitre/coverage", headers=headers)).json()
    claims = body["unknown_technique_claims"]
    assert "AUTH-001" in claims
    assert "T1110" in claims["AUTH-001"]


async def test_disabling_a_rule_lowers_coverage(client: AsyncClient, catalog) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post("/mitre/import", headers=headers, json={})

    before = (await client.get("/mitre/coverage", headers=headers)).json()
    await client.post("/rules/WIN-004/status", headers=headers, json={"status": "disabled"})
    after = (await client.get("/mitre/coverage", headers=headers)).json()

    assert after["covered_techniques"] < before["covered_techniques"]
    by_id = {item["technique_id"]: item for item in after["techniques"]}
    assert by_id["T1070"]["status"] == "uncovered"


async def test_a_stale_catalog_is_flagged(client: AsyncClient, catalog) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")

    before_import = (await client.get("/mitre/coverage", headers=headers)).json()
    assert before_import["catalog_is_stale"] is True
    assert before_import["attack_version"] is None

    await client.post("/mitre/import", headers=headers, json={})
    after_import = (await client.get("/mitre/coverage", headers=headers)).json()
    assert after_import["catalog_is_stale"] is False


async def test_coverage_is_per_tenant(client: AsyncClient, catalog) -> None:
    await _register(client, "acme", "a@example.com")
    await _register(client, "globex", "b@example.com")
    headers_a = await _login(client, "acme", "a@example.com")
    headers_b = await _login(client, "globex", "b@example.com")
    await client.post("/mitre/import", headers=headers_a, json={})

    for rule_key in ("WIN-003", "WIN-004"):
        await client.post(f"/rules/{rule_key}/status", headers=headers_b, json={"status": "disabled"})

    body_a = (await client.get("/mitre/coverage", headers=headers_a)).json()
    body_b = (await client.get("/mitre/coverage", headers=headers_b)).json()

    assert body_a["covered_techniques"] > body_b["covered_techniques"]
    # The catalog itself is shared: both measure against the same matrix.
    assert body_a["total_techniques"] == body_b["total_techniques"]


# ---------------------------------------------------------------------------
# Detections behind the numbers
# ---------------------------------------------------------------------------


async def test_detections_are_counted_per_technique(client: AsyncClient, catalog) -> None:
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post("/mitre/import", headers=headers, json={})

    await _index_detection(org["organization_id"], technique="T1003.001")
    await _index_detection(org["organization_id"], technique="T1003.001")

    body = (await client.get("/mitre/coverage", headers=headers)).json()
    by_id = {item["technique_id"]: item for item in body["techniques"]}
    assert by_id["T1003.001"]["detection_count"] == 2
    assert by_id["T1070"]["detection_count"] == 0


async def test_dry_run_detections_do_not_inflate_the_numbers(
    client: AsyncClient, catalog
) -> None:
    """A rule in `testing` fires deliberately; counting those would make
    "we detect this" true for a rule that never alerts."""
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post("/mitre/import", headers=headers, json={})

    await _index_detection(org["organization_id"], technique="T1070", dry_run=True)

    body = (await client.get("/mitre/coverage", headers=headers)).json()
    by_id = {item["technique_id"]: item for item in body["techniques"]}
    assert by_id["T1070"]["detection_count"] == 0


async def test_another_tenants_detections_are_not_counted(client: AsyncClient, catalog) -> None:
    await _register(client, "acme", "a@example.com")
    org_b = await _register(client, "globex", "b@example.com")
    headers_a = await _login(client, "acme", "a@example.com")
    await client.post("/mitre/import", headers=headers_a, json={})

    await _index_detection(org_b["organization_id"], technique="T1003")

    body = (await client.get("/mitre/coverage", headers=headers_a)).json()
    by_id = {item["technique_id"]: item for item in body["techniques"]}
    assert by_id["T1003"]["detection_count"] == 0


async def test_technique_detail_shows_the_rules_and_the_recent_detections(
    client: AsyncClient, catalog
) -> None:
    org = await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post("/mitre/import", headers=headers, json={})
    await _index_detection(org["organization_id"], technique="T1003.001")

    detail = await client.get("/mitre/techniques/T1003.001", headers=headers)
    assert detail.status_code == 200
    body = detail.json()

    assert body["technique"]["name"] == "LSASS Memory"
    assert body["technique"]["parent_id"] == "T1003"
    assert body["status"] == "covered"
    assert "WIN-003" in body["rule_keys"]
    assert body["detection_count"] == 1
    assert body["recent_detections"][0]["entity_summary"] == "hostname=dc01"


async def test_an_unknown_technique_is_a_404(client: AsyncClient, catalog) -> None:
    await _register(client, "acme")
    headers = await _login(client, "acme")
    await client.post("/mitre/import", headers=headers, json={})

    assert (await client.get("/mitre/techniques/T9999", headers=headers)).status_code == 404


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------


async def test_reading_coverage_needs_authentication(client: AsyncClient) -> None:
    assert (await client.get("/mitre/coverage")).status_code == 401
    assert (await client.get("/mitre/techniques")).status_code == 401


async def test_an_analyst_can_read_coverage(client: AsyncClient, catalog) -> None:
    org = await _register(client, "acme")
    tenant_id = uuid.UUID(org["organization_id"])
    admin = await _login(client, "acme")
    await client.post("/mitre/import", headers=admin, json={})

    await _user_with_role(tenant_id, "l1@example.com", "SOC_ANALYST_L1")
    l1 = await _login(client, "acme", "l1@example.com")

    assert (await client.get("/mitre/coverage", headers=l1)).status_code == 200
    assert (await client.get("/mitre/tactics", headers=l1)).status_code == 200
