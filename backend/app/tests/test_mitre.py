"""ATT&CK import and coverage.

Two acceptance criteria drive this file: the import must be idempotent
(it runs on a schedule, so a second run that duplicates or corrupts the
catalog would be worse than no import at all), and third-party content must
be validated before storage — the bundle is a 50MB JSON document downloaded
from the internet.
"""

import asyncio
import json
import os
import uuid
from pathlib import Path

import pytest
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.db import async_session_factory, tenant_scoped_session
from app.mitre.importer import (
    MAX_DESCRIPTION_LENGTH,
    MAX_NAME_LENGTH,
    ImportError_,
    load_bundle,
    parse_bundle,
)
from app.models.detection import DetectionRuleRecord
from app.models.identity import Organization
from app.models.mitre import MitreTactic, MitreTechnique, MitreTechniqueTactic, RuleMitreMap
from app.services import mitre as service

# A miniature bundle in the real STIX shape: one tactic, a technique, one of
# its sub-techniques, a revoked technique, and objects that must be rejected.
BUNDLE = {
    "type": "bundle",
    "objects": [
        {"type": "x-mitre-collection", "x_mitre_version": "19.2", "name": "Enterprise ATT&CK"},
        {
            "type": "x-mitre-tactic",
            "name": "Credential Access",
            "x_mitre_shortname": "credential-access",
            "description": "The adversary is trying to steal account names and passwords.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "TA0006",
                    "url": "https://attack.mitre.org/tactics/TA0006/",
                }
            ],
        },
        {
            "type": "x-mitre-tactic",
            "name": "Defense Evasion",
            "x_mitre_shortname": "defense-evasion",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0005"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "OS Credential Dumping",
            "description": "Adversaries may attempt to dump credentials.",
            "x_mitre_platforms": ["Windows", "Linux"],
            "x_mitre_version": "2.4",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1003",
                    "url": "https://attack.mitre.org/techniques/T1003/",
                }
            ],
        },
        {
            "type": "attack-pattern",
            "name": "LSASS Memory",
            "x_mitre_is_subtechnique": True,
            "x_mitre_platforms": ["Windows"],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}
            ],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1003.001"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Indicator Removal",
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1070"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Something MITRE Withdrew",
            "revoked": True,
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1099"}
            ],
        },
        # Rejected: no ATT&CK external reference at all.
        {"type": "attack-pattern", "name": "Orphan"},
        # Rejected: an id that is not an ATT&CK technique id.
        {
            "type": "attack-pattern",
            "name": "Bogus",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "NOT-A-TECHNIQUE"}
            ],
        },
        # Ignored, not rejected: object types this phase does not store.
        {"type": "intrusion-set", "name": "APT-Example"},
        {"type": "relationship", "relationship_type": "uses"},
    ],
}


def _bundle(**overrides) -> bytes:
    document = {**BUNDLE, **overrides}
    return json.dumps(document).encode()


async def _tenant() -> uuid.UUID:
    slug = f"t{uuid.uuid4().hex[:12]}"
    async with async_session_factory() as db:
        org = Organization(name=slug, slug=slug)
        db.add(org)
        await db.commit()
        return org.id


async def _rule(tenant_id: uuid.UUID, key: str, techniques: list[str], status: str = "enabled"):
    async with tenant_scoped_session(tenant_id) as db:
        record = DetectionRuleRecord(
            tenant_id=tenant_id,
            rule_key=key,
            name=key,
            severity="high",
            confidence=70,
            risk_score=60,
            status=status,
            rule_type="streaming",
            definition_yaml="rule_id: " + key,
            mitre_techniques=techniques,
        )
        db.add(record)
        await db.commit()
        return record.id


# ---------------------------------------------------------------------------
# Parsing and sanitizing third-party content
# ---------------------------------------------------------------------------


def test_a_bundle_parses_into_tactics_and_techniques() -> None:
    parsed = parse_bundle(_bundle())

    assert {tactic.id for tactic in parsed.tactics} == {"TA0006", "TA0005"}
    assert {technique.id for technique in parsed.techniques} == {
        "T1003",
        "T1003.001",
        "T1070",
        "T1099",
    }
    assert parsed.attack_version == "19.2"

    sub = next(item for item in parsed.techniques if item.id == "T1003.001")
    assert sub.is_subtechnique is True
    assert sub.parent_id == "T1003"
    assert sub.tactic_shortnames == ["credential-access"]


def test_objects_that_are_not_attack_objects_are_rejected_and_counted() -> None:
    """An import that silently drops half the matrix looks exactly like a
    matrix that shrank."""
    parsed = parse_bundle(_bundle())
    assert parsed.rejected == 2  # the orphan and the bogus id


def test_a_revoked_technique_is_kept_but_marked() -> None:
    """Deleting it would leave any rule mapped to it dangling silently; the
    coverage page needs to be able to say "this claim is stale"."""
    parsed = parse_bundle(_bundle())
    revoked = next(item for item in parsed.techniques if item.id == "T1099")
    assert revoked.is_revoked is True


def test_oversized_strings_are_truncated_not_stored_whole() -> None:
    objects = [
        obj
        for obj in BUNDLE["objects"]
        if obj.get("external_references", [{}])[0].get("external_id") != "T1003"
    ]
    objects.append(
        {
            "type": "attack-pattern",
            "name": "N" * 5000,
            "description": "D" * 500_000,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1003"}
            ],
        }
    )
    parsed = parse_bundle(json.dumps({"type": "bundle", "objects": objects}).encode())

    technique = next(item for item in parsed.techniques if item.id == "T1003")
    assert len(technique.name) == MAX_NAME_LENGTH
    assert technique.description is not None
    assert len(technique.description) == MAX_DESCRIPTION_LENGTH


def test_a_non_https_reference_url_is_dropped() -> None:
    """Imported content is rendered in the UI; a javascript: or http: link
    from a third-party feed is not."""
    objects = [
        {
            "type": "attack-pattern",
            "name": "Sketchy",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1234",
                    "url": "javascript:alert(1)",
                }
            ],
        }
    ]
    parsed = parse_bundle(json.dumps({"type": "bundle", "objects": objects}).encode())
    assert parsed.techniques[0].url is None


def test_control_characters_are_stripped_from_imported_text() -> None:
    objects = [
        {
            "type": "attack-pattern",
            "name": "Bad\x00Name\x07",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1234"}
            ],
        }
    ]
    parsed = parse_bundle(json.dumps({"type": "bundle", "objects": objects}).encode())
    assert parsed.techniques[0].name == "BadName"


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"{not json", "not valid JSON"),
        (b'["a list"]', "not a JSON object"),
        (b'{"type": "bundle"}', "no objects array"),
        (b'{"type": "bundle", "objects": []}', "no usable techniques"),
    ],
)
def test_an_unusable_bundle_is_refused_with_a_reason(payload: bytes, message: str) -> None:
    with pytest.raises(ImportError_, match=message):
        parse_bundle(payload)


def test_an_object_flood_is_refused() -> None:
    from app.mitre.importer import MAX_OBJECTS

    objects = [{"type": "relationship"}] * (MAX_OBJECTS + 1)
    with pytest.raises(ImportError_, match="more than"):
        parse_bundle(json.dumps({"type": "bundle", "objects": objects}).encode())


async def test_a_bundle_path_cannot_escape_the_drop_directory(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(tmp_path))
    get_settings.cache_clear()
    try:
        with pytest.raises(ImportError_, match="outside the drop directory"):
            await load_bundle("../../../etc/passwd")
    finally:
        get_settings.cache_clear()


async def test_a_bundle_url_goes_through_the_egress_guard(monkeypatch) -> None:
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "attack.example.com")
    get_settings.cache_clear()
    try:
        with pytest.raises(ImportError_, match="host_not_allowed|non_global_address"):
            await load_bundle("https://169.254.169.254/latest/meta-data/")
    finally:
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Import: idempotency and updates
# ---------------------------------------------------------------------------


async def _import(bundle: bytes = None) -> None:
    async with async_session_factory() as db:
        await service.import_bundle(
            db, bundle=parse_bundle(bundle or _bundle()), source="test-bundle"
        )
        await db.commit()


async def _catalog_counts() -> tuple[int, int, int]:
    async with async_session_factory() as db:
        techniques = (
            await db.execute(select(func.count()).select_from(MitreTechnique))
        ).scalar_one()
        tactics = (await db.execute(select(func.count()).select_from(MitreTactic))).scalar_one()
        links = (
            await db.execute(select(func.count()).select_from(MitreTechniqueTactic))
        ).scalar_one()
    return int(techniques), int(tactics), int(links)


async def test_importing_twice_does_not_duplicate_anything() -> None:
    """The acceptance criterion: ATT&CK is re-imported on a schedule, so a
    non-idempotent import corrupts the catalog on its second run."""
    await _import()
    first = await _catalog_counts()

    await _import()
    second = await _catalog_counts()

    assert first == second == (4, 2, 4)


async def test_a_re_import_updates_changed_fields() -> None:
    await _import()

    renamed = json.loads(_bundle())
    for obj in renamed["objects"]:
        references = obj.get("external_references") or [{}]
        if references[0].get("external_id") == "T1003":
            obj["name"] = "OS Credential Dumping (renamed)"
            obj["x_mitre_deprecated"] = True
    await _import(json.dumps(renamed).encode())

    async with async_session_factory() as db:
        technique = await db.get(MitreTechnique, "T1003")
    assert technique is not None
    assert technique.name == "OS Credential Dumping (renamed)"
    assert technique.is_deprecated is True


async def test_a_technique_moved_between_tactics_loses_its_old_link() -> None:
    """Merging links instead of rebuilding them would leave the old tactic
    inflated forever."""
    await _import()

    moved = json.loads(_bundle())
    for obj in moved["objects"]:
        references = obj.get("external_references") or [{}]
        if references[0].get("external_id") == "T1003":
            obj["kill_chain_phases"] = [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ]
    await _import(json.dumps(moved).encode())

    async with async_session_factory() as db:
        links = list(
            (
                await db.execute(
                    select(MitreTechniqueTactic.tactic_id).where(
                        MitreTechniqueTactic.technique_id == "T1003"
                    )
                )
            ).scalars()
        )
    assert links == ["TA0005"]


async def test_the_import_run_is_recorded() -> None:
    await _import()
    async with async_session_factory() as db:
        last = await service.latest_import(db)
    assert last is not None
    assert last.attack_version == "19.2"
    assert last.techniques_imported == 4
    assert last.objects_rejected == 2


async def test_a_catalog_that_has_never_been_imported_is_stale() -> None:
    async with async_session_factory() as db:
        # Nothing imported in this test's transaction view yet.
        assert await service.stale_import(db, max_age_days=0) is True


# ---------------------------------------------------------------------------
# Rule mapping
# ---------------------------------------------------------------------------


async def test_rules_are_mapped_onto_the_catalog() -> None:
    await _import()
    tenant_id = await _tenant()
    await _rule(tenant_id, "WIN-003", ["T1003", "T1003.001"])

    async with tenant_scoped_session(tenant_id) as db:
        result = await service.sync_rule_mappings(db, tenant_id)
        await db.commit()
        mapped = list((await db.execute(select(RuleMitreMap.technique_id))).scalars())

    assert result.mapped == 2
    assert sorted(mapped) == ["T1003", "T1003.001"]


async def test_a_technique_the_catalog_does_not_know_is_reported_not_dropped() -> None:
    """A typo'd technique id is a coverage claim that is quietly false."""
    await _import()
    tenant_id = await _tenant()
    await _rule(tenant_id, "AUTH-999", ["T1003", "T9999"])

    async with tenant_scoped_session(tenant_id) as db:
        result = await service.sync_rule_mappings(db, tenant_id)
        await db.commit()

    assert result.unknown == {"AUTH-999": ["T9999"]}
    assert result.mapped == 1


async def test_mappings_are_removed_when_a_rule_stops_claiming_a_technique() -> None:
    await _import()
    tenant_id = await _tenant()
    rule_id = await _rule(tenant_id, "WIN-003", ["T1003", "T1070"])

    async with tenant_scoped_session(tenant_id) as db:
        await service.sync_rule_mappings(db, tenant_id)
        await db.commit()

        rule = await db.get(DetectionRuleRecord, rule_id)
        assert rule is not None
        rule.mitre_techniques = ["T1003"]
        await db.commit()

        result = await service.sync_rule_mappings(db, tenant_id)
        await db.commit()
        remaining = list((await db.execute(select(RuleMitreMap.technique_id))).scalars())

    assert result.removed == 1
    assert remaining == ["T1003"]


async def test_one_tenants_mappings_are_invisible_to_another() -> None:
    await _import()
    tenant_a, tenant_b = await _tenant(), await _tenant()
    await _rule(tenant_a, "WIN-003", ["T1003"])

    async with tenant_scoped_session(tenant_a) as db:
        await service.sync_rule_mappings(db, tenant_a)
        await db.commit()

    async with tenant_scoped_session(tenant_b) as db:
        visible = list((await db.execute(select(RuleMitreMap))).scalars())
    assert visible == []


# ---------------------------------------------------------------------------
# Coverage arithmetic
# ---------------------------------------------------------------------------


async def test_coverage_counts_only_what_a_rule_actually_covers() -> None:
    await _import()
    tenant_id = await _tenant()
    await _rule(tenant_id, "WIN-003", ["T1003.001"])

    async with tenant_scoped_session(tenant_id) as db:
        report = await service.coverage(db, tenant_id)
        await db.commit()

    by_id = {item.technique_id: item for item in report.techniques}
    # The sub-technique is covered...
    assert by_id["T1003.001"].status == "covered"
    assert by_id["T1003.001"].rule_keys == ["WIN-003"]
    # ...its parent is only partially covered: detecting LSASS dumping is
    # not detecting all of OS Credential Dumping.
    assert by_id["T1003"].status == "partial"
    assert by_id["T1070"].status == "uncovered"

    # The revoked technique is out of the denominator entirely.
    assert "T1099" not in by_id
    assert report.total_techniques == 3
    assert report.covered_techniques == 1
    assert report.partially_covered_techniques == 1
    assert report.coverage_rate == pytest.approx(33.3)


async def test_a_disabled_rule_is_not_coverage() -> None:
    """The single most common way a coverage page overstates what a SOC can
    actually see."""
    await _import()
    tenant_id = await _tenant()
    await _rule(tenant_id, "WIN-003", ["T1003"], status="disabled")

    async with tenant_scoped_session(tenant_id) as db:
        report = await service.coverage(db, tenant_id)
        await db.commit()

    assert report.covered_techniques == 0
    assert {item.technique_id for item in report.techniques if item.status == "covered"} == set()


async def test_a_testing_rule_still_counts_as_coverage() -> None:
    """Unlike a disabled rule, a rule in `testing` is evaluated on live
    traffic — it is coverage being validated, not coverage switched off."""
    await _import()
    tenant_id = await _tenant()
    await _rule(tenant_id, "WIN-003", ["T1003"], status="testing")

    async with tenant_scoped_session(tenant_id) as db:
        report = await service.coverage(db, tenant_id)
        await db.commit()

    assert report.covered_techniques == 1


async def test_per_tactic_coverage_is_broken_out() -> None:
    await _import()
    tenant_id = await _tenant()
    await _rule(tenant_id, "WIN-003", ["T1003"])

    async with tenant_scoped_session(tenant_id) as db:
        report = await service.coverage(db, tenant_id)
        await db.commit()

    tactics = {tactic.tactic_id: tactic for tactic in report.tactics}
    assert tactics["TA0006"].total == 2  # T1003 and T1003.001
    assert tactics["TA0006"].covered == 1
    assert tactics["TA0006"].coverage_rate == 50.0
    assert tactics["TA0005"].covered == 0


async def test_detection_counts_are_attached_to_techniques() -> None:
    await _import()
    tenant_id = await _tenant()
    await _rule(tenant_id, "WIN-003", ["T1003"])

    async with tenant_scoped_session(tenant_id) as db:
        report = await service.coverage(db, tenant_id, detection_counts={"T1003": 42})
        await db.commit()

    by_id = {item.technique_id: item for item in report.techniques}
    assert by_id["T1003"].detection_count == 42
    assert by_id["T1070"].detection_count == 0


async def test_coverage_reports_the_attack_version_it_measured_against() -> None:
    """"73% coverage" means nothing without saying of what."""
    await _import()
    tenant_id = await _tenant()

    async with tenant_scoped_session(tenant_id) as db:
        report = await service.coverage(db, tenant_id)
        await db.commit()

    assert report.attack_version == "19.2"
    assert report.imported_at is not None


async def test_deprecated_techniques_can_be_included_deliberately() -> None:
    await _import()
    tenant_id = await _tenant()

    async with tenant_scoped_session(tenant_id) as db:
        default = await service.coverage(db, tenant_id)
        with_deprecated = await service.coverage(db, tenant_id, include_deprecated=True)
        await db.commit()

    assert with_deprecated.total_techniques > default.total_techniques


# ---------------------------------------------------------------------------
# The real matrix
# ---------------------------------------------------------------------------

# An optional local copy of the official bundle, downloaded by hand. Not a
# temporary file this code creates — it is read only if a developer put it
# there, and the test skips otherwise.
REAL_BUNDLE = Path(os.environ.get("ATTACK_BUNDLE_PATH", "/tmp/enterprise-attack.json"))  # noqa: S108


@pytest.mark.skipif(
    not REAL_BUNDLE.exists(),
    reason="the official ATT&CK bundle is not present; download it to /tmp to run this",
)
async def test_the_official_attack_bundle_imports() -> None:
    """Run against the real `enterprise-attack.json` when it is available.

    A miniature fixture proves the parsing rules; only the real 52MB bundle
    proves they hold against what MITRE actually publishes — hundreds of
    sub-techniques, revoked entries, multi-tactic techniques and all.
    """
    parsed = parse_bundle(await asyncio.to_thread(REAL_BUNDLE.read_bytes))

    assert len(parsed.tactics) >= 14
    assert len(parsed.techniques) >= 600
    assert parsed.attack_version is not None
    assert parsed.rejected == 0, "the real bundle should not contain unusable ATT&CK objects"

    # Spot-check the shape the platform depends on everywhere else.
    lsass = next(item for item in parsed.techniques if item.id == "T1003.001")
    assert lsass.parent_id == "T1003"
    assert "credential-access" in lsass.tactic_shortnames

    async with async_session_factory() as db:
        record = await service.import_bundle(db, bundle=parsed, source=str(REAL_BUNDLE))
        await db.commit()
        stored = (
            await db.execute(select(func.count()).select_from(MitreTechnique))
        ).scalar_one()

    assert record.techniques_imported == len(parsed.techniques)
    assert int(stored) == len(parsed.techniques)


def test_the_risk_engines_impact_table_only_names_real_techniques() -> None:
    """ATT&CK publishes no impact ranking, so `TECHNIQUE_IMPACT` stays a
    curated judgement — but it must not drift into naming techniques MITRE
    has withdrawn or never had."""
    if not REAL_BUNDLE.exists():
        pytest.skip("the official ATT&CK bundle is not present")

    from app.risk.factors import TECHNIQUE_IMPACT

    parsed = parse_bundle(REAL_BUNDLE.read_bytes())
    live = {
        technique.id
        for technique in parsed.techniques
        if not technique.is_revoked and not technique.is_deprecated
    }
    unknown = sorted(set(TECHNIQUE_IMPACT) - live)
    assert not unknown, f"risk weighting references techniques ATT&CK no longer has: {unknown}"
