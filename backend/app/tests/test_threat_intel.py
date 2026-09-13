"""Indicator normalization, storage, expiry, and the §11 rule.

Spec §11's hard rule — *never automatically treat an indicator as malicious
just because it came from a feed* — is enforced in three separate places
(schema constraint, feed upsert defaults, risk weighting), so it gets tests
in all three.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.core.db import async_session_factory, intel_sync_session, tenant_scoped_session
from app.models.threat_intel import IOC_TYPES, Ioc
from app.services import threat_intel as service
from app.services.threat_intel import FeedIndicator
from app.threat_intel.normalize import (
    InvalidIndicator,
    canonicalize,
    infer_type,
    observables_from_event,
    refang,
)


async def _tenant() -> uuid.UUID:
    """A tenant row, created directly: these tests are about intelligence,
    not about registration."""
    from app.models.identity import Organization

    slug = f"t{uuid.uuid4().hex[:12]}"
    async with async_session_factory() as db:
        org = Organization(name=slug, slug=slug)
        db.add(org)
        await db.commit()
        return org.id


# ---------------------------------------------------------------------------
# Canonicalization and typing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.2.3[.]4", ("1.2.3.4", "ipv4")),
        ("2001:DB8::1", ("2001:db8::1", "ipv6")),
        ("EVIL.COM.", ("evil.com", "domain")),
        ("hxxp://EVIL.com:80/a#fragment", ("http://evil.com/a", "url")),
        ("evil.com/malware.exe", ("http://evil.com/malware.exe", "url")),
        ("D41D8CD98F00B204E9800998ECF8427E", ("d41d8cd98f00b204e9800998ecf8427e", "md5")),
        ("User@Example.COM", ("user@example.com", "email")),
        ("as15169", ("AS15169", "asn")),
    ],
)
def test_canonicalization(raw: str, expected: tuple[str, str]) -> None:
    """Every value is stored in the form it will be compared against, or it
    is an indicator that can never match anything."""
    assert canonicalize(raw) == expected


def test_defanged_forms_are_refanged() -> None:
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("user[at]evil[dot]com") == "user@evil.com"


def test_the_ten_spec_types_are_all_supported() -> None:
    assert set(IOC_TYPES) == {
        "ipv4",
        "ipv6",
        "domain",
        "url",
        "md5",
        "sha1",
        "sha256",
        "email",
        "asn",
        "certificate",
    }


def test_a_certificate_fingerprint_must_be_typed_explicitly() -> None:
    """A fingerprint is indistinguishable from a file hash of the same
    length; guessing would file TLS fingerprints where no hash lookup finds
    them."""
    fingerprint = ":".join(["ab"] * 20)
    assert canonicalize(fingerprint, "certificate") == ("ab" * 20, "certificate")
    with pytest.raises(InvalidIndicator):
        canonicalize(fingerprint)


@pytest.mark.parametrize(
    "value", ["", "   ", "not an indicator", "http://", "999.999.999.999", "1.2.3.4.5"]
)
def test_unusable_values_are_rejected_rather_than_stored(value: str) -> None:
    with pytest.raises(InvalidIndicator):
        canonicalize(value)


def test_an_all_numeric_tld_is_not_a_domain() -> None:
    with pytest.raises(InvalidIndicator):
        infer_type("999.999.999.999")


def test_an_overlong_value_is_rejected() -> None:
    with pytest.raises(InvalidIndicator, match="exceeds"):
        canonicalize("a" * 3000 + ".com")


def test_observables_are_extracted_from_the_places_indicators_live() -> None:
    observables = observables_from_event(
        {
            "source_ip": "8.8.8.8",
            "destination_ip": "1.1.1.1",
            "domain": "Evil.COM",
            "url": "http://x.test/a",
            "hash": {"sha256": "a" * 64, "md5": "b" * 32},
            "user": {"email": "A@B.com"},
            "hostname": "not-an-indicator",
        }
    )
    assert observables["ipv4"] == ["1.1.1.1", "8.8.8.8"]
    assert observables["domain"] == ["evil.com"]
    assert observables["sha256"] == ["a" * 64]
    assert observables["email"] == ["a@b.com"]
    # A hostname is not matched against domain intel: an internal machine
    # name colliding with a feed entry would be a false positive on every
    # event that host produces.
    assert "not-an-indicator" not in str(observables)


def test_a_junk_field_does_not_break_extraction() -> None:
    assert observables_from_event({"source_ip": None, "domain": 42, "hash": "nope"}) == {}


# ---------------------------------------------------------------------------
# Storage, expiry, history
# ---------------------------------------------------------------------------


async def test_create_and_match_an_indicator() -> None:
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.create_ioc(
            db,
            tenant_id=tenant_id,
            value="1.2.3[.]4",
            ioc_type=None,
            classification="malicious",
            confidence=90,
            source="incident-response",
            description="C2 seen in INC-2026-000123",
            tags=["c2"],
            expires_at=None,
            actor_id=None,
        )
        await db.commit()

        matches = await service.match(db, tenant_id, {"ipv4": ["1.2.3.4"]})

    assert len(matches) == 1
    assert matches[0]["classification"] == "malicious"
    assert matches[0]["confidence"] == 90
    assert matches[0]["source"] == "incident-response"


async def test_a_defanged_paste_matches_the_stored_form() -> None:
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.create_ioc(
            db,
            tenant_id=tenant_id,
            value="evil.com",
            ioc_type=None,
            classification="suspicious",
            confidence=60,
            source="manual",
            description=None,
            tags=[],
            expires_at=None,
            actor_id=None,
        )
        await db.commit()
        canonical, ioc_type = canonicalize("EVIL[.]com")
        matches = await service.match(db, tenant_id, {ioc_type: [canonical]})

    assert len(matches) == 1


async def test_an_expired_indicator_stops_matching_immediately() -> None:
    """Expiry is applied by every read, not by a sweeper: a sweeper that
    fails silently would keep stale intelligence alive."""
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.create_ioc(
            db,
            tenant_id=tenant_id,
            value="9.9.9.9",
            ioc_type=None,
            classification="malicious",
            confidence=80,
            source="old-feed",
            description=None,
            tags=[],
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            actor_id=None,
        )
        await db.commit()

        assert await service.match(db, tenant_id, {"ipv4": ["9.9.9.9"]}) == []
        assert await service.list_iocs(db, tenant_id) == []
        # ... but it is still there to be reviewed.
        assert len(await service.list_iocs(db, tenant_id, include_expired=True)) == 1


async def test_purging_only_removes_long_expired_indicators() -> None:
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        for value, expires in (
            ("9.9.9.1", datetime.now(UTC) - timedelta(days=200)),
            ("9.9.9.2", datetime.now(UTC) - timedelta(days=1)),
            ("9.9.9.3", None),
        ):
            await service.create_ioc(
                db,
                tenant_id=tenant_id,
                value=value,
                ioc_type=None,
                classification="unknown",
                confidence=50,
                source="feed",
                description=None,
                tags=[],
                expires_at=expires,
                actor_id=None,
            )
        await db.commit()

        removed = await service.purge_expired(db, older_than_days=90)
        await db.commit()

        remaining = {ioc.value for ioc in await service.list_iocs(db, tenant_id, include_expired=True)}

    assert removed == 1
    assert remaining == {"9.9.9.2", "9.9.9.3"}


async def test_changing_classification_writes_a_history_row() -> None:
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        ioc = await service.create_ioc(
            db,
            tenant_id=tenant_id,
            value="5.5.5.5",
            ioc_type=None,
            classification="malicious",
            confidence=90,
            source="feed",
            description=None,
            tags=[],
            expires_at=None,
            actor_id=None,
        )
        await db.commit()

        await service.update_ioc(
            db,
            tenant_id=tenant_id,
            ioc_id=ioc.id,
            values={"classification": "benign", "confidence": 10},
            actor_id=None,
        )
        await db.commit()

        history = await service.history_for(db, tenant_id, ioc.id)

    changed = {row.changed_field: (row.old_value, row.new_value) for row in history}
    assert changed["classification"] == ("malicious", "benign")
    assert changed["confidence"] == ("90", "10")


async def test_indicator_history_cannot_be_rewritten() -> None:
    """Enforced by a database trigger: "who downgraded this the week before
    the breach" has to survive someone with database access."""
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        ioc = await service.create_ioc(
            db,
            tenant_id=tenant_id,
            value="6.6.6.6",
            ioc_type=None,
            classification="malicious",
            confidence=90,
            source="feed",
            description=None,
            tags=[],
            expires_at=None,
            actor_id=None,
        )
        await db.commit()
        await service.update_ioc(
            db, tenant_id=tenant_id, ioc_id=ioc.id, values={"confidence": 20}, actor_id=None
        )
        await db.commit()

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(text("UPDATE ioc_history SET new_value = '99'"))
        await db.rollback()
    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(text("DELETE FROM ioc_history"))
        await db.rollback()


async def test_the_database_refuses_a_malicious_indicator_with_no_source() -> None:
    """Spec §11 at the storage layer: a claim of malice always names who is
    making it, even if a future code path forgets to."""
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        db.add(
            Ioc(
                tenant_id=tenant_id,
                ioc_type="ipv4",
                value="7.7.7.7",
                classification="malicious",
                confidence=99,
                source="   ",
            )
        )
        with pytest.raises(Exception, match="ck_iocs_source_required"):
            await db.commit()


# ---------------------------------------------------------------------------
# Feeds: "a feed is not proof"
# ---------------------------------------------------------------------------


async def test_a_bare_feed_entry_is_never_promoted_to_malicious() -> None:
    """The §11 rule at the ingestion layer: a feed publishing a list of
    addresses is asserting "I saw this", not "this is malicious"."""
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.upsert_from_feed(
            db,
            tenant_id=tenant_id,
            source="bulk-blocklist",
            indicators=[FeedIndicator(value="203.0.113.7")],
        )
        await db.commit()
        stored = await service.list_iocs(db, tenant_id)

    assert len(stored) == 1
    assert stored[0].classification == "unknown"
    assert stored[0].confidence == 50
    assert stored[0].source == "bulk-blocklist"


async def test_a_feed_that_does_assert_a_verdict_is_recorded_as_it_stated_it() -> None:
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.upsert_from_feed(
            db,
            tenant_id=tenant_id,
            source="curated-feed",
            indicators=[
                FeedIndicator(value="203.0.113.8", classification="malicious", confidence=95)
            ],
        )
        await db.commit()
        stored = await service.list_iocs(db, tenant_id)

    assert (stored[0].classification, stored[0].confidence) == ("malicious", 95)


async def test_feed_indicators_expire_by_default() -> None:
    """Intel is perishable; without a default TTL the platform accumulates
    claims nobody stands behind any more."""
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.upsert_from_feed(
            db,
            tenant_id=tenant_id,
            source="feed",
            indicators=[FeedIndicator(value="203.0.113.9")],
            default_ttl_days=7,
        )
        await db.commit()
        stored = (await service.list_iocs(db, tenant_id))[0]

    assert stored.expires_at is not None
    assert stored.expires_at > datetime.now(UTC)
    assert stored.expires_at < datetime.now(UTC) + timedelta(days=8)


async def test_re_seeing_an_indicator_refreshes_it_without_upgrading_it() -> None:
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.upsert_from_feed(
            db,
            tenant_id=tenant_id,
            source="feed",
            indicators=[FeedIndicator(value="203.0.113.10")],
            default_ttl_days=1,
        )
        await db.commit()
        first = (await service.list_iocs(db, tenant_id))[0]
        first_expiry = first.expires_at

        counts = await service.upsert_from_feed(
            db,
            tenant_id=tenant_id,
            source="feed",
            indicators=[FeedIndicator(value="203.0.113.10")],
            default_ttl_days=30,
        )
        await db.commit()
        refreshed = (await service.list_iocs(db, tenant_id))[0]

    assert counts == {"created": 0, "updated": 1, "skipped": 0}
    assert refreshed.expires_at is not None and first_expiry is not None
    assert refreshed.expires_at > first_expiry
    assert refreshed.classification == "unknown", "re-seeing an indicator upgraded its verdict"


async def test_unparseable_feed_entries_are_counted_not_fatal() -> None:
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        counts = await service.upsert_from_feed(
            db,
            tenant_id=tenant_id,
            source="messy-feed",
            indicators=[
                FeedIndicator(value="203.0.113.11"),
                FeedIndicator(value="### not an indicator ###"),
                FeedIndicator(value=""),
            ],
        )
        await db.commit()

    assert counts == {"created": 1, "updated": 0, "skipped": 2}


# ---------------------------------------------------------------------------
# Shared vs tenant indicators
# ---------------------------------------------------------------------------


async def test_a_shared_indicator_is_visible_to_every_tenant() -> None:
    tenant_a, tenant_b = await _tenant(), await _tenant()
    async with intel_sync_session() as db:
        await service.upsert_from_feed(
            db,
            tenant_id=None,
            source="global-feed",
            indicators=[FeedIndicator(value="198.51.100.20", classification="suspicious")],
        )
        await db.commit()

    for tenant_id in (tenant_a, tenant_b):
        async with tenant_scoped_session(tenant_id) as db:
            matches = await service.match(db, tenant_id, {"ipv4": ["198.51.100.20"]})
        assert len(matches) == 1
        assert matches[0]["shared"] is True


async def test_one_tenants_private_indicator_is_invisible_to_another() -> None:
    tenant_a, tenant_b = await _tenant(), await _tenant()
    async with tenant_scoped_session(tenant_a) as db:
        await service.create_ioc(
            db,
            tenant_id=tenant_a,
            value="198.51.100.21",
            ioc_type=None,
            classification="malicious",
            confidence=90,
            source="ir",
            description="from our incident",
            tags=[],
            expires_at=None,
            actor_id=None,
        )
        await db.commit()

    async with tenant_scoped_session(tenant_b) as db:
        assert await service.match(db, tenant_b, {"ipv4": ["198.51.100.21"]}) == []


async def test_a_tenant_cannot_write_a_shared_indicator() -> None:
    """RLS' WITH CHECK, not application logic: one tenant must not be able
    to inject intelligence into every other tenant's SOC."""
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        db.add(
            Ioc(
                tenant_id=None,
                ioc_type="ipv4",
                value="198.51.100.22",
                classification="malicious",
                confidence=99,
                source="attacker",
            )
        )
        with pytest.raises(Exception, match="row-level security|violates"):
            await db.commit()


async def test_the_sync_session_cannot_touch_a_tenants_indicators() -> None:
    """The mirror image: the shared-intel writer is confined to rows with no
    tenant, so it cannot read or rewrite a tenant's private intelligence."""
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.create_ioc(
            db,
            tenant_id=tenant_id,
            value="198.51.100.23",
            ioc_type=None,
            classification="malicious",
            confidence=90,
            source="ir",
            description=None,
            tags=[],
            expires_at=None,
            actor_id=None,
        )
        await db.commit()

    async with intel_sync_session() as db:
        visible = await service.match(db, None, {"ipv4": ["198.51.100.23"]})
    assert visible == []


async def test_a_session_with_no_context_at_all_sees_nothing() -> None:
    tenant_id = await _tenant()
    async with tenant_scoped_session(tenant_id) as db:
        await service.create_ioc(
            db,
            tenant_id=tenant_id,
            value="198.51.100.24",
            ioc_type=None,
            classification="malicious",
            confidence=90,
            source="ir",
            description=None,
            tags=[],
            expires_at=None,
            actor_id=None,
        )
        await db.commit()

    async with async_session_factory() as db:
        from sqlalchemy import select

        rows = list((await db.execute(select(Ioc))).scalars())
    assert rows == []
