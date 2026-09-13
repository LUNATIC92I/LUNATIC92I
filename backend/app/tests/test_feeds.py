"""Feed connectors and synchronization.

The behaviour that matters most here is what a feed is *not* allowed to do:
assert malice it never claimed, reach a host nobody allow-listed, read a
file outside its drop directory, or fail silently.
"""

import uuid
from pathlib import Path

import pytest

from app.core.config import get_settings
from app.core.db import async_session_factory, intel_sync_session, tenant_scoped_session
from app.models.identity import Organization
from app.models.threat_intel import IocFeed
from app.services import threat_intel as intel_service
from app.services.feeds import sync_feed, sync_shared_feeds
from app.threat_intel.feeds.base import (
    FeedError,
    LocalFileFeedConnector,
    build_connector,
    parse_indicators,
    resolve_credential,
)

CSV_FEED = """value,classification,confidence,tags
203.0.113.1,malicious,90,c2|apt
evil.test,suspicious,60,phishing
"""

JSON_FEED = """
{"data": [
  {"value": "203.0.113.2", "classification": "malicious", "confidence": 80},
  {"value": "203.0.113.3"}
]}
"""

PLAIN_FEED = """# a bulk blocklist
203.0.113.4
203.0.113.5

"""


@pytest.fixture(autouse=True)
def _settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


async def _tenant() -> uuid.UUID:
    slug = f"t{uuid.uuid4().hex[:12]}"
    async with async_session_factory() as db:
        org = Organization(name=slug, slug=slug)
        db.add(org)
        await db.commit()
        return org.id


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_a_plain_list_asserts_existence_not_malice() -> None:
    """Spec §11 at the parser: a bulk blocklist publishes addresses, not
    verdicts, and the parser must not invent one."""
    indicators = parse_indicators(PLAIN_FEED.encode(), fmt="plain", mapping={})

    assert [item.value for item in indicators] == ["203.0.113.4", "203.0.113.5"]
    assert all(item.classification is None for item in indicators)
    assert all(item.confidence is None for item in indicators)


def test_csv_columns_map_to_indicator_fields() -> None:
    indicators = parse_indicators(CSV_FEED.encode(), fmt="csv", mapping={})

    assert indicators[0].value == "203.0.113.1"
    assert indicators[0].classification == "malicious"
    assert indicators[0].confidence == 90
    assert indicators[0].tags == ["c2", "apt"]
    assert indicators[1].classification == "suspicious"


def test_json_feeds_accept_objects_and_bare_strings() -> None:
    indicators = parse_indicators(JSON_FEED.encode(), fmt="json", mapping={})
    assert [item.value for item in indicators] == ["203.0.113.2", "203.0.113.3"]
    assert indicators[1].classification is None

    bare = parse_indicators(b'["203.0.113.6"]', fmt="json", mapping={})
    assert bare[0].value == "203.0.113.6"


def test_malformed_json_is_an_error_not_an_empty_feed() -> None:
    """An empty result would look like "the feed publishes nothing today",
    which is indistinguishable from intelligence quietly disappearing."""
    with pytest.raises(FeedError, match="not valid JSON"):
        parse_indicators(b"{oh no", fmt="json", mapping={})


def test_an_unsupported_format_is_refused() -> None:
    with pytest.raises(FeedError, match="unsupported feed format"):
        parse_indicators(b"x", fmt="xml", mapping={})


def test_a_feed_larger_than_the_cap_is_refused() -> None:
    from app.threat_intel.feeds.base import MAX_INDICATORS_PER_SYNC

    payload = "\n".join(f"203.0.113.{index % 255}" for index in range(MAX_INDICATORS_PER_SYNC + 1))
    with pytest.raises(FeedError, match="cap for a single sync"):
        parse_indicators(payload.encode(), fmt="plain", mapping={})


# ---------------------------------------------------------------------------
# The local-file connector
# ---------------------------------------------------------------------------


async def test_a_file_drop_feed_is_read_from_the_allow_listed_directory(
    monkeypatch, tmp_path: Path
) -> None:
    (tmp_path / "blocklist.txt").write_text(PLAIN_FEED)
    monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(tmp_path))
    get_settings.cache_clear()

    connector = LocalFileFeedConnector(
        name="drop", config={"filename": "blocklist.txt", "format": "plain"}
    )
    indicators = await connector.fetch()
    assert len(indicators) == 2


@pytest.mark.parametrize(
    "filename", ["../../../etc/passwd", "/etc/passwd", "sub/../../outside.txt"]
)
async def test_a_file_drop_feed_cannot_escape_its_directory(
    monkeypatch, tmp_path: Path, filename: str
) -> None:
    """Path traversal, THREAT_MODEL.md §3.8: the filename is feed
    configuration and is treated as untrusted."""
    monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(tmp_path / "drop"))
    (tmp_path / "drop").mkdir()
    (tmp_path / "outside.txt").write_text("203.0.113.9")
    get_settings.cache_clear()

    connector = LocalFileFeedConnector(name="drop", config={"filename": filename})
    with pytest.raises(FeedError, match="outside the intelligence drop directory|does not exist"):
        await connector.fetch()


# ---------------------------------------------------------------------------
# The HTTP connector goes through the guard
# ---------------------------------------------------------------------------


async def test_an_http_feed_url_is_subject_to_the_egress_guard(monkeypatch) -> None:
    monkeypatch.setenv("EGRESS_ALLOWED_HOSTS", "feeds.example.com")
    get_settings.cache_clear()

    connector = build_connector(
        connector_type="http",
        name="metadata-thief",
        # The SSRF an operator (or an attacker who reached feed config)
        # would actually try.
        config={"url": "https://169.254.169.254/latest/meta-data/"},
        credential_ref=None,
    )
    with pytest.raises(FeedError, match="host_not_allowed|non_global_address"):
        await connector.fetch()


async def test_an_http_feed_without_a_url_fails_clearly() -> None:
    connector = build_connector(
        connector_type="http", name="broken", config={}, credential_ref=None
    )
    with pytest.raises(FeedError, match="no url"):
        await connector.fetch()


def test_an_unknown_connector_type_is_refused() -> None:
    with pytest.raises(FeedError, match="unknown connector type"):
        build_connector(connector_type="telepathy", name="x", config={}, credential_ref=None)


def test_credentials_are_read_from_the_environment_not_the_database(monkeypatch) -> None:
    """A feed API key in the database's JSONB config would be readable by
    anyone with a database connection and would end up in every backup."""
    monkeypatch.setenv("FEED_TOKEN_ACME", "s3cret")
    assert resolve_credential("FEED_TOKEN_ACME") == "s3cret"
    assert resolve_credential(None) is None

    with pytest.raises(FeedError, match="not present in the environment"):
        resolve_credential("FEED_TOKEN_MISSING")


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------


async def test_a_successful_sync_records_what_it_wrote(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "feed.csv").write_text(CSV_FEED)
    monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(tmp_path))
    get_settings.cache_clear()
    tenant_id = await _tenant()

    async with tenant_scoped_session(tenant_id) as db:
        feed = IocFeed(
            tenant_id=tenant_id,
            name="drop-csv",
            connector_type="local_file",
            config={"filename": "feed.csv", "format": "csv"},
        )
        db.add(feed)
        await db.flush()

        outcome = await sync_feed(db, feed)
        await db.commit()

        stored = await intel_service.list_iocs(db, tenant_id)

    assert outcome.ok is True
    assert outcome.created == 2
    assert feed.last_synced_at is not None
    assert feed.last_sync_status is not None and feed.last_sync_status.startswith("ok:")
    assert {ioc.value for ioc in stored} == {"203.0.113.1", "evil.test"}
    assert {ioc.source for ioc in stored} == {"drop-csv"}


async def test_a_failing_feed_is_recorded_rather_than_swallowed(
    monkeypatch, tmp_path: Path
) -> None:
    """Silently stale intelligence looks exactly like a quiet week."""
    monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(tmp_path))
    get_settings.cache_clear()
    tenant_id = await _tenant()

    async with tenant_scoped_session(tenant_id) as db:
        feed = IocFeed(
            tenant_id=tenant_id,
            name="missing-file",
            connector_type="local_file",
            config={"filename": "not-there.txt"},
        )
        db.add(feed)
        await db.flush()

        outcome = await sync_feed(db, feed)
        await db.commit()

    assert outcome.ok is False
    assert feed.last_sync_status is not None
    assert feed.last_sync_status.startswith("failed:")
    assert "does not exist" in feed.last_sync_status


async def test_a_shared_feed_writes_indicators_every_tenant_can_see(
    monkeypatch, tmp_path: Path
) -> None:
    (tmp_path / "global.txt").write_text("203.0.113.30\n")
    monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(tmp_path))
    get_settings.cache_clear()
    tenant_id = await _tenant()

    async with intel_sync_session() as db:
        db.add(
            IocFeed(
                tenant_id=None,
                name=f"global-{uuid.uuid4().hex[:8]}",
                connector_type="local_file",
                config={"filename": "global.txt", "format": "plain"},
            )
        )
        await db.commit()

    outcomes = await sync_shared_feeds()
    assert any(outcome.ok and outcome.created == 1 for outcome in outcomes)

    async with tenant_scoped_session(tenant_id) as db:
        matches = await intel_service.match(db, tenant_id, {"ipv4": ["203.0.113.30"]})
    assert len(matches) == 1
    assert matches[0]["shared"] is True
    # Still not a verdict: a bulk list said the address exists, nothing more.
    assert matches[0]["classification"] == "unknown"


async def test_one_broken_feed_does_not_stop_the_others(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "good.txt").write_text("203.0.113.31\n")
    monkeypatch.setenv("THREAT_INTEL_DROP_DIR", str(tmp_path))
    get_settings.cache_clear()

    async with intel_sync_session() as db:
        for name, filename in (("broken", "nope.txt"), ("good", "good.txt")):
            db.add(
                IocFeed(
                    tenant_id=None,
                    name=f"{name}-{uuid.uuid4().hex[:8]}",
                    connector_type="local_file",
                    config={"filename": filename, "format": "plain"},
                )
            )
        await db.commit()

    outcomes = await sync_shared_feeds()
    assert any(not outcome.ok for outcome in outcomes)
    assert any(outcome.ok for outcome in outcomes)
