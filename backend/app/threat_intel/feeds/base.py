"""The feed connector contract (spec §11, ARCHITECTURE.md §7).

A connector's only job is to turn some external representation into
`FeedIndicator`s. It never decides what an indicator *means*: classification
and confidence are carried through exactly as the feed asserted them, and a
feed that asserts nothing produces `unknown`/50 (spec §11's rule that a feed
is not proof, enforced in `services/threat_intel.upsert_from_feed`).

Connectors also never make raw network calls. Anything fetching a URL goes
through `app/core/egress.py`, so a feed URL — which is operator-supplied
configuration, and in a multi-tenant platform is close to user input — can
never become a request to the cloud metadata service (THREAT_MODEL.md §3.8).
"""

import abc
import asyncio
import csv
import io
import json
import logging
import os
from pathlib import Path
from typing import Any, ClassVar

from app.core import egress
from app.core.config import get_settings
from app.services.threat_intel import FeedIndicator

logger = logging.getLogger(__name__)

MAX_INDICATORS_PER_SYNC = 500_000


class FeedError(Exception):
    """The feed could not be read. Always surfaced and counted — a feed that
    fails quietly is intelligence going stale with nobody noticing."""


class FeedConnector(abc.ABC):
    connector_type: ClassVar[str]

    def __init__(self, *, name: str, config: dict[str, Any], credential: str | None = None) -> None:
        self.name = name
        self.config = config
        self._credential = credential

    @abc.abstractmethod
    async def fetch(self) -> list[FeedIndicator]:
        """Returns everything the feed currently publishes."""


def resolve_credential(credential_ref: str | None) -> str | None:
    """Credentials are referenced by name and read from the environment (in
    production, injected from a secrets manager). A feed API key stored in
    the database's JSONB config would be readable by anyone with a database
    connection and would end up in every backup — spec §27."""
    if not credential_ref:
        return None
    value = os.environ.get(credential_ref)
    if value is None:
        raise FeedError(
            f"credential {credential_ref} is not present in the environment; "
            "the feed cannot authenticate"
        )
    return value


def _as_indicator(row: dict[str, Any], mapping: dict[str, str]) -> FeedIndicator | None:
    value = row.get(mapping.get("value", "value"))
    if not isinstance(value, str) or not value.strip():
        return None

    confidence_raw = row.get(mapping.get("confidence", "confidence"))
    try:
        confidence = int(confidence_raw) if confidence_raw not in (None, "") else None
    except (TypeError, ValueError):
        confidence = None

    tags_raw = row.get(mapping.get("tags", "tags")) or []
    if isinstance(tags_raw, str):
        tags = [tag.strip() for tag in tags_raw.split("|") if tag.strip()]
    elif isinstance(tags_raw, list):
        tags = [str(tag) for tag in tags_raw]
    else:
        tags = []

    classification = row.get(mapping.get("classification", "classification"))
    return FeedIndicator(
        value=value.strip(),
        ioc_type=row.get(mapping.get("ioc_type", "ioc_type")) or None,
        # Passed through, never inferred: see the module docstring.
        classification=str(classification).lower() if classification else None,
        confidence=confidence,
        description=row.get(mapping.get("description", "description")) or None,
        tags=tags,
    )


def parse_indicators(payload: bytes, *, fmt: str, mapping: dict[str, str]) -> list[FeedIndicator]:
    """Parses the three shapes real feeds actually ship in."""
    text = payload.decode("utf-8", errors="replace")
    indicators: list[FeedIndicator] = []

    if fmt == "plain":
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # A bare list asserts existence, not malice: no classification
            # and no confidence are attached here on purpose.
            indicators.append(FeedIndicator(value=stripped))
    elif fmt == "csv":
        for row in csv.DictReader(io.StringIO(text)):
            indicator = _as_indicator(dict(row), mapping)
            if indicator is not None:
                indicators.append(indicator)
    elif fmt == "json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FeedError(f"feed is not valid JSON: {exc}") from exc
        rows = document
        if isinstance(document, dict):
            rows = document.get(mapping.get("root", "data"), [])
        if not isinstance(rows, list):
            raise FeedError("feed JSON does not contain a list of indicators")
        for row in rows:
            if isinstance(row, str):
                indicators.append(FeedIndicator(value=row))
            elif isinstance(row, dict):
                indicator = _as_indicator(row, mapping)
                if indicator is not None:
                    indicators.append(indicator)
    else:
        raise FeedError(f"unsupported feed format: {fmt}")

    if len(indicators) > MAX_INDICATORS_PER_SYNC:
        raise FeedError(
            f"feed published {len(indicators)} indicators, above the "
            f"{MAX_INDICATORS_PER_SYNC} cap for a single sync"
        )
    return indicators


class HttpFeedConnector(FeedConnector):
    """Fetches a plain-text, CSV or JSON feed over HTTPS.

    Covers the majority of real-world feeds (abuse.ch, blocklists, most
    commercial exports) without needing a bespoke connector each. The URL is
    operator configuration and is validated by the egress guard on every
    fetch, including across redirects.
    """

    connector_type: ClassVar[str] = "http"

    async def fetch(self) -> list[FeedIndicator]:
        url = self.config.get("url")
        if not isinstance(url, str) or not url:
            raise FeedError("feed config has no url")

        headers: dict[str, str] = dict(self.config.get("headers") or {})
        if self._credential:
            header_name = str(self.config.get("auth_header", "Authorization"))
            template = str(self.config.get("auth_template", "{credential}"))
            headers[header_name] = template.format(credential=self._credential)

        try:
            payload = await egress.fetch(url, headers=headers)
        except egress.EgressBlocked as exc:
            raise FeedError(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001  network failures are the norm, not a crash
            raise FeedError(f"could not fetch {url}: {exc}") from exc

        return parse_indicators(
            payload,
            fmt=str(self.config.get("format", "plain")),
            mapping=dict(self.config.get("mapping") or {}),
        )


class LocalFileFeedConnector(FeedConnector):
    """Reads a feed from a file dropped into an allow-listed directory.

    This is how intelligence reaches an air-gapped deployment, and how a
    subscription whose licence forbids automated pulling gets loaded. The
    path is confined to `THREAT_INTEL_DROP_DIR`: the filename is treated as
    untrusted, resolved, and rejected if it escapes that directory (the
    path-traversal row of THREAT_MODEL.md §3.8).
    """

    connector_type: ClassVar[str] = "local_file"

    @staticmethod
    def _read(filename: str) -> bytes:
        return _read_drop_file(filename)

    async def fetch(self) -> list[FeedIndicator]:
        filename = self.config.get("filename")
        if not isinstance(filename, str) or not filename:
            raise FeedError("feed config has no filename")

        # Filesystem work happens off the event loop: an intel drop can be
        # hundreds of megabytes, and blocking here would stall every other
        # feed sync sharing this worker.
        payload = await asyncio.to_thread(self._read, filename)
        return parse_indicators(
            payload,
            fmt=str(self.config.get("format", "plain")),
            mapping=dict(self.config.get("mapping") or {}),
        )


def _read_drop_file(filename: str) -> bytes:
    root = Path(get_settings().threat_intel_drop_dir).resolve()
    candidate = (root / filename).resolve()
    if not candidate.is_relative_to(root):
        raise FeedError(f"{filename} resolves outside the intelligence drop directory")
    if not candidate.is_file():
        raise FeedError(f"{candidate} does not exist")
    return candidate.read_bytes()


CONNECTORS: dict[str, type[FeedConnector]] = {
    HttpFeedConnector.connector_type: HttpFeedConnector,
    LocalFileFeedConnector.connector_type: LocalFileFeedConnector,
}


def build_connector(
    *, connector_type: str, name: str, config: dict[str, Any], credential_ref: str | None
) -> FeedConnector:
    try:
        connector_class = CONNECTORS[connector_type]
    except KeyError as exc:
        raise FeedError(f"unknown connector type: {connector_type}") from exc
    return connector_class(
        name=name, config=config, credential=resolve_credential(credential_ref)
    )
