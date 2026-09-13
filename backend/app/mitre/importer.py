"""Importing the ATT&CK matrix from a STIX 2.1 bundle (spec §12).

The catalog is data, not code. MITRE publishes several revisions a year, so
a hardcoded matrix is one that silently drifts while still claiming to
measure coverage — the Phase 10 acceptance criteria call this out
explicitly. The importer reads the official `enterprise-attack.json` bundle
(or any bundle in the same shape) from a file drop or over HTTPS through the
egress guard.

**Third-party content is never trusted as-is** (the phase's security review
item). The bundle is a 50MB JSON document published on the internet;
everything taken out of it is:

- **bounded** — the file size, the object count, and every string field have
  caps, so a hostile or corrupted bundle cannot exhaust memory or fill the
  database with a single 100MB "description";
- **shape-checked** — ids must match the ATT&CK id pattern, and an object
  missing the fields that make it a technique is rejected rather than
  stored half-formed;
- **counted** — rejected objects are tallied and recorded on the import row,
  because an import that silently drops half the matrix looks exactly like a
  matrix that shrank.

Nothing from the bundle is ever executed, formatted into SQL, or rendered as
markup: values are bound parameters and are escaped by the frontend like any
other data.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core import egress
from app.core.config import get_settings
from app.models.mitre import TACTIC_ID_PATTERN, TECHNIQUE_ID_PATTERN

logger = logging.getLogger(__name__)

# The official enterprise bundle is ~52MB today and grows a few MB a year.
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_OBJECTS = 200_000
MAX_NAME_LENGTH = 300
MAX_DESCRIPTION_LENGTH = 20_000
MAX_LIST_ITEMS = 64
MAX_URL_LENGTH = 500

_TECHNIQUE_ID = re.compile(TECHNIQUE_ID_PATTERN)
_TACTIC_ID = re.compile(TACTIC_ID_PATTERN)
_ATTACK_SOURCE = "mitre-attack"


class ImportError_(Exception):
    """Raised when a bundle cannot be used at all. Named with a trailing
    underscore to avoid shadowing the builtin."""


@dataclass
class ParsedTactic:
    id: str
    name: str
    shortname: str
    description: str | None
    url: str | None


@dataclass
class ParsedTechnique:
    id: str
    name: str
    description: str | None
    is_subtechnique: bool
    parent_id: str | None
    platforms: list[str]
    data_sources: list[str]
    is_deprecated: bool
    is_revoked: bool
    attack_version: str | None
    url: str | None
    tactic_shortnames: list[str]


@dataclass
class ParsedBundle:
    tactics: list[ParsedTactic] = field(default_factory=list)
    techniques: list[ParsedTechnique] = field(default_factory=list)
    attack_version: str | None = None
    spec_version: str | None = None
    rejected: int = 0


def _text(value: Any, limit: int) -> str | None:
    """Every string that leaves the bundle passes through here: type-checked
    and length-capped, so one malformed object cannot put a megabyte of
    anything into a column."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    # Control characters would otherwise travel into logs and UI intact.
    cleaned = "".join(char for char in cleaned if char.isprintable() or char in "\n\t")
    return cleaned[:limit]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value[:MAX_LIST_ITEMS]:
        text = _text(item, 200)
        if text:
            items.append(text)
    return items


def _attack_reference(obj: dict[str, Any]) -> tuple[str | None, str | None]:
    """The ATT&CK id and URL live in `external_references`, not in the STIX
    id. An object without one is not an ATT&CK object we can key on."""
    for reference in obj.get("external_references", [])[:MAX_LIST_ITEMS]:
        if not isinstance(reference, dict):
            continue
        if reference.get("source_name") != _ATTACK_SOURCE:
            continue
        external_id = _text(reference.get("external_id"), 16)
        url = _text(reference.get("url"), MAX_URL_LENGTH)
        if url and not url.startswith("https://"):
            # A non-HTTPS link in imported content is not rendered.
            url = None
        return external_id, url
    return None, None


def _parse_tactic(obj: dict[str, Any]) -> ParsedTactic | None:
    tactic_id, url = _attack_reference(obj)
    name = _text(obj.get("name"), MAX_NAME_LENGTH)
    shortname = _text(obj.get("x_mitre_shortname"), 100)
    if not tactic_id or not _TACTIC_ID.match(tactic_id) or not name or not shortname:
        return None
    return ParsedTactic(
        id=tactic_id,
        name=name,
        shortname=shortname,
        description=_text(obj.get("description"), MAX_DESCRIPTION_LENGTH),
        url=url,
    )


def _parse_technique(obj: dict[str, Any]) -> ParsedTechnique | None:
    technique_id, url = _attack_reference(obj)
    name = _text(obj.get("name"), MAX_NAME_LENGTH)
    if not technique_id or not _TECHNIQUE_ID.match(technique_id) or not name:
        return None

    is_subtechnique = bool(obj.get("x_mitre_is_subtechnique")) or "." in technique_id
    parent_id = technique_id.split(".")[0] if "." in technique_id else None

    tactics = []
    for phase in obj.get("kill_chain_phases", [])[:MAX_LIST_ITEMS]:
        if isinstance(phase, dict) and phase.get("kill_chain_name") == _ATTACK_SOURCE:
            shortname = _text(phase.get("phase_name"), 100)
            if shortname:
                tactics.append(shortname)

    return ParsedTechnique(
        id=technique_id,
        name=name,
        description=_text(obj.get("description"), MAX_DESCRIPTION_LENGTH),
        is_subtechnique=is_subtechnique,
        parent_id=parent_id,
        platforms=_string_list(obj.get("x_mitre_platforms")),
        data_sources=_string_list(obj.get("x_mitre_data_sources")),
        is_deprecated=bool(obj.get("x_mitre_deprecated")),
        is_revoked=bool(obj.get("revoked")),
        attack_version=_text(obj.get("x_mitre_version"), 32),
        url=url,
        tactic_shortnames=tactics,
    )


def parse_bundle(payload: bytes) -> ParsedBundle:
    """Turns a STIX bundle into the objects we store, rejecting anything
    that does not hold up."""
    if len(payload) > MAX_BUNDLE_BYTES:
        raise ImportError_(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")

    try:
        document = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ImportError_(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ImportError_("bundle is not a JSON object")

    objects = document.get("objects")
    if not isinstance(objects, list):
        raise ImportError_("bundle has no objects array")
    if len(objects) > MAX_OBJECTS:
        raise ImportError_(f"bundle contains more than {MAX_OBJECTS} objects")

    bundle = ParsedBundle(spec_version=_text(document.get("spec_version"), 32))
    seen_tactics: set[str] = set()
    seen_techniques: set[str] = set()

    for obj in objects:
        if not isinstance(obj, dict):
            bundle.rejected += 1
            continue

        object_type = obj.get("type")
        if object_type == "x-mitre-collection":
            bundle.attack_version = _text(obj.get("x_mitre_version"), 32)
            continue
        if object_type == "x-mitre-tactic":
            tactic = _parse_tactic(obj)
            if tactic is None or tactic.id in seen_tactics:
                bundle.rejected += 1
                continue
            seen_tactics.add(tactic.id)
            bundle.tactics.append(tactic)
        elif object_type == "attack-pattern":
            technique = _parse_technique(obj)
            if technique is None or technique.id in seen_techniques:
                bundle.rejected += 1
                continue
            seen_techniques.add(technique.id)
            bundle.techniques.append(technique)
        # Everything else in the bundle (groups, software, relationships,
        # analytics) is deliberately ignored: this phase maps detections to
        # techniques, and importing objects nothing reads would be storage
        # and attack surface for no benefit.

    if not bundle.techniques:
        # A bundle that parses but yields nothing is far more likely to be
        # the wrong file than a real ATT&CK release with no techniques.
        raise ImportError_("bundle contained no usable techniques")

    return bundle


async def load_bundle(source: str) -> tuple[bytes, str]:
    """Reads a bundle from a URL (through the egress guard) or from a file
    in the intelligence drop directory. Returns the payload and a
    description of where it came from."""
    if source.startswith(("http://", "https://")):
        try:
            payload = await egress.fetch(source, max_bytes=MAX_BUNDLE_BYTES)
        except egress.EgressBlocked as exc:
            raise ImportError_(str(exc)) from exc
        except Exception as exc:  # noqa: BLE001  network failure is expected, not exceptional
            raise ImportError_(f"could not fetch {source}: {exc}") from exc
        return payload, source

    # Reading a 50MB bundle off disk happens in a thread: blocking the
    # event loop for it would stall every other request this process is
    # serving.
    return await asyncio.to_thread(_read_local_bundle, source)


def _read_local_bundle(source: str) -> tuple[bytes, str]:
    root = Path(get_settings().threat_intel_drop_dir).resolve()
    candidate = (root / source).resolve()
    # The filename is operator-supplied configuration, so it is confined to
    # the drop directory (path traversal, THREAT_MODEL.md §3.8).
    if not candidate.is_relative_to(root):
        raise ImportError_(f"{source} resolves outside the drop directory")
    if not candidate.is_file():
        raise ImportError_(f"{candidate} does not exist")
    if candidate.stat().st_size > MAX_BUNDLE_BYTES:
        raise ImportError_(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    return candidate.read_bytes(), str(candidate)
