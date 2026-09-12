"""OCSF normalization tests.

Beyond per-format mapping, these assert two contracts the rest of the
platform is built on: the raw payload always survives normalization, and the
document shape stays in sync with the index mapping written in Phase 0
(`docs/database/opensearch_indices.md`). A drift between the mapper and that
mapping means fields silently stop being searchable — the kind of failure
that shows up months later as "why did no rule fire".
"""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.normalization.ocsf import (
    CLASS_AUTHENTICATION,
    CLASS_HTTP_ACTIVITY,
    CLASS_NETWORK_ACTIVITY,
    SCHEMA_VERSION,
    normalize,
)
from app.parsers.registry import ParserRegistry

_REGISTRY = ParserRegistry()
_RECEIVED_AT = datetime(2026, 9, 12, 5, 0, 0, tzinfo=UTC)


def _normalize(raw: bytes, source_type: str = "test") -> dict:
    parsed = _REGISTRY.parse(raw)
    return normalize(
        parsed=parsed,
        tenant_id="11111111-1111-1111-1111-111111111111",
        raw_payload=raw,
        source_type=source_type,
        collector_id="test-collector",
        received_at=_RECEIVED_AT,
    )


# ---------------------------------------------------------------------------
# Universal contracts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        b'{"action": "login", "user": {"name": "alice"}}',
        b"<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password for root from 10.0.0.9",
        b"CEF:0|Fortinet|FortiGate|7.2|13|Denied|5|src=10.1.1.5 dst=8.8.8.8",
        b'10.1.1.5 - - [12/Sep/2026:05:14:15 +0000] "GET /a HTTP/1.1" 200 12',
    ],
)
def test_raw_payload_always_survives_normalization(raw: bytes) -> None:
    """Spec §4: the original bytes are the forensic record. A mis-mapped
    field is recoverable; a discarded payload is not."""
    document = _normalize(raw)
    assert document["raw_event"] == raw.decode()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"action": "login"}',
        b"<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password for root",
        b"CEF:0|V|P|1.0|1|Name|3|src=10.1.1.5",
    ],
)
def test_every_document_carries_required_identity_fields(raw: bytes) -> None:
    document = _normalize(raw)

    assert document["tenant_id"] == "11111111-1111-1111-1111-111111111111"
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["event_id"]
    assert document["timestamp"]
    assert document["ingestion_timestamp"]
    assert document["normalized_event"]["metadata"]["version"] == "1.1.0"


def test_document_is_json_serializable() -> None:
    """It has to survive the trip to the bus and to OpenSearch."""
    document = _normalize(b'{"action": "login", "count": 3, "ok": true}')
    assert json.loads(json.dumps(document, default=str))["source_type"] == "test"


# ---------------------------------------------------------------------------
# Classification and field mapping
# ---------------------------------------------------------------------------


def test_ssh_failure_maps_to_authentication_with_user_and_source_ip() -> None:
    raw = b"<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password for root from 10.0.0.9 port 22"
    document = _normalize(raw, source_type="syslog_udp")

    assert document["normalized_event"]["class_uid"] == CLASS_AUTHENTICATION
    assert document["class"] == "Authentication"
    assert document["activity"] == "Logon Failed"
    assert document["user"]["name"] == "root"
    assert document["source_ip"] == "10.0.0.9"
    assert document["hostname"] == "web01"
    assert document["authentication"]["outcome"] == "failure"


def test_ssh_success_maps_to_successful_logon() -> None:
    raw = b"<34>Oct 11 22:14:15 web01 sshd[1234]: Accepted password for alice from 10.0.0.9"
    document = _normalize(raw)

    assert document["activity"] == "Logon"
    assert document["authentication"]["outcome"] == "success"
    assert document["user"]["name"] == "alice"


def test_windows_4625_maps_to_failed_authentication() -> None:
    raw = (
        b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        b"<System><EventID>4625</EventID>"
        b'<TimeCreated SystemTime="2026-09-12T05:14:15.123456Z"/>'
        b"<Computer>WKSTN-042</Computer></System>"
        b'<EventData><Data Name="TargetUserName">alice</Data>'
        b'<Data Name="TargetDomainName">CORP</Data>'
        b'<Data Name="IpAddress">10.1.1.5</Data></EventData></Event>'
    )
    document = _normalize(raw, source_type="windows")

    assert document["class"] == "Authentication"
    assert document["activity"] == "Logon Failed"
    assert document["user"] == {"name": "alice", "domain": "CORP"}
    assert document["source_ip"] == "10.1.1.5"
    assert document["hostname"] == "WKSTN-042"
    # The source's own timestamp wins over ingestion time when it is unambiguous.
    assert document["timestamp"].startswith("2026-09-12T05:14:15")


def test_firewall_cef_maps_to_network_activity_with_both_endpoints() -> None:
    raw = (
        b"CEF:0|Fortinet|FortiGate|7.2|13|Traffic Denied|5|"
        b"src=10.1.1.5 dst=8.8.8.8 spt=51234 dpt=53 proto=UDP act=deny"
    )
    document = _normalize(raw, source_type="firewall")

    assert document["normalized_event"]["class_uid"] == CLASS_NETWORK_ACTIVITY
    assert document["source_ip"] == "10.1.1.5"
    assert document["destination_ip"] == "8.8.8.8"
    assert document["source_port"] == 51234
    assert document["destination_port"] == 53
    assert document["protocol"] == "UDP"
    assert document["severity"] == "medium"  # CEF severity 5 of 10


def test_web_access_maps_to_http_activity() -> None:
    raw = (
        b'10.1.1.5 - alice [12/Sep/2026:05:14:15 +0000] "GET /admin HTTP/1.1" 401 512 '
        b'"https://example.test/" "Mozilla/5.0"'
    )
    document = _normalize(raw, source_type="nginx")

    assert document["normalized_event"]["class_uid"] == CLASS_HTTP_ACTIVITY
    assert document["url"] == "/admin"
    assert document["activity"] == "HTTP GET"
    assert document["source_ip"] == "10.1.1.5"
    assert document["normalized_event"]["http_request"]["status_code"] == 401
    assert document["normalized_event"]["http_request"]["user_agent"] == "Mozilla/5.0"


def test_unclassifiable_event_falls_back_to_base_event_rather_than_guessing() -> None:
    """A wrong class is worse than an unclassified one: detection rules key
    off class, so a mis-filed event is invisible to the rules meant to catch
    it and noise to the ones that fire."""
    document = _normalize(b'{"something": "entirely unfamiliar", "value": 42}')

    assert document["class"] == "Base Event"
    assert document["normalized_event"]["unmapped"]["something"] == "entirely unfamiliar"


def test_severity_maps_from_syslog_priority() -> None:
    # PRI 34 -> severity 2 (crit)
    critical = _normalize(b"<34>Oct 11 22:14:15 h app: msg")
    # PRI 38 -> severity 6 (info)
    informational = _normalize(b"<38>Oct 11 22:14:15 h app: msg")

    assert critical["severity"] == "critical"
    assert informational["severity"] == "informational"


def test_sha256_hash_is_extracted_and_lowercased() -> None:
    digest = "A" * 64
    raw = f'{{"event": "file_write", "sha256": "{digest}"}}'.encode()
    document = _normalize(raw)

    assert document["hash"]["sha256"] == "a" * 64


def test_unmapped_fields_are_preserved_for_detection_engineers() -> None:
    raw = b"CEF:0|V|P|1.0|1|Name|3|src=10.1.1.5 customVendorField=interesting"
    document = _normalize(raw)

    assert document["normalized_event"]["unmapped"]["customVendorField"] == "interesting"


# ---------------------------------------------------------------------------
# Contract with the index mapping written in Phase 0
# ---------------------------------------------------------------------------


def test_document_fields_are_all_declared_in_the_opensearch_mapping() -> None:
    """The index template uses `dynamic: false`, so a top-level field the
    mapper emits but the mapping never declared is silently NOT indexed —
    stored, invisible to search, and impossible to write a rule against.
    This test fails the build instead of letting that happen quietly."""
    mapping_doc = (
        Path(__file__).resolve().parents[3] / "docs" / "database" / "opensearch_indices.md"
    ).read_text()

    # The normalized-events template is the first ```json block in the doc.
    normalized_section = mapping_doc.split("## 3. Index template: `lunatic-events-normalized`")[1]
    json_block = re.search(r"```json\n(.*?)\n```", normalized_section, re.DOTALL)
    assert json_block is not None, "could not locate the normalized-events mapping block"
    declared = set(json.loads(json_block.group(1))["template"]["mappings"]["properties"])

    emitted: set[str] = set()
    for raw in (
        b'{"action": "login"}',
        b"<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password for root from 10.0.0.9",
        b"CEF:0|Fortinet|FortiGate|7.2|13|Denied|5|src=10.1.1.5 dst=8.8.8.8 spt=1 dpt=53 proto=UDP",
        b'10.1.1.5 - alice [12/Sep/2026:05:14:15 +0000] "GET /a HTTP/1.1" 200 12 "-" "curl"',
    ):
        emitted.update(_normalize(raw))

    undeclared = emitted - declared
    assert not undeclared, (
        f"normalizer emits fields absent from the OpenSearch mapping: {sorted(undeclared)}. "
        "Add them to docs/database/opensearch_indices.md or stop emitting them."
    )
