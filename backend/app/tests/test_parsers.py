"""Per-format parser tests.

Every format gets, per the Phase 4 acceptance criteria: a positive case
against a realistic payload, and a malformed case proving the parser
*rejects* rather than crashing or silently returning junk. The registry
tests then prove the ordering between overlapping formats is deliberate.
"""

import pytest

from app.parsers.base import ParserError
from app.parsers.cef import CefParser
from app.parsers.json_parser import JsonParser
from app.parsers.keyvalue import KeyValueParser
from app.parsers.leef import LeefParser
from app.parsers.registry import ParserRegistry
from app.parsers.syslog import SyslogParser
from app.parsers.web import WebAccessLogParser
from app.parsers.windows_xml import WindowsEventXmlParser

# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_json_parses_and_flattens_nested_objects() -> None:
    raw = b'{"user": {"name": "alice", "id": 7}, "action": "login", "ok": true}'
    parsed = JsonParser().parse(raw)

    assert parsed.format_name == "json"
    assert parsed.fields == {"user.name": "alice", "user.id": 7, "action": "login", "ok": True}


def test_json_rejects_malformed_document() -> None:
    with pytest.raises(ParserError, match="invalid JSON"):
        JsonParser().parse(b'{"user": "alice",,,}')


def test_json_rejects_array_rather_than_silently_taking_first_element() -> None:
    """A batch is not an event: collapsing it would break the
    one-payload-one-event contract dedup and replay depend on."""
    with pytest.raises(ParserError, match="arrays are not single events"):
        JsonParser().parse(b'[{"a": 1}, {"a": 2}]')


def test_json_rejects_bare_scalar() -> None:
    with pytest.raises(ParserError, match="expected a JSON object"):
        JsonParser().parse(b'"just a string"')


# ---------------------------------------------------------------------------
# Syslog
# ---------------------------------------------------------------------------


def test_syslog_rfc3164_extracts_tag_pid_and_message() -> None:
    raw = b"<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password for root from 10.0.0.9 port 22"
    parsed = SyslogParser().parse(raw)

    assert parsed.fields["hostname"] == "web01"
    assert parsed.fields["app_name"] == "sshd"
    assert parsed.fields["proc_id"] == "1234"
    assert parsed.fields["message"].startswith("Failed password for root")
    # PRI 34 = facility 4 (auth), severity 2 (crit)
    assert parsed.fields["facility_label"] == "auth"
    assert parsed.fields["severity_label"] == "crit"


def test_syslog_rfc5424_extracts_structured_data_and_nil_values() -> None:
    raw = (
        b'<165>1 2026-09-12T05:14:15.003Z fw01 sshd - ID47 [exampleSDID@32473 iut="3"] '
        b"An application event log entry"
    )
    parsed = SyslogParser().parse(raw)

    assert parsed.fields["syslog_version"] == 1
    assert parsed.fields["hostname"] == "fw01"
    assert parsed.fields["app_name"] == "sshd"
    assert parsed.fields["proc_id"] is None  # "-" means absent, not the literal string
    assert parsed.fields["msg_id"] == "ID47"
    assert parsed.fields["structured_data"] == '[exampleSDID@32473 iut="3"]'
    assert parsed.fields["message"] == "An application event log entry"


def test_syslog_rejects_payload_without_valid_structure() -> None:
    with pytest.raises(ParserError, match="does not match RFC"):
        SyslogParser().parse(b"<34>this is not a syslog line at all")


# ---------------------------------------------------------------------------
# CEF
# ---------------------------------------------------------------------------


def test_cef_parses_header_and_extension() -> None:
    raw = (
        b"CEF:0|Fortinet|FortiGate|7.2|13|Traffic Denied|5|"
        b"src=10.1.1.5 dst=8.8.8.8 spt=51234 dpt=53 proto=UDP act=deny"
    )
    parsed = CefParser().parse(raw)

    assert parsed.fields["device_vendor"] == "Fortinet"
    assert parsed.fields["device_product"] == "FortiGate"
    assert parsed.fields["signature_id"] == "13"
    assert parsed.fields["name"] == "Traffic Denied"
    assert parsed.fields["severity"] == "5"
    assert parsed.fields["src"] == "10.1.1.5"
    assert parsed.fields["dpt"] == "53"
    assert parsed.fields["act"] == "deny"


def test_cef_preserves_spaces_in_extension_values() -> None:
    """A value only ends where the next `key=` begins — splitting on spaces
    would truncate every message field in the product."""
    raw = b"CEF:0|V|P|1.0|100|Name|3|msg=user alice failed to log in suser=alice"
    parsed = CefParser().parse(raw)

    assert parsed.fields["msg"] == "user alice failed to log in"
    assert parsed.fields["suser"] == "alice"


def test_cef_handles_escaped_pipe_in_header() -> None:
    raw = rb"CEF:0|Vendor|Pro\|duct|1.0|100|Name|3|src=1.2.3.4"
    parsed = CefParser().parse(raw)

    assert parsed.fields["device_product"] == "Pro|duct"


def test_cef_strips_leading_syslog_envelope() -> None:
    raw = b"<134>Sep 12 05:14:15 fw01 CEF:0|Fortinet|FortiGate|7.2|13|Denied|5|src=10.1.1.5"
    parsed = CefParser().parse(raw)

    assert parsed.fields["device_vendor"] == "Fortinet"
    assert parsed.fields["src"] == "10.1.1.5"


def test_cef_rejects_truncated_header() -> None:
    with pytest.raises(ParserError, match="expected at least 8"):
        CefParser().parse(b"CEF:0|Vendor|Product|1.0")


# ---------------------------------------------------------------------------
# LEEF
# ---------------------------------------------------------------------------


def test_leef_1_0_parses_tab_delimited_attributes() -> None:
    raw = b"LEEF:1.0|Lancope|StealthWatch|1.0|41|src=10.1.1.5\tdst=8.8.8.8\tsev=5"
    parsed = LeefParser().parse(raw)

    assert parsed.fields["device_vendor"] == "Lancope"
    assert parsed.fields["event_id"] == "41"
    assert parsed.fields["src"] == "10.1.1.5"
    assert parsed.fields["sev"] == "5"


def test_leef_2_0_honors_declared_delimiter() -> None:
    raw = b"LEEF:2.0|Vendor|Product|1.0|4321|^|src=10.1.1.5^dst=8.8.8.8^action=block"
    parsed = LeefParser().parse(raw)

    assert parsed.fields["src"] == "10.1.1.5"
    assert parsed.fields["action"] == "block"


def test_leef_rejects_truncated_header() -> None:
    with pytest.raises(ParserError, match="expected at least 6"):
        LeefParser().parse(b"LEEF:1.0|Vendor|Product")


# ---------------------------------------------------------------------------
# Windows Event XML
# ---------------------------------------------------------------------------

_WINDOWS_4625 = b"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-09-12T05:14:15.123456Z"/>
    <Computer>WKSTN-042</Computer>
    <Execution ProcessID="600" ThreadID="900"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="IpAddress">10.1.1.5</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>"""


def test_windows_xml_extracts_system_and_event_data() -> None:
    parsed = WindowsEventXmlParser().parse(_WINDOWS_4625)

    assert parsed.fields["event_id"] == 4625
    assert parsed.fields["computer"] == "WKSTN-042"
    assert parsed.fields["provider_name"] == "Microsoft-Windows-Security-Auditing"
    assert parsed.fields["time_created"] == "2026-09-12T05:14:15.123456Z"
    assert parsed.fields["process_id"] == 600
    assert parsed.fields["event_data.TargetUserName"] == "alice"
    assert parsed.fields["event_data.IpAddress"] == "10.1.1.5"


def test_windows_xml_rejects_malformed_document() -> None:
    with pytest.raises(ParserError, match="invalid Windows Event XML"):
        WindowsEventXmlParser().parse(b"<Event><System><EventID>4625</System></Event>")


def test_windows_xml_refuses_xxe_external_entity() -> None:
    """XXE would turn the SIEM into a file-read/SSRF oracle for anyone who
    can get a log line ingested (THREAT_MODEL.md §3.8). defusedxml must
    refuse the entity declaration outright — and the refusal must surface as
    a normal parse failure, not a crash."""
    xxe = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE Event [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        b"<Event><System><Computer>&xxe;</Computer></System></Event>"
    )
    with pytest.raises(ParserError):
        WindowsEventXmlParser().parse(xxe)


def test_windows_xml_refuses_billion_laughs_expansion() -> None:
    bomb = (
        b'<?xml version="1.0"?>'
        b"<!DOCTYPE lolz ["
        b'<!ENTITY lol "lol">'
        b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        b"]>"
        b"<Event><System><Computer>&lol3;</Computer></System></Event>"
    )
    with pytest.raises(ParserError):
        WindowsEventXmlParser().parse(bomb)


# ---------------------------------------------------------------------------
# Web access logs
# ---------------------------------------------------------------------------


def test_web_access_parses_combined_log_format() -> None:
    raw = (
        b'10.1.1.5 - alice [12/Sep/2026:05:14:15 +0000] "GET /admin/login HTTP/1.1" 401 512 '
        b'"https://example.test/" "Mozilla/5.0"'
    )
    parsed = WebAccessLogParser().parse(raw)

    assert parsed.fields["remote_host"] == "10.1.1.5"
    assert parsed.fields["user"] == "alice"
    assert parsed.fields["http_method"] == "GET"
    assert parsed.fields["url_path"] == "/admin/login"
    assert parsed.fields["status"] == 401
    assert parsed.fields["user_agent"] == "Mozilla/5.0"


def test_web_access_parses_common_log_format_without_referer() -> None:
    raw = b'10.1.1.5 - - [12/Sep/2026:05:14:15 +0000] "POST /api HTTP/1.1" 200 -'
    parsed = WebAccessLogParser().parse(raw)

    assert parsed.fields["user"] is None
    assert parsed.fields["bytes_sent"] is None
    assert parsed.fields["status"] == 200


def test_web_access_rejects_non_access_log_line() -> None:
    with pytest.raises(ParserError, match="Common or Combined"):
        WebAccessLogParser().parse(b"this is not an access log line")


# ---------------------------------------------------------------------------
# Key-value
# ---------------------------------------------------------------------------


def test_keyvalue_parses_quoted_and_bare_values() -> None:
    raw = b'date=2026-09-12 devname="fw 01" srcip=10.1.1.5 action=deny'
    parsed = KeyValueParser().parse(raw)

    assert parsed.fields["devname"] == "fw 01"
    assert parsed.fields["srcip"] == "10.1.1.5"
    assert parsed.fields["action"] == "deny"


def test_keyvalue_rejects_prose_without_enough_pairs() -> None:
    with pytest.raises(ParserError, match="key=value pairs"):
        KeyValueParser().parse(b"the system is fine, nothing to see here")


# ---------------------------------------------------------------------------
# Registry: format detection and ordering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "expected_format"),
    [
        (b'{"action": "login"}', "json"),
        (b"CEF:0|V|P|1.0|1|Name|3|src=1.2.3.4", "cef"),
        (b"LEEF:1.0|V|P|1.0|1|src=1.2.3.4\tdst=8.8.8.8", "leef"),
        (_WINDOWS_4625, "windows_event_xml"),
        (
            b'10.1.1.5 - - [12/Sep/2026:05:14:15 +0000] "GET / HTTP/1.1" 200 12',
            "web_access",
        ),
        (b"<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password", "syslog"),
        (b"date=2026-09-12 srcip=10.1.1.5 action=deny", "keyvalue"),
    ],
)
def test_registry_detects_each_format(payload: bytes, expected_format: str) -> None:
    assert ParserRegistry().parse(payload).format_name == expected_format


def test_registry_prefers_cef_over_syslog_and_keyvalue_for_wrapped_payload() -> None:
    """A Fortinet CEF event is simultaneously valid syslog and full of
    key=value pairs. Detection order must pick the parser that actually
    extracts the vendor/signature/severity a detection rule needs."""
    raw = b"<134>Sep 12 05:14:15 fw01 CEF:0|Fortinet|FortiGate|7.2|13|Denied|5|src=10.1.1.5"
    parsed = ParserRegistry().parse(raw)

    assert parsed.format_name == "cef"
    assert parsed.fields["device_vendor"] == "Fortinet"


def test_registry_rejects_unrecognizable_payload_rather_than_storing_a_blob() -> None:
    """Silently keeping an unparsed blob would be a detection gap: indexed,
    searchable by nobody, matched by no rule."""
    with pytest.raises(ParserError):
        ParserRegistry().parse(b"\x00\x01\x02 not a log line at all \xff")


def test_registry_rejects_empty_payload() -> None:
    with pytest.raises(ParserError, match="empty payload"):
        ParserRegistry().parse(b"   ")


def test_registry_never_raises_unexpected_exception_types() -> None:
    """Fuzz-ish sweep: whatever the input, the registry's only failure mode
    is ParserError. A worker relies on that to stay alive."""
    payloads = [
        b"",
        b"\x00" * 100,
        b"{" * 500,
        b"<Event" + b"x" * 1000,
        b"CEF:0|" + b"|" * 50,
        b"LEEF:2.0|" + b"^" * 50,
        b"<34>" + b"\xff" * 200,
        "héllo wörld unicode".encode("latin-1"),
    ]
    registry = ParserRegistry()
    for payload in payloads:
        try:
            registry.parse(payload)
        except ParserError:
            pass  # the only acceptable failure
