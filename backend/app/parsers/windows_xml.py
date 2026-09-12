"""Windows Event Log XML (the `<Event>` documents `wevtutil`/WEF emit).

Security note: this parser handles attacker-influenced XML from endpoints,
so it uses `defusedxml`, which refuses DTDs, entity declarations and
external references outright. The classic attacks it blocks are XXE (an
entity pointing at `file:///etc/passwd` or an internal URL, turning the SIEM
into an SSRF/file-read oracle) and billion-laughs entity expansion. This is
not defense-in-depth garnish — it is the reason this module does not import
`xml.etree` at all (THREAT_MODEL.md §3.8).
"""

from typing import Any, ClassVar

# Imported for type annotations only — every actual parse in this module
# goes through defusedxml.fromstring below, and the XXE / billion-laughs
# tests in app/tests/test_parsers.py are what hold that claim honest.
from xml.etree.ElementTree import Element  # noqa: S405  # nosec B405

from defusedxml.ElementTree import ParseError as DefusedParseError
from defusedxml.ElementTree import fromstring as safe_fromstring

from app.parsers.base import ParsedEvent, Parser, ParserError, decode_utf8

_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


class WindowsEventXmlParser(Parser):
    format_name: ClassVar[str] = "windows_event_xml"
    priority: ClassVar[int] = 30

    def can_parse(self, raw: bytes) -> bool:
        head = raw.lstrip()[:512].lower()
        return head.startswith(b"<") and b"<event" in head

    def parse(self, raw: bytes) -> ParsedEvent:
        try:
            root = safe_fromstring(decode_utf8(raw))
        except DefusedParseError as exc:
            raise ParserError(f"invalid Windows Event XML: {exc}") from exc
        except Exception as exc:  # noqa: BLE001  defusedxml raises its own refusal types
            # A refused DTD/entity lands here. It is a parse failure, not a
            # crash: the event is dead-lettered with the reason intact.
            raise ParserError(f"refused unsafe XML construct: {type(exc).__name__}: {exc}") from exc

        if _localname(root.tag) != "Event":
            raise ParserError(f"root element is <{_localname(root.tag)}>, expected <Event>")

        fields: dict[str, Any] = {}
        system = _find_child(root, "System")
        if system is not None:
            fields.update(_parse_system(system))

        event_data = _find_child(root, "EventData")
        if event_data is not None:
            fields.update(_parse_event_data(event_data))

        if not fields:
            raise ParserError("Windows Event XML contained neither System nor EventData")

        return ParsedEvent(format_name=self.format_name, fields=fields)


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_child(parent: Element, name: str) -> Element | None:
    """Namespaced first, then bare. Must compare against None explicitly: an
    Element with no children is falsy, so `find(a) or find(b)` would skip a
    present-but-empty element (and raises outright in future Python)."""
    child = parent.find(f"{_EVENT_NS}{name}")
    if child is None:
        child = parent.find(name)
    return child


def _parse_system(system: Element) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for child in system:
        name = _localname(child.tag)
        if name == "Provider":
            fields["provider_name"] = child.get("Name")
            fields["provider_guid"] = child.get("Guid")
        elif name == "TimeCreated":
            fields["time_created"] = child.get("SystemTime")
        elif name == "Execution":
            fields["process_id"] = _to_int(child.get("ProcessID"))
            fields["thread_id"] = _to_int(child.get("ThreadID"))
        elif name == "Security":
            fields["security_user_id"] = child.get("UserID")
        elif name == "EventID":
            fields["event_id"] = _to_int((child.text or "").strip())
        elif name in ("Level", "Task", "Opcode", "Version"):
            fields[_snake(name)] = _to_int((child.text or "").strip())
        elif child.text and child.text.strip():
            fields[_snake(name)] = child.text.strip()
    return fields


def _parse_event_data(event_data: Element) -> dict[str, Any]:
    """`<Data Name="TargetUserName">alice</Data>` is the normal shape;
    unnamed `<Data>` elements (some providers) are collected positionally so
    their content is not lost."""
    fields: dict[str, Any] = {}
    unnamed: list[str] = []
    for child in event_data:
        if _localname(child.tag) != "Data":
            continue
        value = (child.text or "").strip()
        name = child.get("Name")
        if name:
            fields[f"event_data.{name}"] = value
        elif value:
            unnamed.append(value)
    if unnamed:
        fields["event_data.unnamed"] = unnamed
    return fields


def _snake(name: str) -> str:
    out: list[str] = []
    for index, char in enumerate(name):
        if char.isupper() and index > 0 and not name[index - 1].isupper():
            out.append("_")
        out.append(char.lower())
    return "".join(out)


def _to_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError:
        return None
