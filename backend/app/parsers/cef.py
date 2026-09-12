"""ArcSight Common Event Format (CEF), emitted by most firewall, IPS and
appliance vendors.

    CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value ...

The two things that make CEF fiddly are both handled here: pipes inside
header fields are backslash-escaped, and the extension is space-separated
key=value pairs where *values* may contain spaces (a key is only a key if
it is followed by `=`).
"""

import re
from typing import ClassVar

from app.parsers.base import ParsedEvent, Parser, ParserError, decode_utf8

_CEF_PREFIX = re.compile(rb"CEF:\s*\d+\|")
_HEADER_FIELDS = (
    "cef_version",
    "device_vendor",
    "device_product",
    "device_version",
    "signature_id",
    "name",
    "severity",
)
# A key=value boundary: a run of non-space, non-equals characters that is
# immediately followed by '='. Splitting on this instead of on spaces is what
# keeps values containing spaces intact.
_EXTENSION_KEY = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_.\-]*)=")


class CefParser(Parser):
    format_name: ClassVar[str] = "cef"
    priority: ClassVar[int] = 20

    def can_parse(self, raw: bytes) -> bool:
        return _CEF_PREFIX.search(raw[:200]) is not None

    def parse(self, raw: bytes) -> ParsedEvent:
        text = decode_utf8(raw)
        start = text.find("CEF:")
        if start == -1:
            raise ParserError("no CEF header found")
        # Anything before "CEF:" is a syslog envelope the appliance added.
        text = text[start:]

        segments = _split_unescaped(text, "|")
        if len(segments) < 8:
            raise ParserError(f"CEF header has {len(segments)} segments, expected at least 8")

        version = segments[0].removeprefix("CEF:").strip()
        fields: dict[str, object] = {"cef_version": version}
        for name, value in zip(_HEADER_FIELDS[1:], segments[1:7], strict=True):
            fields[name] = _unescape(value)

        extension = "|".join(segments[7:])  # unescaped pipes belong to the extension
        fields.update(_parse_extension(extension))
        return ParsedEvent(format_name=self.format_name, fields=fields)


def _split_unescaped(text: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == delimiter:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _unescape(value: str) -> str:
    return value.replace("\\|", "|").replace("\\=", "=").replace("\\\\", "\\").strip()


def _parse_extension(extension: str) -> dict[str, str]:
    matches = list(_EXTENSION_KEY.finditer(extension))
    fields: dict[str, str] = {}
    for index, match in enumerate(matches):
        key = match.group(1)
        value_start = match.end()
        value_end = matches[index + 1].start() if index + 1 < len(matches) else len(extension)
        fields[key] = _unescape(extension[value_start:value_end])
    return fields
