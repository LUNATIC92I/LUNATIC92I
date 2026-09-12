"""IBM QRadar Log Event Extended Format (LEEF).

    LEEF:1.0|Vendor|Product|Version|EventID|key=value<TAB>key=value
    LEEF:2.0|Vendor|Product|Version|EventID|^|key=value^key=value

LEEF 2.0 may declare its own attribute delimiter as a sixth header field,
which is why the header length differs between versions.
"""

import re
from typing import ClassVar

from app.parsers.base import ParsedEvent, Parser, ParserError, decode_utf8

_LEEF_PREFIX = re.compile(rb"LEEF:\s*\d+\.\d+\|")
_DEFAULT_DELIMITER = "\t"


class LeefParser(Parser):
    format_name: ClassVar[str] = "leef"
    priority: ClassVar[int] = 20

    def can_parse(self, raw: bytes) -> bool:
        return _LEEF_PREFIX.search(raw[:200]) is not None

    def parse(self, raw: bytes) -> ParsedEvent:
        text = decode_utf8(raw)
        start = text.find("LEEF:")
        if start == -1:
            raise ParserError("no LEEF header found")
        text = text[start:]

        segments = text.split("|")
        if len(segments) < 6:
            raise ParserError(f"LEEF header has {len(segments)} segments, expected at least 6")

        version = segments[0].removeprefix("LEEF:").strip()
        fields: dict[str, object] = {
            "leef_version": version,
            "device_vendor": segments[1].strip(),
            "device_product": segments[2].strip(),
            "device_version": segments[3].strip(),
            "event_id": segments[4].strip(),
        }

        delimiter = _DEFAULT_DELIMITER
        attribute_index = 5
        if version.startswith("2") and len(segments) >= 7:
            declared = segments[5].strip()
            if declared:
                delimiter = _resolve_delimiter(declared)
                attribute_index = 6

        attributes = "|".join(segments[attribute_index:])
        for pair in attributes.split(delimiter):
            key, separator, value = pair.partition("=")
            if separator and key.strip():
                fields[key.strip()] = value.strip()

        return ParsedEvent(format_name=self.format_name, fields=fields)


def _resolve_delimiter(declared: str) -> str:
    """LEEF 2.0 allows the delimiter to be given literally ("^") or as a hex
    escape ("x09"/"0x09")."""
    lowered = declared.lower()
    for prefix in ("0x", "x"):
        if lowered.startswith(prefix):
            try:
                return chr(int(lowered[len(prefix) :], 16))
            except ValueError:
                break
    return declared[0]
