"""Format detection: pick the right parser for a payload, or fail cleanly.

Detection is ordered by each parser's `priority` (low first), because the
formats overlap. A Fortinet CEF event arrives wrapped in a syslog envelope
and is also full of `key=value` pairs — all three parsers would "match" it,
but only the CEF parser extracts the vendor, signature and severity that
detection rules need. Ordering encodes "most specific wins" explicitly
rather than leaving it to dict iteration order.

A payload that no parser claims, or that every candidate rejects, raises
`ParserError`. It is never quietly stored as an unparsed blob: that would
be a silent detection gap, where events land in the index but no rule can
ever match them.
"""

import logging

from app.parsers.base import ParsedEvent, Parser, ParserError
from app.parsers.cef import CefParser
from app.parsers.json_parser import JsonParser
from app.parsers.keyvalue import KeyValueParser
from app.parsers.leef import LeefParser
from app.parsers.syslog import SyslogParser
from app.parsers.web import WebAccessLogParser
from app.parsers.windows_xml import WindowsEventXmlParser

logger = logging.getLogger(__name__)

DEFAULT_PARSERS: tuple[Parser, ...] = (
    JsonParser(),
    CefParser(),
    LeefParser(),
    WindowsEventXmlParser(),
    WebAccessLogParser(),
    SyslogParser(),
    KeyValueParser(),
)


class ParserRegistry:
    def __init__(self, parsers: tuple[Parser, ...] = DEFAULT_PARSERS) -> None:
        self._parsers = tuple(sorted(parsers, key=lambda parser: parser.priority))

    @property
    def formats(self) -> tuple[str, ...]:
        return tuple(parser.format_name for parser in self._parsers)

    def parse(self, raw: bytes) -> ParsedEvent:
        if not raw.strip():
            raise ParserError("empty payload")

        attempted: list[str] = []
        for parser in self._parsers:
            try:
                if not parser.can_parse(raw):
                    continue
            except Exception as exc:  # noqa: BLE001
                # A detector that throws is a bug in that parser, not a
                # reason to abandon the event — try the remaining ones.
                logger.exception(
                    "parser detection raised", extra={"format": parser.format_name}
                )
                attempted.append(f"{parser.format_name} (detection error: {exc})")
                continue

            try:
                return parser.parse(raw)
            except ParserError as exc:
                # Claimed it but could not parse it: fall through to the
                # next candidate rather than dead-lettering immediately.
                attempted.append(f"{parser.format_name} ({exc})")
            except Exception as exc:  # noqa: BLE001
                logger.exception("parser crashed", extra={"format": parser.format_name})
                attempted.append(f"{parser.format_name} (crashed: {type(exc).__name__}: {exc})")

        if attempted:
            raise ParserError("no parser could handle payload; tried: " + "; ".join(attempted))
        raise ParserError("no parser recognized this payload format")
