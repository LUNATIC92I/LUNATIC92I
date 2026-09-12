"""Apache/Nginx access logs in Common and Combined Log Format.

    127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326
    ... plus "referer" "user-agent"   <- Combined

Both servers emit the same two shapes by default, so one parser covers them;
`format_name` stays "web_access" rather than guessing which daemon produced
a line that is byte-identical either way.
"""

import re
from typing import ClassVar

from app.parsers.base import ParsedEvent, Parser, ParserError, decode_utf8

_ACCESS_LOG = re.compile(
    r"^(?P<remote_host>\S+)\s+"
    r"(?P<identity>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<bytes_sent>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r"\s*$"
)

_REQUEST = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<protocol>HTTP/[\d.]+))?$")


class WebAccessLogParser(Parser):
    format_name: ClassVar[str] = "web_access"
    priority: ClassVar[int] = 40

    def can_parse(self, raw: bytes) -> bool:
        return _ACCESS_LOG.match(decode_utf8(raw).strip()) is not None

    def parse(self, raw: bytes) -> ParsedEvent:
        match = _ACCESS_LOG.match(decode_utf8(raw).strip())
        if match is None:
            raise ParserError("does not match Common or Combined Log Format")

        fields: dict[str, object] = {
            "remote_host": match.group("remote_host"),
            "user": _dash_to_none(match.group("user")),
            "timestamp_raw": match.group("timestamp"),
            "request": match.group("request"),
            "status": int(match.group("status")),
            "bytes_sent": _int_or_none(match.group("bytes_sent")),
        }

        request_match = _REQUEST.match(match.group("request"))
        if request_match is not None:
            fields["http_method"] = request_match.group("method")
            fields["url_path"] = request_match.group("path")
            fields["http_protocol"] = request_match.group("protocol")

        if match.group("referer") is not None:
            fields["referer"] = _dash_to_none(match.group("referer"))
            fields["user_agent"] = _dash_to_none(match.group("user_agent"))

        return ParsedEvent(format_name=self.format_name, fields=fields)


def _dash_to_none(value: str | None) -> str | None:
    return None if value in (None, "-", "") else value


def _int_or_none(value: str) -> int | None:
    return None if value == "-" else int(value)
