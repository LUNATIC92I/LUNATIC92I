"""Syslog, both wire formats that appear in practice:

- **RFC 5424** (modern): ``<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG``
- **RFC 3164** (BSD, still everywhere): ``<PRI>MMM dd HH:mm:ss HOST TAG: MSG``

The priority value encodes facility and severity (``PRI = facility*8 +
severity``), which the OCSF mapper uses for event severity, so both are
decoded here rather than left for downstream guessing.

RFC 3164 timestamps carry no year and no timezone. Rather than invent one,
the parser records what the source actually said in `timestamp_raw` and
leaves assigning a real instant to normalization, which has the ingestion
time available as context.
"""

import re
from typing import ClassVar

from app.parsers.base import ParsedEvent, Parser, ParserError, decode_utf8

_PRI = re.compile(r"^<(\d{1,3})>")

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2})\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<proc_id>\S+)\s+"
    r"(?P<msg_id>\S+)\s+"
    r"(?P<rest>.*)$",
    re.DOTALL,
)

_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<rest>.*)$",
    re.DOTALL,
)

# "sshd[1234]: message" or "sudo: message"
_TAG = re.compile(
    r"^(?P<app_name>[^\s:\[]+)(?:\[(?P<proc_id>\d+)\])?:\s*(?P<message>.*)$", re.DOTALL
)

_FACILITIES = (
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
)
_SEVERITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")


class SyslogParser(Parser):
    format_name: ClassVar[str] = "syslog"
    # Runs late: a bare "<13>..." prefix also fronts CEF and LEEF payloads
    # from appliances, and those parsers extract far more.
    priority: ClassVar[int] = 80

    def can_parse(self, raw: bytes) -> bool:
        return _PRI.match(decode_utf8(raw[:8])) is not None

    def parse(self, raw: bytes) -> ParsedEvent:
        text = decode_utf8(raw).strip()

        match = _RFC5424.match(text)
        if match is not None:
            return ParsedEvent(self.format_name, self._parse_5424(match))

        match = _RFC3164.match(text)
        if match is not None:
            return ParsedEvent(self.format_name, self._parse_3164(match))

        raise ParserError("does not match RFC 5424 or RFC 3164 syslog structure")

    def _parse_5424(self, match: re.Match[str]) -> dict[str, object]:
        fields = _decode_priority(int(match.group("pri")))
        fields.update(
            {
                "syslog_version": int(match.group("version")),
                "timestamp_raw": match.group("timestamp"),
                "hostname": _nil(match.group("hostname")),
                "app_name": _nil(match.group("app_name")),
                "proc_id": _nil(match.group("proc_id")),
                "msg_id": _nil(match.group("msg_id")),
            }
        )
        structured_data, message = _split_structured_data(match.group("rest"))
        if structured_data is not None:
            fields["structured_data"] = structured_data
        fields["message"] = message.strip()
        return fields

    def _parse_3164(self, match: re.Match[str]) -> dict[str, object]:
        fields = _decode_priority(int(match.group("pri")))
        fields.update(
            {
                "timestamp_raw": match.group("timestamp"),
                "hostname": match.group("hostname"),
            }
        )
        rest = match.group("rest")
        tag_match = _TAG.match(rest)
        if tag_match is not None:
            fields["app_name"] = tag_match.group("app_name")
            if tag_match.group("proc_id"):
                fields["proc_id"] = tag_match.group("proc_id")
            fields["message"] = tag_match.group("message").strip()
        else:
            fields["message"] = rest.strip()
        return fields


def _nil(value: str) -> str | None:
    """RFC 5424 writes an absent value as "-"."""
    return None if value == "-" else value


def _decode_priority(pri: int) -> dict[str, object]:
    facility_index, severity_index = divmod(pri, 8)
    return {
        "priority": pri,
        "facility": facility_index,
        "facility_label": (
            _FACILITIES[facility_index] if facility_index < len(_FACILITIES) else None
        ),
        "severity": severity_index,
        "severity_label": (
            _SEVERITIES[severity_index] if severity_index < len(_SEVERITIES) else None
        ),
    }


def _split_structured_data(rest: str) -> tuple[str | None, str]:
    rest = rest.strip()
    if rest.startswith("-"):
        return None, rest[1:]
    if not rest.startswith("["):
        return None, rest

    depth = 0
    escaped = False
    for index, char in enumerate(rest):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return rest[: index + 1], rest[index + 1 :]
    # Unbalanced brackets: treat the whole remainder as the message rather
    # than dropping it — a truncated event still carries evidence.
    return None, rest
