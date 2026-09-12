"""Generic ``key=value`` logs — the shape most firewalls (Fortinet, pfSense,
Palo Alto's LEEF-less output) and many auth/VPN appliances emit:

    date=2026-09-12 time=05:22:01 devname="fw01" srcip=10.1.1.5 action=deny

This is the deliberate catch-all of the parser set and runs last: it will
match almost anything containing an ``=``, so it must never get the chance
to claim a payload a structured parser could have handled properly.
"""

import re
from typing import Any, ClassVar

from app.parsers.base import ParsedEvent, Parser, ParserError, decode_utf8

# key=value where the value is either "quoted, possibly spaced" or bare.
_PAIR = re.compile(r'([A-Za-z_][A-Za-z0-9_.\-]*)=(?:"([^"]*)"|([^\s]*))')

_MIN_PAIRS = 2


class KeyValueParser(Parser):
    format_name: ClassVar[str] = "keyvalue"
    priority: ClassVar[int] = 90

    def can_parse(self, raw: bytes) -> bool:
        return len(_PAIR.findall(decode_utf8(raw[:2048]))) >= _MIN_PAIRS

    def parse(self, raw: bytes) -> ParsedEvent:
        text = decode_utf8(raw).strip()
        matches = _PAIR.findall(text)
        if len(matches) < _MIN_PAIRS:
            raise ParserError(
                f"found {len(matches)} key=value pairs, need at least {_MIN_PAIRS} "
                "to treat this as a key-value log"
            )

        fields: dict[str, Any] = {}
        for key, quoted, bare in matches:
            fields[key] = quoted if quoted != "" else bare
        return ParsedEvent(format_name=self.format_name, fields=fields)
