"""The common parser interface (spec §6).

A parser's only job is to turn raw bytes into a flat dict of extracted
fields. It does not normalize to OCSF (that is `app/normalization`), does
not enrich, and does not decide whether an event is interesting. Keeping
parsing this narrow is what lets a new log format be added without touching
anything downstream.

Hard rules every parser obeys:

- **Never execute input.** No `eval`, no `pickle`, no format string
  interpolation of payload content, no shelling out. A SIEM parses hostile
  input by definition — a parser that can be made to execute is a remote
  code execution path straight into the security platform
  (THREAT_MODEL.md §3.1).
- **Fail loudly, never silently.** A parser that cannot handle a payload
  raises `ParserError`; it never returns a half-filled dict or swallows the
  problem. The caller dead-letters it, which is how spec §6's "never lose an
  event" is honored.
- **Never mutate the raw payload.** The original bytes are the forensic
  record (spec §4).
"""

import abc
from dataclasses import dataclass, field
from typing import Any, ClassVar


class ParserError(Exception):
    """Raised when a parser cannot extract fields from a payload. Carries a
    human-readable reason that travels with the dead-lettered event."""


@dataclass(frozen=True)
class ParsedEvent:
    """Format-specific fields extracted from one raw payload.

    `fields` is intentionally a loose dict: every format has its own
    vocabulary, and forcing a common shape here would push guesswork into
    the parsers. Reconciling those vocabularies is exactly what the OCSF
    normalization step exists to do.
    """

    format_name: str
    fields: dict[str, Any] = field(default_factory=dict)


class Parser(abc.ABC):
    format_name: ClassVar[str]

    # Lower runs first. Formats with a distinctive, unambiguous signature
    # (CEF's "CEF:0|", a leading "<" for XML) claim payloads before looser
    # ones like generic syslog, which would otherwise match almost anything.
    priority: ClassVar[int] = 100

    @abc.abstractmethod
    def can_parse(self, raw: bytes) -> bool:
        """Cheap structural check — no full parse, no exceptions. Used only
        to choose a candidate; `parse()` is still allowed to reject."""

    @abc.abstractmethod
    def parse(self, raw: bytes) -> ParsedEvent:
        """Extracts fields, or raises `ParserError` with a reason."""


def decode_utf8(raw: bytes) -> str:
    """Log sources emit imperfect encodings constantly. Replacing undecodable
    bytes rather than raising keeps a mostly-readable event flowing instead
    of dead-lettering it over one bad character — and the pristine bytes are
    still retained on the event as `raw_event` for forensics."""
    return raw.decode("utf-8", errors="replace")
