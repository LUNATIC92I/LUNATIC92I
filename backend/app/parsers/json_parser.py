import json
from typing import Any, ClassVar

from app.parsers.base import ParsedEvent, Parser, ParserError, decode_utf8


class JsonParser(Parser):
    """Structured JSON events — the native format of most cloud and EDR
    sources (M365, AWS CloudTrail, Defender, ...)."""

    format_name: ClassVar[str] = "json"
    priority: ClassVar[int] = 10

    def can_parse(self, raw: bytes) -> bool:
        stripped = raw.lstrip()
        return stripped.startswith(b"{") or stripped.startswith(b"[")

    def parse(self, raw: bytes) -> ParsedEvent:
        try:
            document = json.loads(decode_utf8(raw))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ParserError(f"invalid JSON: {exc}") from exc

        if isinstance(document, list):
            # A JSON array is a batch, not an event. Splitting it here would
            # break the one-payload-one-event contract the pipeline (and
            # deduplication) relies on, so it is rejected rather than
            # silently collapsed into the first element.
            raise ParserError("JSON arrays are not single events; send one event per payload")
        if not isinstance(document, dict):
            raise ParserError(f"expected a JSON object, got {type(document).__name__}")

        return ParsedEvent(format_name=self.format_name, fields=_flatten(document))


def _flatten(document: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flattens nested objects to dotted keys (`user.name`) so the OCSF
    mapper can address deep fields uniformly. Lists are left intact — their
    order and contents are meaningful and flattening them by index would
    invent field names that vary event to event."""
    flat: dict[str, Any] = {}
    for key, value in document.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, prefix=f"{path}."))
        else:
            flat[path] = value
    return flat
