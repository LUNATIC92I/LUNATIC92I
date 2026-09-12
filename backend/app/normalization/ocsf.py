"""OCSF 1.1.0 normalization (spec §4, ARCHITECTURE.md §1 row 6).

Turns a `ParsedEvent` (format-specific vocabulary) into the single document
shape the whole platform queries, whose mapping is defined in
`docs/database/opensearch_indices.md`. Two things travel together in that
document and neither is optional:

- the **OCSF object** (`normalized_event`), which is the interoperable,
  schema-versioned representation, and
- **flat projections** (`source_ip`, `user.name`, `process.name`, ...),
  which are what actually gets indexed and searched. They are *derived from*
  the OCSF object, not a second hand-maintained schema — that duplication
  was called out as a spec inconsistency in Phase 0 and resolved this way.

`raw_event` is always carried through untouched. An event whose fields we
mapped badly is recoverable; an event whose original bytes we discarded is
not (spec §4).
"""

import ipaddress
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from app.parsers.base import ParsedEvent

OCSF_VERSION = "1.1.0"
SCHEMA_VERSION = "lunatic-1"

# OCSF class_uid values used so far. The mapper deliberately covers a small,
# honest subset and falls back to Base Event rather than forcing every log
# into a class it does not belong to — a wrong class is worse than an
# unclassified one, because detection rules key off it.
CLASS_BASE_EVENT = 0
CLASS_FILE_ACTIVITY = 1001
CLASS_PROCESS_ACTIVITY = 1007
CLASS_AUTHENTICATION = 3002
CLASS_NETWORK_ACTIVITY = 4001
CLASS_HTTP_ACTIVITY = 4002

_CLASS_NAMES = {
    CLASS_BASE_EVENT: "Base Event",
    CLASS_FILE_ACTIVITY: "File System Activity",
    CLASS_PROCESS_ACTIVITY: "Process Activity",
    CLASS_AUTHENTICATION: "Authentication",
    CLASS_NETWORK_ACTIVITY: "Network Activity",
    CLASS_HTTP_ACTIVITY: "HTTP Activity",
}

# OCSF category_uid per class.
_CLASS_CATEGORY = {
    CLASS_BASE_EVENT: (0, "Uncategorized"),
    CLASS_FILE_ACTIVITY: (1, "System Activity"),
    CLASS_PROCESS_ACTIVITY: (1, "System Activity"),
    CLASS_AUTHENTICATION: (3, "Identity & Access Management"),
    CLASS_NETWORK_ACTIVITY: (4, "Network Activity"),
    CLASS_HTTP_ACTIVITY: (4, "Network Activity"),
}

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")

# Windows security event ids that are unambiguously authentication.
_WINDOWS_AUTH_EVENT_IDS = {4624, 4625, 4634, 4647, 4648, 4768, 4769, 4771, 4776}
_WINDOWS_PROCESS_EVENT_IDS = {1, 4688}

_SSH_FAILURE = re.compile(
    r"Failed (?:password|publickey) for(?: invalid user)? (?P<user>\S+)", re.I
)
_SSH_SUCCESS = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+)", re.I)
_FROM_IP = re.compile(r"\bfrom\s+(?P<ip>[0-9a-fA-F:.]+)")
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")


class NormalizationError(Exception):
    """Raised only when an event cannot be represented at all. Missing or
    unmappable *fields* are never an error: they are simply absent, and the
    raw event is still carried."""


def normalize(
    *,
    parsed: ParsedEvent,
    tenant_id: str,
    raw_payload: bytes,
    source_type: str,
    collector_id: str,
    received_at: datetime,
    source_ip: str | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    """Builds the indexable document. Shape must stay in sync with
    `docs/database/opensearch_indices.md`; `app/tests/test_normalization.py`
    asserts that it does."""
    fields = parsed.fields
    class_uid = _classify(parsed)
    category_uid, category_name = _CLASS_CATEGORY[class_uid]

    user = _extract_user(parsed)
    device = _extract_device(parsed)
    process = _extract_process(parsed)
    network = _extract_network(parsed)
    http = _extract_http(parsed)
    auth = _extract_authentication(parsed, class_uid)
    file_info = _extract_file(parsed)
    hashes = _extract_hashes(parsed)
    severity = _extract_severity(parsed)
    timestamp = _extract_timestamp(parsed, fallback=received_at)

    normalized_event = {
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "LUNATIC-IT SIEM", "vendor_name": "Lunatic-IT"},
            "original_time": fields.get("timestamp_raw"),
            "log_provider": fields.get("provider_name") or source_type,
        },
        "class_uid": class_uid,
        "class_name": _CLASS_NAMES[class_uid],
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_name": _activity_name(parsed, class_uid),
        "severity": severity,
        "time": int(timestamp.timestamp() * 1000),
        "actor": {"user": user} if user else {},
        "device": device,
        "process": process,
        "network": network,
        "http_request": http,
        "authentication": auth,
        "file": file_info,
        "unmapped": _unmapped(parsed),
    }

    document: dict[str, Any] = {
        "event_id": event_id or str(uuid.uuid4()),
        "timestamp": timestamp.isoformat(),
        "ingestion_timestamp": datetime.now(UTC).isoformat(),
        "tenant_id": tenant_id,
        "source": collector_id,
        "source_type": source_type,
        "category": category_name,
        "class": _CLASS_NAMES[class_uid],
        "severity": severity,
        "activity": _activity_name(parsed, class_uid),
        "actor": {"user": user.get("name")} if user else {},
        "user": user,
        "device": device,
        "source_ip": network.get("src_ip") or source_ip,
        "destination_ip": network.get("dst_ip"),
        "source_port": network.get("src_port"),
        "destination_port": network.get("dst_port"),
        "protocol": network.get("protocol"),
        "hostname": device.get("hostname"),
        "process": process,
        "command_line": process.get("cmd_line"),
        "file": file_info,
        "hash": hashes,
        "domain": http.get("domain") or _first_str(fields, ("domain", "dns_query", "query")),
        "url": http.get("url"),
        "cloud": _extract_cloud(parsed),
        "authentication": auth,
        "mitre_techniques": [],  # populated by the detection engine (Phase 6)
        "ioc_matches": [],  # populated by enrichment (Phase 5)
        "enrichment_partial": False,
        "schema_version": SCHEMA_VERSION,
        "raw_event": raw_payload.decode("utf-8", errors="replace"),
        "normalized_event": normalized_event,
    }
    return _drop_empty(document)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _classify(parsed: ParsedEvent) -> int:
    fields = parsed.fields

    if parsed.format_name == "web_access":
        return CLASS_HTTP_ACTIVITY

    if parsed.format_name == "windows_event_xml":
        event_id = fields.get("event_id")
        if event_id in _WINDOWS_AUTH_EVENT_IDS:
            return CLASS_AUTHENTICATION
        if event_id in _WINDOWS_PROCESS_EVENT_IDS:
            return CLASS_PROCESS_ACTIVITY
        return CLASS_BASE_EVENT

    message = str(fields.get("message") or "")
    app_name = str(fields.get("app_name") or "").lower()
    if (
        app_name in ("sshd", "sudo", "su", "login")
        or _SSH_FAILURE.search(message)
        or _SSH_SUCCESS.search(message)
    ):
        return CLASS_AUTHENTICATION

    if _first_str(fields, ("src", "srcip", "src_ip", "source_ip")) and _first_str(
        fields, ("dst", "dstip", "dst_ip", "destination_ip")
    ):
        return CLASS_NETWORK_ACTIVITY

    if _first_str(fields, ("process_name", "image", "event_data.NewProcessName", "exe")):
        return CLASS_PROCESS_ACTIVITY

    if _first_str(fields, ("url", "request_url", "http_url")):
        return CLASS_HTTP_ACTIVITY

    return CLASS_BASE_EVENT


def _activity_name(parsed: ParsedEvent, class_uid: int) -> str | None:
    fields = parsed.fields
    if class_uid == CLASS_AUTHENTICATION:
        outcome = _auth_outcome(parsed)
        if outcome == "failure":
            return "Logon Failed"
        if outcome == "success":
            return "Logon"
        return "Authentication"
    if class_uid == CLASS_HTTP_ACTIVITY:
        method = _first_str(fields, ("http_method", "method", "requestMethod"))
        return f"HTTP {method}" if method else "HTTP Request"
    if class_uid == CLASS_PROCESS_ACTIVITY:
        return "Process Activity"
    if class_uid == CLASS_NETWORK_ACTIVITY:
        action = _first_str(fields, ("action", "act", "disposition"))
        return f"Network Traffic {action}".strip() if action else "Network Traffic"
    return _first_str(fields, ("name", "msg_id", "event_id_name"))


def _auth_outcome(parsed: ParsedEvent) -> str | None:
    fields = parsed.fields
    event_id = fields.get("event_id")
    if event_id == 4624:
        return "success"
    if event_id in (4625, 4771, 4776):
        return "failure"

    message = str(fields.get("message") or "")
    if _SSH_FAILURE.search(message):
        return "failure"
    if _SSH_SUCCESS.search(message):
        return "success"

    explicit = _first_str(fields, ("outcome", "result", "status", "action", "act"))
    if explicit:
        lowered = explicit.lower()
        if lowered in ("success", "succeeded", "accept", "allow", "allowed", "0"):
            return "success"
        if lowered in ("failure", "failed", "deny", "denied", "blocked"):
            return "failure"
    return None


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------


def _extract_user(parsed: ParsedEvent) -> dict[str, Any]:
    fields = parsed.fields
    name = _first_str(
        fields,
        (
            "event_data.TargetUserName",
            "event_data.SubjectUserName",
            "user",
            "username",
            "user_name",
            "suser",
            "duser",
            "usrName",
            "account",
        ),
    )
    if name is None:
        message = str(fields.get("message") or "")
        for pattern in (_SSH_FAILURE, _SSH_SUCCESS):
            match = pattern.search(message)
            if match:
                name = match.group("user")
                break

    domain = _first_str(fields, ("event_data.TargetDomainName", "user_domain", "domain_name"))
    uid = _first_str(fields, ("event_data.TargetUserSid", "security_user_id", "uid"))
    return _drop_empty({"name": name, "domain": domain, "uid": uid})


def _extract_device(parsed: ParsedEvent) -> dict[str, Any]:
    fields = parsed.fields
    hostname = _first_str(fields, ("hostname", "computer", "host", "dvchost", "devname", "dvc"))
    ip = _first_ip(fields, ("device_ip", "dvc", "dvcip", "host_ip"))
    return _drop_empty(
        {"hostname": hostname, "ip": ip, "os": _first_str(fields, ("os", "platform"))}
    )


def _extract_process(parsed: ParsedEvent) -> dict[str, Any]:
    fields = parsed.fields
    name = _first_str(
        fields,
        (
            "event_data.NewProcessName",
            "event_data.Image",
            "process_name",
            "image",
            "exe",
            "app_name",
        ),
    )
    cmd_line = _first_str(
        fields,
        ("event_data.CommandLine", "command_line", "cmd", "cmdline", "process_command_line"),
    )
    pid = _first_int(fields, ("event_data.ProcessId", "process_id", "pid", "proc_id"))
    parent = _first_str(
        fields,
        ("event_data.ParentProcessName", "event_data.ParentImage", "parent_process_name"),
    )
    return _drop_empty({"name": name, "cmd_line": cmd_line, "pid": pid, "parent_name": parent})


def _extract_network(parsed: ParsedEvent) -> dict[str, Any]:
    fields = parsed.fields
    src_ip = _first_ip(
        fields,
        ("src", "srcip", "src_ip", "source_ip", "remote_host", "event_data.IpAddress"),
    )
    if src_ip is None:
        match = _FROM_IP.search(str(fields.get("message") or ""))
        if match and _is_ip(match.group("ip")):
            src_ip = match.group("ip")

    return _drop_empty(
        {
            "src_ip": src_ip,
            "dst_ip": _first_ip(fields, ("dst", "dstip", "dst_ip", "destination_ip")),
            "src_port": _first_int(fields, ("spt", "srcport", "src_port", "source_port")),
            "dst_port": _first_int(fields, ("dpt", "dstport", "dst_port", "destination_port")),
            "protocol": _first_str(fields, ("proto", "protocol", "transport", "http_protocol")),
        }
    )


def _extract_http(parsed: ParsedEvent) -> dict[str, Any]:
    fields = parsed.fields
    url = _first_str(fields, ("url", "request", "request_url", "requestUrl", "url_path"))
    if parsed.format_name == "web_access":
        url = _first_str(fields, ("url_path",)) or url
    return _drop_empty(
        {
            "method": _first_str(fields, ("http_method", "method", "requestMethod")),
            "url": url,
            "status_code": _first_int(fields, ("status", "status_code", "response_code")),
            "user_agent": _first_str(fields, ("user_agent", "requestClientApplication")),
            "referrer": _first_str(fields, ("referer", "referrer")),
            "domain": _first_str(fields, ("host_header", "domain", "dhost")),
        }
    )


def _extract_authentication(parsed: ParsedEvent, class_uid: int) -> dict[str, Any]:
    if class_uid != CLASS_AUTHENTICATION:
        return {}
    fields = parsed.fields
    return _drop_empty(
        {
            "outcome": _auth_outcome(parsed),
            "method": _first_str(
                fields, ("event_data.LogonType", "auth_method", "authentication_method")
            ),
            "logon_type": _first_str(fields, ("event_data.LogonType",)),
            "mfa_used": None,  # no source in this phase reports it reliably
        }
    )


def _extract_file(parsed: ParsedEvent) -> dict[str, Any]:
    fields = parsed.fields
    return _drop_empty(
        {
            "name": _first_str(
                fields, ("filename", "fname", "file_name", "event_data.TargetFilename")
            ),
            "path": _first_str(
                fields, ("filepath", "file_path", "filePath", "event_data.TargetFilename")
            ),
            "size": _first_int(fields, ("fsize", "file_size", "bytes_sent")),
        }
    )


def _extract_hashes(parsed: ParsedEvent) -> dict[str, Any]:
    fields = parsed.fields
    hashes: dict[str, Any] = {}
    for key in ("hash", "file_hash", "fileHash", "event_data.Hashes", "md5", "sha1", "sha256"):
        value = fields.get(key)
        if not isinstance(value, str):
            continue
        for candidate in re.split(r"[,\s]+", value):
            candidate = candidate.split("=")[-1].strip()
            if _SHA256.match(candidate):
                hashes.setdefault("sha256", candidate.lower())
            elif _SHA1.match(candidate):
                hashes.setdefault("sha1", candidate.lower())
            elif _MD5.match(candidate):
                hashes.setdefault("md5", candidate.lower())
    return hashes


def _extract_cloud(parsed: ParsedEvent) -> dict[str, Any]:
    fields = parsed.fields
    return _drop_empty(
        {
            "provider": _first_str(fields, ("cloud_provider", "cloud.provider", "provider")),
            "account_id": _first_str(
                fields, ("account_id", "cloud.account_id", "recipientAccountId")
            ),
            "region": _first_str(fields, ("region", "cloud.region", "awsRegion")),
        }
    )


def _extract_severity(parsed: ParsedEvent) -> str:
    fields = parsed.fields

    label = fields.get("severity_label")
    if isinstance(label, str):
        return _map_syslog_severity(label)

    raw_severity = fields.get("severity")
    if isinstance(raw_severity, int):
        return _map_numeric_severity(raw_severity, parsed.format_name)
    if isinstance(raw_severity, str) and raw_severity.strip():
        stripped = raw_severity.strip()
        if stripped.isdigit():
            return _map_numeric_severity(int(stripped), parsed.format_name)
        lowered = stripped.lower()
        if lowered in SEVERITY_ORDER:
            return lowered
        return _map_syslog_severity(lowered)

    if parsed.format_name == "web_access":
        status = fields.get("status")
        if isinstance(status, int) and status >= 500:
            return "medium"
        if isinstance(status, int) and status >= 400:
            return "low"

    return "informational"


def _map_syslog_severity(label: str) -> str:
    return {
        "emerg": "critical",
        "alert": "critical",
        "crit": "critical",
        "err": "high",
        "error": "high",
        "warning": "medium",
        "warn": "medium",
        "notice": "low",
        "info": "informational",
        "debug": "informational",
    }.get(label.lower(), "informational")


def _map_numeric_severity(value: int, format_name: str) -> str:
    if format_name == "cef":
        # CEF severity is 0-10.
        if value >= 9:
            return "critical"
        if value >= 7:
            return "high"
        if value >= 4:
            return "medium"
        if value >= 1:
            return "low"
        return "informational"
    # Syslog numeric severity: 0 (emerg) .. 7 (debug).
    return _map_syslog_severity(
        ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")[value]
        if 0 <= value <= 7
        else "info"
    )


def _extract_timestamp(parsed: ParsedEvent, fallback: datetime) -> datetime:
    """Uses the source's own timestamp when it is unambiguous. RFC 3164
    syslog omits the year and timezone entirely, so rather than guessing (and
    silently mis-bucketing events across a new year), that case falls back to
    ingestion time — the original string is preserved in
    `metadata.original_time` either way."""
    for key in ("time_created", "timestamp", "event_time", "@timestamp"):
        value = parsed.fields.get(key)
        if isinstance(value, str) and value.strip():
            parsed_dt = _parse_iso8601(value)
            if parsed_dt is not None:
                return parsed_dt

    raw = parsed.fields.get("timestamp_raw")
    if isinstance(raw, str):
        parsed_dt = _parse_iso8601(raw)
        if parsed_dt is not None:
            return parsed_dt

    return fallback


def _parse_iso8601(value: str) -> datetime | None:
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_str(fields: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = fields.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, int | float) and not isinstance(value, bool):
            return str(value)
    return None


def _first_int(fields: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = fields.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return None


def _first_ip(fields: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = fields.get(key)
        if isinstance(value, str) and _is_ip(value.strip()):
            return value.strip()
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _unmapped(parsed: ParsedEvent) -> dict[str, Any]:
    """Everything the mapper did not promote to a typed field. Kept so a
    detection engineer can see what a source actually provides instead of
    having to go back to raw bytes to find out."""
    return {key: value for key, value in parsed.fields.items() if value not in (None, "", [])}


def _drop_empty(document: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in document.items() if value not in (None, "", {}, [])}
