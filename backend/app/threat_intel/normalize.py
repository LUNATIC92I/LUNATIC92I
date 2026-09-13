"""Canonicalizing and typing indicators (spec §11).

An indicator only works if the form it is stored in is the form it will be
compared against. `EVIL.COM`, `evil.com.`, `hxxp://evil[.]com/a` and
`http://EVIL.com/a` are one domain and one URL; stored naively they are four
rows, three of which will never match anything. So every value goes through
`canonicalize` on the way in and every observable goes through the same
function on the way to a lookup.

Defanged forms (`1.2.3[.]4`, `hxxps://`) are refanged deliberately: they are
how indicators are shared in reports and chat, and rejecting them just means
analysts paste them in by hand later, wrongly. Refanging is done before
typing so `1.2.3[.]4` is recognised as an IPv4 address rather than as a
domain.

One type is never inferred: `certificate`. A certificate is identified by
its SHA-1 or SHA-256 fingerprint, which is indistinguishable from a file
hash of the same length, so the caller has to say which it meant. Guessing
would silently file TLS fingerprints under `sha1` where no file-hash lookup
will ever find them.
"""

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from app.models.threat_intel import IOC_TYPES

MAX_VALUE_LENGTH = 2048

_MD5 = re.compile(r"^[a-f0-9]{32}$")
_SHA1 = re.compile(r"^[a-f0-9]{40}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_ASN = re.compile(r"^as\d{1,10}$")
_EMAIL = re.compile(r"^[^@\s]+@[a-z0-9.-]+\.[a-z]{2,}$")
# The final label must contain a letter: no real TLD is all-digits, and
# without that rule a malformed address like "999.999.999.999" is accepted
# as a domain and stored as an indicator that can never match anything.
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[a-z0-9-]{1,63}(?<!-))*"
    r"\.(?!-)[a-z0-9-]*[a-z][a-z0-9-]*(?<!-)$"
)
_CERT_FINGERPRINT = re.compile(r"^[a-f0-9]{40}$|^[a-f0-9]{64}$")

# Defanging conventions seen in reports, chat and vendor advisories.
_DEFANG_REPLACEMENTS = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("[@]", "@"),
    ("(@)", "@"),
    ("[at]", "@"),
    ("[dot]", "."),
    ("hxxp", "http"),
    ("hxxps", "https"),
    ("fxp", "ftp"),
)


class InvalidIndicator(ValueError):
    pass


def refang(value: str) -> str:
    lowered = value.strip()
    for defanged, real in _DEFANG_REPLACEMENTS:
        lowered = lowered.replace(defanged, real)
        lowered = lowered.replace(defanged.upper(), real)
    return lowered


def canonicalize(value: str, ioc_type: str | None = None) -> tuple[str, str]:
    """Returns (canonical value, type). Infers the type when not given.

    Raises `InvalidIndicator` rather than storing something unmatched: a
    row that can never match anything is worse than a rejected paste,
    because nobody ever finds out it is dead.
    """
    if not value or not value.strip():
        raise InvalidIndicator("indicator is empty")
    if len(value) > MAX_VALUE_LENGTH:
        raise InvalidIndicator(f"indicator exceeds {MAX_VALUE_LENGTH} characters")

    cleaned = refang(value)
    inferred = ioc_type or infer_type(cleaned)
    if inferred not in IOC_TYPES:
        raise InvalidIndicator(f"unknown indicator type: {inferred}")

    canonical = _canonicalize_as(cleaned, inferred)
    if not _validates_as(canonical, inferred):
        raise InvalidIndicator(f"'{value}' is not a valid {inferred}")
    return canonical, inferred


def _canonicalize_as(value: str, ioc_type: str) -> str:
    match ioc_type:
        case "ipv4" | "ipv6":
            try:
                return str(ipaddress.ip_address(value.strip()))
            except ValueError:
                return value.strip()
        case "domain":
            # A trailing dot is the DNS root and matches the same name; the
            # scheme-less "www." prefix is deliberately NOT stripped, since
            # www.evil.com and evil.com are different names.
            return value.strip().rstrip(".").lower()
        case "url":
            return _canonical_url(value)
        case "email":
            return value.strip().lower()
        case "asn":
            digits = value.strip().lower().removeprefix("as")
            return f"AS{int(digits)}" if digits.isdigit() else value.strip().upper()
        case "md5" | "sha1" | "sha256" | "certificate":
            return value.strip().lower().replace(":", "")
        case _:  # pragma: no cover - guarded by the IOC_TYPES check
            return value.strip()


def _canonical_url(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"http://{candidate}"
    parts = urlsplit(candidate)
    # Host is case-insensitive, path is not. A default port is dropped so
    # http://evil.com:80/a and http://evil.com/a are one indicator.
    netloc = parts.netloc.lower()
    for scheme, port in (("http", ":80"), ("https", ":443")):
        if parts.scheme == scheme and netloc.endswith(port):
            netloc = netloc[: -len(port)]
    # The fragment never reaches the server, so it cannot be part of what
    # an indicator identifies.
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def infer_type(value: str) -> str:
    candidate = value.strip()
    lowered = candidate.lower()

    if "://" in lowered:
        return "url"
    try:
        address = ipaddress.ip_address(candidate)
        return "ipv4" if address.version == 4 else "ipv6"
    except ValueError:
        pass
    if _MD5.match(lowered):
        return "md5"
    if _SHA1.match(lowered):
        return "sha1"
    if _SHA256.match(lowered):
        return "sha256"
    if _ASN.match(lowered):
        return "asn"
    if _EMAIL.match(lowered):
        return "email"
    if "/" in lowered and _DOMAIN.match(lowered.split("/", 1)[0]):
        # A bare "evil.com/path" is a URL an analyst pasted without a
        # scheme, not a domain with a slash in it.
        return "url"
    # The trailing dot is the DNS root and is stripped during
    # canonicalization; it must not stop the value being recognised as a
    # domain in the first place.
    if _DOMAIN.match(lowered.rstrip(".")):
        return "domain"
    raise InvalidIndicator(f"cannot determine the indicator type of '{value}'")


def _validates_as(value: str, ioc_type: str) -> bool:
    lowered = value.lower()
    match ioc_type:
        case "ipv4":
            return _is_ip(value, version=4)
        case "ipv6":
            return _is_ip(value, version=6)
        case "domain":
            return bool(_DOMAIN.match(lowered))
        case "url":
            parts = urlsplit(value)
            return bool(parts.scheme and parts.netloc)
        case "email":
            return bool(_EMAIL.match(lowered))
        case "asn":
            return bool(_ASN.match(lowered))
        case "md5":
            return bool(_MD5.match(lowered))
        case "sha1":
            return bool(_SHA1.match(lowered))
        case "sha256":
            return bool(_SHA256.match(lowered))
        case "certificate":
            # A certificate is identified by its SHA-1 or SHA-256
            # fingerprint; the certificate body itself is not an indicator.
            return bool(_CERT_FINGERPRINT.match(lowered))
        case _:  # pragma: no cover
            return False


def _is_ip(value: str, *, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


def observables_from_event(document: dict[str, Any]) -> dict[str, list[str]]:
    """Every value in a normalized event that could match an indicator,
    grouped by indicator type.

    Kept deliberately narrow: matching every string in a document against
    the intel set would produce false positives (a hostname that happens to
    look like a domain in a feed) and would cost a lookup per field.
    """
    candidates: dict[str, set[str]] = {ioc_type: set() for ioc_type in IOC_TYPES}

    def add(raw: object, ioc_type: str | None = None) -> None:
        if not isinstance(raw, str) or not raw.strip():
            return
        try:
            canonical, resolved = canonicalize(raw, ioc_type)
        except InvalidIndicator:
            return
        candidates[resolved].add(canonical)

    for key in ("source_ip", "destination_ip"):
        value = document.get(key)
        if isinstance(value, str):
            add(value, "ipv4" if ":" not in value else "ipv6")

    device = document.get("device")
    if isinstance(device, dict):
        ip = device.get("ip")
        if isinstance(ip, str):
            add(ip, "ipv4" if ":" not in ip else "ipv6")

    add(document.get("domain"), "domain")
    add(document.get("url"), "url")

    hashes = document.get("hash")
    if isinstance(hashes, dict):
        for algorithm in ("md5", "sha1", "sha256"):
            add(hashes.get(algorithm), algorithm)

    user = document.get("user")
    if isinstance(user, dict) and isinstance(user.get("email"), str):
        add(user["email"], "email")

    return {ioc_type: sorted(values) for ioc_type, values in candidates.items() if values}
