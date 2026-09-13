"""Outbound HTTP, allow-listed (THREAT_MODEL.md §3.8).

Every outbound request the platform makes on its own behalf — intelligence
feeds now, playbook webhooks in Phase 15 — goes through here. A SIEM is a
uniquely attractive SSRF target: it runs inside the management network, it
holds credentials for everything, and it is *designed* to fetch URLs that
appear in data. "Fetch this feed URL" and "fetch the cloud metadata service"
look identical to an HTTP client that does not check.

The guard, in order:

1. **Scheme.** HTTPS only. Plain HTTP is available behind an explicit
   setting for local development and is refused otherwise, because a feed
   fetched over HTTP is a feed an on-path attacker chooses the contents of.
2. **Host allow-list.** Empty means nothing is reachable — fail closed. A
   leading dot (`.example.com`) matches subdomains; anything else must match
   exactly.
3. **Resolved address.** Every address the host resolves to must be a
   global unicast address. Loopback, private, link-local (which includes
   169.254.169.254, the cloud metadata service), multicast, and reserved
   ranges are all refused. This is the check that stops an allow-listed
   hostname whose DNS record points at the inside of the network.
4. **Redirects are not followed automatically.** Each hop is re-validated
   against the whole guard, so a permitted host cannot bounce the request
   into the metadata service.
5. **Caps.** Connect/read timeouts and a maximum response size, streamed —
   a feed that never stops sending must not exhaust the worker.

**Residual risk, stated rather than papered over:** validation resolves the
hostname and then makes an ordinary request, so a DNS server that answers
differently on the second lookup (rebinding) has a window between the check
and the connection. Closing it properly requires pinning the socket to the
validated address, which needs a custom transport; it is recorded as
follow-up hardening rather than claimed as done. The host allow-list is what
makes the residual risk small in practice: an attacker must already control
DNS for a host an operator explicitly allowed.
"""

import ipaddress
import logging
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from app.core import metrics
from app.core.config import get_settings

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_MAX_BYTES = 32 * 1024 * 1024
MAX_REDIRECTS = 3


class EgressBlocked(Exception):
    """The request was refused before it left the process."""


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    host: str
    addresses: list[str]


def _allowed_hosts() -> list[str]:
    raw = get_settings().egress_allowed_hosts
    return [entry.strip().lower() for entry in raw.split(",") if entry.strip()]


def _host_allowed(host: str, allow_list: list[str]) -> bool:
    for entry in allow_list:
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


def _block(reason: str, detail: str) -> EgressBlocked:
    metrics.egress_requests_blocked_total.labels(reason=reason).inc()
    logger.warning("outbound request blocked", extra={"reason": reason, "detail": detail})
    return EgressBlocked(f"{reason}: {detail}")


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise _block("dns_failure", f"{host} does not resolve") from exc
    # sockaddr is (host, port) for IPv4 and (host, port, flow, scope) for
    # IPv6; the address is always the first element, always a string.
    return sorted({str(info[4][0]) for info in infos})


def validate_url(url: str) -> ValidatedTarget:
    """Runs the whole guard and returns the target, or raises
    `EgressBlocked`. Exposed separately so callers (and tests) can check a
    URL without performing a request."""
    settings = get_settings()
    parts = urlsplit(url)

    allowed_schemes = {"https"} | ({"http"} if settings.egress_allow_http else set())
    if parts.scheme.lower() not in allowed_schemes:
        raise _block("scheme", f"{parts.scheme or '(none)'} is not permitted")

    host = (parts.hostname or "").lower()
    if not host:
        raise _block("host", "the URL has no host")

    allow_list = _allowed_hosts()
    if not allow_list:
        # Fail closed. An empty allow-list is a deployment that has not
        # decided where it may talk to, not a deployment that may talk
        # anywhere.
        raise _block("allow_list_empty", "no outbound host is allow-listed")
    if not _host_allowed(host, allow_list):
        raise _block("host_not_allowed", host)

    addresses = _resolve(host)
    if not settings.egress_allow_private_destinations:
        for address in addresses:
            parsed = ipaddress.ip_address(address)
            if not parsed.is_global or parsed.is_multicast:
                # `is_global` is False for loopback, private, link-local
                # (169.254.169.254 — the cloud metadata service), and
                # reserved ranges.
                raise _block("non_global_address", f"{host} resolves to {address}")

    return ValidatedTarget(url=url, host=host, addresses=addresses)


async def fetch(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> bytes:
    """Fetches `url` through the guard, following re-validated redirects."""
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        target = validate_url(current)
        async with httpx.AsyncClient(
            timeout=timeout_seconds,
            # Never automatic: each hop goes back through the whole guard.
            follow_redirects=False,
            headers=headers or {},
        ) as client:
            async with client.stream("GET", target.url) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise _block("redirect", "redirect without a location")
                    current = str(httpx.URL(target.url).join(location))
                    continue
                response.raise_for_status()
                return await _read_capped(response, max_bytes)

    raise _block("redirect_loop", f"more than {MAX_REDIRECTS} redirects")


async def _read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > max_bytes:
            # Refused rather than truncated: a partially-read feed would be
            # silently incomplete intelligence, which is worse than none.
            raise _block("response_too_large", f"exceeded {max_bytes} bytes")
    return bytes(body)
