"""Secure response headers (Phase 17; OWASP ASVS V14, API Security Top 10
API8/API9): the fixed set every response carries, regardless of route.

This is a pure JSON API — it never renders HTML and never wants to be
framed, embedded, or have its responses sniffed into an unexpected content
type — so the policy here is the strict end of each header's range rather
than a permissive default meant for a page with a real front end to run.
The frontend SPA is a separate origin/service and sets its own headers.
"""

from collections.abc import Awaitable, Callable

from fastapi import Request, Response

SECURITY_HEADERS: dict[str, str] = {
    # Instructs a browser that ever reaches this API over HTTPS to never
    # downgrade to HTTP again, for itself or any subdomain, for two years.
    # Harmless to send over local, unterminated HTTP in development — a
    # browser only honors HSTS on a response it received over HTTPS.
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    # A JSON API response is never an executable context; stop a browser
    # from ever guessing otherwise from sniffed content.
    "X-Content-Type-Options": "nosniff",
    # This API is never meant to be framed — there is no legitimate reason
    # for a browser to load a JSON response inside an <iframe>.
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # The legacy XSS-Auditor header is deprecated and, in older browsers,
    # could itself be turned into an information-disclosure vector — OWASP's
    # current guidance is to explicitly disable it rather than omit it.
    "X-XSS-Protection": "0",
    # No script, style, frame, or object ever has a legitimate reason to
    # load in the context of a JSON response.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}

Handler = Callable[[Request], Awaitable[Response]]


async def add_security_headers(request: Request, call_next: Handler) -> Response:
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
    return response
