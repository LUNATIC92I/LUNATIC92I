# Threat intelligence

Indicators of compromise, where they come from, what they are allowed to
claim, and how they reach the pipeline.

## The rule that governs everything here

Spec §11: **an indicator is never automatically treated as malicious just
because it came from a feed.** A feed publishing a list of addresses is
asserting "I saw this", not "this is malicious", and the difference has to
survive all the way into the alert an analyst reads.

That is enforced in four places, not asserted once:

1. **The schema.** `ck_iocs_source_required` refuses any malicious or
   suspicious row whose `source` is blank — a claim of malice always names
   who is making it, even if a future code path forgets to.
2. **The parser.** A plain-list feed produces indicators with no
   classification and no confidence at all.
3. **The upsert.** An indicator arriving with no verdict is stored as
   `unknown` at confidence 50, and re-seeing it refreshes `last_seen` and
   its expiry but never upgrades its classification.
4. **The risk engine.** An indicator's contribution to a score is scaled by
   its own recorded confidence, so a 40%-confidence bulk-list hit moves a
   score far less than a 95%-confidence incident-response one
   (`docs/RISK_SCORING.md`).

## Indicator types

The ten types from spec §11: `ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`,
`sha256`, `email`, `asn`, `certificate`.

Every value is canonicalized on the way in and every observable is
canonicalized the same way on the way to a lookup
(`app/threat_intel/normalize.py`), because an indicator that only matches
when the case happens to line up is worse than no indicator:

| Pasted | Stored |
|---|---|
| `1.2.3[.]4` | `1.2.3.4` (ipv4) |
| `hxxp://EVIL.com:80/a#frag` | `http://evil.com/a` (url) |
| `EVIL.COM.` | `evil.com` (domain) |
| `D41D8CD9…427E` | lowercase (md5) |
| `as15169` | `AS15169` (asn) |

Defanged forms are refanged deliberately: that is how indicators travel in
reports and chat, and rejecting them just means analysts retype them
wrongly. `certificate` is the one type never inferred — a fingerprint is
indistinguishable from a file hash of the same length, so the caller says
which it meant.

## Shared vs. tenant indicators

`iocs.tenant_id` is nullable, and that is a deliberate difference from
detection rules (where it is NOT NULL):

- **NULL** = a shared/global feed indicator. Every tenant can read it; no
  tenant can write it.
- **A tenant id** = that tenant's own intelligence, invisible to everyone
  else.

A feed of a million indicators duplicated per tenant is neither affordable
nor meaningful — unlike a detection rule, an indicator is a claim about the
outside world, not a judgement a tenant tunes. Two RLS policies express
this: the tenant policy reads global rows but only accepts writes stamped
with the caller's own tenant, and a second policy — enabled only by the
`app.intel_sync` GUC that `intel_sync_session()` sets — accepts *only* rows
with no tenant. Neither session can reach the other's data, and both are
tested.

## Expiry

Every read path filters on `expires_at`, so an indicator stops matching the
moment it lapses. This is not a background job on purpose: a sweeper that
fails silently would keep stale intelligence alive, which is how a SOC ends
up chasing an address that was reassigned to a CDN six months ago.

Feed indicators get a default TTL (`THREAT_INTEL_DEFAULT_TTL_DAYS`, 30 days)
unless the feed states its own. `purge_expired()` reclaims space afterwards
and is deliberately separate: a purge that fails degrades storage, never
detection correctness.

## Feeds

A connector's only job is to turn some external representation into
indicators. Two ship:

| Connector | Use |
|---|---|
| `http` | Fetches a `plain`, `csv` or `json` feed over HTTPS. Covers most public and commercial feeds. |
| `local_file` | Reads a file from `THREAT_INTEL_DROP_DIR`. Air-gapped deployments, and subscriptions whose licence forbids automated pulling. |

Credentials are **never** stored in the database: `ioc_feeds.credential_ref`
names an environment variable, resolved at sync time from the environment
(injected from a secrets manager in production). A feed API key in a JSONB
config column would be readable by anyone with a database connection and
would end up in every backup (spec §27).

Each sync records `last_synced_at` and `last_sync_status` on the feed row,
and failures increment `ioc_feed_sync_failures_total`. A feed that fails
quietly is intelligence going stale with nobody noticing — which looks
exactly like a quiet week. Failures are isolated per feed.

The worker (`python -m app.workers.feed_worker`, the `feeds` compose
service) syncs shared feeds and then each tenant's, on
`THREAT_INTEL_FEED_INTERVAL_SECONDS`.

## The egress guard

Every outbound request the platform makes on its own behalf goes through
`app/core/egress.py`. A SIEM is a uniquely attractive SSRF target: it runs
inside the management network, holds credentials for everything, and is
*designed* to fetch URLs that appear in configuration and data
(THREAT_MODEL.md §3.8).

1. **HTTPS only.** Plain HTTP is available behind an explicit
   development-only setting.
2. **Host allow-list** (`EGRESS_ALLOWED_HOSTS`). Empty means nothing is
   reachable — fail closed. A leading dot matches subdomains.
3. **Resolved address.** Every address the host resolves to must be global
   unicast; loopback, private, link-local (including 169.254.169.254, the
   cloud metadata service), multicast and reserved ranges are refused. This
   is the check that stops an allow-listed name whose DNS points inside.
4. **Redirects are re-validated**, never followed automatically, so an
   allowed host cannot bounce a request into the metadata service.
5. **Caps** on time and on response size, streamed — a feed that never stops
   sending must not exhaust the worker.

**Residual risk, stated rather than papered over:** validation resolves the
hostname and then makes an ordinary request, so a DNS server answering
differently on the second lookup (rebinding) has a window between the check
and the connection. Closing it needs the socket pinned to the validated
address, which requires a custom transport; it is recorded as follow-up
hardening rather than claimed as done. The allow-list keeps the residual
risk small: an attacker must already control DNS for a host an operator
explicitly allowed.

`egress_requests_blocked_total` counts every refusal — any value there is
either a misconfiguration or an SSRF attempt.

## Matching

`IocMatchProvider` runs in the enrichment pipeline: it extracts the event's
observables (source and destination addresses, domain, URL, file hashes,
user email — deliberately not hostnames, which collide with feed entries),
canonicalizes them, and resolves them in one indexed query per event.

What it writes is not a boolean:

```json
"ioc_matches": [
  {"value": "203.0.113.77", "type": "ipv4", "classification": "malicious",
   "confidence": 90, "source": "incident-response", "tags": ["c2"],
   "ioc_id": "…", "shared": false}
]
```

An empty list is a real result — "we looked and found nothing" — which is
what lets the risk engine score threat intel as available-and-zero rather
than unknown. A partially-failed enrichment records neither, because the
provider that timed out may well have been this one.

## API

| Endpoint | Permission | |
|---|---|---|
| `GET /iocs`, `GET /iocs/{id}` | `ioc:read` | `include_expired` shows lapsed ones |
| `POST /iocs` | `ioc:write` | type inferred, value canonicalized, `source` required |
| `PATCH /iocs/{id}` | `ioc:write` | writes per-field history |
| `DELETE /iocs/{id}` | `ioc:delete` | |
| `GET /iocs/{id}/history` | `ioc:read` | who changed what, when |
| `POST /iocs/match` | `ioc:read` | triage lookup; accepts defanged pastes and ignores noise lines |

Reclassification is audited under its own action (`RECLASSIFY_IOC`), because
downgrading an indicator to benign is as consequential as disabling a
detection rule. `ioc_history` is append-only at the database level.

## Known limits

- There is no MISP/STIX/TAXII connector yet. The interface exists and the
  HTTP connector covers plain/CSV/JSON feeds; a structured-intel connector
  is additive work, not a redesign.
- Matching is one query per event with no cache. That is correct and
  bounded by an index today; whether it needs a cache is a Phase 18
  benchmark question, not a guess to act on now.
- Indicator relationships (this hash was served by that domain) are not
  modelled. Phase 12's incident linkage is where that starts to matter.
