"""Prometheus metrics, defined in one place (spec §28).

Metrics live here rather than next to their call sites so that importing two
modules can never double-register the same collector, and so the full metric
surface is reviewable at a glance.

A note on labels: `tenant_id` is deliberately NOT a label. Prometheus label
cardinality is multiplicative and a multi-tenant SIEM can have thousands of
tenants; per-tenant volume belongs in OpenSearch aggregations, not in the
metrics backend. `reason` labels use a small fixed set of codes, never free
text — the detailed reason travels with the dead-lettered event itself.
"""

from prometheus_client import Counter, Histogram

api_requests_total = Counter(
    "api_requests_total", "Total API requests", ["method", "path", "status"]
)

events_ingested_total = Counter(
    "events_ingested_total",
    "Events accepted and published to the pipeline",
    ["source_type"],
)

events_duplicate_total = Counter(
    "events_duplicate_total",
    "Events rejected as duplicates of an already-ingested event (idempotency)",
    ["source_type"],
)

events_rate_limited_total = Counter(
    "events_rate_limited_total",
    "Events rejected because the tenant exceeded its ingestion quota",
    ["source_type"],
)

events_deadlettered_total = Counter(
    "events_deadlettered_total",
    "Events routed to the dead-letter topic instead of the pipeline",
    ["source_type", "reason"],
)

events_rejected_total = Counter(
    "events_rejected_total",
    "Events refused at the collector edge for security reasons (not lost data)",
    ["source_type", "reason"],
)

events_dropped_total = Counter(
    "events_dropped_total",
    (
        "Events that could be neither published nor dead-lettered. This is the "
        "silent-loss canary required by spec §26: any non-zero value is an "
        "incident, not a statistic, and must alert."
    ),
    ["source_type"],
)

ingestion_latency_seconds = Histogram(
    "ingestion_latency_seconds",
    "Time from event receipt to publication on the event bus",
    ["source_type"],
)
