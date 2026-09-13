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

events_processed_total = Counter(
    "events_processed_total",
    "Events successfully parsed, normalized and published onward",
    ["format"],
)

parser_errors_total = Counter(
    "parser_errors_total",
    "Payloads no parser could handle, or that failed normalization",
    ["stage"],
)

processing_latency_seconds = Histogram(
    "processing_latency_seconds",
    "Time to parse and normalize one event",
    ["format"],
)

enrichment_failures_total = Counter(
    "enrichment_failures_total",
    "Enrichment providers that timed out or errored (the event still indexes)",
    ["provider", "reason"],
)

events_indexed_total = Counter(
    "events_indexed_total",
    "Normalized events written to the OpenSearch event store",
    ["source_type"],
)

index_failures_total = Counter(
    "index_failures_total",
    "Documents OpenSearch rejected or that could not be written",
    ["reason"],
)

index_latency_seconds = Histogram(
    "index_latency_seconds",
    "Time to write one bulk batch to OpenSearch",
)

detections_total = Counter(
    "detections_total",
    "Rule matches produced by the detection engine",
    ["rule_id", "severity", "dry_run"],
)

detections_suppressed_total = Counter(
    "detections_suppressed_total",
    "Matches held back by a rule's suppression window (alert-fatigue control)",
    ["rule_id"],
)

detection_exceptions_applied_total = Counter(
    "detection_exceptions_applied_total",
    (
        "Matches dropped by a documented rule exception. A high value is a "
        "coverage hole that is deliberate but must stay visible (spec §7)."
    ),
    ["rule_id"],
)

detection_rule_errors_total = Counter(
    "detection_rule_errors_total",
    "Rules that raised while evaluating and were skipped for that event",
    ["rule_id"],
)

detection_regex_timeouts_total = Counter(
    "detection_regex_timeouts_total",
    (
        "Regex conditions abandoned after exceeding their match timeout. Any "
        "sustained value means a rule has effectively stopped detecting."
    ),
)

detection_latency_seconds = Histogram(
    "detection_latency_seconds",
    "Time to evaluate the full streaming rule set against one event",
)

windowed_rule_runs_total = Counter(
    "windowed_rule_runs_total",
    "Scheduled evaluations of windowed (threshold) rules",
    ["rule_id", "outcome"],
)

correlations_total = Counter(
    "correlations_total",
    "Multi-stage correlation rules that completed",
    ["correlation_id", "severity"],
)

correlations_suppressed_total = Counter(
    "correlations_suppressed_total",
    "Completed correlations held back by the rule's suppression window",
    ["correlation_id"],
)

correlation_inputs_total = Counter(
    "correlation_inputs_total",
    "Events and detections examined by the correlation engine",
    ["kind"],
)

correlation_stage_hits_total = Counter(
    "correlation_stage_hits_total",
    "Inputs recorded against a correlation stage",
    ["correlation_id", "stage"],
)

correlation_state_trimmed_total = Counter(
    "correlation_state_trimmed_total",
    (
        "Stage hits dropped because one entity's state hit its cap. Non-zero "
        "means a correlation timeline can no longer be reconstructed in full."
    ),
)

correlation_timestamp_clamped_total = Counter(
    "correlation_timestamp_clamped_total",
    (
        "Inputs whose source timestamp was too far from their ingestion time "
        "to be believed, and were correlated on ingestion time instead "
        "(Technical Risk #5: timestamp-manipulation evasion)."
    ),
    ["direction"],
)

correlation_latency_seconds = Histogram(
    "correlation_latency_seconds",
    "Time to evaluate one input against the full correlation rule set",
)

risk_scores_total = Counter(
    "risk_scores_total",
    "Risk assessments computed, by bucket",
    ["bucket"],
)

ioc_feed_indicators_total = Counter(
    "ioc_feed_indicators_total",
    "Indicators written by a threat-intelligence feed sync",
    ["source", "outcome"],
)

ioc_feed_sync_failures_total = Counter(
    "ioc_feed_sync_failures_total",
    "Feed syncs that failed. Sustained values mean the intel is going stale.",
    ["source", "reason"],
)

ioc_matches_total = Counter(
    "ioc_matches_total",
    "Events enriched with at least one indicator match",
    ["classification"],
)

egress_requests_blocked_total = Counter(
    "egress_requests_blocked_total",
    (
        "Outbound requests refused by the egress guard. Any value here is "
        "either a misconfiguration or an SSRF attempt (THREAT_MODEL.md §3.8)."
    ),
    ["reason"],
)

alerts_created_total = Counter(
    "alerts_created_total",
    "Alerts raised for an analyst to work",
    ["source", "severity"],
)

alerts_deduplicated_total = Counter(
    "alerts_deduplicated_total",
    (
        "Detections folded into an existing open alert instead of raising a "
        "new one. The gap between this and alerts_created_total is how much "
        "noise deduplication is absorbing."
    ),
    ["source"],
)

alert_transitions_total = Counter(
    "alert_transitions_total",
    "Alert status changes, by the status moved to",
    ["to_status"],
)
