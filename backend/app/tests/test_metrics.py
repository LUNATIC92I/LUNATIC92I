"""Metrics-present tests (Phase 16, spec §28): the scrape endpoint must
actually expose the names this platform's dashboards and alerts are wired
to, not just have Python objects that could in principle produce them.

Every metric here is touched with a representative label set before
scraping — a `Counter`/`Histogram` with labels does not appear in
`generate_latest()` output at all until at least one concrete label
combination has been recorded, so "the object exists" and "the name is on
the wire" are genuinely different claims worth testing separately.
"""

from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest

from app.core import metrics as m

# name -> how many labels it takes. Every metric in app/core/metrics.py is
# listed here on purpose: a metric added to that module without a line here
# is a metric this test cannot prove ever reaches Prometheus.
_COUNTERS: dict[str, int] = {
    "api_requests_total": 3,
    "events_ingested_total": 1,
    "events_duplicate_total": 1,
    "events_rate_limited_total": 1,
    "events_deadlettered_total": 2,
    "events_rejected_total": 2,
    "events_dropped_total": 1,
    "events_processed_total": 1,
    "parser_errors_total": 1,
    "enrichment_failures_total": 2,
    "events_indexed_total": 1,
    "index_failures_total": 1,
    "detections_total": 3,
    "detections_suppressed_total": 1,
    "detection_exceptions_applied_total": 1,
    "detection_rule_errors_total": 1,
    "detection_regex_timeouts_total": 0,
    "windowed_rule_runs_total": 2,
    "correlations_total": 2,
    "correlations_suppressed_total": 1,
    "correlation_inputs_total": 1,
    "correlation_stage_hits_total": 2,
    "correlation_state_trimmed_total": 0,
    "correlation_timestamp_clamped_total": 1,
    "risk_scores_total": 1,
    "ioc_feed_indicators_total": 2,
    "ioc_feed_sync_failures_total": 2,
    "ioc_matches_total": 1,
    "egress_requests_blocked_total": 1,
    "alerts_created_total": 2,
    "alerts_deduplicated_total": 1,
    "alert_transitions_total": 1,
    "incidents_created_total": 1,
    "incident_transitions_total": 1,
    "hunt_searches_total": 0,
    "hunt_exports_total": 2,
    "playbook_runs_total": 2,
    "playbook_approvals_total": 1,
}

_HISTOGRAMS: dict[str, int] = {
    "ingestion_latency_seconds": 1,
    "processing_latency_seconds": 1,
    "index_latency_seconds": 0,
    "detection_latency_seconds": 0,
    "correlation_latency_seconds": 0,
}


def _touch(name: str, label_count: int) -> None:
    metric = getattr(m, name)
    if label_count:
        metric.labels(*[f"x{i}" for i in range(label_count)]).inc()
    else:
        metric.inc()


def _touch_histogram(name: str, label_count: int) -> None:
    metric = getattr(m, name)
    if label_count:
        metric.labels(*[f"x{i}" for i in range(label_count)]).observe(0.01)
    else:
        metric.observe(0.01)


def test_every_declared_counter_reaches_the_scrape_output() -> None:
    for name, label_count in _COUNTERS.items():
        _touch(name, label_count)
    body = generate_latest(REGISTRY).decode()
    missing = [name for name in _COUNTERS if name not in body]
    assert not missing, f"counters never reached the scrape output: {missing}"


def test_every_declared_histogram_reaches_the_scrape_output() -> None:
    for name, label_count in _HISTOGRAMS.items():
        _touch_histogram(name, label_count)
    body = generate_latest(REGISTRY).decode()
    missing = [name for name in _HISTOGRAMS if f"{name}_bucket" not in body]
    assert not missing, f"histograms never reached the scrape output: {missing}"


def test_content_type_is_the_prometheus_text_format() -> None:
    assert CONTENT_TYPE_LATEST.startswith("text/plain")


def test_no_metric_in_the_module_is_missing_from_this_test() -> None:
    """Guards the guard: a metric added to `app/core/metrics.py` without a
    matching entry in `_COUNTERS`/`_HISTOGRAMS` above would otherwise ship
    with no proof it is ever actually exported."""
    from prometheus_client import Counter, Histogram

    declared = {
        name
        for name, obj in vars(m).items()
        if isinstance(obj, Counter | Histogram) and not name.startswith("_")
    }
    covered = set(_COUNTERS) | set(_HISTOGRAMS)
    assert declared == covered, f"uncovered metrics: {declared - covered}"
