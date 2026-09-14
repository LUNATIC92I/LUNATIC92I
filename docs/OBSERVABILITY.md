# Observability

Every service in this platform — the API and all six pipeline workers —
answers the same three questions the same way: is it alive (`/health`), can
it actually do its job right now (`/ready`), and what has it done
(`/metrics`). A fourth question, "where did this event's time go across the
whole pipeline," is answered by distributed tracing.

## `/health`, `/ready`, `/metrics`

The API serves `/health` and `/ready` on its normal public port (they carry
no more than a boolean and a reason code, and container orchestrators
expect to reach a pod's liveness/readiness probe on its primary port). Every
worker — having no other port at all — and, for `/metrics` specifically,
the API too, serve all three from a second, **internal-only** port
(`Settings.metrics_port`, default `9100`): a hand-rolled HTTP/1.1 responder
(`app/core/observability.py`) understanding exactly these three GET
requests, never bound to a port docker-compose publishes to the host.

**Why `/metrics` moves off the public port and `/health`/`/ready` do not.**
This phase's own security review criterion is that metrics and health
endpoints must not be reachable from outside the deployment without auth.
`/health` and `/ready` return nothing an outside caller gains from — a
status string and, at most, which of three fixed dependency names is down.
`/metrics`, on the other hand, is real operational intelligence: request
volume, alert/detection/incident counts, playbook run outcomes. Publishing
that on the same port as the public API is a smaller reconnaissance leak
than most, but it is a leak the review criterion names directly, so it gets
its own port rather than a middleware guard that a Docker bridge network's
NAT'd source IPs cannot enforce reliably anyway.

**Readiness checks three real dependencies, run concurrently**
(`app/core/observability.py::postgres_ready/redis_ready/opensearch_ready`,
`combine()`): a worker or the API that cannot reach Postgres, Redis or
OpenSearch is not ready to do its job, whichever of the three it happens to
need. Each check is a cheap, direct probe (`SELECT 1`, `PING`, cluster
`ping()`) against a dedicated short-lived connection — never a session the
caller might be holding open in a bad state.

| Service | Readiness depends on |
|---|---|
| API | Postgres, Redis, OpenSearch |
| parser | Redis |
| indexer | Redis, OpenSearch |
| detection | Postgres, Redis, OpenSearch |
| correlation | Redis |
| feeds | Postgres |
| alerting | Postgres, Redis |
| syslog-collector | Redis |

Docker Compose `healthcheck:` blocks call `/health` on this same internal
port for every worker (the Dockerfile's own baked-in `HEALTHCHECK` targets
`:8000`, correct for the API image but wrong for a worker container built
from the same image with a different `command:` — each worker's compose
entry overrides it).

## Metrics (spec §28)

Every metric is defined once, in `app/core/metrics.py`, so importing two
modules can never double-register the same collector and the full metric
surface is reviewable at a glance. `tenant_id` is deliberately never a
label — cardinality is multiplicative and this is a multi-tenant SIEM;
per-tenant volume belongs in OpenSearch aggregations, not Prometheus.

Two families are canaries, not activity graphs, and are graphed as
single-stat panels with a red/orange threshold at any value above zero
rather than a trend line:

- **`events_dropped_total`** — spec §26's silent-loss guarantee: an event
  that could be neither published nor dead-lettered. Any non-zero value is
  an incident.
- **`egress_requests_blocked_total`** — THREAT_MODEL.md §3.8: an outbound
  request the egress guard refused. Any value is either a misconfiguration
  or an SSRF attempt.

`app/tests/test_metrics.py` is a self-guarding presence test: it lists
every `Counter`/`Histogram` declared in `app/core/metrics.py`, touches each
with a representative label set, and asserts the name actually reaches
`generate_latest()`'s output — plus one more test asserting that list is
never allowed to fall behind the module itself, so a metric added without
updating the test fails loudly rather than shipping unverified.

### Prometheus & Grafana

`docker/prometheus/prometheus.yml` scrapes the API and all six workers on
their internal `:9100/metrics`, over the `app` network — no target here is
ever a host-published port. `docker/grafana/dashboards/pipeline-overview.
json` (provisioned automatically via `docker/grafana/provisioning/
dashboards/dashboards.yml`) is one checked-in dashboard covering the whole
pipeline: ingestion and processing latency, detection/correlation
throughput by severity, alerts created vs. deduplicated, incidents opened,
playbook run outcomes, hunt activity, IOC matches, and both canaries.

## Distributed tracing

The pipeline is not a request/response call chain — it is a series of hops
across `EventBus` topics (`events.raw` → `events.normalized` →
`detections.created`/`correlations.created` → `alerts.created`), each
consumed by an independent worker process. W3C trace context therefore
cannot ride HTTP headers between two services behind a load balancer the
way it normally would; it rides `EventBusMessage.headers` instead — the
same dict every message already carries for other cross-cutting metadata
(`source_type`, `dead_letter_reason`, ...).

`app/core/tracing.py` exposes exactly two functions call sites need:

- `inject_trace_headers(headers)` — called from inside the span that should
  be the parent, right before `bus.publish()`.
- `extract_trace_context(headers)` — called right after `bus.subscribe()`
  hands back a message, to use as `context=` on the consumer's own
  `start_as_current_span()`.

One trace now covers the whole documented path:

```
ingestion.ingest  (app/services/ingestion.py)
  -> parser.handle  (app/workers/parser_worker.py)
       -> detection.evaluate  (app/workers/detection_worker.py, streaming path)
            -> alert.create  (app/workers/alert_worker.py)
```

A message with no `traceparent` header — a producer that predates tracing,
or a hand-built test message — extracts to an empty context and simply
starts a fresh root span; this is never an error condition.

**Export is opt-in and fails closed**, the same shape as
`EGRESS_ALLOWED_HOSTS`: with `OTEL_EXPORTER_OTLP_ENDPOINT` unset, spans are
still created — propagation across a hop is real and is what `app/tests/
test_tracing.py` proves — but nothing leaves the process. Point it at a
real collector (Jaeger, Tempo, an OTel Collector in front of either) to
actually see traces. `configure_tracing()` is idempotent and called once
from every worker's `run()` and the API's lifespan.

`app/tests/test_tracing.py::test_a_real_ingest_to_parse_hop_produces_one_
connected_trace` is the propagation test this phase's acceptance criteria
calls for, run against the real `IngestionService`/`ParserWorker` code —
not a simulation of the mechanism — with only the two modules' `tracer`
objects swapped for ones bound to an in-memory exporter.

## Security review

- **`/metrics` is not reachable from outside the deployment.** Proven by
  `app/tests/test_health.py::test_metrics_is_not_exposed_on_the_public_app`
  (404 on the public app) and `app/tests/test_observability.py` (200 on the
  internal server) together — the two halves of the claim.
- **`/health`/`/ready` leak nothing sensitive.** `/health` returns a fixed
  string. `/ready` returns `{"status", "reason", "reasons"}` where `reason`
  is one of three fixed dependency names, never an exception message,
  connection string, or stack trace.
- **Metrics carry no tenant-identifying data.** No metric in
  `app/core/metrics.py` takes a `tenant_id` label; per-tenant volume is
  answered from OpenSearch, which is already DLS/tenant-scoped.
- **Tracing carries no sensitive payload data.** Span attributes set by
  this codebase are limited to routing metadata (`source_type`) — never
  event bodies, credentials, or PII. `traceparent`/`tracestate` are the W3C
  standard's own opaque trace/span identifiers, not application data.
