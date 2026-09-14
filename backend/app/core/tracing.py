"""OpenTelemetry tracing across the pipeline (Phase 16, spec §28).

The pipeline is not a request/response call chain — it is a series of hops
across `EventBus` topics, each consumed by an independent worker process.
W3C trace context therefore cannot ride HTTP headers the way it would
between two services behind a load balancer; it rides `EventBusMessage.
headers` instead, the same dict every message already carries for exactly
this kind of cross-cutting metadata (`source_type`, `dead_letter_reason`,
...). `inject_trace_headers`/`extract_trace_context` are the only two
functions a call site needs: inject before `bus.publish()`, extract right
after reading a message back off `bus.subscribe()`.

Export is opt-in and fails closed like the egress guard
(`EGRESS_ALLOWED_HOSTS`): with no `OTEL_EXPORTER_OTLP_ENDPOINT` configured,
spans are still created — so propagation across a hop is real and testable
— but nothing leaves the process. Configure the endpoint to point spans at
a real collector (Jaeger, Tempo, ...).
"""

import logging

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.propagate import extract, inject
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Tracer

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_configured = False


def configure_tracing(service_name: str | None = None) -> None:
    """Sets the process-wide `TracerProvider`. Idempotent — every worker's
    `run()` and the API's lifespan call this unconditionally on startup;
    a second call (e.g. from a test importing more than one worker module)
    is a no-op rather than a duplicate exporter."""
    global _configured
    if _configured:
        return

    settings = get_settings()
    resource = Resource.create({"service.name": service_name or settings.otel_service_name})
    provider = TracerProvider(resource=resource)

    if settings.otel_exporter_otlp_endpoint:
        exporter = OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        logger.info(
            "tracing configured with an OTLP exporter",
            extra={"endpoint": settings.otel_exporter_otlp_endpoint},
        )
    else:
        logger.info("tracing configured with no exporter (OTEL_EXPORTER_OTLP_ENDPOINT unset)")

    trace.set_tracer_provider(provider)
    _configured = True


def get_tracer(name: str = "lunatic-siem") -> Tracer:
    return trace.get_tracer(name)


def inject_trace_headers(headers: dict[str, str]) -> dict[str, str]:
    """Injects the *current* span's context into `headers` in place (W3C
    `traceparent`/`tracestate`) and returns it, so a call can be written as
    `message.headers = inject_trace_headers({...})`. Call this from inside
    the span that should be the parent of whatever reads `headers` back."""
    inject(headers)
    return headers


def extract_trace_context(headers: dict[str, str] | None) -> Context:
    """Recovers the parent context a producer injected into message
    headers, for use as `context=` on the consumer's own
    `start_as_current_span()`. Headers with no `traceparent` (a message
    from a producer that predates tracing, or a test that never injected
    one) extract to an empty context, which starts a fresh root span —
    never an error."""
    return extract(headers or {})
