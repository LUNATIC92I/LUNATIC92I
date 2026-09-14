"""Trace propagation across a pipeline hop (Phase 16). The pipeline moves
between processes over `EventBus` topics, not HTTP, so the property that
matters is narrower than "spans get created": a span opened on the
*consuming* side of a hop must be a child of the span open on the
*producing* side, carried purely through `EventBusMessage.headers` — the
same dict a real worker reads off Redis Streams.
"""

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from app.core.tracing import extract_trace_context, inject_trace_headers


def _tracer():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("test"), exporter


def test_injected_headers_carry_a_w3c_traceparent() -> None:
    tracer, _exporter = _tracer()
    headers: dict[str, str] = {}
    with tracer.start_as_current_span("producer.publish"):
        inject_trace_headers(headers)
    assert "traceparent" in headers
    assert headers["traceparent"].count("-") == 3  # version-traceid-spanid-flags


def test_a_span_extracted_from_headers_is_a_child_of_the_producing_span() -> None:
    tracer, exporter = _tracer()
    headers: dict[str, str] = {}

    with tracer.start_as_current_span("producer.publish") as producer_span:
        inject_trace_headers(headers)
        producer_trace_id = producer_span.get_span_context().trace_id

    # Simulates a worker on the other side of a Redis Streams hop, with
    # nothing shared but the headers dict that traveled on the message.
    parent_context = extract_trace_context(headers)
    with tracer.start_as_current_span("consumer.handle", context=parent_context) as consumer_span:
        consumer_ctx = consumer_span.get_span_context()

    assert consumer_ctx.trace_id == producer_trace_id

    finished = {span.name: span for span in exporter.get_finished_spans()}
    consumer_recorded = finished["consumer.handle"]
    producer_recorded = finished["producer.publish"]
    assert consumer_recorded.parent is not None
    assert consumer_recorded.parent.span_id == producer_recorded.context.span_id


def test_extracting_from_headers_with_no_traceparent_starts_a_fresh_trace() -> None:
    """A message from before tracing existed, or a test double that never
    injected anything, must not be an error — just a new root span."""
    tracer, _exporter = _tracer()
    parent_context = extract_trace_context({})
    with tracer.start_as_current_span("consumer.handle", context=parent_context) as span:
        assert span.get_span_context().is_valid


def test_extract_trace_context_accepts_none() -> None:
    context = extract_trace_context(None)
    assert context is not None


# ---------------------------------------------------------------------------
# The full pipeline hop, through real production code
# ---------------------------------------------------------------------------


async def test_a_real_ingest_to_parse_hop_produces_one_connected_trace(monkeypatch) -> None:
    """The property the phase asks for, proven end to end rather than at
    the primitive level: `IngestionService.ingest()` publishes a raw event
    with trace headers attached, and `ParserWorker.handle()` — reading that
    exact message back off the bus — opens a span that is a child of it.
    Nothing here is a fake; both are the real pipeline code, wired through
    a real `InMemoryEventBus`, with only the two modules' `tracer` objects
    swapped for ones bound to a capturing exporter instead of whatever the
    process-wide provider happens to be."""
    import uuid

    import app.services.ingestion as ingestion_module
    import app.workers.parser_worker as parser_worker_module
    from app.collectors.rest import RestCollector
    from app.core.eventbus import TOPIC_EVENTS_RAW, InMemoryEventBus
    from app.core.redis import get_redis
    from app.services.ingestion import IngestionService
    from app.workers.parser_worker import ParserWorker

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    test_tracer = provider.get_tracer("test-pipeline")
    monkeypatch.setattr(ingestion_module, "tracer", test_tracer)
    monkeypatch.setattr(parser_worker_module, "tracer", test_tracer)

    bus = InMemoryEventBus()
    ingestion = IngestionService(bus=bus, redis=get_redis(), max_payload_bytes=1024)
    parser = ParserWorker(bus=bus)

    collector = RestCollector(collector_id="trace-test-collector")
    event = collector.build_event(
        tenant_id=uuid.uuid4(),
        raw_payload=b"<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password for root from 10.0.0.9",
    )

    result = await ingestion.ingest(event)
    [raw_message] = await bus.peek(TOPIC_EVENTS_RAW)
    await parser.handle(raw_message)

    spans = {span.name: span for span in exporter.get_finished_spans()}
    assert "ingestion.ingest" in spans
    assert "parser.handle" in spans
    ingest_span = spans["ingestion.ingest"]
    parse_span = spans["parser.handle"]

    assert result.outcome.value == "accepted"
    assert parse_span.context.trace_id == ingest_span.context.trace_id
    assert parse_span.parent is not None
    assert parse_span.parent.span_id == ingest_span.context.span_id
