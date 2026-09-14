"""Alert worker: `detections.created` + `correlations.created` -> alerts.

Run with:  python -m app.workers.alert_worker

This is where machine output becomes human work. Three rules govern what
gets through:

- **Dry-run detections never become alerts.** A rule in `testing` status is
  being evaluated on live traffic precisely so it can be judged without
  waking anybody; if its output alerted, "testing" would mean nothing.
- **Repeats fold into the alert they repeat.** Sixty brute-force firings
  against one account are one alert with sixty occurrences. The alternative
  is a queue nobody can read, and alert fatigue is an attack surface in its
  own right (THREAT_MODEL.md §3.4).
- **Only genuinely new alerts are published.** `alerts.created` is what
  notifications and (Phase 15) playbooks hang off, so a fifty-first
  occurrence must not page anyone.

Everything is written in one transaction per message: the alert, its
transition row, and its audit trail commit together or not at all.
"""

import asyncio
import contextlib
import json
import logging
import signal
import uuid
from typing import Any

from app.core.config import get_settings
from app.core.db import tenant_scoped_session
from app.core.eventbus import (
    TOPIC_ALERTS_CREATED,
    TOPIC_CORRELATIONS_CREATED,
    TOPIC_DETECTIONS_CREATED,
    EventBus,
    EventBusMessage,
    consumer_identity,
    get_event_bus,
)
from app.core.logging import configure_logging
from app.core.observability import (
    combine,
    postgres_ready,
    redis_ready,
    start_observability_server,
)
from app.core.tracing import (
    configure_tracing,
    extract_trace_context,
    get_tracer,
    inject_trace_headers,
)
from app.services.alerts import AlertInput, create_or_update

logger = logging.getLogger(__name__)
tracer = get_tracer(__name__)

CONSUMER_GROUP = "alerting"
# Below this score an alert is noise in a queue rather than work: the
# detection is still recorded and searchable, it just does not become
# somebody's task. Configurable, because where that line sits is a SOC
# staffing decision, not an engineering one.
DEFAULT_MIN_RISK_SCORE = 0


def detection_to_alert(document: dict[str, Any]) -> AlertInput | None:
    """Builds an alert from a detection, or returns None if it should not
    become one."""
    if document.get("dry_run"):
        return None
    tenant_id = _tenant(document)
    if tenant_id is None:
        return None

    entity = document.get("entity") or {}
    evidence = document.get("evidence") or {}
    rule_key = str(document.get("rule_id") or "unknown")

    return AlertInput(
        tenant_id=tenant_id,
        source="detection",
        rule_key=rule_key,
        title=str(document.get("rule_name") or rule_key)[:300],
        description=_describe_detection(document, entity),
        severity=str(document.get("severity") or "medium"),
        confidence=int(document.get("confidence") or 50),
        risk_score=int(document.get("risk_score") or 0),
        risk_bucket=document.get("risk_bucket"),
        risk_explanation=document.get("risk_explanation") or {},
        # The rule plus the entity it fired about: the same rule firing for
        # two different users is two different problems, and for the same
        # user twice is one.
        dedup_key=f"detection:{rule_key}:{document.get('entity_summary') or ''}",
        event_ids=[str(value) for value in (document.get("event_ids") or [])],
        detection_ids=[str(document.get("detection_id"))] if document.get("detection_id") else [],
        evidence=evidence if isinstance(evidence, dict) else {},
        mitre_techniques=[str(value) for value in (document.get("mitre_attack") or [])],
        affected_user=_entity_value(entity, evidence, "user.name", ("user", "name")),
        affected_host=_entity_value(entity, evidence, "hostname", ("hostname",)),
        source_ip=_entity_value(entity, evidence, "source_ip", ("source_ip",)),
        destination_ip=_entity_value(entity, evidence, "destination_ip", ("destination_ip",)),
    )


def correlation_to_alert(document: dict[str, Any]) -> AlertInput | None:
    tenant_id = _tenant(document)
    if tenant_id is None:
        return None

    entity = document.get("entity") or {}
    correlation_id = str(document.get("correlation_id") or "unknown")
    stages = document.get("stages_matched") or []
    entity_text = ", ".join(f"{key}={value}" for key, value in sorted(entity.items()))

    return AlertInput(
        tenant_id=tenant_id,
        source="correlation",
        correlation_id=correlation_id,
        title=str(document.get("name") or correlation_id)[:300],
        description=(
            f"{correlation_id} matched for {entity_text or 'an unidentified entity'}: "
            f"{' → '.join(str(stage) for stage in stages)} "
            f"over {document.get('span_seconds', 0)}s."
        ),
        severity=str(document.get("severity") or "high"),
        confidence=int(document.get("confidence") or 50),
        risk_score=int(document.get("risk_score") or 0),
        risk_bucket=document.get("risk_bucket"),
        risk_explanation=document.get("risk_explanation") or {},
        dedup_key=f"correlation:{correlation_id}:{entity_text}",
        event_ids=[str(value) for value in (document.get("event_ids") or [])],
        detection_ids=[],
        # The timeline is the whole point of a correlation alert: an analyst
        # opening it should see the chain, not go and rebuild it.
        evidence={
            "timeline": document.get("timeline") or [],
            "first_seen": document.get("first_seen"),
            "last_seen": document.get("last_seen"),
            "stages_matched": stages,
        },
        mitre_techniques=[str(value) for value in (document.get("mitre_attack") or [])],
        affected_user=entity.get("user.name"),
        affected_host=entity.get("hostname"),
        source_ip=entity.get("source_ip"),
    )


def _tenant(document: dict[str, Any]) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(document.get("tenant_id")))
    except (TypeError, ValueError):
        return None


def _entity_value(
    entity: dict[str, Any],
    evidence: dict[str, Any],
    entity_key: str,
    evidence_path: tuple[str, ...],
) -> str | None:
    value = entity.get(entity_key)
    if value:
        return str(value)
    current: Any = evidence
    for part in evidence_path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return str(current) if current else None


def _describe_detection(document: dict[str, Any], entity: dict[str, Any]) -> str:
    entity_text = ", ".join(f"{key}={value}" for key, value in sorted(entity.items()))
    techniques = ", ".join(str(value) for value in (document.get("mitre_attack") or []))
    parts = [f"{document.get('rule_name') or document.get('rule_id')} fired"]
    if entity_text:
        parts.append(f"for {entity_text}")
    if techniques:
        parts.append(f"({techniques})")
    return " ".join(parts) + "."


class AlertWorker:
    def __init__(
        self,
        *,
        bus: EventBus,
        consumer_name: str = "alerting-1",
        output_topic: str = TOPIC_ALERTS_CREATED,
        dedup_window_minutes: int | None = None,
        min_risk_score: int | None = None,
    ) -> None:
        settings = get_settings()
        self._bus = bus
        self._consumer_name = consumer_name
        self._output_topic = output_topic
        self._window = (
            dedup_window_minutes
            if dedup_window_minutes is not None
            else settings.alert_dedup_window_minutes
        )
        self._min_risk_score = (
            min_risk_score if min_risk_score is not None else settings.alert_min_risk_score
        )

    async def accept(self, topic: str, message: EventBusMessage) -> None:
        # The last hop of "ingestion -> detection -> alert": a child of
        # whatever the detection or correlation worker injected into this
        # message's headers (docs/OBSERVABILITY.md).
        with tracer.start_as_current_span(
            "alert.create", context=extract_trace_context(message.headers)
        ):
            try:
                document = json.loads(message.payload)
            except (json.JSONDecodeError, ValueError) as exc:
                await self._reject(topic, message, f"undecodable payload: {exc}")
                return
            if not isinstance(document, dict):
                await self._reject(topic, message, "payload is not an object")
                return

            payload = (
                correlation_to_alert(document)
                if topic == TOPIC_CORRELATIONS_CREATED
                else detection_to_alert(document)
            )

            if payload is not None and payload.risk_score >= self._min_risk_score:
                async with tenant_scoped_session(payload.tenant_id) as db:
                    alert, created = await create_or_update(
                        db, payload, window_minutes=self._window
                    )
                    summary = {
                        "alert_id": str(alert.id),
                        "display_id": alert.display_id,
                        "tenant_id": str(alert.tenant_id),
                        "title": alert.title,
                        "severity": alert.severity,
                        "risk_score": alert.risk_score,
                        "risk_bucket": alert.risk_bucket,
                        "status": alert.status,
                        "source": alert.source,
                        "mitre_techniques": list(alert.mitre_techniques),
                        "occurrence_count": alert.occurrence_count,
                    }
                    await db.commit()

                if created:
                    # Only new alerts are published: notifications and
                    # playbooks hang off this topic, and a fifty-first
                    # occurrence must not page anyone.
                    await self._publish(summary)

            if message.message_id is not None:
                await self._bus.ack(topic, CONSUMER_GROUP, message.message_id)

    async def _publish(self, summary: dict[str, Any]) -> None:
        await self._bus.publish(
            self._output_topic,
            EventBusMessage(
                tenant_id=summary["tenant_id"],
                key=summary["alert_id"],
                payload=json.dumps(summary).encode(),
                headers=inject_trace_headers(
                    {
                        "severity": str(summary["severity"]),
                        "risk_bucket": str(summary.get("risk_bucket") or ""),
                    }
                ),
            ),
        )

    async def _reject(self, topic: str, message: EventBusMessage, reason: str) -> None:
        await self._bus.dead_letter(topic, message, reason=reason)
        if message.message_id is not None:
            await self._bus.ack(topic, CONSUMER_GROUP, message.message_id)

    async def _consume(self, topic: str, stop: asyncio.Event) -> None:
        async for message in self._bus.subscribe(topic, CONSUMER_GROUP, self._consumer_name):
            await self.accept(topic, message)
            if stop.is_set():
                break

    async def run(self, stop: asyncio.Event) -> None:
        tasks = [
            asyncio.create_task(self._consume(topic, stop))
            for topic in (TOPIC_DETECTIONS_CREATED, TOPIC_CORRELATIONS_CREATED)
        ]
        try:
            done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task


async def run() -> None:
    configure_logging()
    configure_tracing()
    worker = AlertWorker(bus=get_event_bus(), consumer_name=consumer_identity("alerting"))
    obs = await start_observability_server(
        get_settings().metrics_port, ready_check=combine(redis_ready, postgres_ready)
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    logger.info("alert worker running")
    try:
        await worker.run(stop)
    finally:
        obs.close()
        await obs.wait_closed()
    logger.info("alert worker stopped")


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
