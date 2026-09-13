"""Enrichment provider interface and pipeline (ARCHITECTURE.md §7.4).

The governing rule, stated in the Phase 0 data flow (step 5): **enrichment
must never block ingestion**. An enrichment source is by nature something
that can be slow, down, or rate-limited — an asset database, a GeoIP
service, a threat-intel feed. If any of those can stop an event from being
indexed, then the SIEM stops seeing the estate the moment a side service has
a bad day, which is precisely when visibility matters most.

So every provider is:

- **time-boxed** — it gets a deadline, and exceeding it is not an error, it
  is just an absent field;
- **failure-isolated** — a provider that raises degrades its own fields
  only, and the event proceeds;
- **recorded** — degraded events carry `enrichment_partial: true` and the
  names of the providers that failed, so an analyst can tell "this event
  had no asset context" apart from "this asset has no context".
"""

import abc
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, ClassVar

from app.core import metrics

logger = logging.getLogger(__name__)

DEFAULT_PROVIDER_TIMEOUT_SECONDS = 2.0


@dataclass
class EnrichmentResult:
    """Fields to merge into the document. Nested dicts are merged one level
    deep so two providers can both contribute to e.g. `asset` without
    clobbering each other."""

    fields: dict[str, Any] = field(default_factory=dict)


class EnrichmentProvider(abc.ABC):
    name: ClassVar[str]

    @abc.abstractmethod
    async def enrich(self, document: dict[str, Any]) -> EnrichmentResult:
        """Returns fields to merge. Raising is allowed — the pipeline
        contains it — but returning empty is preferred for the ordinary
        "nothing known about this entity" case, which is not a failure."""


class EnrichmentPipeline:
    def __init__(
        self,
        providers: tuple[EnrichmentProvider, ...],
        *,
        timeout_seconds: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    ) -> None:
        self._providers = providers
        self._timeout_seconds = timeout_seconds

    async def enrich(self, document: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(document)
        failures: list[str] = []

        # Providers run concurrently: they are independent I/O, and running
        # them in series would make the pipeline's latency the sum of every
        # provider's worst case.
        results = await asyncio.gather(
            *(self._run_provider(provider, document) for provider in self._providers),
            return_exceptions=False,
        )

        for provider, result in zip(self._providers, results, strict=True):
            if result is None:
                failures.append(provider.name)
                continue
            _merge(enriched, result.fields)

        if failures:
            enriched["enrichment_partial"] = True
            enriched["enrichment_errors"] = failures
        return enriched

    async def _run_provider(
        self, provider: EnrichmentProvider, document: dict[str, Any]
    ) -> EnrichmentResult | None:
        """Returns None if the provider failed or timed out — never raises."""
        try:
            async with asyncio.timeout(self._timeout_seconds):
                return await provider.enrich(document)
        except TimeoutError:
            logger.warning("enrichment provider timed out", extra={"provider": provider.name})
            metrics.enrichment_failures_total.labels(
                provider=provider.name, reason="timeout"
            ).inc()
            return None
        except Exception:  # noqa: BLE001  a broken provider must not lose the event
            logger.exception("enrichment provider failed", extra={"provider": provider.name})
            metrics.enrichment_failures_total.labels(provider=provider.name, reason="error").inc()
            return None


def _merge(target: dict[str, Any], additions: dict[str, Any]) -> None:
    for key, value in additions.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            target[key] = {**target[key], **value}
        else:
            target[key] = value
