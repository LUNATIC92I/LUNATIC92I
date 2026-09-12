# Deployable pipeline workers (ingestion consumer, parsing, normalization,
# enrichment, detection, correlation) — each subscribes to one EventBus topic
# and runs as its own process/container, separate from the API (Phase 3+).
