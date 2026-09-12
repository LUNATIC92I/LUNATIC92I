# Collectors

Standalone collector binaries/configs that are **not** embedded in the
`backend` API image (e.g. a lightweight forwarder deployed on customer
infrastructure). The `Collector` interface and in-process collector
implementations used by the Ingestion Gateway live in
`backend/app/collectors/` — this directory is for anything that ships and
runs separately from the backend.

Populated starting Phase 3 (Event ingestion). See `ARCHITECTURE.md` §5 for
the collector list and `docs/DEVELOPMENT_PLAN.md` (Phase 3) for acceptance
criteria.
