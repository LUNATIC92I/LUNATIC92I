# Parser grammars & fixtures

Shared parser grammars, sample payloads, and format fixtures used by the
parser engine in `backend/app/parsers/` for both implementation and its
mandatory per-format positive/negative test cases (spec §29). Kept outside
`backend/` so fixtures can be reused by tooling other than the backend test
suite (e.g. a future standalone collector's own tests).

Populated starting Phase 4 (Normalization). See `docs/DEVELOPMENT_PLAN.md`
(Phase 4) for the supported format list and acceptance criteria.
