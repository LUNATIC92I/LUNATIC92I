# Playbooks

YAML SOAR playbook definitions, loaded by `backend/app/playbooks/loader.py`
and installed into a tenant at registration (mirroring `rules/` for
detection rules). See `docs/DEVELOPMENT_PLAN.md` (Phase 15) for the
playbook DSL, the action set, and the approval state machine, and
`ARCHITECTURE.md` §7.5 for the destructive-action contract.

Each file is one playbook: a `key` (`PB-NNN`), a `trigger_type`
(`manual` or `alert`), and an ordered `steps` list naming a registered
action (`backend/app/playbooks/actions.py::ACTION_REGISTRY`) and its
params. A step naming an unknown action is a load-time error, not a
runtime surprise.

Shipped:

- `PB-001` — Brute Force Triage: enrich -> IOC check -> reputation ->
  incident -> notify. Entirely non-destructive; runs to completion in one
  call.
- `PB-002` — Contain Compromised Account: enrich -> `disable_user`
  (destructive; halts for approval).
- `PB-003` — Contain Host: enrich -> `isolate_host` (destructive; halts for
  approval).
