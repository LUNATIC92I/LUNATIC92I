# SOAR Playbooks

A detection or a hunt tells an analyst something is worth looking at. A
playbook is what happens next: a fixed sequence of steps — enrich, check,
score, open a case, notify, and sometimes act — run automatically or
on demand, with the destructive steps stopped at the door until a second
person says yes (spec §18; ARCHITECTURE.md §7.5).

## Playbooks are data, never code

A playbook step names a registered action by its fixed identifier
(`enrich_ip`, `disable_user`, ...) and a dict of params — never an
expression, never `eval`. The same reasoning that keeps the detection rule
DSL free of arbitrary evaluation (THREAT_MODEL.md §3.4) applies here with
higher stakes: a playbook step that could name arbitrary behavior would be
a remote-code-execution path directly into the platform's most
consequential actions (`app/playbooks/schema.py`).

A step's `action` is checked against the real action registry
(`app/playbooks/actions.py::ACTION_REGISTRY`) at the point the playbook is
defined, not the first time it runs — both for the shipped YAML pack
(`app/playbooks/loader.py`) and for one submitted through the API
(`app/services/playbooks.py::create_playbook`). A typo'd action name is a
422 at creation time, never an unhandled `KeyError` the first time someone
runs it.

## The action set

| Action | Destructive | What it does |
|---|---|---|
| `enrich_ip` | no | Asset and network-privacy context for an address |
| `enrich_host` | no | Asset context for a hostname |
| `enrich_user` | no | Account context for an email/username |
| `check_ioc` | no | Looks the alert's source IP up against this tenant's own indicator set (Phase 9) |
| `calculate_reputation` | no | A local heuristic over the IOC match and asset criticality from prior steps |
| `create_incident` | no | Opens an incident (Phase 12), carrying the reputation finding into its description |
| `notify_analyst` | no | Writes a note on the incident and an audit entry |
| `disable_user` | **yes** | Sets the account's `is_active` to false |
| `isolate_host` | **yes** | Sets the asset's `is_isolated` to true |

**"Reputation" and "notify" are honest about what they are.** There is no
external threat-intel vendor integration beyond the IOC set this platform
already manages, and no configured outbound notification channel —
THREAT_MODEL.md §3.6 flags exactly this as a risk (leaked webhook/
integration credentials pivoting into customer infrastructure). So
`calculate_reputation` scores from this tenant's own data rather than
calling a vendor that isn't there, and `notify_analyst` writes to the
incident record and the platform audit log rather than pretending to email
or page anyone. Wiring either to a real feed or a real notification channel
is future work, not a stub disguised as a feature.

**`is_isolated` is the SIEM's own record, not a live signal.** No
integration in this codebase actually drives a firewall or EDR to isolate a
host. `isolate_host` records that isolation was ordered and approved
through this platform — the same distinction as the detection engine
recording that a rule fired, versus a rule actually blocking traffic. A
future EDR/firewall integration would set this field as a side effect of a
real action, not replace what it means.

## Steps hand state to each other

Each step's result is kept in `PlaybookContext.state`, keyed by action name.
`check_ioc`'s match feeds `calculate_reputation`'s score; `calculate_
reputation`'s verdict feeds `create_incident`'s description;
`create_incident`'s incident becomes the target `notify_analyst` writes a
note on. This is the DSL's only "templating" — there is no expression
language, just steps reading what an earlier step already put in a fixed
dict key (`app/playbooks/context.py`).

A step with nothing to act on — `enrich_ip` with neither an alert nor an
`ip` param — raises `ActionTargetNotFound` rather than silently doing
nothing: a step that quietly no-ops is indistinguishable from one that
worked, and a run report that says "enriched 203.0.113.9" when nothing
matched anything is worse than a run that stopped and said why
(`app/playbooks/actions.py`).

## Dry run vs execute — a real divergence, not a flag

A dry run (`POST /playbooks/{key}/run` with `dry_run: true`) previews
**every** step, destructive or not, and never creates an approval record or
mutates anything. An execute run stops at the first destructive step with
no approval and creates one. These two paths must actually diverge — a dry
run that quietly executed a destructive step, or that left a pending
approval behind for a run nobody asked to execute, would defeat the point
of asking for a preview first (`app/playbooks/engine.py`).

## The approval gate: a type, not a convention

A non-destructive action's `execute()` takes only a `PlaybookContext`. A
destructive action's `execute()` additionally requires an `ApprovalGrant` —
an object that can only come from `require_approved()`, which looks up a
real `PlaybookActionApproval` row and confirms its status is `APPROVED` for
this exact run, step, and action.

The engine only calls `execute()` after that lookup succeeds — but the more
important property is that **every destructive action's `execute()` does
the same check again, independently**, before it touches anything
(`DestructiveAction._verify_grant`). Python has no truly private
constructors, so a caller could in principle build an `ApprovalGrant` by
hand; `_verify_grant` re-queries the database for that exact `approval_id`
and confirms it is `APPROVED`, references this tenant, and names this exact
action, before the state mutation happens. The tests in
`app/tests/test_playbooks.py` bypass the engine entirely and call
`DisableUserAction.execute()` / `IsolateHostAction.execute()` directly with
forged, stale, cross-tenant, and wrong-action grants to prove each is
refused — the real security boundary is "does an `APPROVED` row for this
exact step exist," never "did the caller claim to have checked."

## Dual control: requester ≠ approver, enforced three times

The person who triggers a run is never allowed to approve its own
destructive step. This is checked in three independent places
(THREAT_MODEL.md §3.6):

1. `approve_action()` / `reject_action()` in Python, ahead of the database —
   so the caller gets a clear 403 (`SelfApprovalError`) instead of an
   opaque constraint violation.
2. The `ck_playbook_action_approvals_dual_control` CHECK constraint —
   `decided_by IS NULL OR decided_by != requested_by` — so the rule holds
   even for a write that bypasses the service layer entirely.
3. `requested_by` is `NOT NULL`. SQL's three-valued logic treats a `NULL`
   comparison as unknown, not false — a nullable `requested_by` would let
   *any* `decided_by` slip through constraint #2 unchecked. This is a load-
   bearing schema detail, not incidental strictness (`app/models/
   playbooks.py`).

## Resuming, not replaying

`PlaybookRun.current_step` is the single source of truth for where a halted
(`AWAITING_APPROVAL`) run picks back up. When an approval is granted,
`run_playbook()` is called again and starts from `current_step` — never
from the beginning. This matters because some non-destructive actions are
not idempotent: `notify_analyst` writes a note. A run that replayed from
step zero on every resume would write that note again every time a later
destructive step needed approval.

## Installing and running

The shipped pack (`playbooks/`) installs into every new tenant at
registration, the same best-effort, non-blocking pattern as the shipped
detection rule pack — a missing or unreadable playbooks directory must
never prevent creating an organization, and `POST /playbooks/install-
defaults` recovers it later. A key the tenant already has is skipped, never
overwritten.

| Playbook | Trigger | Chain |
|---|---|---|
| `PB-001` Brute Force Triage | alert | enrich → IOC check → reputation → incident → notify (never halts) |
| `PB-002` Contain Compromised Account | alert | enrich → `disable_user` (halts for approval) |
| `PB-003` Contain Host | alert | enrich → `isolate_host` (halts for approval) |

## Permissions

`playbook: read | write | execute | approve`.

| Action | Permission |
|---|---|
| List/get a playbook, list runs/approvals | `playbook:read` |
| Create a playbook, install the default pack | `playbook:write` |
| Run a playbook (dry run or execute) | `playbook:execute` |
| Approve or reject a pending destructive step | `playbook:approve` |

## API

Route order is deliberate: `/playbooks/runs`, `/playbooks/approvals` and
`/playbooks/install-defaults` are registered before the generic
`/playbooks/{key}` — FastAPI matches path operations in registration order,
so a literal segment declared after the catch-all would never be reached (a
request for `/playbooks/runs` would otherwise match `{key}="runs"`).

```
GET    /playbooks                        list this tenant's playbooks
POST   /playbooks                        create a playbook
POST   /playbooks/install-defaults       (re)install the shipped pack
GET    /playbooks/runs                   list runs
GET    /playbooks/runs/{run_id}          fetch one run
GET    /playbooks/approvals              list pending approvals
POST   /playbooks/approvals/{id}/approve approve a pending destructive step
POST   /playbooks/approvals/{id}/reject  reject it, with a reason
GET    /playbooks/{key}                  fetch one playbook
POST   /playbooks/{key}/run              run it (dry_run: true|false, optional alert_id)
```
