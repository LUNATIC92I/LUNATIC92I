"""The playbook engine: runs a definition's steps in order, halting at the
first destructive step with no APPROVED record instead of executing it
(ARCHITECTURE.md §7.5).

**Dry run previews every step, destructive or not, and never creates an
approval request.** This is the "dry-run-vs-execute divergence" the phase's
own test set checks for: the two paths must actually diverge — a dry run
that quietly executed a destructive step, or that left a pending approval
behind for a run nobody asked to execute, would defeat the point of asking
for a preview first.

**A halted run resumes, it does not replay.** `PlaybookRun.current_step` is
the only source of truth for where a run is; `run_playbook()` is called
again after an approval decision and always starts from there, so an
approved step's non-idempotent side effects (like `notify_analyst` writing
a note) only ever happen once per run.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.models.alerts import Alert
from app.models.incidents import Incident
from app.models.playbooks import Playbook, PlaybookActionApproval, PlaybookRun
from app.playbooks.actions import (
    ACTION_REGISTRY,
    ActionResult,
    ActionTargetNotFound,
    ApprovalRequired,
    DestructiveAction,
    require_approved,
)
from app.playbooks.context import PlaybookContext
from app.playbooks.schema import PlaybookDefinition


@dataclass
class StepOutcome:
    step_index: int
    action: str
    kind: str  # "preview" | "result" | "awaiting_approval" | "error"
    summary: str
    details: dict[str, object]


async def _load_context(
    db: AsyncSession, run: PlaybookRun, *, actor_id: uuid.UUID | None
) -> PlaybookContext:
    alert = await db.get(Alert, run.alert_id) if run.alert_id else None
    incident = await db.get(Incident, run.incident_id) if run.incident_id else None
    return PlaybookContext(
        db=db, tenant_id=run.tenant_id, actor_id=actor_id, alert=alert, incident=incident
    )


async def _create_pending_approval(
    db: AsyncSession,
    *,
    run: PlaybookRun,
    step_index: int,
    action_name: str,
    preview: dict[str, object],
    requested_by: uuid.UUID,
) -> PlaybookActionApproval:
    approval = PlaybookActionApproval(
        tenant_id=run.tenant_id,
        playbook_run_id=run.id,
        step_index=step_index,
        action_name=action_name,
        preview=preview,
        status="PENDING_APPROVAL",
        requested_by=requested_by,
    )
    db.add(approval)
    await db.flush()
    await record_audit_event(
        db,
        tenant_id=run.tenant_id,
        actor_id=requested_by,
        action="PLAYBOOK_APPROVAL_REQUESTED",
        object_type="playbook_action_approval",
        object_id=str(approval.id),
        after_state={"action": action_name, "step_index": step_index},
        result="success",
    )
    return approval


async def run_playbook(
    db: AsyncSession,
    *,
    run: PlaybookRun,
    playbook: Playbook,
    actor_id: uuid.UUID | None,
) -> list[StepOutcome]:
    """Executes (or dry-runs) `run` starting at `run.current_step`. Mutates
    `run` in place — status, `current_step`, `results` — and returns the
    outcomes produced by this call only (not the whole run's history)."""
    definition = PlaybookDefinition.model_validate(playbook.definition)
    context = await _load_context(db, run, actor_id=actor_id)
    outcomes: list[StepOutcome] = []

    run.status = "RUNNING"
    for index in range(run.current_step, len(definition.steps)):
        step = definition.steps[index]
        action = ACTION_REGISTRY[step.action]
        context.params = dict(step.params)

        if run.dry_run:
            preview = await action.dry_run(context)
            outcome = StepOutcome(index, step.action, "preview", preview.summary, preview.details)
            outcomes.append(outcome)
            run.results = [*run.results, _outcome_dict(outcome)]
            continue

        try:
            if isinstance(action, DestructiveAction):
                try:
                    grant = await require_approved(
                        context, run_id=run.id, step_index=index, action_name=step.action
                    )
                except ApprovalRequired:
                    if actor_id is None:
                        raise
                    preview = await action.dry_run(context)
                    await _create_pending_approval(
                        db,
                        run=run,
                        step_index=index,
                        action_name=step.action,
                        preview=preview.details,
                        requested_by=actor_id,
                    )
                    run.status = "AWAITING_APPROVAL"
                    run.current_step = index
                    outcomes.append(
                        StepOutcome(
                            index,
                            step.action,
                            "awaiting_approval",
                            preview.summary,
                            preview.details,
                        )
                    )
                    return outcomes
                result: ActionResult = await action.execute(context, grant)
                approval = await db.get(PlaybookActionApproval, grant.approval_id)
                assert approval is not None  # nosec B101 - require_approved just confirmed this row
                approval.status = "EXECUTED"
            else:
                result = await action.execute(context)
        except (ActionTargetNotFound, ApprovalRequired) as exc:
            run.status = "FAILED"
            run.error = str(exc)
            run.current_step = index
            outcome = StepOutcome(index, step.action, "error", str(exc), {})
            outcomes.append(outcome)
            run.results = [*run.results, _outcome_dict(outcome)]
            return outcomes

        outcome = StepOutcome(index, step.action, "result", result.summary, result.details)
        outcomes.append(outcome)
        run.results = [*run.results, _outcome_dict(outcome)]
        run.current_step = index + 1
        if context.incident is not None:
            run.incident_id = context.incident.id

    run.status = "COMPLETED"
    return outcomes


def _outcome_dict(outcome: StepOutcome) -> dict[str, object]:
    return {
        "step_index": outcome.step_index,
        "action": outcome.action,
        "kind": outcome.kind,
        "summary": outcome.summary,
        "details": outcome.details,
    }


__all__ = ["StepOutcome", "run_playbook", "require_approved"]
