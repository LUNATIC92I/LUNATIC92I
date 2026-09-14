"""Playbook CRUD, run orchestration, and the approval workflow (spec §18).

The approval half of this module is the one thing in the whole platform
where "who can act" and "who can authorize that act" must never be the same
answer for the same request — see `THREAT_MODEL.md §3.6` and
`app.models.playbooks.PlaybookActionApproval`'s dual-control CHECK
constraint. `approve_action()` re-asserts the same rule in Python before
ever reaching the database, so the error an approver sees names the actual
problem instead of surfacing as an opaque constraint violation.
"""

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_audit_event
from app.core.config import get_settings
from app.core.metrics import playbook_approvals_total, playbook_runs_total
from app.models.alerts import Alert
from app.models.playbooks import Playbook, PlaybookActionApproval, PlaybookRun
from app.playbooks.actions import ACTION_REGISTRY
from app.playbooks.engine import StepOutcome, run_playbook
from app.playbooks.loader import PlaybookLoadError, load_playbooks
from app.playbooks.schema import PlaybookDefinition


class PlaybookNotFound(LookupError):
    pass


class UnknownAction(ValueError):
    """A step named an action outside `ACTION_REGISTRY`. Caught here rather
    than at run time: the alternative is a `KeyError` deep in the engine the
    first time someone runs the playbook, on a step that could have been
    rejected at creation instead — the same reasoning as the YAML loader's
    own check (`app/playbooks/loader.py`), applied to API-submitted
    playbooks too."""


class RunNotFound(LookupError):
    pass


class ApprovalNotFound(LookupError):
    pass


class DuplicatePlaybook(ValueError):
    pass


class SelfApprovalError(PermissionError):
    """Dual control, asserted in Python ahead of the database CHECK
    constraint that also enforces it — see the module docstring."""


class InvalidApprovalState(ValueError):
    pass


def default_playbooks_directory() -> Path:
    return Path(get_settings().playbooks_path)


async def _get_by_key(db: AsyncSession, tenant_id: uuid.UUID, key: str) -> Playbook | None:
    stmt = select(Playbook).where(Playbook.tenant_id == tenant_id, Playbook.key == key)
    return (await db.execute(stmt)).scalar_one_or_none()


async def get_playbook(db: AsyncSession, tenant_id: uuid.UUID, key: str) -> Playbook:
    playbook = await _get_by_key(db, tenant_id, key)
    if playbook is None:
        raise PlaybookNotFound(key)
    return playbook


async def list_playbooks(db: AsyncSession, tenant_id: uuid.UUID) -> list[Playbook]:
    stmt = select(Playbook).where(Playbook.tenant_id == tenant_id).order_by(Playbook.key)
    return list((await db.execute(stmt)).scalars())


async def create_playbook(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    definition: PlaybookDefinition,
    actor_id: uuid.UUID | None,
    actor_ip: str | None = None,
) -> Playbook:
    if await _get_by_key(db, tenant_id, definition.key) is not None:
        raise DuplicatePlaybook(definition.key)
    unknown = [s.action for s in definition.steps if s.action not in ACTION_REGISTRY]
    if unknown:
        raise UnknownAction(f"unknown action(s): {', '.join(unknown)}")

    playbook = Playbook(
        tenant_id=tenant_id,
        key=definition.key,
        name=definition.name,
        description=definition.description,
        trigger_type=definition.trigger_type,
        definition=definition.model_dump(mode="json"),
        created_by=actor_id,
    )
    db.add(playbook)
    await db.flush()
    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        actor_ip=actor_ip,
        action="CREATE_PLAYBOOK",
        object_type="playbook",
        object_id=playbook.key,
        after_state={"name": playbook.name, "steps": len(definition.steps)},
        result="success",
    )
    return playbook


async def install_default_playbooks(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    actor_id: uuid.UUID | None = None,
    directory: Path | None = None,
) -> list[str]:
    """Installs the shipped playbook pack into a tenant. Idempotent and
    non-destructive, mirroring `detection_rules.install_default_rules`: a
    key the tenant already has is skipped, never overwritten."""
    directory = directory or default_playbooks_directory()
    result = load_playbooks(directory)
    if not result.ok:
        raise PlaybookLoadError("; ".join(result.errors))

    installed: list[str] = []
    for definition in result.playbooks:
        if await _get_by_key(db, tenant_id, definition.key) is not None:
            continue
        await create_playbook(db, tenant_id=tenant_id, definition=definition, actor_id=actor_id)
        installed.append(definition.key)
    return installed


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------


async def start_run(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    playbook: Playbook,
    actor_id: uuid.UUID | None,
    dry_run: bool,
    alert_id: uuid.UUID | None = None,
) -> tuple[PlaybookRun, list[StepOutcome]]:
    if alert_id is not None:
        alert = await db.scalar(
            select(Alert).where(Alert.tenant_id == tenant_id, Alert.id == alert_id)
        )
        if alert is None:
            raise ValueError(f"no alert {alert_id} in this tenant")

    run = PlaybookRun(
        tenant_id=tenant_id,
        playbook_id=playbook.id,
        status="PENDING",
        dry_run=dry_run,
        triggered_by=actor_id,
        alert_id=alert_id,
    )
    db.add(run)
    await db.flush()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action="PLAYBOOK_RUN_STARTED",
        object_type="playbook_run",
        object_id=str(run.id),
        after_state={"playbook": playbook.key, "dry_run": dry_run},
        result="success",
    )

    outcomes = await run_playbook(db, run=run, playbook=playbook, actor_id=actor_id)
    playbook_runs_total.labels(status=run.status, dry_run=str(dry_run).lower()).inc()
    return run, outcomes


async def get_run(db: AsyncSession, tenant_id: uuid.UUID, run_id: uuid.UUID) -> PlaybookRun:
    run = await db.scalar(
        select(PlaybookRun).where(PlaybookRun.tenant_id == tenant_id, PlaybookRun.id == run_id)
    )
    if run is None:
        raise RunNotFound(str(run_id))
    return run


async def list_runs(db: AsyncSession, tenant_id: uuid.UUID) -> list[PlaybookRun]:
    stmt = (
        select(PlaybookRun)
        .where(PlaybookRun.tenant_id == tenant_id)
        .order_by(PlaybookRun.started_at.desc())
    )
    return list((await db.execute(stmt)).scalars())


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------


async def list_pending_approvals(
    db: AsyncSession, tenant_id: uuid.UUID
) -> list[PlaybookActionApproval]:
    stmt = (
        select(PlaybookActionApproval)
        .where(
            PlaybookActionApproval.tenant_id == tenant_id,
            PlaybookActionApproval.status == "PENDING_APPROVAL",
        )
        .order_by(PlaybookActionApproval.requested_at)
    )
    return list((await db.execute(stmt)).scalars())


async def get_approval(
    db: AsyncSession, tenant_id: uuid.UUID, approval_id: uuid.UUID
) -> PlaybookActionApproval:
    approval = await db.scalar(
        select(PlaybookActionApproval).where(
            PlaybookActionApproval.tenant_id == tenant_id,
            PlaybookActionApproval.id == approval_id,
        )
    )
    if approval is None:
        raise ApprovalNotFound(str(approval_id))
    return approval


async def approve_action(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    approval_id: uuid.UUID,
    approver_id: uuid.UUID,
    actor_ip: str | None = None,
) -> tuple[PlaybookActionApproval, PlaybookRun, list[StepOutcome]]:
    """Approves a pending destructive step and resumes its run. Raises
    `SelfApprovalError` if the approver is the same person who requested
    it — checked here, ahead of the database CHECK constraint, so the
    caller gets a clear 403 rather than an internal server error surfacing
    a raw constraint violation."""
    approval = await get_approval(db, tenant_id, approval_id)
    if approval.status != "PENDING_APPROVAL":
        raise InvalidApprovalState(f"approval is {approval.status}, not PENDING_APPROVAL")
    if approver_id == approval.requested_by:
        raise SelfApprovalError("the requester cannot approve their own destructive action")

    approval.status = "APPROVED"
    approval.decided_by = approver_id
    approval.decided_at = datetime.now(UTC)
    await db.flush()
    playbook_approvals_total.labels(outcome="approved").inc()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=approver_id,
        actor_ip=actor_ip,
        action="PLAYBOOK_APPROVAL_GRANTED",
        object_type="playbook_action_approval",
        object_id=str(approval.id),
        before_state={"status": "PENDING_APPROVAL"},
        after_state={"status": "APPROVED", "requested_by": str(approval.requested_by)},
        result="success",
    )

    run = await get_run(db, tenant_id, approval.playbook_run_id)
    playbook = await db.get(Playbook, run.playbook_id)
    assert playbook is not None  # nosec B101 - a run always references a real playbook row
    outcomes = await run_playbook(db, run=run, playbook=playbook, actor_id=run.triggered_by)
    playbook_runs_total.labels(status=run.status, dry_run=str(run.dry_run).lower()).inc()
    return approval, run, outcomes


async def reject_action(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    approval_id: uuid.UUID,
    approver_id: uuid.UUID,
    reason: str,
    actor_ip: str | None = None,
) -> PlaybookActionApproval:
    approval = await get_approval(db, tenant_id, approval_id)
    if approval.status != "PENDING_APPROVAL":
        raise InvalidApprovalState(f"approval is {approval.status}, not PENDING_APPROVAL")
    if approver_id == approval.requested_by:
        raise SelfApprovalError("the requester cannot reject their own request")

    approval.status = "REJECTED"
    approval.decided_by = approver_id
    approval.reason = reason
    approval.decided_at = datetime.now(UTC)
    playbook_approvals_total.labels(outcome="rejected").inc()

    run = await get_run(db, tenant_id, approval.playbook_run_id)
    run.status = "REJECTED"
    run.error = f"step {approval.step_index} ({approval.action_name}) rejected: {reason}"
    playbook_runs_total.labels(status=run.status, dry_run=str(run.dry_run).lower()).inc()

    await record_audit_event(
        db,
        tenant_id=tenant_id,
        actor_id=approver_id,
        actor_ip=actor_ip,
        action="PLAYBOOK_APPROVAL_REJECTED",
        object_type="playbook_action_approval",
        object_id=str(approval.id),
        after_state={"status": "REJECTED", "reason": reason},
        result="success",
    )
    return approval
