"""SOAR playbooks API (spec §18 `/playbooks`).

Route order is deliberate: `/playbooks/runs`, `/playbooks/approvals` and
`/playbooks/install-defaults` are declared before the generic
`/playbooks/{key}` — FastAPI matches path operations in registration order,
so a literal segment declared after the catch-all would never be reached
(a request for `/playbooks/runs` would match `{key}="runs"` instead).
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth.dependencies import AuthContext, require_permission
from app.models.playbooks import Playbook, PlaybookActionApproval, PlaybookRun
from app.playbooks.schema import PlaybookDefinition
from app.schemas.playbooks import (
    ApprovalPublic,
    DefaultPlaybooksInstalled,
    PlaybookCreate,
    PlaybookPublic,
    RejectRequest,
    RunPublic,
    RunRequest,
)
from app.services import playbooks as service

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _uuid(value: str, *, not_found_message: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, not_found_message) from exc


def _playbook_public(playbook: Playbook) -> PlaybookPublic:
    return PlaybookPublic(
        id=str(playbook.id),
        key=playbook.key,
        name=playbook.name,
        description=playbook.description,
        trigger_type=playbook.trigger_type,
        status=playbook.status,
        definition=playbook.definition,
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
    )


def _run_public(run: PlaybookRun, playbook_key: str) -> RunPublic:
    return RunPublic(
        id=str(run.id),
        playbook_key=playbook_key,
        status=run.status,
        dry_run=run.dry_run,
        current_step=run.current_step,
        results=run.results,
        error=run.error,
        started_at=run.started_at,
        completed_at=run.completed_at,
    )


def _approval_public(approval: PlaybookActionApproval) -> ApprovalPublic:
    return ApprovalPublic(
        id=str(approval.id),
        playbook_run_id=str(approval.playbook_run_id),
        step_index=approval.step_index,
        action_name=approval.action_name,
        preview=approval.preview,
        status=approval.status,
        requested_by=str(approval.requested_by) if approval.requested_by else None,
        requested_at=approval.requested_at,
        decided_by=str(approval.decided_by) if approval.decided_by else None,
        decided_at=approval.decided_at,
        reason=approval.reason,
    )


@router.get("", response_model=list[PlaybookPublic])
async def list_playbooks(
    ctx: AuthContext = Depends(require_permission("playbook", "read")),
) -> list[PlaybookPublic]:
    rows = await service.list_playbooks(ctx.db, ctx.user.tenant_id)
    return [_playbook_public(row) for row in rows]


@router.post("", response_model=PlaybookPublic, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    payload: PlaybookCreate,
    request: Request,
    ctx: AuthContext = Depends(require_permission("playbook", "write")),
) -> PlaybookPublic:
    definition = PlaybookDefinition(
        key=payload.key,
        name=payload.name,
        description=payload.description,
        trigger_type=payload.trigger_type,
        steps=payload.steps,
    )
    try:
        playbook = await service.create_playbook(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            definition=definition,
            actor_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.DuplicatePlaybook as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, f"playbook key already exists: {exc}"
        ) from exc
    except service.UnknownAction as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await ctx.db.commit()
    return _playbook_public(playbook)


@router.post("/install-defaults", response_model=DefaultPlaybooksInstalled)
async def install_defaults(
    ctx: AuthContext = Depends(require_permission("playbook", "write")),
) -> DefaultPlaybooksInstalled:
    try:
        installed = await service.install_default_playbooks(
            ctx.db, tenant_id=ctx.user.tenant_id, actor_id=ctx.user.id
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a 422, not a 500
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await ctx.db.commit()
    return DefaultPlaybooksInstalled(installed=installed)


@router.get("/runs", response_model=list[RunPublic])
async def list_runs(
    ctx: AuthContext = Depends(require_permission("playbook", "read")),
) -> list[RunPublic]:
    runs = await service.list_runs(ctx.db, ctx.user.tenant_id)
    keys: dict[uuid.UUID, str] = {}
    result = []
    for run in runs:
        if run.playbook_id not in keys:
            playbook = await ctx.db.get(Playbook, run.playbook_id)
            keys[run.playbook_id] = playbook.key if playbook else "unknown"
        result.append(_run_public(run, keys[run.playbook_id]))
    return result


@router.get("/runs/{run_id}", response_model=RunPublic)
async def get_run(
    run_id: str,
    ctx: AuthContext = Depends(require_permission("playbook", "read")),
) -> RunPublic:
    rid = _uuid(run_id, not_found_message="run not found")
    try:
        run = await service.get_run(ctx.db, ctx.user.tenant_id, rid)
    except service.RunNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found") from exc
    playbook = await ctx.db.get(Playbook, run.playbook_id)
    return _run_public(run, playbook.key if playbook else "unknown")


@router.get("/approvals", response_model=list[ApprovalPublic])
async def list_pending_approvals(
    ctx: AuthContext = Depends(require_permission("playbook", "approve")),
) -> list[ApprovalPublic]:
    rows = await service.list_pending_approvals(ctx.db, ctx.user.tenant_id)
    return [_approval_public(row) for row in rows]


@router.post("/approvals/{approval_id}/approve", response_model=RunPublic)
async def approve(
    approval_id: str,
    request: Request,
    ctx: AuthContext = Depends(require_permission("playbook", "approve")),
) -> RunPublic:
    aid = _uuid(approval_id, not_found_message="approval not found")
    try:
        _approval, run, _outcomes = await service.approve_action(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            approval_id=aid,
            approver_id=ctx.user.id,
            actor_ip=_client_ip(request),
        )
    except service.ApprovalNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
    except service.SelfApprovalError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except service.InvalidApprovalState as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await ctx.db.commit()
    playbook = await ctx.db.get(Playbook, run.playbook_id)
    return _run_public(run, playbook.key if playbook else "unknown")


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalPublic)
async def reject(
    approval_id: str,
    payload: RejectRequest,
    request: Request,
    ctx: AuthContext = Depends(require_permission("playbook", "approve")),
) -> ApprovalPublic:
    aid = _uuid(approval_id, not_found_message="approval not found")
    try:
        approval = await service.reject_action(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            approval_id=aid,
            approver_id=ctx.user.id,
            reason=payload.reason,
            actor_ip=_client_ip(request),
        )
    except service.ApprovalNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "approval not found") from exc
    except service.SelfApprovalError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    except service.InvalidApprovalState as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await ctx.db.commit()
    return _approval_public(approval)


@router.get("/{key}", response_model=PlaybookPublic)
async def get_playbook(
    key: str,
    ctx: AuthContext = Depends(require_permission("playbook", "read")),
) -> PlaybookPublic:
    try:
        playbook = await service.get_playbook(ctx.db, ctx.user.tenant_id, key)
    except service.PlaybookNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "playbook not found") from exc
    return _playbook_public(playbook)


@router.post("/{key}/run", response_model=RunPublic)
async def run(
    key: str,
    payload: RunRequest,
    ctx: AuthContext = Depends(require_permission("playbook", "execute")),
) -> RunPublic:
    try:
        playbook = await service.get_playbook(ctx.db, ctx.user.tenant_id, key)
    except service.PlaybookNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "playbook not found") from exc

    alert_id = (
        _uuid(payload.alert_id, not_found_message="alert not found") if payload.alert_id else None
    )
    try:
        run_row, _outcomes = await service.start_run(
            ctx.db,
            tenant_id=ctx.user.tenant_id,
            playbook=playbook,
            actor_id=ctx.user.id,
            dry_run=payload.dry_run,
            alert_id=alert_id,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    await ctx.db.commit()
    return _run_public(run_row, playbook.key)
