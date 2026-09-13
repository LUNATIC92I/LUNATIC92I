"""The SOAR playbook engine and approval workflow (spec §18;
ARCHITECTURE.md §7.5).

Three properties are the acceptance criteria for this phase, and this file
is organized around them:

1. A non-destructive playbook (PB-001's brute-force-triage chain) runs
   start to finish in one call, handing state from step to step.
2. Dry run and execute genuinely diverge: dry run previews every step,
   destructive or not, and never creates an approval record or mutates
   anything.
3. A destructive step is architecturally unreachable without a real
   `APPROVED` row — enforced independently by the engine (`require_approved`)
   *and* by each destructive action's own `execute()` (`_verify_grant`), and
   dual control (requester != approver) is enforced in Python ahead of the
   database CHECK constraint that also enforces it.
"""

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.db import async_session_factory, intel_sync_session, tenant_scoped_session
from app.models.alerts import Alert
from app.models.assets import Asset
from app.models.identity import Organization, User
from app.models.playbooks import Playbook, PlaybookActionApproval
from app.models.threat_intel import Ioc
from app.playbooks.actions import (
    ACTION_REGISTRY,
    ApprovalGrant,
    ApprovalRequired,
    DisableUserAction,
    IsolateHostAction,
)
from app.playbooks.context import PlaybookContext
from app.playbooks.loader import PlaybookLoadError
from app.playbooks.schema import PlaybookDefinition, StepDefinition
from app.services import incidents as incident_service
from app.services import playbooks as service


async def _tenant() -> uuid.UUID:
    slug = f"t{uuid.uuid4().hex[:12]}"
    async with async_session_factory() as db:
        org = Organization(name=slug, slug=slug)
        db.add(org)
        await db.commit()
        return org.id


async def _user(tenant_id: uuid.UUID, email: str = "analyst@example.com") -> uuid.UUID:
    from app.core.security import hash_password as _hash

    async with tenant_scoped_session(tenant_id) as db:
        user = User(
            tenant_id=tenant_id, email=email, password_hash=_hash("x"), full_name="Test Analyst"
        )
        db.add(user)
        await db.commit()
        return user.id


async def _alert(tenant_id: uuid.UUID, **overrides) -> Alert:
    kwargs = {
        "tenant_id": tenant_id,
        "display_id": f"ALT-{uuid.uuid4().hex[:8]}",
        "title": "Repeated failed logins",
        "description": "d",
        "severity": "high",
        "confidence": 70,
        "risk_score": 60,
        "dedup_key": str(uuid.uuid4()),
    }
    kwargs.update(overrides)
    async with tenant_scoped_session(tenant_id) as db:
        alert = Alert(**kwargs)
        db.add(alert)
        await db.commit()
        return alert


async def _asset(tenant_id: uuid.UUID, hostname: str, **overrides) -> uuid.UUID:
    kwargs = {"tenant_id": tenant_id, "asset_type": "server", "hostname": hostname}
    kwargs.update(overrides)
    async with tenant_scoped_session(tenant_id) as db:
        asset = Asset(**kwargs)
        db.add(asset)
        await db.commit()
        return asset.id


async def _ioc(value: str, classification: str = "malicious") -> None:
    async with intel_sync_session() as db:
        db.add(
            Ioc(
                tenant_id=None,
                ioc_type="ipv4",
                value=value,
                classification=classification,
                confidence=90,
                source="ir",
            )
        )
        await db.commit()


async def _custom_playbook(
    tenant_id: uuid.UUID, actor_id: uuid.UUID, key: str, steps: list[dict]
) -> Playbook:
    definition = PlaybookDefinition(
        key=key,
        name=key,
        trigger_type="alert",
        steps=[StepDefinition(**s) for s in steps],
    )
    async with tenant_scoped_session(tenant_id) as db:
        playbook = await service.create_playbook(
            db, tenant_id=tenant_id, definition=definition, actor_id=actor_id
        )
        await db.commit()
        return playbook


# ---------------------------------------------------------------------------
# Installing the shipped pack
# ---------------------------------------------------------------------------


async def test_installing_default_playbooks_loads_all_three() -> None:
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        installed = await service.install_default_playbooks(
            db, tenant_id=tenant_id, actor_id=actor_id
        )
        await db.commit()

    assert sorted(installed) == ["PB-001", "PB-002", "PB-003"]


async def test_installing_default_playbooks_twice_is_idempotent() -> None:
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.install_default_playbooks(db, tenant_id=tenant_id, actor_id=actor_id)
        await db.commit()

    async with tenant_scoped_session(tenant_id) as db:
        second = await service.install_default_playbooks(
            db, tenant_id=tenant_id, actor_id=actor_id
        )
        await db.commit()

    assert second == []


async def test_installing_from_a_missing_directory_raises() -> None:
    from pathlib import Path

    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(PlaybookLoadError):
            await service.install_default_playbooks(
                db, tenant_id=tenant_id, actor_id=actor_id, directory=Path("/no/such/dir")
            )


async def test_creating_a_playbook_with_an_unregistered_action_is_refused() -> None:
    """A typo'd action name must be rejected at creation, not surface as an
    unhandled `KeyError` in the engine the first time someone runs it."""
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)
    definition = PlaybookDefinition(
        key="PB-899", name="bad", steps=[StepDefinition(action="not_a_real_action")]
    )
    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(service.UnknownAction):
            await service.create_playbook(
                db, tenant_id=tenant_id, definition=definition, actor_id=actor_id
            )


async def test_creating_a_playbook_with_a_duplicate_key_is_refused() -> None:
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)
    await _custom_playbook(tenant_id, actor_id, "PB-900", [{"action": "enrich_ip"}])

    definition = PlaybookDefinition(key="PB-900", name="dup", steps=[StepDefinition(action="enrich_ip")])
    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(service.DuplicatePlaybook):
            await service.create_playbook(
                db, tenant_id=tenant_id, definition=definition, actor_id=actor_id
            )


# ---------------------------------------------------------------------------
# End-to-end non-destructive run (PB-001's chain)
# ---------------------------------------------------------------------------


async def test_end_to_end_non_destructive_playbook_runs_to_completion() -> None:
    """spec §18's example: brute force -> enrich -> IOC check -> reputation
    -> incident -> notify, in one call, with state handed from step to
    step (check_ioc's match feeding calculate_reputation's score feeding
    create_incident's description)."""
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)
    await _ioc("203.0.113.50", classification="malicious")
    alert = await _alert(tenant_id, source_ip="203.0.113.50")
    playbook = await _custom_playbook(
        tenant_id,
        actor_id,
        "PB-901",
        [
            {"action": "enrich_ip"},
            {"action": "check_ioc"},
            {"action": "calculate_reputation"},
            {"action": "create_incident", "params": {"severity": "high"}},
            {"action": "notify_analyst", "params": {"message": "triage complete"}},
        ],
    )

    async with tenant_scoped_session(tenant_id) as db:
        run, outcomes = await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=actor_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()

    assert run.status == "COMPLETED"
    assert [o.kind for o in outcomes] == ["result"] * 5
    assert run.incident_id is not None

    async with tenant_scoped_session(tenant_id) as db:
        incident = await incident_service.get_incident(db, tenant_id, run.incident_id)
        timeline = await incident_service.timeline_for(db, tenant_id, run.incident_id)

    assert "malicious" in (incident.description or "")
    assert any(entry.kind == "note" for entry in timeline)


async def test_a_step_with_no_target_fails_the_run_with_a_clear_error() -> None:
    """`enrich_ip` with neither an alert nor a param has nothing to act on
    — a step that quietly did nothing would be worse than one that fails
    loudly (see the module docstring in actions.py)."""
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)
    playbook = await _custom_playbook(tenant_id, actor_id, "PB-902", [{"action": "enrich_ip"}])

    async with tenant_scoped_session(tenant_id) as db:
        run, outcomes = await service.start_run(
            db, tenant_id=tenant_id, playbook=playbook, actor_id=actor_id, dry_run=False
        )
        await db.commit()

    assert run.status == "FAILED"
    assert outcomes[-1].kind == "error"


# ---------------------------------------------------------------------------
# Dry run vs execute: the divergence
# ---------------------------------------------------------------------------


async def test_dry_run_previews_every_step_including_destructive_ones_and_completes() -> None:
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)
    await _user(tenant_id, "victim@example.com")
    alert = await _alert(tenant_id, affected_user="victim@example.com")
    playbook = await _custom_playbook(
        tenant_id, actor_id, "PB-903", [{"action": "enrich_user"}, {"action": "disable_user"}]
    )

    async with tenant_scoped_session(tenant_id) as db:
        run, outcomes = await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=actor_id,
            dry_run=True,
            alert_id=alert.id,
        )
        await db.commit()

    assert run.status == "COMPLETED"
    assert [o.kind for o in outcomes] == ["preview", "preview"]

    async with tenant_scoped_session(tenant_id) as db:
        approvals = list(
            (
                await db.execute(
                    select(PlaybookActionApproval).where(
                        PlaybookActionApproval.tenant_id == tenant_id
                    )
                )
            ).scalars()
        )
        victim = await db.scalar(select(User).where(User.email == "victim@example.com"))

    assert approvals == []
    assert victim is not None and victim.is_active is True


async def test_a_real_execute_run_of_the_same_playbook_halts_for_approval() -> None:
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)
    await _user(tenant_id, "victim2@example.com")
    alert = await _alert(tenant_id, affected_user="victim2@example.com")
    playbook = await _custom_playbook(
        tenant_id, actor_id, "PB-904", [{"action": "enrich_user"}, {"action": "disable_user"}]
    )

    async with tenant_scoped_session(tenant_id) as db:
        run, outcomes = await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=actor_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()

    assert run.status == "AWAITING_APPROVAL"
    assert run.current_step == 1
    assert outcomes[-1].kind == "awaiting_approval"

    async with tenant_scoped_session(tenant_id) as db:
        pending = await service.list_pending_approvals(db, tenant_id)
        victim = await db.scalar(select(User).where(User.email == "victim2@example.com"))

    assert len(pending) == 1
    assert pending[0].step_index == 1
    assert pending[0].action_name == "disable_user"
    assert pending[0].status == "PENDING_APPROVAL"
    assert victim is not None and victim.is_active is True


# ---------------------------------------------------------------------------
# Approval state machine and dual control
# ---------------------------------------------------------------------------


async def test_approving_resumes_the_run_and_executes_the_destructive_step() -> None:
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "requester@example.com")
    approver_id = await _user(tenant_id, "approver@example.com")
    await _user(tenant_id, "victim3@example.com")
    alert = await _alert(tenant_id, affected_user="victim3@example.com")
    playbook = await _custom_playbook(tenant_id, requester_id, "PB-905", [{"action": "disable_user"}])

    async with tenant_scoped_session(tenant_id) as db:
        run, _ = await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        approval, resumed, outcomes = await service.approve_action(
            db, tenant_id=tenant_id, approval_id=pending[0].id, approver_id=approver_id
        )
        await db.commit()

    assert approval.status == "EXECUTED"
    assert resumed.status == "COMPLETED"
    assert outcomes[-1].kind == "result"

    async with tenant_scoped_session(tenant_id) as db:
        victim = await db.scalar(select(User).where(User.email == "victim3@example.com"))
    assert victim is not None and victim.is_active is False


async def test_notify_analyst_does_not_replay_after_a_resume() -> None:
    """The property `PlaybookRun.current_step` exists to protect: a
    non-idempotent step executed before a halt must not run a second time
    when the run resumes."""
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "requester4@example.com")
    approver_id = await _user(tenant_id, "approver4@example.com")
    await _user(tenant_id, "victim4@example.com")
    alert = await _alert(tenant_id, affected_user="victim4@example.com")
    playbook = await _custom_playbook(
        tenant_id,
        requester_id,
        "PB-906",
        [{"action": "notify_analyst"}, {"action": "disable_user"}],
    )

    async with tenant_scoped_session(tenant_id) as db:
        run, _ = await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.approve_action(
            db, tenant_id=tenant_id, approval_id=pending[0].id, approver_id=approver_id
        )
        await db.commit()

    async with tenant_scoped_session(tenant_id) as db:
        from app.models.audit import AuditLog

        rows = list(
            (
                await db.execute(select(AuditLog).where(AuditLog.action == "PLAYBOOK_NOTIFY"))
            ).scalars()
        )
    assert len(rows) == 1


async def test_self_approval_is_refused() -> None:
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "solo@example.com")
    await _user(tenant_id, "victim5@example.com")
    alert = await _alert(tenant_id, affected_user="victim5@example.com")
    playbook = await _custom_playbook(tenant_id, requester_id, "PB-907", [{"action": "disable_user"}])

    async with tenant_scoped_session(tenant_id) as db:
        await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(service.SelfApprovalError):
            await service.approve_action(
                db, tenant_id=tenant_id, approval_id=pending[0].id, approver_id=requester_id
            )


async def test_self_rejection_is_also_refused() -> None:
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "solo2@example.com")
    await _user(tenant_id, "victim6@example.com")
    alert = await _alert(tenant_id, affected_user="victim6@example.com")
    playbook = await _custom_playbook(tenant_id, requester_id, "PB-908", [{"action": "disable_user"}])

    async with tenant_scoped_session(tenant_id) as db:
        await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(service.SelfApprovalError):
            await service.reject_action(
                db,
                tenant_id=tenant_id,
                approval_id=pending[0].id,
                approver_id=requester_id,
                reason="nope",
            )


async def test_the_database_check_constraint_refuses_self_approval_even_bypassing_python() -> None:
    """The Python check in `approve_action` is a nicer error message, not
    the real boundary — the CHECK constraint is. Proven here by going
    around the service layer entirely with a raw UPDATE."""
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "solo3@example.com")
    await _user(tenant_id, "victim7@example.com")
    alert = await _alert(tenant_id, affected_user="victim7@example.com")
    playbook = await _custom_playbook(tenant_id, requester_id, "PB-909", [{"action": "disable_user"}])

    async with tenant_scoped_session(tenant_id) as db:
        await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(IntegrityError):
            await db.execute(
                text(
                    "UPDATE playbook_action_approvals "
                    "SET status = 'APPROVED', decided_by = requested_by "
                    "WHERE id = :id"
                ),
                {"id": pending[0].id},
            )
        await db.rollback()


async def test_rejecting_halts_the_run_without_executing() -> None:
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "requester8@example.com")
    approver_id = await _user(tenant_id, "approver8@example.com")
    await _user(tenant_id, "victim8@example.com")
    alert = await _alert(tenant_id, affected_user="victim8@example.com")
    playbook = await _custom_playbook(tenant_id, requester_id, "PB-910", [{"action": "disable_user"}])

    async with tenant_scoped_session(tenant_id) as db:
        await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        approval = await service.reject_action(
            db,
            tenant_id=tenant_id,
            approval_id=pending[0].id,
            approver_id=approver_id,
            reason="not authorized",
        )
        run = await service.get_run(db, tenant_id, approval.playbook_run_id)
        await db.commit()

    assert approval.status == "REJECTED"
    assert run.status == "REJECTED"
    assert "not authorized" in (run.error or "")

    async with tenant_scoped_session(tenant_id) as db:
        victim = await db.scalar(select(User).where(User.email == "victim8@example.com"))
    assert victim is not None and victim.is_active is True


async def test_deciding_an_already_decided_approval_is_refused() -> None:
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "requester9@example.com")
    approver_id = await _user(tenant_id, "approver9@example.com")
    await _user(tenant_id, "victim9@example.com")
    alert = await _alert(tenant_id, affected_user="victim9@example.com")
    playbook = await _custom_playbook(tenant_id, requester_id, "PB-911", [{"action": "disable_user"}])

    async with tenant_scoped_session(tenant_id) as db:
        await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.approve_action(
            db, tenant_id=tenant_id, approval_id=pending[0].id, approver_id=approver_id
        )
        await db.commit()

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(service.InvalidApprovalState):
            await service.approve_action(
                db, tenant_id=tenant_id, approval_id=pending[0].id, approver_id=approver_id
            )


# ---------------------------------------------------------------------------
# The negative test: execute() is unreachable without a real APPROVED row
# ---------------------------------------------------------------------------


async def test_calling_execute_directly_with_a_forged_grant_is_refused() -> None:
    """Bypasses the engine and `require_approved()` entirely: constructs an
    `ApprovalGrant` by hand (Python has no private constructors) pointing at
    a UUID with no backing row, and calls `DisableUserAction.execute()`
    directly. `_verify_grant` must independently refuse it."""
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id, "target@example.com")
    alert = await _alert(tenant_id, affected_user="target@example.com")

    forged = ApprovalGrant(approval_id=uuid.uuid4())
    async with tenant_scoped_session(tenant_id) as db:
        context = PlaybookContext(db=db, tenant_id=tenant_id, actor_id=actor_id, alert=alert)
        with pytest.raises(ApprovalRequired):
            await DisableUserAction().execute(context, forged)

    async with tenant_scoped_session(tenant_id) as db:
        user = await db.scalar(select(User).where(User.email == "target@example.com"))
    assert user is not None and user.is_active is True


async def test_calling_execute_with_a_grant_for_a_pending_not_approved_row_is_refused() -> None:
    """A grant that references a real row is still refused if that row's
    status isn't APPROVED — a forged/pending id must not be enough."""
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "req10@example.com")
    await _user(tenant_id, "target2@example.com")
    alert = await _alert(tenant_id, affected_user="target2@example.com")
    playbook = await _custom_playbook(tenant_id, requester_id, "PB-912", [{"action": "disable_user"}])

    async with tenant_scoped_session(tenant_id) as db:
        await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    assert pending[0].status == "PENDING_APPROVAL"
    forged = ApprovalGrant(approval_id=pending[0].id)

    async with tenant_scoped_session(tenant_id) as db:
        context = PlaybookContext(db=db, tenant_id=tenant_id, actor_id=requester_id, alert=alert)
        with pytest.raises(ApprovalRequired):
            await DisableUserAction().execute(context, forged)

    async with tenant_scoped_session(tenant_id) as db:
        user = await db.scalar(select(User).where(User.email == "target2@example.com"))
    assert user is not None and user.is_active is True


async def test_calling_execute_with_a_grant_approved_for_a_different_action_is_refused() -> None:
    """An APPROVED row for `isolate_host` must not authorize
    `disable_user` — `_verify_grant` checks `action_name`, not just status."""
    tenant_id = await _tenant()
    requester_id = await _user(tenant_id, "req11@example.com")
    approver_id = await _user(tenant_id, "app11@example.com")
    await _user(tenant_id, "target3@example.com")
    await _asset(tenant_id, "dc-11")
    alert = await _alert(tenant_id, affected_user="target3@example.com", affected_host="dc-11")
    playbook = await _custom_playbook(tenant_id, requester_id, "PB-913", [{"action": "isolate_host"}])

    async with tenant_scoped_session(tenant_id) as db:
        await service.start_run(
            db,
            tenant_id=tenant_id,
            playbook=playbook,
            actor_id=requester_id,
            dry_run=False,
            alert_id=alert.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.approve_action(
            db, tenant_id=tenant_id, approval_id=pending[0].id, approver_id=approver_id
        )
        await db.commit()

    # The approval is APPROVED (then EXECUTED) for isolate_host. Try to
    # spend it on disable_user instead.
    mismatched = ApprovalGrant(approval_id=pending[0].id)
    async with tenant_scoped_session(tenant_id) as db:
        context = PlaybookContext(db=db, tenant_id=tenant_id, actor_id=requester_id, alert=alert)
        with pytest.raises(ApprovalRequired):
            await DisableUserAction().execute(context, mismatched)

    async with tenant_scoped_session(tenant_id) as db:
        user = await db.scalar(select(User).where(User.email == "target3@example.com"))
    assert user is not None and user.is_active is True


async def test_isolate_host_also_requires_a_real_approved_grant() -> None:
    tenant_id = await _tenant()
    actor_id = await _user(tenant_id)
    await _asset(tenant_id, "web-01")
    alert = await _alert(tenant_id, affected_host="web-01")

    forged = ApprovalGrant(approval_id=uuid.uuid4())
    async with tenant_scoped_session(tenant_id) as db:
        context = PlaybookContext(db=db, tenant_id=tenant_id, actor_id=actor_id, alert=alert)
        with pytest.raises(ApprovalRequired):
            await IsolateHostAction().execute(context, forged)

    async with tenant_scoped_session(tenant_id) as db:
        asset = await db.scalar(select(Asset).where(Asset.hostname == "web-01"))
    assert asset is not None and asset.is_isolated is False


async def test_a_grant_for_another_tenants_approval_is_refused() -> None:
    """`_verify_grant` checks `tenant_id`, closing the cross-tenant IDOR
    a bare approval-id lookup would otherwise open."""
    tenant_a = await _tenant()
    tenant_b = await _tenant()
    requester_a = await _user(tenant_a, "reqA@example.com")
    approver_a = await _user(tenant_a, "appA@example.com")
    await _user(tenant_a, "targetA@example.com")
    alert_a = await _alert(tenant_a, affected_user="targetA@example.com")
    playbook_a = await _custom_playbook(
        tenant_a, requester_a, "PB-914", [{"action": "disable_user"}]
    )

    async with tenant_scoped_session(tenant_a) as db:
        await service.start_run(
            db,
            tenant_id=tenant_a,
            playbook=playbook_a,
            actor_id=requester_a,
            dry_run=False,
            alert_id=alert_a.id,
        )
        await db.commit()
        pending = await service.list_pending_approvals(db, tenant_a)

    async with tenant_scoped_session(tenant_a) as db:
        await service.approve_action(
            db, tenant_id=tenant_a, approval_id=pending[0].id, approver_id=approver_a
        )
        await db.commit()

    stolen_grant = ApprovalGrant(approval_id=pending[0].id)
    await _user(tenant_b, "victimB@example.com")
    alert_b = await _alert(tenant_b, affected_user="victimB@example.com")

    async with tenant_scoped_session(tenant_b) as db:
        context = PlaybookContext(db=db, tenant_id=tenant_b, actor_id=None, alert=alert_b)
        with pytest.raises(ApprovalRequired):
            await DisableUserAction().execute(context, stolen_grant)


def test_every_destructive_action_is_registered_and_has_the_destructive_flag() -> None:
    destructive = {"disable_user", "isolate_host"}
    for name in destructive:
        assert ACTION_REGISTRY[name].destructive is True
    for name, action in ACTION_REGISTRY.items():
        if name not in destructive:
            assert action.destructive is False
