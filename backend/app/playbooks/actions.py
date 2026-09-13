"""The action set (spec §18) and the approval gate destructive actions run
through (ARCHITECTURE.md §7.5).

**The gate is a type, not a convention.** A non-destructive action's
`execute()` takes only a `PlaybookContext`. A destructive action's
`execute()` additionally requires an `ApprovalGrant` — an object that can
only come from `require_approved()`, which does one thing: look up a real
`PlaybookActionApproval` row and confirm its status is `APPROVED` for this
exact run, step and action. The engine only ever calls `execute()` after
that lookup succeeds — but the more important property is that so does
every destructive action's `execute()` itself, independently, before it
touches anything: an `ApprovalGrant` a caller assembled by hand (Python has
no truly private constructors) still gets re-verified against the database
inside `execute()`, so the real security boundary is "does an APPROVED row
for this exact step exist," not "did the caller claim to have checked."
`test_playbooks_engine.py::test_calling_execute_directly_without_an_approved_record_...`
is the negative test this buys: it calls a destructive action's `execute()`
directly, bypassing the engine entirely, and confirms the state mutation
still cannot happen.

**"Reputation" and "notify" are honest about what they are.** There is no
external threat-intel vendor integration beyond the IOC set this platform
already manages (Phase 9), and no configured outbound notification channel
— THREAT_MODEL.md §3.6 flags exactly this as a risk (leaked webhook/
integration credentials pivoting into customer infrastructure). So
`calculate_reputation` is a local heuristic over this tenant's own IOC
matches and asset criticality, not a call to a vendor that isn't there, and
`notify_analyst` writes to the incident's own record and the platform audit
log rather than pretending to email or page anyone.
"""

import ipaddress
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import select

from app.audit.service import record_audit_event
from app.models.assets import Asset
from app.models.identity import User
from app.models.playbooks import PlaybookActionApproval
from app.playbooks.context import PlaybookContext
from app.services import incidents as incident_service
from app.services.threat_intel import match as match_indicators
from app.threat_intel.normalize import InvalidIndicator, canonicalize


@dataclass(frozen=True)
class ActionPreview:
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionResult:
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


class ActionTargetNotFound(ValueError):
    """The step has nothing to act on (e.g. the alert names no affected
    user). Raised rather than silently no-opping, because a step that
    quietly does nothing is indistinguishable from one that worked."""


class ApprovalRequired(PermissionError):
    """Raised by `require_approved()` when no APPROVED record exists, and
    independently re-raised inside a destructive action's own `execute()`
    if the grant it was handed doesn't check out — see the module
    docstring."""


@dataclass(frozen=True)
class ApprovalGrant:
    """Proof an approval was checked. Only ever constructed by
    `require_approved()`."""

    approval_id: uuid.UUID


async def require_approved(
    context: PlaybookContext, *, run_id: uuid.UUID, step_index: int, action_name: str
) -> ApprovalGrant:
    approval = await context.db.scalar(
        select(PlaybookActionApproval).where(
            PlaybookActionApproval.tenant_id == context.tenant_id,
            PlaybookActionApproval.playbook_run_id == run_id,
            PlaybookActionApproval.step_index == step_index,
            PlaybookActionApproval.action_name == action_name,
            PlaybookActionApproval.status == "APPROVED",
        )
    )
    if approval is None:
        raise ApprovalRequired(f"step {step_index} ({action_name}) has no approved record")
    return ApprovalGrant(approval_id=approval.id)


class PlaybookAction(ABC):
    name: ClassVar[str]
    destructive: ClassVar[bool] = False

    @abstractmethod
    async def dry_run(self, context: PlaybookContext) -> ActionPreview: ...

    @abstractmethod
    async def execute(self, context: PlaybookContext) -> ActionResult: ...


class DestructiveAction(ABC):
    name: ClassVar[str]
    destructive: ClassVar[bool] = True

    @abstractmethod
    async def dry_run(self, context: PlaybookContext) -> ActionPreview: ...

    @abstractmethod
    async def execute(self, context: PlaybookContext, grant: ApprovalGrant) -> ActionResult: ...

    async def _verify_grant(self, context: PlaybookContext, grant: ApprovalGrant) -> None:
        """The independent re-check every destructive action performs
        before doing anything, regardless of what the caller already did
        (see the module docstring)."""
        approval = await context.db.get(PlaybookActionApproval, grant.approval_id)
        if (
            approval is None
            or approval.tenant_id != context.tenant_id
            or approval.action_name != self.name
            or approval.status != "APPROVED"
        ):
            raise ApprovalRequired(f"grant for {self.name} does not reference an approved record")


def _target_ip(context: PlaybookContext) -> str:
    ip = context.params.get("ip") or (context.alert.source_ip if context.alert else None)
    if not ip:
        raise ActionTargetNotFound("no IP address on the alert or in step params")
    return str(ip)


def _is_private(ip: str) -> bool | None:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return None


class EnrichIpAction(PlaybookAction):
    """Asset and network-privacy context for an address — the same lookup
    `AssetContextProvider` does for events, reused here for a playbook step
    rather than duplicated."""

    name: ClassVar[str] = "enrich_ip"

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        ip = _target_ip(context)
        return ActionPreview(summary=f"Would look up asset and network context for {ip}")

    async def execute(self, context: PlaybookContext) -> ActionResult:
        ip = _target_ip(context)
        asset = await context.db.scalar(
            select(Asset).where(Asset.tenant_id == context.tenant_id, Asset.ip_address == ip)
        )
        details: dict[str, Any] = {"ip": ip, "is_private": _is_private(ip)}
        if asset is not None:
            details["asset"] = {
                "id": str(asset.id),
                "hostname": asset.hostname,
                "criticality": asset.criticality,
            }
        context.state[self.name] = details
        return ActionResult(summary=f"Enriched {ip}", details=details)


class EnrichHostAction(PlaybookAction):
    name: ClassVar[str] = "enrich_host"

    def _hostname(self, context: PlaybookContext) -> str:
        hostname = context.params.get("hostname") or (
            context.alert.affected_host if context.alert else None
        )
        if not hostname:
            raise ActionTargetNotFound("no hostname on the alert or in step params")
        return str(hostname)

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        return ActionPreview(summary=f"Would look up asset context for {self._hostname(context)}")

    async def execute(self, context: PlaybookContext) -> ActionResult:
        hostname = self._hostname(context)
        asset = await context.db.scalar(
            select(Asset).where(Asset.tenant_id == context.tenant_id, Asset.hostname == hostname)
        )
        if asset is None:
            raise ActionTargetNotFound(f"no asset registered with hostname {hostname}")
        details = {
            "asset_id": str(asset.id),
            "hostname": hostname,
            "criticality": asset.criticality,
            "is_isolated": asset.is_isolated,
        }
        context.state[self.name] = details
        return ActionResult(summary=f"Enriched host {hostname}", details=details)


class EnrichUserAction(PlaybookAction):
    name: ClassVar[str] = "enrich_user"

    def _email(self, context: PlaybookContext) -> str:
        email = context.params.get("email") or (
            context.alert.affected_user if context.alert else None
        )
        if not email:
            raise ActionTargetNotFound("no affected user on the alert or in step params")
        return str(email)

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        return ActionPreview(summary=f"Would look up account context for {self._email(context)}")

    async def execute(self, context: PlaybookContext) -> ActionResult:
        email = self._email(context)
        user = await context.db.scalar(
            select(User).where(User.tenant_id == context.tenant_id, User.email == email)
        )
        if user is None:
            raise ActionTargetNotFound(f"no user account found for {email}")
        details = {"user_id": str(user.id), "email": email, "is_active": user.is_active}
        context.state[self.name] = details
        return ActionResult(summary=f"Enriched account {email}", details=details)


class CheckIocAction(PlaybookAction):
    """Looks the alert's source IP up against this tenant's own indicator
    set (Phase 9) — not a third-party reputation call."""

    name: ClassVar[str] = "check_ioc"

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        ip = _target_ip(context)
        return ActionPreview(summary=f"Would check {ip} against known indicators")

    async def execute(self, context: PlaybookContext) -> ActionResult:
        ip = _target_ip(context)
        try:
            canonical, ioc_type = canonicalize(ip)
        except InvalidIndicator as exc:
            raise ActionTargetNotFound(str(exc)) from exc
        matches = await match_indicators(context.db, context.tenant_id, {ioc_type: [canonical]})
        details = {"ip": ip, "matches": matches}
        context.state[self.name] = details
        is_malicious = any(m["classification"] == "malicious" for m in matches)
        verdict = "known-malicious" if is_malicious else "no match"
        return ActionResult(summary=f"IOC check for {ip}: {verdict}", details=details)


class CalculateReputationAction(PlaybookAction):
    """A local heuristic over this tenant's own IOC matches and asset
    criticality — see the module docstring for why this is not a call to an
    external reputation vendor."""

    name: ClassVar[str] = "calculate_reputation"

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        return ActionPreview(summary="Would compute a reputation score from prior enrichment")

    async def execute(self, context: PlaybookContext) -> ActionResult:
        ioc_result = context.state.get("check_ioc", {})
        matches = ioc_result.get("matches", [])
        score = 0
        if any(m["classification"] == "malicious" for m in matches):
            score += 70
        elif any(m["classification"] == "suspicious" for m in matches):
            score += 40
        enrich_result = context.state.get("enrich_ip", {})
        if enrich_result.get("asset", {}).get("criticality") in ("HIGH", "CRITICAL"):
            score += 20
        score = min(score, 100)
        verdict = "malicious" if score >= 70 else "suspicious" if score >= 30 else "unknown"
        details = {"score": score, "verdict": verdict}
        context.state[self.name] = details
        return ActionResult(summary=f"Reputation: {verdict} ({score}/100)", details=details)


class CreateIncidentAction(PlaybookAction):
    name: ClassVar[str] = "create_incident"

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        title = self._title(context)
        return ActionPreview(summary=f"Would open an incident: {title}")

    def _title(self, context: PlaybookContext) -> str:
        default = context.alert.title if context.alert else "Playbook-created incident"
        return str(context.params.get("title") or default)

    async def execute(self, context: PlaybookContext) -> ActionResult:
        reputation = context.state.get("calculate_reputation", {})
        description_parts = [f"Opened automatically by playbook step '{self.name}'."]
        if reputation:
            verdict, score = reputation.get("verdict"), reputation.get("score")
            description_parts.append(f"Reputation: {verdict} ({score}/100).")
        draft = incident_service.IncidentDraft(
            title=self._title(context),
            description=" ".join(description_parts),
            severity=str(context.params.get("severity", "medium")),
            alert_ids=(context.alert.id,) if context.alert else (),
        )
        incident = await incident_service.create_incident(
            context.db, tenant_id=context.tenant_id, draft=draft, actor_id=context.actor_id
        )
        context.incident = incident
        details = {"incident_id": str(incident.id), "display_id": incident.display_id}
        context.state[self.name] = details
        return ActionResult(summary=f"Opened {incident.display_id}", details=details)


class NotifyAnalystAction(PlaybookAction):
    """Writes to the incident this run opened (or links to) and to the
    platform audit log. There is no outbound email/chat integration
    configured in this codebase to notify anyone through — see the module
    docstring."""

    name: ClassVar[str] = "notify_analyst"

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        return ActionPreview(summary="Would record a note on the incident and an audit entry")

    async def execute(self, context: PlaybookContext) -> ActionResult:
        message = str(context.params.get("message", "Playbook run completed."))
        if context.incident is not None:
            await incident_service.add_note(
                context.db,
                tenant_id=context.tenant_id,
                incident_id=context.incident.id,
                body=message,
                author_id=context.actor_id,
            )
        target = context.incident or context.alert
        await record_audit_event(
            context.db,
            tenant_id=context.tenant_id,
            actor_id=context.actor_id,
            action="PLAYBOOK_NOTIFY",
            object_type="incident" if context.incident else "alert",
            object_id=str(target.id) if target else None,
            after_state={"message": message},
            result="success",
        )
        details = {"message": message}
        context.state[self.name] = details
        return ActionResult(summary="Analyst notified", details=details)


class DisableUserAction(DestructiveAction):
    name: ClassVar[str] = "disable_user"

    def _email(self, context: PlaybookContext) -> str:
        email = context.params.get("email") or (
            context.alert.affected_user if context.alert else None
        )
        if not email:
            raise ActionTargetNotFound("no affected user on the alert or in step params")
        return str(email)

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        email = self._email(context)
        return ActionPreview(
            summary=f"Would disable the account {email}",
            details={"email": email, "destructive": True},
        )

    async def execute(self, context: PlaybookContext, grant: ApprovalGrant) -> ActionResult:
        await self._verify_grant(context, grant)
        email = self._email(context)
        user = await context.db.scalar(
            select(User).where(User.tenant_id == context.tenant_id, User.email == email)
        )
        if user is None:
            raise ActionTargetNotFound(f"no user account found for {email}")
        before = {"is_active": user.is_active}
        user.is_active = False
        await record_audit_event(
            context.db,
            tenant_id=context.tenant_id,
            actor_id=context.actor_id,
            action="PLAYBOOK_DISABLE_USER",
            object_type="user",
            object_id=str(user.id),
            before_state=before,
            after_state={"is_active": False},
            result="success",
        )
        details = {"user_id": str(user.id), "email": email}
        context.state[self.name] = details
        return ActionResult(summary=f"Disabled account {email}", details=details)


class IsolateHostAction(DestructiveAction):
    name: ClassVar[str] = "isolate_host"

    def _hostname(self, context: PlaybookContext) -> str:
        hostname = context.params.get("hostname") or (
            context.alert.affected_host if context.alert else None
        )
        if not hostname:
            raise ActionTargetNotFound("no hostname on the alert or in step params")
        return str(hostname)

    async def dry_run(self, context: PlaybookContext) -> ActionPreview:
        hostname = self._hostname(context)
        return ActionPreview(
            summary=f"Would mark {hostname} contained",
            details={"hostname": hostname, "destructive": True},
        )

    async def execute(self, context: PlaybookContext, grant: ApprovalGrant) -> ActionResult:
        await self._verify_grant(context, grant)
        hostname = self._hostname(context)
        asset = await context.db.scalar(
            select(Asset).where(Asset.tenant_id == context.tenant_id, Asset.hostname == hostname)
        )
        if asset is None:
            raise ActionTargetNotFound(f"no asset registered with hostname {hostname}")
        before = {"is_isolated": asset.is_isolated}
        asset.is_isolated = True
        asset.isolated_at = datetime.now(UTC)
        await record_audit_event(
            context.db,
            tenant_id=context.tenant_id,
            actor_id=context.actor_id,
            action="PLAYBOOK_ISOLATE_HOST",
            object_type="asset",
            object_id=str(asset.id),
            before_state=before,
            after_state={"is_isolated": True},
            result="success",
        )
        details = {"asset_id": str(asset.id), "hostname": hostname}
        context.state[self.name] = details
        return ActionResult(summary=f"Marked {hostname} contained", details=details)


ACTION_REGISTRY: dict[str, PlaybookAction | DestructiveAction] = {
    action.name: action
    for action in (
        EnrichIpAction(),
        EnrichHostAction(),
        EnrichUserAction(),
        CheckIocAction(),
        CalculateReputationAction(),
        CreateIncidentAction(),
        NotifyAnalystAction(),
        DisableUserAction(),
        IsolateHostAction(),
    )
}
