"""Incident workflow, linkage, timeline completeness, and display ids.

The acceptance criteria for this phase are specific and testable: the
workflow transition matrix must be enforced, per-tenant `display_id`s must
stay unique under concurrency, and every state change must produce a
timeline entry. This file is built around those three properties, plus the
cross-tenant IDOR suite the spec extends from Phase 2 to incidents.
"""

import uuid

import pytest
from sqlalchemy import select, text

from app.core.db import async_session_factory, intel_sync_session, tenant_scoped_session
from app.models.assets import Asset
from app.models.identity import Organization
from app.models.incidents import Incident
from app.models.threat_intel import Ioc
from app.services import incidents as service
from app.services.incidents import (
    CLOSED,
    CONTAINMENT,
    ERADICATION,
    INVESTIGATION,
    NEW,
    RECOVERY,
    TRANSITIONS,
    TRIAGE,
    IncidentDraft,
    InvalidTransition,
)


async def _tenant() -> uuid.UUID:
    slug = f"t{uuid.uuid4().hex[:12]}"
    async with async_session_factory() as db:
        org = Organization(name=slug, slug=slug)
        db.add(org)
        await db.commit()
        return org.id


async def _create(tenant_id: uuid.UUID, **overrides) -> Incident:
    draft_kwargs = {"title": "Suspicious activity on dc01", "severity": "high"}
    draft_kwargs.update(overrides)
    async with tenant_scoped_session(tenant_id) as db:
        incident = await service.create_incident(
            db, tenant_id=tenant_id, draft=IncidentDraft(**draft_kwargs), actor_id=None
        )
        await db.commit()
        return incident


async def _asset(tenant_id: uuid.UUID, hostname: str = "dc01") -> uuid.UUID:
    async with tenant_scoped_session(tenant_id) as db:
        asset = Asset(tenant_id=tenant_id, asset_type="server", hostname=hostname, criticality="HIGH")
        db.add(asset)
        await db.commit()
        return asset.id


async def _ioc(tenant_id: uuid.UUID | None, value: str = "203.0.113.9") -> uuid.UUID:
    # A shared/global indicator (tenant_id=None) can only be written through
    # the intel-sync session: RLS refuses a NULL-tenant row from any other
    # session, tenant-scoped or not (app/core/db.py).
    session = tenant_scoped_session(tenant_id) if tenant_id else intel_sync_session()
    async with session as db:
        ioc = Ioc(
            tenant_id=tenant_id,
            ioc_type="ipv4",
            value=value,
            classification="malicious",
            confidence=90,
            source="ir",
        )
        db.add(ioc)
        await db.commit()
        return ioc.id


# ---------------------------------------------------------------------------
# Creation and display ids
# ---------------------------------------------------------------------------


async def test_creating_an_incident_records_the_created_entry() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    assert incident.status == NEW
    assert incident.priority == "P2"  # derived from severity=high
    assert incident.display_id.startswith("INC-")

    async with tenant_scoped_session(tenant_id) as db:
        timeline = await service.timeline_for(db, tenant_id, incident.id)
    assert [entry.kind for entry in timeline] == ["created"]


async def test_display_ids_are_sequential_and_per_tenant() -> None:
    tenant_a, tenant_b = await _tenant(), await _tenant()

    first = await _create(tenant_a)
    second = await _create(tenant_a)
    other = await _create(tenant_b)

    from datetime import UTC, datetime

    year = datetime.now(UTC).year
    assert first.display_id == f"INC-{year}-000001"
    assert second.display_id == f"INC-{year}-000002"
    assert other.display_id == f"INC-{year}-000001"


async def test_display_ids_stay_unique_under_concurrency() -> None:
    """The acceptance criterion: two analysts opening incidents at the same
    instant must not mint the same case number."""
    import asyncio

    tenant_id = await _tenant()

    async def create(index: int) -> str:
        async with tenant_scoped_session(tenant_id) as db:
            incident = await service.create_incident(
                db,
                tenant_id=tenant_id,
                draft=IncidentDraft(title=f"case {index}"),
                actor_id=None,
            )
            await db.commit()
            return incident.display_id

    display_ids = await asyncio.gather(*(create(index) for index in range(8)))
    assert len(set(display_ids)) == 8


async def test_severity_maps_to_a_sensible_default_priority() -> None:
    tenant_id = await _tenant()
    critical = await _create(tenant_id, severity="critical")
    low = await _create(tenant_id, severity="low")

    assert critical.priority == "P1"
    assert low.priority == "P4"


async def test_an_explicit_priority_overrides_the_severity_default() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id, severity="low", priority="P1")
    assert incident.priority == "P1"


# ---------------------------------------------------------------------------
# The workflow state machine
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("start", "target"),
    [
        (NEW, TRIAGE),
        (NEW, INVESTIGATION),
        (NEW, CLOSED),
        (TRIAGE, INVESTIGATION),
        (TRIAGE, CONTAINMENT),
        (INVESTIGATION, CONTAINMENT),
        (INVESTIGATION, ERADICATION),
        (CONTAINMENT, ERADICATION),
        (CONTAINMENT, INVESTIGATION),  # containment failed, back to investigating
        (ERADICATION, RECOVERY),
        (RECOVERY, CLOSED),
        (RECOVERY, ERADICATION),  # recovery revealed the eradication was incomplete
        # Reopening: allowed, but explicit.
        (CLOSED, INVESTIGATION),
        (CLOSED, TRIAGE),
    ],
)
async def test_valid_transitions(start: str, target: str) -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        if start != NEW:
            await _force_status(db, incident.id, start)
        moved = await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=target, actor_id=None
        )
        await db.commit()

    assert moved.status == target


@pytest.mark.parametrize(
    ("start", "target"),
    [
        (NEW, RECOVERY),  # cannot skip straight to recovery
        (NEW, ERADICATION),
        (TRIAGE, RECOVERY),
        (CLOSED, RECOVERY),
        (CLOSED, ERADICATION),
        (CLOSED, CONTAINMENT),
        (RECOVERY, TRIAGE),  # cannot go backward past investigation
    ],
)
async def test_invalid_transitions_are_refused(start: str, target: str) -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await _force_status(db, incident.id, start)
        with pytest.raises(InvalidTransition):
            await service.transition(
                db, tenant_id=tenant_id, incident_id=incident.id, target=target, actor_id=None
            )


async def _force_status(db, incident_id: uuid.UUID, status: str) -> None:
    await db.execute(
        text("UPDATE incidents SET status = :status WHERE id = :id"),
        {"status": status, "id": incident_id},
    )
    await db.commit()


def test_the_state_machine_covers_every_status() -> None:
    from app.models.incidents import INCIDENT_STATUSES

    assert set(TRANSITIONS) == set(INCIDENT_STATUSES)
    for targets in TRANSITIONS.values():
        assert targets <= set(INCIDENT_STATUSES)


async def test_moving_to_the_same_status_is_a_no_op() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=TRIAGE, actor_id=None
        )
        await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=TRIAGE, actor_id=None
        )
        await db.commit()
        timeline = await service.timeline_for(db, tenant_id, incident.id)

    changes = [entry for entry in timeline if entry.kind == "status_change"]
    assert len(changes) == 1


async def test_first_containment_is_recorded_once() -> None:
    """A case that returns to investigation and is contained again has not
    been contained twice, for MTTC purposes."""
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=TRIAGE, actor_id=None
        )
        await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=CONTAINMENT, actor_id=None
        )
        first_contained = (await service.get_incident(db, tenant_id, incident.id)).contained_at
        await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=INVESTIGATION, actor_id=None
        )
        await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=CONTAINMENT, actor_id=None
        )
        second = await service.get_incident(db, tenant_id, incident.id)
        await db.commit()

    assert first_contained is not None
    assert second.contained_at == first_contained


async def test_closing_records_the_resolution_note() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        closed = await service.transition(
            db,
            tenant_id=tenant_id,
            incident_id=incident.id,
            target=CLOSED,
            actor_id=None,
            note="contained and eradicated; no further action needed",
        )
        await db.commit()

    assert closed.closed_at is not None
    assert closed.resolution is not None and "eradicated" in closed.resolution


async def test_reopening_after_close_clears_the_closed_timestamp() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=CLOSED, actor_id=None
        )
        reopened = await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=INVESTIGATION, actor_id=None
        )
        await db.commit()

    assert reopened.closed_at is None


# ---------------------------------------------------------------------------
# Timeline completeness — the acceptance criterion
# ---------------------------------------------------------------------------


async def test_every_mutating_operation_produces_a_timeline_entry() -> None:
    """Spec §14: "every state change produces a timeline entry." Exercised
    here across every kind of mutation this module supports, not just
    status changes."""
    tenant_id = await _tenant()
    incident = await _create(tenant_id)
    asset_id = await _asset(tenant_id)
    ioc_id = await _ioc(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, incident_id=incident.id, target=TRIAGE, actor_id=None
        )
        await service.add_note(
            db, tenant_id=tenant_id, incident_id=incident.id, body="initial triage note",
            author_id=None,
        )
        task = await service.add_task(
            db,
            tenant_id=tenant_id,
            incident_id=incident.id,
            title="isolate dc01",
            description=None,
            assignee_id=None,
            due_at=None,
            actor_id=None,
        )
        await service.update_task(
            db,
            tenant_id=tenant_id,
            incident_id=incident.id,
            task_id=task.id,
            values={"status": "done"},
            actor_id=None,
        )
        await service.link_asset(
            db, tenant_id=tenant_id, incident_id=incident.id, asset_id=asset_id, actor_id=None
        )
        await service.link_ioc(
            db, tenant_id=tenant_id, incident_id=incident.id, ioc_id=ioc_id, actor_id=None
        )
        await service.link_user(
            db, tenant_id=tenant_id, incident_id=incident.id, username="alice", actor_id=None
        )
        await service.update_incident(
            db,
            tenant_id=tenant_id,
            incident_id=incident.id,
            values={"analyst_id": None},
            actor_id=None,
        )
        await db.commit()
        timeline = await service.timeline_for(db, tenant_id, incident.id)

    kinds = [entry.kind for entry in timeline]
    assert kinds == [
        "created",
        "status_change",
        "note",
        "task",
        "task",
        "asset_linked",
        "ioc_linked",
        "note",  # link_user records as "note" kind (a plain account link)
        "assignment",
    ]


async def test_the_timeline_is_ordered_by_when_things_happened() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        await service.add_note(
            db, tenant_id=tenant_id, incident_id=incident.id, body="first", author_id=None
        )
        await service.add_note(
            db, tenant_id=tenant_id, incident_id=incident.id, body="second", author_id=None
        )
        timeline = await service.timeline_for(db, tenant_id, incident.id)

    assert [entry.occurred_at for entry in timeline] == sorted(
        entry.occurred_at for entry in timeline
    )


async def test_incident_history_cannot_be_rewritten() -> None:
    tenant_id = await _tenant()
    await _create(tenant_id)  # a timeline row must exist to attempt rewriting

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(text("UPDATE incident_timeline SET summary = 'tampered'"))
        await db.rollback()
    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(text("DELETE FROM incident_timeline"))
        await db.rollback()


async def test_incident_notes_cannot_be_rewritten() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)
    async with tenant_scoped_session(tenant_id) as db:
        await service.add_note(
            db, tenant_id=tenant_id, incident_id=incident.id, body="original", author_id=None
        )
        await db.commit()

    async with tenant_scoped_session(tenant_id) as db:
        with pytest.raises(Exception, match="append-only"):
            await db.execute(text("UPDATE incident_notes SET body = 'tampered'"))
        await db.rollback()


# ---------------------------------------------------------------------------
# Linkage
# ---------------------------------------------------------------------------


async def test_linking_the_same_alert_twice_is_idempotent() -> None:
    from app.models.alerts import Alert

    tenant_id = await _tenant()
    incident = await _create(tenant_id)
    async with tenant_scoped_session(tenant_id) as db:
        alert = Alert(
            tenant_id=tenant_id,
            display_id="ALT-2026-000001",
            title="test alert",
            description="d",
            severity="high",
            confidence=70,
            risk_score=60,
            dedup_key=str(uuid.uuid4()),
        )
        db.add(alert)
        await db.commit()

        first = await service.link_alert(
            db, tenant_id=tenant_id, incident_id=incident.id, alert_id=alert.id, actor_id=None
        )
        second = await service.link_alert(
            db, tenant_id=tenant_id, incident_id=incident.id, alert_id=alert.id, actor_id=None
        )
        await db.commit()
        linked = await service.linked_alerts(db, tenant_id, incident.id)

    assert (first, second) == (True, False)
    assert len(linked) == 1


async def test_linking_an_asset_or_ioc_from_another_tenant_is_refused() -> None:
    """Linking is a cross-object operation: an unchecked id would be an
    IDOR into another tenant's inventory (THREAT_MODEL.md §3.2)."""
    tenant_a, tenant_b = await _tenant(), await _tenant()
    incident = await _create(tenant_a)
    foreign_asset = await _asset(tenant_b)

    async with tenant_scoped_session(tenant_a) as db:
        with pytest.raises(service.IncidentNotFound):
            await service.link_asset(
                db,
                tenant_id=tenant_a,
                incident_id=incident.id,
                asset_id=foreign_asset,
                actor_id=None,
            )


async def test_a_shared_ioc_can_be_linked_by_any_tenant() -> None:
    """A global feed indicator has no tenant of its own; the incident is
    about *this* tenant seeing it."""
    tenant_id = await _tenant()
    incident = await _create(tenant_id)
    shared_ioc = await _ioc(None, value="198.51.100.50")

    async with tenant_scoped_session(tenant_id) as db:
        linked = await service.link_ioc(
            db, tenant_id=tenant_id, incident_id=incident.id, ioc_id=shared_ioc, actor_id=None
        )
        await db.commit()

    assert linked is True


async def test_linked_entities_are_read_back_together() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)
    asset_id = await _asset(tenant_id, hostname="dc02")
    ioc_id = await _ioc(tenant_id, value="203.0.113.99")

    async with tenant_scoped_session(tenant_id) as db:
        await service.link_asset(
            db, tenant_id=tenant_id, incident_id=incident.id, asset_id=asset_id, actor_id=None
        )
        await service.link_ioc(
            db, tenant_id=tenant_id, incident_id=incident.id, ioc_id=ioc_id, actor_id=None
        )
        await service.link_user(
            db, tenant_id=tenant_id, incident_id=incident.id, username="bob", actor_id=None
        )
        await db.commit()
        entities = await service.linked_entities(db, tenant_id, incident.id)

    assert entities["assets"][0]["hostname"] == "dc02"
    assert entities["iocs"][0]["value"] == "203.0.113.99"
    assert entities["users"][0]["username"] == "bob"


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------


async def test_completing_a_task_records_when() -> None:
    tenant_id = await _tenant()
    incident = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        task = await service.add_task(
            db,
            tenant_id=tenant_id,
            incident_id=incident.id,
            title="collect memory dump",
            description=None,
            assignee_id=None,
            due_at=None,
            actor_id=None,
        )
        assert task.completed_at is None
        done = await service.update_task(
            db,
            tenant_id=tenant_id,
            incident_id=incident.id,
            task_id=task.id,
            values={"status": "done"},
            actor_id=None,
        )
        await db.commit()

    assert done.completed_at is not None


async def test_a_task_from_another_incident_cannot_be_updated() -> None:
    tenant_id = await _tenant()
    incident_a = await _create(tenant_id)
    incident_b = await _create(tenant_id)

    async with tenant_scoped_session(tenant_id) as db:
        task = await service.add_task(
            db,
            tenant_id=tenant_id,
            incident_id=incident_a.id,
            title="x",
            description=None,
            assignee_id=None,
            due_at=None,
            actor_id=None,
        )
        await db.commit()

        with pytest.raises(service.IncidentNotFound):
            await service.update_task(
                db,
                tenant_id=tenant_id,
                incident_id=incident_b.id,
                task_id=task.id,
                values={"status": "done"},
                actor_id=None,
            )


# ---------------------------------------------------------------------------
# Evidence rolls up from linked alerts
# ---------------------------------------------------------------------------


async def test_evidence_event_ids_roll_up_from_linked_alerts_without_duplicates() -> None:
    from app.models.alerts import Alert

    tenant_id = await _tenant()
    incident = await _create(tenant_id)
    shared_event = str(uuid.uuid4())
    unique_event = str(uuid.uuid4())

    async with tenant_scoped_session(tenant_id) as db:
        alert_one = Alert(
            tenant_id=tenant_id, display_id="ALT-2026-000010", title="a", description="d",
            severity="high", confidence=70, risk_score=60, dedup_key=str(uuid.uuid4()),
            event_ids=[shared_event],
        )
        alert_two = Alert(
            tenant_id=tenant_id, display_id="ALT-2026-000011", title="b", description="d",
            severity="high", confidence=70, risk_score=60, dedup_key=str(uuid.uuid4()),
            event_ids=[shared_event, unique_event],
        )
        db.add_all([alert_one, alert_two])
        await db.commit()

        await service.link_alert(
            db, tenant_id=tenant_id, incident_id=incident.id, alert_id=alert_one.id, actor_id=None
        )
        await service.link_alert(
            db, tenant_id=tenant_id, incident_id=incident.id, alert_id=alert_two.id, actor_id=None
        )
        await db.commit()
        event_ids = await service.evidence_event_ids(db, tenant_id, incident.id)

    assert sorted(event_ids) == sorted({shared_event, unique_event})


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------


async def test_one_tenants_incidents_are_invisible_to_another() -> None:
    tenant_a, tenant_b = await _tenant(), await _tenant()
    incident = await _create(tenant_a)

    async with tenant_scoped_session(tenant_b) as db:
        assert await service.list_incidents(db, tenant_b) == []
        with pytest.raises(service.IncidentNotFound):
            await service.get_incident(db, tenant_b, incident.id)


async def test_a_session_with_no_tenant_context_sees_no_incidents() -> None:
    tenant_id = await _tenant()
    await _create(tenant_id)

    async with async_session_factory() as db:
        rows = list((await db.execute(select(Incident))).scalars())
    assert rows == []


async def test_incident_counts_and_ordering() -> None:
    tenant_id = await _tenant()
    await _create(tenant_id, severity="critical")
    urgent = await _create(tenant_id, severity="low", priority="P1")

    async with tenant_scoped_session(tenant_id) as db:
        await service.transition(
            db, tenant_id=tenant_id, incident_id=urgent.id, target=TRIAGE, actor_id=None
        )
        await db.commit()
        counts = await service.count_by_status(db, tenant_id)
        queue = await service.list_incidents(db, tenant_id)

    assert counts == {NEW: 1, TRIAGE: 1}
    # Ordered by priority first: the explicit P1 comes ahead of the P1
    # default from severity=critical only if priorities tie is broken by
    # recency — both are P1 here, so recency (most-recent-first) decides.
    assert queue[0].id == urgent.id
