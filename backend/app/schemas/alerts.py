"""Alert API schemas (spec §22 `/alerts`)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.alerts import ALERT_STATUSES


class AlertPublic(BaseModel):
    id: str
    display_id: str
    title: str
    description: str
    source: str
    rule_key: str | None
    correlation_id: str | None
    severity: str
    confidence: int
    risk_score: int
    risk_bucket: str | None
    status: str
    analyst_id: str | None
    affected_user: str | None
    affected_host: str | None
    source_ip: str | None
    destination_ip: str | None
    mitre_techniques: list[str]
    # How many times this same thing has happened inside the dedup window.
    # An alert seen 60 times is a different situation from one seen once,
    # and hiding that would be the deduplication lying.
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    acknowledged_at: datetime | None
    closed_at: datetime | None
    created_at: datetime


class AlertDetail(AlertPublic):
    event_ids: list[str]
    detection_ids: list[str]
    evidence: dict[str, Any]
    risk_explanation: dict[str, Any]
    resolution_note: str | None


class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    note: str | None = Field(default=None, max_length=2000)

    @property
    def is_known_status(self) -> bool:
        return self.status in ALERT_STATUSES


class AssignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # None unassigns — handing an alert back to the queue is a normal act,
    # not an edge case.
    analyst_id: uuid.UUID | None = None


class NoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=5000)


class NotePublic(BaseModel):
    id: str
    author_id: str | None
    body: str
    created_at: datetime


class TransitionPublic(BaseModel):
    from_status: str | None
    to_status: str
    actor_id: str | None
    note: str | None
    occurred_at: datetime


class EvidenceDocument(BaseModel):
    event_id: str
    found: bool
    document: dict[str, Any] | None = None


class EvidenceResponse(BaseModel):
    alert_id: str
    display_id: str
    total_event_ids: int
    resolved: int
    # Ids the alert cites that are no longer in the event store — usually
    # because retention aged them out. Reported rather than hidden: an
    # analyst must know the difference between "no evidence" and "the
    # evidence expired".
    missing_event_ids: list[str]
    documents: list[EvidenceDocument]


class AlertCounts(BaseModel):
    by_status: dict[str, int]
    open_total: int
