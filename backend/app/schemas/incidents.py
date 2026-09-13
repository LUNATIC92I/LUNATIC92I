"""Incident API schemas (spec §22 `/incidents`, spec §14's workflow)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.incidents import INCIDENT_PRIORITIES, INCIDENT_SEVERITIES


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=10_000)
    severity: str = "medium"
    priority: str | None = None
    # Alerts to promote into the case at creation time. Promoting later is
    # POST /incidents/{id}/alerts, so this is a convenience, not the only path.
    alert_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)

    @field_validator("severity")
    @classmethod
    def _known_severity(cls, value: str) -> str:
        if value not in INCIDENT_SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(INCIDENT_SEVERITIES)}")
        return value

    @field_validator("priority")
    @classmethod
    def _known_priority(cls, value: str | None) -> str | None:
        if value is not None and value not in INCIDENT_PRIORITIES:
            raise ValueError(f"priority must be one of {', '.join(INCIDENT_PRIORITIES)}")
        return value


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=10_000)
    severity: str | None = None
    priority: str | None = None
    analyst_id: uuid.UUID | None = None
    lessons_learned: str | None = Field(default=None, max_length=20_000)

    @field_validator("severity")
    @classmethod
    def _known_severity(cls, value: str | None) -> str | None:
        if value is not None and value not in INCIDENT_SEVERITIES:
            raise ValueError(f"severity must be one of {', '.join(INCIDENT_SEVERITIES)}")
        return value

    @field_validator("priority")
    @classmethod
    def _known_priority(cls, value: str | None) -> str | None:
        if value is not None and value not in INCIDENT_PRIORITIES:
            raise ValueError(f"priority must be one of {', '.join(INCIDENT_PRIORITIES)}")
        return value


class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    note: str | None = Field(default=None, max_length=2000)


class LinkAlertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: uuid.UUID


class LinkAssetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID


class LinkIocRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc_id: uuid.UUID


class LinkUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=300)


class NoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1, max_length=5000)


class NotePublic(BaseModel):
    id: str
    author_id: str | None
    body: str
    created_at: datetime


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    description: str | None = Field(default=None, max_length=5000)
    assignee_id: uuid.UUID | None = None
    due_at: datetime | None = None


class TaskUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = None
    assignee_id: uuid.UUID | None = None
    status: str | None = None
    due_at: datetime | None = None

    @field_validator("status")
    @classmethod
    def _known_status(cls, value: str | None) -> str | None:
        from app.models.incidents import TASK_STATUSES

        if value is not None and value not in TASK_STATUSES:
            raise ValueError(f"status must be one of {', '.join(TASK_STATUSES)}")
        return value


class TaskPublic(BaseModel):
    id: str
    title: str
    description: str | None
    assignee_id: str | None
    status: str
    due_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class TimelineEntryPublic(BaseModel):
    kind: str
    summary: str
    detail: dict[str, Any]
    actor_id: str | None
    occurred_at: datetime


class LinkedAlertPublic(BaseModel):
    id: str
    display_id: str
    title: str
    severity: str
    risk_score: int
    status: str


class LinkedEntities(BaseModel):
    assets: list[dict[str, Any]]
    iocs: list[dict[str, Any]]
    users: list[dict[str, Any]]


class IncidentPublic(BaseModel):
    id: str
    display_id: str
    title: str
    description: str | None
    severity: str
    priority: str
    status: str
    analyst_id: str | None
    resolution: str | None
    lessons_learned: str | None
    detected_at: datetime | None
    contained_at: datetime | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class IncidentDetail(IncidentPublic):
    alerts: list[LinkedAlertPublic]
    linked: LinkedEntities


class IncidentCounts(BaseModel):
    by_status: dict[str, int]
    open_total: int


class EvidenceDocument(BaseModel):
    event_id: str
    found: bool
    document: dict[str, Any] | None = None


class EvidenceResponse(BaseModel):
    incident_id: str
    display_id: str
    total_event_ids: int
    resolved: int
    missing_event_ids: list[str]
    documents: list[EvidenceDocument]

