"""Playbook API schemas (spec §18 `/playbooks`).

Playbooks are submitted as structured JSON, not YAML-as-a-string like
detection rules: the step-list DSL here (`{action, params}`) is flat enough
that a second text format buys no safety detection rules' richer grammar
needed, and a normal JSON body gets normal schema validation for free.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.playbooks.schema import StepDefinition


class PlaybookCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=r"^PB-\d{3,}$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    trigger_type: str = "manual"
    steps: list[StepDefinition] = Field(min_length=1, max_length=20)


class PlaybookPublic(BaseModel):
    id: str
    key: str
    name: str
    description: str | None
    trigger_type: str
    status: str
    definition: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = False
    alert_id: str | None = None


class StepOutcomePublic(BaseModel):
    step_index: int
    action: str
    kind: str
    summary: str
    details: dict[str, Any]


class RunPublic(BaseModel):
    id: str
    playbook_key: str
    status: str
    dry_run: bool
    current_step: int
    results: list[dict[str, Any]]
    error: str | None
    started_at: datetime
    completed_at: datetime | None


class ApprovalPublic(BaseModel):
    id: str
    playbook_run_id: str
    step_index: int
    action_name: str
    preview: dict[str, Any]
    status: str
    requested_by: str | None
    requested_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    reason: str | None


class RejectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)


class DefaultPlaybooksInstalled(BaseModel):
    installed: list[str]
