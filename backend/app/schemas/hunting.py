"""Threat hunting API schemas (spec §15 `/hunting`)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.schema import ConditionNode
from app.hunting.pivots import PivotName


class HuntQuery(BaseModel):
    """The analyst-facing hunt request. This exact shape is also what a
    saved hunt persists (app/models/hunting.py) — it is re-validated and
    re-compiled against the current field allowlist every time it runs
    rather than stored as compiled OpenSearch DSL."""

    model_config = ConfigDict(extra="forbid")

    free_text: str | None = Field(default=None, max_length=512)
    filters: ConditionNode | None = None
    since: datetime | None = None
    until: datetime | None = None

    @field_validator("free_text")
    @classmethod
    def _blank_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None

    @model_validator(mode="after")
    def _at_least_one_criterion(self) -> "HuntQuery":
        if self.free_text is None and self.filters is None:
            raise ValueError("a hunt query needs free_text and/or filters")
        return self


class HuntSearchRequest(HuntQuery):
    limit: int = Field(default=100, ge=1, le=1000)


class HuntSearchResponse(BaseModel):
    total: int
    events: list[dict[str, Any]]


class HuntFieldsResponse(BaseModel):
    fields: list[str]


class SavedHuntCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    query: HuntQuery


class SavedHuntUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    query: HuntQuery | None = None


class SavedHuntPublic(BaseModel):
    id: str
    name: str
    description: str | None
    query: dict[str, Any]
    created_by: str | None
    created_at: datetime
    updated_at: datetime


class PivotRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pivot: PivotName
    value: str = Field(min_length=1, max_length=512)
    limit: int | None = Field(default=None, ge=1, le=1000)


class PivotValueCount(BaseModel):
    value: str
    count: int


class PivotResponse(BaseModel):
    pivot: str
    result_type: Literal["events", "values"]
    total: int
    events: list[dict[str, Any]] = Field(default_factory=list)
    values: list[PivotValueCount] = Field(default_factory=list)


class ExportRequest(HuntQuery):
    format: Literal["csv", "json"] = "json"
    max_rows: int | None = Field(default=None, ge=1, le=10_000)
