"""IOC API schemas.

`source` is required on write and cannot be blank: spec §11 forbids an
indicator being treated as malicious merely because it exists somewhere, so
every claim names who is making it. The database enforces the same rule, and
these schemas are the layer that gives the analyst a usable error instead of
a constraint violation.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.threat_intel import CLASSIFICATIONS, IOC_TYPES


class IocCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, max_length=2048)
    # Optional: the type is inferred from the value when omitted. It must be
    # given for `certificate`, which is indistinguishable from a file hash.
    ioc_type: str | None = None
    classification: str = "unknown"
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=32)
    expires_at: datetime | None = None

    @field_validator("ioc_type")
    @classmethod
    def _known_type(cls, value: str | None) -> str | None:
        if value is not None and value not in IOC_TYPES:
            raise ValueError(f"ioc_type must be one of {', '.join(IOC_TYPES)}")
        return value

    @field_validator("classification")
    @classmethod
    def _known_classification(cls, value: str) -> str:
        if value not in CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {', '.join(CLASSIFICATIONS)}")
        return value


class IocUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: str | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    source: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = Field(default=None, max_length=32)
    expires_at: datetime | None = None

    @field_validator("classification")
    @classmethod
    def _known_classification(cls, value: str | None) -> str | None:
        if value is not None and value not in CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {', '.join(CLASSIFICATIONS)}")
        return value


class IocPublic(BaseModel):
    id: str
    ioc_type: str
    value: str
    classification: str
    confidence: int
    source: str
    description: str | None
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    is_expired: bool
    # True for a shared feed indicator: visible to every tenant, editable by
    # none of them.
    shared: bool


class IocHistoryPublic(BaseModel):
    changed_field: str
    old_value: str | None
    new_value: str | None
    changed_by: str | None
    changed_at: datetime


class IocMatchRequest(BaseModel):
    """Ad-hoc lookup, for triage: "is this address known?"."""

    model_config = ConfigDict(extra="forbid")

    values: list[str] = Field(min_length=1, max_length=100)


class IocMatchResult(BaseModel):
    value: str
    type: str
    classification: str
    confidence: int
    source: str
    tags: list[str]
    ioc_id: str
    shared: bool


class FeedSyncResult(BaseModel):
    source: str
    created: int
    updated: int
    skipped: int
