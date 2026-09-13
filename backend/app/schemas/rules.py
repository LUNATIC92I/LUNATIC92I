"""Request/response schemas for the detection-rule API.

The write payload is the YAML itself rather than a JSON mirror of the rule
fields. One authored form, validated by one loader, executed by one engine:
a parallel JSON shape would be a second grammar to keep in sync, and the
first time the two disagreed a rule would run differently from how it reads.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.detection.schema import RuleStatus


class RuleSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Bounded: rule YAML is parsed, and an unbounded parse is a cheap way to
    # spend the API's memory (THREAT_MODEL.md §3.8).
    definition_yaml: str = Field(min_length=1, max_length=64_000)
    change_summary: str | None = Field(default=None, max_length=500)


class RuleStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: RuleStatus


class RuleExceptionSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)
    conditions: dict[str, Any]
    expires_at: datetime | None = None


class RulePublic(BaseModel):
    id: str
    rule_key: str
    name: str
    description: str | None
    severity: str
    confidence: int
    risk_score: int
    status: str
    rule_type: str
    mitre_techniques: list[str]
    references_urls: list[str]
    false_positive_notes: str | None
    investigation_steps: str | None
    author: str | None
    current_version: int
    definition_yaml: str


class RuleVersionPublic(BaseModel):
    version: int
    change_summary: str | None
    changed_by: str | None
    created_at: datetime
    definition_yaml: str


class RuleExceptionPublic(BaseModel):
    id: str
    reason: str
    conditions: dict[str, Any]
    expires_at: datetime | None
    created_at: datetime


class RuleTestRequest(BaseModel):
    """Dry-run a rule against a supplied event without storing anything.

    This is the detection engineer's inner loop: write a rule, paste the
    event it should catch, see whether it does — before the rule is ever
    enabled on live traffic.
    """

    model_config = ConfigDict(extra="forbid")

    definition_yaml: str = Field(min_length=1, max_length=64_000)
    event: dict[str, Any]


class RuleTestResult(BaseModel):
    matched: bool
    rule_id: str
    rule_type: str
    excepted_by: str | None = None
    entity: dict[str, Any] = Field(default_factory=dict)
    note: str | None = None


class DefaultRulesInstalled(BaseModel):
    installed: list[str]
