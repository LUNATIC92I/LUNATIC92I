"""The correlation rule DSL (spec §9).

A detection rule answers "is this event bad?". A correlation rule answers a
different question: "have these things happened to the same entity, close
enough together, in this order?" — a failed-login burst, then a success,
then a privilege change, then a bulk download is an account takeover, while
each of those alone is a Tuesday.

The DSL reuses the detection engine's `ConditionNode` for stage matching,
deliberately: one condition grammar, one evaluator, one set of safety
properties (no `eval`, bounded regex, THREAT_MODEL.md §3.4). What is new
here is everything that makes a rule *stateful*:

- **`correlate_by`** — the entity the chain is about. Without it, unrelated
  activity across thousands of users would chain together into nonsense.
  An input that cannot resolve every entity field simply does not
  participate; guessing would be worse.
- **`stages`** — the things that must happen. Each is a condition tree plus
  a `min_count`; a stage marked `required: false` enriches the timeline
  without gating the correlation.
- **`ordered`** — whether the stages must occur in the listed order. Order
  is judged on event time, never on arrival order, because a queue backlog
  or a slow collector must not silently break a correlation.
- **`window`** — how far apart the first and last stage may be.
"""

import re
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.detection.schema import ConditionNode, RuleStatus, Severity

CORRELATION_ID_PATTERN = r"^[A-Z][A-Z0-9]*-\d{3,}$"
_DURATION = re.compile(r"^(?P<value>\d+)(?P<unit>[smhd])$")
_DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# A correlation holds state per (rule, entity) for the length of its window,
# so an unbounded window is an unbounded memory commitment across every
# entity in the estate. A day is already generous for a single chain.
MAX_WINDOW_SECONDS = 86_400


def duration_seconds(value: str) -> int:
    match = _DURATION.match(value)
    if match is None:  # pragma: no cover - callers validate with the same pattern
        raise ValueError(f"invalid duration: {value}")
    return int(match.group("value")) * _DURATION_SECONDS[match.group("unit")]


class InputKind(StrEnum):
    """What a stage matches against.

    Both streams reach the correlation engine, and a stage says which one it
    means. A stage matching detections is how the rules built in Phase 6 get
    chained ("AUTH-001 fired, then a privileged logon succeeded"); a stage
    matching events is how a chain reaches activity no single rule flags.
    """

    EVENT = "event"
    DETECTION = "detection"
    ANY = "any"


class CorrelationStage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    description: str | None = Field(default=None, max_length=500)
    matches: InputKind = InputKind.ANY
    conditions: ConditionNode
    min_count: int = Field(default=1, ge=1, le=1000)
    # A non-required stage never gates the correlation; it only adds context
    # to the timeline. Useful for "and we also saw X", which an analyst wants
    # to know but which must not be the reason an alert did or did not fire.
    required: bool = True


class CorrelationRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: str = Field(pattern=CORRELATION_ID_PATTERN)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    risk_score: int = Field(ge=0, le=100)
    status: RuleStatus = RuleStatus.DISABLED
    version: int = Field(default=1, ge=1)
    author: str = Field(min_length=1)

    window: str = Field(pattern=_DURATION.pattern)
    # Dotted paths, resolved against every input. All must resolve, or the
    # input is not part of any chain for this rule.
    correlate_by: list[str] = Field(min_length=1, max_length=3)
    ordered: bool = True
    stages: list[CorrelationStage] = Field(min_length=2, max_length=10)

    suppression: str | None = Field(default=None, pattern=_DURATION.pattern)

    mitre_attack: list[str] = Field(default_factory=list)

    # Spec §37 metadata, mandatory for the same reason as on detection rules:
    # a correlation fires rarely and matters when it does, so the analyst
    # picking it up at 3am must not have to reverse-engineer the intent.
    false_positive_notes: str = Field(min_length=1)
    investigation_steps: str = Field(min_length=1)
    references: list[str] = Field(default_factory=list)

    @field_validator("mitre_attack")
    @classmethod
    def _validate_techniques(cls, value: list[str]) -> list[str]:
        for technique in value:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique):
                raise ValueError(f"'{technique}' is not a MITRE technique id (T1110, T1110.001)")
        return value

    @model_validator(mode="after")
    def _check_shape(self) -> Self:
        names = [stage.name for stage in self.stages]
        if len(names) != len(set(names)):
            # Stage names key the state and label the timeline; duplicates
            # would silently merge two different things into one.
            raise ValueError("stage names must be unique within a rule")
        if not any(stage.required for stage in self.stages):
            raise ValueError("a correlation rule needs at least one required stage")
        if sum(1 for stage in self.stages if stage.required) < 2:
            # One required stage is a detection rule wearing a correlation
            # rule's clothes, and it would fire on every single event.
            raise ValueError("a correlation rule needs at least two required stages")
        if self.window_seconds > MAX_WINDOW_SECONDS:
            raise ValueError(f"window exceeds the {MAX_WINDOW_SECONDS}s maximum")
        return self

    @property
    def window_seconds(self) -> int:
        return duration_seconds(self.window)

    @property
    def suppression_seconds(self) -> int:
        return duration_seconds(self.suppression) if self.suppression else 0

    @property
    def required_stages(self) -> list[CorrelationStage]:
        return [stage for stage in self.stages if stage.required]
