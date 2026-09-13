"""The detection rule DSL (spec §7, §37).

One schema, two execution shapes — the resolution to the Phase 0 finding
that the spec mixed single-event and windowed semantics under one rule
shape (ARCHITECTURE.md §1 row 4):

- a rule **without** `window`/`threshold` compiles to a **streaming** rule,
  evaluated against each event as it arrives;
- a rule **with** them compiles to a **windowed** rule, evaluated by
  aggregating over a time window in OpenSearch.

The DSL is deliberately declarative and operator-based rather than an
expression language. A rule is data, never code: there is no `eval`, no
template rendering, and no way for a rule — or for the log data a rule
matches against — to execute anything. A SIEM whose rule format can run
code is a remote-code-execution path into the security platform itself
(THREAT_MODEL.md §3.4).

Every rule also carries the quality metadata spec §37 requires
(`false_positive_notes`, `investigation_steps`, references, author,
version). These are not decoration: an alert an analyst cannot triage is
indistinguishable from noise, and Phase 6 is where that context has to be
captured — by the person who understood the detection.
"""

import re
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

RULE_ID_PATTERN = r"^[A-Z][A-Z0-9]*-\d{3,}$"
_DURATION = re.compile(r"^(?P<value>\d+)(?P<unit>[smhd])$")
_DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# A regex in a rule is matched against attacker-influenced log data, so a
# pathological pattern is a denial-of-service vector. The length cap here
# and the subject truncation in conditions.py reduce the cost of an honest
# pattern; neither bounds catastrophic backtracking, which is exponential
# in subject length. The real bound is the per-match timeout in
# conditions.py — see the note there before relaxing any of the three.
MAX_PATTERN_LENGTH = 512


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    # Evaluated, but its matches are recorded as dry-run only and never
    # become alerts — how a new rule earns its way into production.
    TESTING = "testing"


class Operator(StrEnum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    MATCHES = "matches"
    IN = "in"
    NOT_IN = "not_in"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    EXISTS = "exists"
    CIDR = "cidr"


class Condition(BaseModel):
    """A single field test. `field` is a dotted path into the normalized
    document (`user.name`, `process.cmd_line`)."""

    model_config = ConfigDict(extra="forbid")

    field_path: str = Field(alias="field", min_length=1, max_length=200)
    operator: Operator
    value: Any = None
    # Case-insensitive by default for string comparisons: log sources are
    # wildly inconsistent about casing (DOMAIN\Alice vs domain\alice), and a
    # detection that misses because of it is worse than useless.
    case_sensitive: bool = False

    @model_validator(mode="after")
    def _check_value_present(self) -> Self:
        if self.operator is Operator.EXISTS:
            if not isinstance(self.value, bool):
                raise ValueError("operator 'exists' requires a boolean value")
            return self
        if self.value is None:
            raise ValueError(f"operator '{self.operator.value}' requires a value")
        if self.operator in (Operator.IN, Operator.NOT_IN) and not isinstance(self.value, list):
            raise ValueError(f"operator '{self.operator.value}' requires a list value")
        if self.operator is Operator.MATCHES:
            self._validate_regex()
        return self

    def _validate_regex(self) -> None:
        if not isinstance(self.value, str):
            raise ValueError("operator 'matches' requires a string pattern")
        if len(self.value) > MAX_PATTERN_LENGTH:
            raise ValueError(f"regex pattern exceeds {MAX_PATTERN_LENGTH} characters")
        try:
            re.compile(self.value)
        except re.error as exc:
            # Caught at load time, not at 3am when the rule finally matches.
            raise ValueError(f"invalid regex: {exc}") from exc


class ConditionGroup(BaseModel):
    """Boolean combinator. Exactly one of `all` / `any` / `not_` is set,
    which keeps the tree unambiguous without needing precedence rules."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    all_of: list["ConditionNode"] | None = Field(default=None, alias="all")
    any_of: list["ConditionNode"] | None = Field(default=None, alias="any")
    not_of: "ConditionNode | None" = Field(default=None, alias="not")

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        present = [f for f in (self.all_of, self.any_of, self.not_of) if f is not None]
        if len(present) != 1:
            raise ValueError("a condition group must set exactly one of: all, any, not")
        if isinstance(present[0], list) and not present[0]:
            raise ValueError("a condition group's list must not be empty")
        return self


ConditionNode = Annotated[Condition | ConditionGroup, Field(union_mode="left_to_right")]


class WindowSpec(BaseModel):
    """Turns a rule into a windowed one. `threshold` counts *distinct
    events* by default; `distinct_field` counts unique values instead, which
    is what separates password spraying (one attempt against many accounts)
    from brute force (many attempts against one)."""

    model_config = ConfigDict(extra="forbid")

    duration: str = Field(pattern=_DURATION.pattern)
    threshold: int = Field(ge=1)
    group_by: list[str] = Field(min_length=1, max_length=5)
    distinct_field: str | None = None

    @property
    def duration_seconds(self) -> int:
        match = _DURATION.match(self.duration)
        if match is None:  # pragma: no cover - the field pattern guarantees this
            raise ValueError(f"invalid duration: {self.duration}")
        return int(match.group("value")) * _DURATION_SECONDS[match.group("unit")]


class RuleException(BaseModel):
    """A documented, expiring carve-out. `reason` is mandatory: an exception
    nobody can explain later is how coverage quietly erodes."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=500)
    conditions: ConditionNode
    expires_at: str | None = None


class DetectionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(pattern=RULE_ID_PATTERN)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    severity: Severity
    confidence: int = Field(ge=0, le=100)
    risk_score: int = Field(ge=0, le=100)
    status: RuleStatus = RuleStatus.DISABLED
    version: int = Field(default=1, ge=1)
    author: str = Field(min_length=1)

    conditions: ConditionNode
    window: WindowSpec | None = None
    exceptions: list[RuleException] = Field(default_factory=list)
    # Once a rule fires for a given entity, hold further matches for this
    # long. Alert fatigue is itself an attack surface: a rule that fires
    # 500 times buries the one that matters (THREAT_MODEL.md §3.4).
    suppression: str | None = Field(default=None, pattern=_DURATION.pattern)

    # Which entity suppression is scoped to. Empty means the whole rule is
    # suppressed once it fires, which is almost never what you want: one
    # noisy host would then hide every other host. Windowed rules default to
    # their `group_by`, the entity the threshold was counted over.
    suppress_by: list[str] = Field(default_factory=list, max_length=5)

    mitre_attack: list[str] = Field(default_factory=list)

    # Spec §37 detection-quality metadata.
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

    @property
    def rule_type(self) -> Literal["streaming", "windowed"]:
        return "windowed" if self.window is not None else "streaming"

    @property
    def suppression_fields(self) -> list[str]:
        if self.suppress_by:
            return self.suppress_by
        return list(self.window.group_by) if self.window is not None else []

    @property
    def suppression_seconds(self) -> int:
        if self.suppression is None:
            return 0
        match = _DURATION.match(self.suppression)
        if match is None:  # pragma: no cover - the field pattern guarantees this
            raise ValueError(f"invalid suppression duration: {self.suppression}")
        return int(match.group("value")) * _DURATION_SECONDS[match.group("unit")]


ConditionGroup.model_rebuild()
RuleException.model_rebuild()
DetectionRule.model_rebuild()
