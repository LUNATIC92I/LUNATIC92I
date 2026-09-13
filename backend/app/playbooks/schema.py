"""The playbook definition DSL (spec §18).

A playbook is data — a list of steps naming a registered action by its
fixed identifier — never code. The same reasoning that keeps `eval` out of
the detection rule DSL (THREAT_MODEL.md §3.4) applies here with higher
stakes: a playbook step that could name arbitrary behavior would be a
remote-code-execution path directly into destructive actions.
"""

from pydantic import BaseModel, ConfigDict, Field

from app.models.playbooks import TRIGGER_TYPES


class StepDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=100)
    params: dict[str, object] = Field(default_factory=dict)


class PlaybookDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=r"^PB-\d{3,}$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    trigger_type: str = "manual"
    steps: list[StepDefinition] = Field(min_length=1, max_length=20)

    def model_post_init(self, __context: object) -> None:
        if self.trigger_type not in TRIGGER_TYPES:
            raise ValueError(f"trigger_type must be one of {', '.join(TRIGGER_TYPES)}")
