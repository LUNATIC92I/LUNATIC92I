"""Loading playbooks from YAML (spec §18), mirroring the detection rule
loader's safety rules (`app/detection/loader.py`): `yaml.safe_load` only,
strict schema validation (`extra="forbid"`), every `action` name checked
against the real registry so a typo in a step is a load-time error instead
of a silent no-op the first time the playbook runs.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.playbooks.actions import ACTION_REGISTRY
from app.playbooks.schema import PlaybookDefinition

logger = logging.getLogger(__name__)

PLAYBOOK_SUFFIXES = (".yml", ".yaml")


class PlaybookLoadError(ValueError):
    pass


@dataclass
class LoadResult:
    playbooks: list[PlaybookDefinition] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def load_playbooks(directory: Path) -> LoadResult:
    result = LoadResult()
    if not directory.is_dir():
        result.errors.append(f"playbook directory does not exist: {directory}")
        return result

    seen_keys: dict[str, Path] = {}
    for path in sorted(directory.rglob("*")):
        if path.suffix not in PLAYBOOK_SUFFIXES or not path.is_file():
            continue
        try:
            raw = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            result.errors.append(f"{path}: invalid YAML: {exc}")
            continue
        if not isinstance(raw, dict):
            result.errors.append(f"{path}: playbook document must be a mapping")
            continue
        try:
            definition = PlaybookDefinition.model_validate(raw)
        except ValidationError as exc:
            result.errors.append(f"{path}: {exc}")
            continue

        unknown_actions = [s.action for s in definition.steps if s.action not in ACTION_REGISTRY]
        if unknown_actions:
            result.errors.append(f"{path}: unknown action(s): {', '.join(unknown_actions)}")
            continue

        if definition.key in seen_keys:
            other = seen_keys[definition.key]
            result.errors.append(
                f"{path}: duplicate playbook key {definition.key} (already in {other})"
            )
            continue
        seen_keys[definition.key] = path
        result.playbooks.append(definition)

    return result
