"""Loading rules from YAML (spec §7, §37).

`yaml.safe_load`, never `yaml.load`. PyYAML's default loader instantiates
arbitrary Python objects named in the document (`!!python/object/apply`),
which turns "an analyst edited a detection rule" into remote code execution
inside the detection worker — the exact scenario THREAT_MODEL.md §3.4 calls
out. Rules also arrive from the API and the database, not only from disk, so
this is not a "trusted local file" situation even in principle.

Validation is strict and happens at load time, because the alternative is
discovering a broken rule at the moment it should have fired:

- unknown keys are rejected (`extra="forbid"`), so a typo like `severty` is
  an error rather than a silently ignored field;
- duplicate `rule_id`s across files are rejected — two rules with one id
  means one of them silently wins;
- a windowed rule using an operator that cannot be compiled to an equivalent
  OpenSearch query is rejected with the reason (see `query.py`);
- a windowed rule without suppression is warned about, since overlapping
  runs will re-fire it while its events stay in window.

A file that fails validation never silently disappears: `load_rules`
collects errors per file and the caller decides, and the worker refuses to
start on a directory that contains an invalid rule rather than running with
a partial rule set nobody notices is partial.
"""

import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.detection.query import unsupported_operators
from app.detection.schema import DetectionRule

logger = logging.getLogger(__name__)

RULE_SUFFIXES = (".yml", ".yaml")

# The correlation pack lives inside the same rules tree but is a different
# grammar (app/correlation/schema.py), so the detection loader skips it by
# name rather than by trying to parse it and calling the failure a skip —
# a rule file that quietly does not load is the thing this module exists to
# prevent.
CORRELATION_DIRNAME = "correlation"


class RuleLoadError(ValueError):
    pass


@dataclass
class LoadResult:
    rules: list[DetectionRule] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def parse_rule(source: str, *, origin: str = "<string>") -> DetectionRule:
    """Parses and validates one rule document. Raises `RuleLoadError` with
    the origin attached — a validation message with no file name in it is
    close to useless when a hundred rules load at boot."""
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{origin}: not valid YAML: {exc}") from exc

    if not isinstance(document, dict):
        raise RuleLoadError(f"{origin}: a rule must be a YAML mapping")

    try:
        rule = DetectionRule.model_validate(document)
    except ValidationError as exc:
        raise RuleLoadError(f"{origin}: invalid rule: {exc}") from exc

    _check_execution_shape(rule, origin)
    return rule


def _check_execution_shape(rule: DetectionRule, origin: str) -> None:
    if rule.rule_type != "windowed":
        return
    unsupported = sorted(set(unsupported_operators(rule.conditions)))
    if unsupported:
        raise RuleLoadError(
            f"{origin}: windowed rule {rule.rule_id} uses operator(s) "
            f"{', '.join(unsupported)}, which cannot be evaluated as an "
            "OpenSearch aggregation with the same meaning they have in the "
            "streaming evaluator. Use contains/starts_with/ends_with/in, or "
            "make this a streaming rule."
        )
    for exception in rule.exceptions:
        unsupported = sorted(set(unsupported_operators(exception.conditions)))
        if unsupported:
            raise RuleLoadError(
                f"{origin}: exception on windowed rule {rule.rule_id} uses "
                f"operator(s) {', '.join(unsupported)}, which cannot be "
                "applied inside the aggregation query"
            )


def _warnings_for(rule: DetectionRule, origin: str) -> list[str]:
    warnings: list[str] = []
    if rule.rule_type == "windowed" and rule.suppression is None:
        warnings.append(
            f"{origin}: windowed rule {rule.rule_id} has no suppression; "
            "overlapping scheduled runs will re-fire it for as long as its "
            "events remain in window"
        )
    if rule.suppression is not None and not rule.suppression_fields:
        warnings.append(
            f"{origin}: rule {rule.rule_id} suppresses globally (no "
            "suppress_by), so one noisy entity will hide every other one"
        )
    return warnings


def iter_rule_files(
    directory: Path, *, skip_dirs: Sequence[str] = ()
) -> Iterator[tuple[str, Path]]:
    """Yields (origin, path) for every rule file under `directory`.

    Shared with the correlation loader so both packs are discovered exactly
    the same way — one place to change if, say, a new file extension is ever
    accepted.
    """
    skipped = {name.lower() for name in skip_dirs}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in RULE_SUFFIXES:
            continue
        relative = path.relative_to(directory)
        if any(part.lower() in skipped for part in relative.parts[:-1]):
            continue
        yield str(relative), path


def load_rules(directory: Path, *, skip_dirs: Sequence[str] = (CORRELATION_DIRNAME,)) -> LoadResult:
    """Loads every detection rule file under `directory`, recursively."""
    result = LoadResult()
    if not directory.exists():
        result.errors.append(f"rule directory does not exist: {directory}")
        return result

    seen: dict[str, str] = {}
    for origin, path in iter_rule_files(directory, skip_dirs=skip_dirs):
        try:
            rule = parse_rule(path.read_text(encoding="utf-8"), origin=origin)
        except (RuleLoadError, OSError, UnicodeDecodeError) as exc:
            result.errors.append(str(exc))
            continue

        if rule.rule_id in seen:
            result.errors.append(
                f"{origin}: duplicate rule_id {rule.rule_id} (already defined "
                f"in {seen[rule.rule_id]})"
            )
            continue

        seen[rule.rule_id] = origin
        result.rules.append(rule)
        result.warnings.extend(_warnings_for(rule, origin))

    return result


def load_rules_or_raise(directory: Path) -> list[DetectionRule]:
    """For the worker's startup path: a rule set that does not fully load is
    a rule set nobody can reason about, so it is a hard failure rather than
    a partial run with silently missing coverage."""
    result = load_rules(directory)
    for warning in result.warnings:
        logger.warning(warning)
    if not result.ok:
        raise RuleLoadError(
            f"{len(result.errors)} rule file(s) failed to load:\n  "
            + "\n  ".join(result.errors)
        )
    logger.info("loaded detection rules", extra={"count": len(result.rules)})
    return result.rules


def rule_to_yaml(rule: DetectionRule) -> str:
    """Round-trips a validated rule back to YAML — used when a rule created
    through the API is stored as its authored form (`definition_yaml`) so
    the database keeps one canonical representation, not two."""
    document: dict[str, Any] = rule.model_dump(mode="json", by_alias=True, exclude_none=True)
    dumped: str = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    return dumped
