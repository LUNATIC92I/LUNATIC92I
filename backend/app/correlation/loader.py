"""Loading correlation rules from YAML.

Same safety posture as the detection loader and the same discovery code
(`detection.loader.iter_rule_files`): `yaml.safe_load` only, unknown keys
rejected, duplicate ids rejected, and a pack that does not fully load is a
hard failure for the worker rather than a quietly partial rule set.

Correlation rules live in `rules/correlation/`. They are a different grammar
from detection rules, which is why the two loaders are separate functions
rather than one that guesses from the document's keys — a rule file that
loads as the wrong kind of rule, or silently as neither, is exactly the
failure both loaders are built to make impossible.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.correlation.schema import CorrelationRule
from app.detection.loader import CORRELATION_DIRNAME, RuleLoadError, iter_rule_files

logger = logging.getLogger(__name__)


@dataclass
class CorrelationLoadResult:
    rules: list[CorrelationRule] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def parse_correlation_rule(source: str, *, origin: str = "<string>") -> CorrelationRule:
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{origin}: not valid YAML: {exc}") from exc

    if not isinstance(document, dict):
        raise RuleLoadError(f"{origin}: a correlation rule must be a YAML mapping")

    try:
        return CorrelationRule.model_validate(document)
    except ValidationError as exc:
        raise RuleLoadError(f"{origin}: invalid correlation rule: {exc}") from exc


def correlation_directory(rules_root: Path) -> Path:
    return rules_root / CORRELATION_DIRNAME


def _warnings_for(rule: CorrelationRule, origin: str) -> list[str]:
    warnings: list[str] = []
    if rule.suppression is None:
        # A correlation re-evaluates on every input, so once a chain is
        # complete every further input for that entity completes it again.
        warnings.append(
            f"{origin}: {rule.correlation_id} has no suppression; it will re-fire "
            "on every subsequent input for the same entity while its window holds"
        )
    if not rule.ordered:
        warnings.append(
            f"{origin}: {rule.correlation_id} is unordered — check that the chain "
            "really is order-independent, since ordering is most of what makes a "
            "correlation more specific than its parts"
        )
    return warnings


def load_correlation_rules(rules_root: Path) -> CorrelationLoadResult:
    result = CorrelationLoadResult()
    directory = correlation_directory(rules_root)
    if not directory.exists():
        result.errors.append(f"correlation rule directory does not exist: {directory}")
        return result

    seen: dict[str, str] = {}
    for origin, path in iter_rule_files(directory):
        try:
            rule = parse_correlation_rule(path.read_text(encoding="utf-8"), origin=origin)
        except (RuleLoadError, OSError, UnicodeDecodeError) as exc:
            result.errors.append(str(exc))
            continue

        if rule.correlation_id in seen:
            result.errors.append(
                f"{origin}: duplicate correlation_id {rule.correlation_id} "
                f"(already defined in {seen[rule.correlation_id]})"
            )
            continue

        seen[rule.correlation_id] = origin
        result.rules.append(rule)
        result.warnings.extend(_warnings_for(rule, origin))

    return result


def load_correlation_rules_or_raise(rules_root: Path) -> list[CorrelationRule]:
    result = load_correlation_rules(rules_root)
    for warning in result.warnings:
        logger.warning(warning)
    if not result.ok:
        raise RuleLoadError(
            f"{len(result.errors)} correlation rule file(s) failed to load:\n  "
            + "\n  ".join(result.errors)
        )
    logger.info("loaded correlation rules", extra={"count": len(result.rules)})
    return result.rules


def correlation_rule_to_yaml(rule: CorrelationRule) -> str:
    document: dict[str, Any] = rule.model_dump(mode="json", by_alias=True, exclude_none=True)
    dumped: str = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    return dumped
