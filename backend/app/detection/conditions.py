"""Condition evaluation for the rule DSL (spec §7).

The evaluator is the security boundary of the detection engine. It takes two
untrusted-ish inputs — a rule (authored by an analyst, but stored in the
database and editable through the API) and an event document (built from
data an attacker controls) — and must produce a boolean without ever
executing either of them. So: no `eval`, no `exec`, no format-string
rendering, no attribute lookup driven by rule content. A field path only
ever indexes into dictionaries and lists, and an operator only ever selects
one of the fixed functions below.

Two robustness properties worth stating outright, because both are the
difference between "a detection fired late" and "the SOC went blind":

- **A condition never raises.** A comparison against a field of the wrong
  type (`gt` against the string "banana") is a non-match, not an exception.
  One malformed event must not stop a rule from evaluating the next one.
- **Regex matching is time-bounded.** Patterns are length-capped at load
  time (`schema.MAX_PATTERN_LENGTH`) and the subject is truncated to
  `MAX_MATCH_LENGTH`, but neither actually bounds catastrophic
  backtracking: a nested quantifier is exponential in the subject length,
  so even a few dozen characters can hang a match forever. The bound that
  really holds is a wall-clock timeout on each match, which is why matching
  uses the `regex` module rather than the standard library's `re` — `re`
  offers no way to interrupt a running match. A pattern that exceeds the
  timeout is counted, logged with its rule, and treated as a non-match:
  losing one detection is bad, a detection worker wedged on one event is
  worse.

Field paths are dotted (`user.name`, `process.cmd_line`) and resolve against
the flat projections of the normalized document
(`docs/database/opensearch_indices.md` §3). A path that crosses a list
resolves to every element, and the condition matches if **any** of them
match — `all`/`any`/`not` at the group level is where negation is expressed,
which keeps "no element matched" and "the field is absent" from silently
meaning different things inside a single condition.
"""

import ipaddress
import logging
from functools import lru_cache
from typing import Any

import regex

from app.core import metrics
from app.detection.schema import Condition, ConditionGroup, ConditionNode, Operator

logger = logging.getLogger(__name__)

# Subject-length cap for regex matching: generous enough for any real
# command line or URL, and it keeps ordinary matching cheap.
MAX_MATCH_LENGTH = 8192
# The bound that actually holds against catastrophic backtracking. Sized so
# that no honest pattern on an 8KB subject comes close to it.
REGEX_TIMEOUT_SECONDS = 0.25

_MISSING = object()


@lru_cache(maxsize=1024)
def _compiled(pattern: str, case_sensitive: bool) -> regex.Pattern[str]:
    """Compiled patterns are cached: a streaming rule set re-evaluates the
    same handful of patterns against every event in the pipeline, and
    recompiling per event is pure waste. The pattern was already validated
    and length-capped by the schema."""
    return regex.compile(pattern, 0 if case_sensitive else regex.IGNORECASE)


def resolve_path(document: Any, path: str) -> list[Any]:
    """Resolves a dotted path to the list of values it reaches.

    Empty when the path is absent — which is distinct from reaching a
    present `None`, so `exists` can tell the two apart."""
    current: list[Any] = [document]
    for segment in path.split("."):
        following: list[Any] = []
        for node in current:
            if isinstance(node, dict):
                value = node.get(segment, _MISSING)
                if value is not _MISSING:
                    following.append(value)
            elif isinstance(node, list):
                # A list in the middle of a path fans out: `hash.sha256`
                # against a list of hash objects checks each of them.
                for item in node:
                    if isinstance(item, dict):
                        value = item.get(segment, _MISSING)
                        if value is not _MISSING:
                            following.append(value)
        if not following:
            return []
        current = following

    # Flatten a terminal list so `mitre_techniques` (a list field) is
    # treated as several candidate values rather than one list value.
    flattened: list[Any] = []
    for node in current:
        if isinstance(node, list):
            flattened.extend(node)
        else:
            flattened.append(node)
    return flattened


def _as_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        # Deliberately before the numeric branch: in Python `True` is an
        # int, and "true"/"1" comparing equal would be a surprising match.
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    return None


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _equal(left: Any, right: Any, *, case_sensitive: bool) -> bool:
    left_number, right_number = _as_number(left), _as_number(right)
    if left_number is not None and right_number is not None:
        # Log sources are inconsistent about quoting numbers: port 22 and
        # port "22" are the same port, and a rule author should not have to
        # know which shape a given source emits.
        return left_number == right_number
    left_text, right_text = _as_text(left), _as_text(right)
    if left_text is None or right_text is None:
        return bool(left == right)
    if case_sensitive:
        return left_text == right_text
    return left_text.casefold() == right_text.casefold()


def _text_pair(left: Any, right: Any, *, case_sensitive: bool) -> tuple[str, str] | None:
    left_text, right_text = _as_text(left), _as_text(right)
    if left_text is None or right_text is None:
        return None
    if case_sensitive:
        return left_text, right_text
    return left_text.casefold(), right_text.casefold()


def _compare(left: Any, right: Any, operator: Operator) -> bool:
    left_number, right_number = _as_number(left), _as_number(right)
    if left_number is None or right_number is None:
        # An ordering comparison against something that is not a number is
        # a non-match, never an error (see the module docstring).
        return False
    match operator:
        case Operator.GT:
            return left_number > right_number
        case Operator.GTE:
            return left_number >= right_number
        case Operator.LT:
            return left_number < right_number
        case _:
            return left_number <= right_number


def _cidr_match(value: Any, networks: Any) -> bool:
    address_text = _as_text(value)
    if address_text is None:
        return False
    try:
        address = ipaddress.ip_address(address_text.strip())
    except ValueError:
        return False
    candidates = networks if isinstance(networks, list) else [networks]
    for candidate in candidates:
        candidate_text = _as_text(candidate)
        if candidate_text is None:
            continue
        try:
            network = ipaddress.ip_network(candidate_text.strip(), strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def _regex_match(value: Any, pattern: str, *, case_sensitive: bool) -> bool:
    text = _as_text(value)
    if text is None:
        return False
    try:
        found = _compiled(pattern, case_sensitive).search(
            text[:MAX_MATCH_LENGTH], timeout=REGEX_TIMEOUT_SECONDS
        )
    except TimeoutError:
        # Never silent: a rule whose pattern keeps timing out is a rule that
        # has stopped detecting, and that has to be visible as a metric
        # rather than as an inexplicable gap in coverage.
        metrics.detection_regex_timeouts_total.inc()
        logger.warning("regex evaluation timed out and was treated as a non-match")
        return False
    return found is not None


def _matches_value(condition: Condition, value: Any) -> bool:
    """Whether one resolved value satisfies the condition's operator.
    Negative operators (`not_equals`, `not_contains`, `not_in`) are the
    positive test inverted here, so their group-level meaning stays
    "no resolved value matched"."""
    operator = condition.operator
    expected = condition.value
    case_sensitive = condition.case_sensitive

    match operator:
        case Operator.EQUALS:
            return _equal(value, expected, case_sensitive=case_sensitive)
        case Operator.NOT_EQUALS:
            return not _equal(value, expected, case_sensitive=case_sensitive)
        case Operator.CONTAINS | Operator.NOT_CONTAINS:
            pair = _text_pair(value, expected, case_sensitive=case_sensitive)
            contains = pair is not None and pair[1] in pair[0]
            return contains if operator is Operator.CONTAINS else not contains
        case Operator.STARTS_WITH:
            pair = _text_pair(value, expected, case_sensitive=case_sensitive)
            return pair is not None and pair[0].startswith(pair[1])
        case Operator.ENDS_WITH:
            pair = _text_pair(value, expected, case_sensitive=case_sensitive)
            return pair is not None and pair[0].endswith(pair[1])
        case Operator.MATCHES:
            return _regex_match(value, str(expected), case_sensitive=case_sensitive)
        case Operator.IN | Operator.NOT_IN:
            candidates = expected if isinstance(expected, list) else [expected]
            found = any(
                _equal(value, candidate, case_sensitive=case_sensitive) for candidate in candidates
            )
            return found if operator is Operator.IN else not found
        case Operator.GT | Operator.GTE | Operator.LT | Operator.LTE:
            return _compare(value, expected, operator)
        case Operator.CIDR:
            return _cidr_match(value, expected)
        case _:  # pragma: no cover - EXISTS is handled before value resolution
            return False


def evaluate_condition(condition: Condition, document: dict[str, Any]) -> bool:
    values = resolve_path(document, condition.field_path)

    if condition.operator is Operator.EXISTS:
        # A field present but null counts as absent: a normalized document
        # that carries `user: null` has no user, and a rule author writing
        # `exists: true` means "there is a value here".
        present = any(value is not None for value in values)
        return present is bool(condition.value)

    return any(_matches_value(condition, value) for value in values if value is not None)


def evaluate_node(node: ConditionNode, document: dict[str, Any]) -> bool:
    if isinstance(node, ConditionGroup):
        if node.all_of is not None:
            return all(evaluate_node(child, document) for child in node.all_of)
        if node.any_of is not None:
            return any(evaluate_node(child, document) for child in node.any_of)
        if node.not_of is not None:
            return not evaluate_node(node.not_of, document)
        # Unreachable: the schema validator guarantees exactly one branch.
        # Raising rather than asserting, because `assert` disappears under
        # `python -O` and this must not degrade into a silent False.
        raise ValueError("condition group has no branch set")
    return evaluate_condition(node, document)
