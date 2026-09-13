"""Compiling rule conditions into OpenSearch query DSL.

Windowed rules cannot be evaluated event-by-event — counting "5 failures in
5 minutes per user" means asking the event store, not the stream. So the
same `conditions` tree that `conditions.py` evaluates in Python has to
become a query the cluster can run. Two rules govern that translation:

**It must mean the same thing on both paths.** A rule that matches one set
of events streaming and a different set windowed is a silent detection gap,
which is worse than a rule that does not exist — nobody audits a detection
they believe is working. The subtle case is negation: in Lucene, a bare
`must_not` also matches documents where the field is *absent*, while the
Python evaluator treats an absent field as "did not match". Every negative
operator below therefore compiles to `must exists` + `must_not <positive>`,
so both paths agree.

**An operator whose semantics cannot be reproduced faithfully is rejected,
not approximated.** `matches` is the one: Python's `re` and Lucene's regexp
are different languages (Lucene has no `\\d`, `\\w`, anchors or
lookarounds, and is implicitly whole-string). Translating between them would
produce rules that quietly match differently in the two engines, so a
windowed rule using `matches` is refused at load time with a message telling
the author what to use instead. That refusal is enforced in `loader.py`, so
it happens when the rule is written rather than at 3am when it should have
fired.
"""

from functools import lru_cache
from typing import Any

from app.detection.schema import Condition, ConditionGroup, ConditionNode, Operator

# Operators with no faithful OpenSearch equivalent (see the module docstring).
UNSUPPORTED_IN_QUERY = frozenset({Operator.MATCHES})

_RANGE_OPERATORS = {
    Operator.GT: "gt",
    Operator.GTE: "gte",
    Operator.LT: "lt",
    Operator.LTE: "lte",
}

# Field types for which OpenSearch rejects `case_insensitive` outright — it
# is a text concept, and an `ip` or numeric field does not have one. Derived
# from the index mapping rather than hardcoded, so a field that changes type
# there cannot leave a stale list behind here: the failure mode is a rule
# that works in the streaming evaluator and 400s in the windowed one.
_TEXTUAL_TYPES = frozenset({"keyword", "text"})


@lru_cache(maxsize=1)
def non_textual_fields() -> frozenset[str]:
    from app.services.index_management import normalized_mapping

    found: set[str] = set()

    def walk(properties: dict[str, Any], prefix: str) -> None:
        for name, definition in properties.items():
            path = f"{prefix}{name}"
            if "properties" in definition:
                walk(definition["properties"], f"{path}.")
            elif definition.get("type") not in _TEXTUAL_TYPES:
                found.add(path)

    walk(normalized_mapping()["properties"], "")
    return frozenset(found)


def case_insensitive_allowed(field: str, requested: bool) -> bool:
    """Whether a case-insensitive comparison is legal for `field`.

    OpenSearch rejects `case_insensitive` outright on non-textual field
    types (`ip`, numeric, boolean, date) — it is a text concept, and a
    query asking for it on an `ip` field 400s rather than being ignored.
    Shared with `app.hunting.pivots`, which hits the exact same fields.
    """
    return requested and field not in non_textual_fields()


_NEGATIVE_OPERATORS = {
    Operator.NOT_EQUALS: Operator.EQUALS,
    Operator.NOT_CONTAINS: Operator.CONTAINS,
    Operator.NOT_IN: Operator.IN,
}


class UnsupportedQueryOperator(ValueError):
    """A condition cannot be expressed as an OpenSearch query with the same
    meaning it has in the Python evaluator."""


def _escape_wildcard(value: str) -> str:
    """`*` and `?` are wildcard metacharacters; a literal one in a rule value
    (a URL query string, a Windows share path) must not silently widen the
    match."""
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _positive_clause(condition: Condition) -> dict[str, Any]:
    field = condition.field_path
    value = condition.value
    insensitive = case_insensitive_allowed(field, not condition.case_sensitive)

    match condition.operator:
        case Operator.EQUALS:
            return {"term": {field: {"value": _text(value), "case_insensitive": insensitive}}}
        case Operator.IN:
            values = value if isinstance(value, list) else [value]
            # `terms` has no case_insensitive option, so a case-insensitive
            # `in` is a should-of-terms rather than a single clause.
            return {
                "bool": {
                    "should": [
                        {"term": {field: {"value": _text(item), "case_insensitive": insensitive}}}
                        for item in values
                    ],
                    "minimum_should_match": 1,
                }
            }
        case Operator.CONTAINS:
            return {
                "wildcard": {
                    field: {
                        "value": f"*{_escape_wildcard(_text(value))}*",
                        "case_insensitive": insensitive,
                    }
                }
            }
        case Operator.STARTS_WITH:
            return {
                "prefix": {
                    field: {"value": _text(value), "case_insensitive": insensitive}
                }
            }
        case Operator.ENDS_WITH:
            return {
                "wildcard": {
                    field: {
                        "value": f"*{_escape_wildcard(_text(value))}",
                        "case_insensitive": insensitive,
                    }
                }
            }
        case Operator.GT | Operator.GTE | Operator.LT | Operator.LTE:
            return {"range": {field: {_RANGE_OPERATORS[condition.operator]: value}}}
        case Operator.CIDR:
            values = value if isinstance(value, list) else [value]
            # An `ip`-typed field accepts CIDR notation directly in a term
            # query — this is why `source_ip` is mapped as `ip` and not as a
            # keyword (docs/database/opensearch_indices.md §3).
            return {
                "bool": {
                    "should": [{"term": {field: _text(item)}} for item in values],
                    "minimum_should_match": 1,
                }
            }
        case Operator.EXISTS:
            clause: dict[str, Any] = {"exists": {"field": field}}
            return clause if value else {"bool": {"must_not": [clause]}}
        case _:
            raise UnsupportedQueryOperator(
                f"operator '{condition.operator.value}' cannot be compiled to an "
                "OpenSearch query with identical semantics; use it in a streaming "
                "rule, or express it with contains/starts_with/ends_with"
            )


def compile_condition(condition: Condition) -> dict[str, Any]:
    positive = _NEGATIVE_OPERATORS.get(condition.operator)
    if positive is None:
        return _positive_clause(condition)

    inverted = condition.model_copy(update={"operator": positive})
    # `must exists` is not decoration: without it this clause would also
    # match documents that simply do not have the field, diverging from the
    # Python evaluator (see the module docstring).
    return {
        "bool": {
            "must": [{"exists": {"field": condition.field_path}}],
            "must_not": [_positive_clause(inverted)],
        }
    }


def compile_conditions(node: ConditionNode) -> dict[str, Any]:
    """Turns a condition tree into a query clause. Raises
    `UnsupportedQueryOperator` if any leaf cannot be faithfully expressed."""
    if isinstance(node, ConditionGroup):
        if node.all_of is not None:
            return {"bool": {"filter": [compile_conditions(child) for child in node.all_of]}}
        if node.any_of is not None:
            return {
                "bool": {
                    "should": [compile_conditions(child) for child in node.any_of],
                    "minimum_should_match": 1,
                }
            }
        if node.not_of is not None:
            return {"bool": {"must_not": [compile_conditions(node.not_of)]}}
        raise ValueError("condition group has no branch set")
    return compile_condition(node)


def unsupported_operators(node: ConditionNode) -> list[str]:
    """Every operator in the tree that cannot be compiled. Used by the loader
    to refuse a windowed rule at load time rather than at match time."""
    if isinstance(node, ConditionGroup):
        children: list[ConditionNode] = []
        if node.all_of is not None:
            children = list(node.all_of)
        elif node.any_of is not None:
            children = list(node.any_of)
        elif node.not_of is not None:
            children = [node.not_of]
        found: list[str] = []
        for child in children:
            found.extend(unsupported_operators(child))
        return found
    return [node.operator.value] if node.operator in UNSUPPORTED_IN_QUERY else []
