"""Rule DSL: schema validation, safe loading, and condition evaluation.

The security-relevant assertions here are the ones about what a rule
*cannot* do — execute code, compile an unbounded regex, or mean one thing
streaming and another windowed. Those are the properties that make a rule
format safe to expose to users through an API (THREAT_MODEL.md §3.4).
"""

import time
from pathlib import Path

import pytest

from app.detection.conditions import (
    MAX_MATCH_LENGTH,
    REGEX_TIMEOUT_SECONDS,
    evaluate_node,
    resolve_path,
)
from app.detection.loader import RuleLoadError, load_rules, parse_rule, rule_to_yaml
from app.detection.query import compile_conditions, unsupported_operators
from app.detection.schema import (
    MAX_PATTERN_LENGTH,
    Condition,
    ConditionGroup,
    DetectionRule,
    RuleStatus,
)

RULES_DIR = Path(__file__).resolve().parents[3] / "rules"

MINIMAL_RULE = """
rule_id: TEST-001
name: Minimal rule
description: A rule with only the required fields.
severity: medium
confidence: 50
risk_score: 40
author: tests
conditions:
  field: user.name
  operator: equals
  value: alice
false_positive_notes: none known
investigation_steps: look at it
"""


def _condition(**kwargs) -> Condition:
    return Condition.model_validate(kwargs)


# ---------------------------------------------------------------------------
# Safety: a rule is data, never code
# ---------------------------------------------------------------------------


def test_yaml_python_object_tags_are_refused() -> None:
    """The whole reason for safe_load. With yaml.load this document runs a
    command in the detection worker."""
    with pytest.raises(RuleLoadError):
        parse_rule('!!python/object/apply:os.system ["echo pwned"]')


def test_yaml_alias_bomb_is_not_expanded_into_a_rule() -> None:
    """A billion-laughs document must fail as an invalid rule rather than
    being expanded into memory as one."""
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: [*b,*b,*b,*b]\n"
    with pytest.raises(RuleLoadError):
        parse_rule(bomb)


def test_an_unknown_field_is_an_error_not_a_silent_ignore() -> None:
    with pytest.raises(RuleLoadError, match="severty|extra"):
        parse_rule(MINIMAL_RULE + "severty: high\n")


def test_an_overlong_regex_pattern_is_refused_at_load_time() -> None:
    pattern = "a" * (MAX_PATTERN_LENGTH + 1)
    with pytest.raises(ValueError, match="exceeds"):
        _condition(field="command_line", operator="matches", value=pattern)


def test_an_invalid_regex_is_refused_at_load_time_not_at_match_time() -> None:
    with pytest.raises(ValueError, match="invalid regex"):
        _condition(field="command_line", operator="matches", value="(unclosed")


def test_catastrophic_backtracking_is_bounded_by_the_match_timeout() -> None:
    """The ReDoS bound that actually holds.

    Neither the pattern-length cap nor subject truncation helps here:
    `(a+)+b` is exponential in the subject length, so even a few dozen
    characters would run effectively forever. The per-match timeout is what
    keeps the worker alive, and a timed-out match is a non-match.
    """
    condition = _condition(field="command_line", operator="matches", value="(a+)+b")
    document = {"command_line": "a" * (MAX_MATCH_LENGTH * 4)}

    started = time.perf_counter()
    assert evaluate_node(condition, document) is False
    elapsed = time.perf_counter() - started
    assert elapsed < REGEX_TIMEOUT_SECONDS * 8, f"regex evaluation ran for {elapsed:.2f}s"


def test_a_long_field_is_truncated_before_matching() -> None:
    """Truncation is not a security control (see the test above), but it is
    a documented behaviour: content past the cut is not matched, so a rule
    author is not misled into thinking a 2MB field is searched end to end."""
    condition = _condition(field="command_line", operator="contains", value="needle")
    beyond_the_cut = {"command_line": "x" * (MAX_MATCH_LENGTH + 10) + "needle"}
    within_the_cut = {"command_line": "needle" + "x" * 10}

    # `contains` does not truncate — only regex matching does.
    assert evaluate_node(condition, beyond_the_cut) is True

    regex_condition = _condition(field="command_line", operator="matches", value="needle")
    assert evaluate_node(regex_condition, within_the_cut) is True
    assert evaluate_node(regex_condition, beyond_the_cut) is False


# ---------------------------------------------------------------------------
# Schema rules
# ---------------------------------------------------------------------------


def test_a_group_must_set_exactly_one_of_all_any_not() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        ConditionGroup.model_validate({"all": [], "any": []})
    with pytest.raises(ValueError, match="exactly one"):
        ConditionGroup.model_validate({})


def test_an_empty_condition_list_is_refused() -> None:
    # `all: []` is vacuously true and would match every event in the estate.
    with pytest.raises(ValueError, match="must not be empty"):
        ConditionGroup.model_validate({"all": []})


def test_operators_that_need_a_value_say_so() -> None:
    with pytest.raises(ValueError, match="requires a value"):
        _condition(field="user.name", operator="equals")
    with pytest.raises(ValueError, match="requires a list"):
        _condition(field="user.name", operator="in", value="alice")
    with pytest.raises(ValueError, match="requires a boolean"):
        _condition(field="user.name", operator="exists", value="yes")


def test_mitre_technique_ids_are_validated() -> None:
    with pytest.raises(ValueError, match="MITRE technique"):
        DetectionRule.model_validate(
            {**parse_rule(MINIMAL_RULE).model_dump(by_alias=True), "mitre_attack": ["TA0006"]}
        )


def test_rule_type_is_derived_from_the_presence_of_a_window() -> None:
    streaming = parse_rule(MINIMAL_RULE)
    assert streaming.rule_type == "streaming"

    windowed = parse_rule(
        MINIMAL_RULE + "window:\n  duration: 5m\n  threshold: 5\n  group_by: [user.name]\n"
    )
    assert windowed.rule_type == "windowed"
    assert windowed.window is not None
    assert windowed.window.duration_seconds == 300
    # A windowed rule suppresses per its group_by unless told otherwise.
    assert windowed.suppression_fields == ["user.name"]


def test_durations_parse_across_units() -> None:
    for text, seconds in (("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400)):
        rule = parse_rule(
            MINIMAL_RULE
            + f"window:\n  duration: {text}\n  threshold: 2\n  group_by: [user.name]\n"
        )
        assert rule.window is not None
        assert rule.window.duration_seconds == seconds


def test_a_rule_round_trips_through_yaml_unchanged() -> None:
    rule = parse_rule(MINIMAL_RULE)
    assert parse_rule(rule_to_yaml(rule)) == rule


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------


def test_dotted_paths_resolve_into_nested_objects() -> None:
    assert resolve_path({"user": {"name": "alice"}}, "user.name") == ["alice"]
    assert resolve_path({"user": {"name": "alice"}}, "user.domain") == []
    assert resolve_path({}, "user.name") == []


def test_a_path_crossing_a_list_fans_out() -> None:
    document = {"hash": [{"sha256": "a"}, {"sha256": "b"}]}
    assert resolve_path(document, "hash.sha256") == ["a", "b"]


def test_a_terminal_list_is_treated_as_several_values() -> None:
    document = {"mitre_techniques": ["T1110", "T1078"]}
    condition = _condition(field="mitre_techniques", operator="equals", value="T1078")
    assert evaluate_node(condition, document) is True


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("operator", "value", "field_value", "expected"),
    [
        ("equals", "alice", "alice", True),
        ("equals", "alice", "ALICE", True),  # case-insensitive by default
        ("equals", "alice", "bob", False),
        ("not_equals", "alice", "bob", True),
        ("not_equals", "alice", "alice", False),
        ("contains", "power", "powershell.exe", True),
        ("contains", "bash", "powershell.exe", False),
        ("not_contains", "bash", "powershell.exe", True),
        ("starts_with", "power", "powershell.exe", True),
        ("ends_with", ".exe", "powershell.exe", True),
        ("matches", "^power.*exe$", "powershell.exe", True),
        ("in", ["root", "admin"], "ADMIN", True),
        ("in", ["root", "admin"], "alice", False),
        ("not_in", ["root", "admin"], "alice", True),
        ("gt", 1000, 4000, True),
        ("gt", 1000, 80, False),
        ("gte", 4000, 4000, True),
        ("lt", 1024, 80, True),
        ("lte", 80, 80, True),
        ("cidr", "10.0.0.0/8", "10.1.2.3", True),
        ("cidr", "10.0.0.0/8", "192.168.1.1", False),
        ("cidr", ["10.0.0.0/8", "192.168.0.0/16"], "192.168.1.1", True),
    ],
)
def test_operator_semantics(operator: str, value, field_value, expected: bool) -> None:
    condition = _condition(field="probe", operator=operator, value=value)
    assert evaluate_node(condition, {"probe": field_value}) is expected


def test_case_sensitivity_can_be_demanded() -> None:
    condition = _condition(
        field="user.name", operator="equals", value="alice", case_sensitive=True
    )
    assert evaluate_node(condition, {"user": {"name": "ALICE"}}) is False


def test_numbers_and_numeric_strings_compare_equal() -> None:
    """Sources disagree about quoting numbers; a rule author should not have
    to know which shape a given source emits."""
    condition = _condition(field="destination_port", operator="equals", value=22)
    assert evaluate_node(condition, {"destination_port": "22"}) is True


def test_a_missing_field_never_matches_and_never_raises() -> None:
    for operator, value in (
        ("equals", "x"),
        ("not_equals", "x"),
        ("contains", "x"),
        ("not_contains", "x"),
        ("gt", 1),
        ("cidr", "10.0.0.0/8"),
        ("in", ["x"]),
        ("not_in", ["x"]),
    ):
        condition = _condition(field="absent.field", operator=operator, value=value)
        assert evaluate_node(condition, {"user": {"name": "alice"}}) is False


def test_a_type_mismatch_is_a_non_match_not_an_exception() -> None:
    condition = _condition(field="probe", operator="gt", value=5)
    assert evaluate_node(condition, {"probe": "banana"}) is False


def test_exists_distinguishes_absent_from_null() -> None:
    present = _condition(field="user.name", operator="exists", value=True)
    absent = _condition(field="user.name", operator="exists", value=False)

    assert evaluate_node(present, {"user": {"name": "alice"}}) is True
    assert evaluate_node(present, {"user": {"name": None}}) is False
    assert evaluate_node(absent, {}) is True


def test_boolean_values_are_not_confused_with_numbers() -> None:
    condition = _condition(field="probe", operator="equals", value=1)
    assert evaluate_node(condition, {"probe": True}) is False


# ---------------------------------------------------------------------------
# Boolean combinators
# ---------------------------------------------------------------------------


def test_all_any_and_not_compose() -> None:
    group = ConditionGroup.model_validate(
        {
            "all": [
                {"field": "class", "operator": "equals", "value": "Authentication"},
                {
                    "any": [
                        {"field": "user.name", "operator": "equals", "value": "root"},
                        {"field": "user.name", "operator": "equals", "value": "admin"},
                    ]
                },
                {"not": {"field": "source_ip", "operator": "cidr", "value": "10.0.0.0/8"}},
            ]
        }
    )
    matching = {"class": "Authentication", "user": {"name": "root"}, "source_ip": "203.0.113.1"}
    internal = {"class": "Authentication", "user": {"name": "root"}, "source_ip": "10.0.0.5"}

    assert evaluate_node(group, matching) is True
    assert evaluate_node(group, internal) is False


# ---------------------------------------------------------------------------
# Query compilation (the streaming/windowed equivalence contract)
# ---------------------------------------------------------------------------


def test_negative_operators_compile_with_an_exists_guard() -> None:
    """Without the guard, Lucene's must_not would also match documents where
    the field is absent — diverging from the Python evaluator, which does
    not."""
    compiled = compile_conditions(_condition(field="user.name", operator="not_equals", value="x"))
    assert compiled["bool"]["must"] == [{"exists": {"field": "user.name"}}]
    assert "must_not" in compiled["bool"]


def test_wildcard_metacharacters_in_a_value_are_escaped() -> None:
    compiled = compile_conditions(_condition(field="url", operator="contains", value="a*b"))
    assert compiled["wildcard"]["url"]["value"] == "*a\\*b*"


def test_a_windowed_rule_using_an_uncompilable_operator_is_refused() -> None:
    windowed = (
        MINIMAL_RULE.replace(
            "conditions:\n  field: user.name\n  operator: equals\n  value: alice\n",
            "conditions:\n  field: command_line\n  operator: matches\n  value: 'a.*b'\n",
        )
        + "window:\n  duration: 5m\n  threshold: 5\n  group_by: [user.name]\n"
    )
    with pytest.raises(RuleLoadError, match="matches"):
        parse_rule(windowed)

    # The same conditions are perfectly acceptable in a streaming rule.
    streaming = windowed.replace(
        "window:\n  duration: 5m\n  threshold: 5\n  group_by: [user.name]\n", ""
    )
    assert unsupported_operators(parse_rule(streaming).conditions) == ["matches"]


# ---------------------------------------------------------------------------
# Loading the shipped pack
# ---------------------------------------------------------------------------


def test_the_shipped_rule_pack_loads_cleanly() -> None:
    result = load_rules(RULES_DIR)
    assert result.errors == []
    assert result.warnings == []
    assert len(result.rules) >= 10


def test_every_shipped_rule_carries_its_triage_metadata() -> None:
    """Spec §37: an alert an analyst cannot triage is indistinguishable from
    noise, so the notes are part of the rule, not documentation elsewhere."""
    for rule in load_rules(RULES_DIR).rules:
        assert rule.false_positive_notes.strip(), rule.rule_id
        assert rule.investigation_steps.strip(), rule.rule_id
        assert rule.mitre_attack, f"{rule.rule_id} claims no ATT&CK technique"
        assert rule.references, f"{rule.rule_id} cites no reference"
        assert rule.status is RuleStatus.ENABLED, f"{rule.rule_id} ships disabled"


def test_shipped_rules_have_unique_ids_and_the_expected_families() -> None:
    rules = load_rules(RULES_DIR).rules
    ids = [rule.rule_id for rule in rules]
    assert len(ids) == len(set(ids))
    assert {i for i in ids if i.startswith("AUTH-")}, "no Authentication family"
    assert {i for i in ids if i.startswith("WIN-")}, "no Windows family"


def test_duplicate_rule_ids_across_files_are_an_error(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(MINIMAL_RULE)
    (tmp_path / "b.yml").write_text(MINIMAL_RULE.replace("Minimal rule", "Copy"))
    result = load_rules(tmp_path)
    assert not result.ok
    assert "duplicate rule_id TEST-001" in result.errors[0]


def test_a_windowed_rule_without_suppression_warns(tmp_path: Path) -> None:
    (tmp_path / "a.yml").write_text(
        MINIMAL_RULE + "window:\n  duration: 5m\n  threshold: 5\n  group_by: [user.name]\n"
    )
    result = load_rules(tmp_path)
    assert result.ok
    assert any("no suppression" in warning for warning in result.warnings)
