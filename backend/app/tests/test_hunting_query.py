"""The hunt query builder (spec §15): one unit test per filter operator,
field-allowlist enforcement, the `matches` refusal, and free-text
compilation. None of this touches OpenSearch — `compile_filters` and
`compile_free_text` are pure functions over the (already-loaded, in-memory)
index mapping, so these tests run fast and exercise every branch directly
rather than only through an end-to-end search.
"""

from datetime import UTC, datetime

import pytest

from app.detection.schema import Condition, ConditionGroup
from app.hunting.query import (
    FREE_TEXT_FIELDS,
    InvalidHuntQuery,
    build_query,
    compile_filters,
    compile_free_text,
    compile_time_range,
    known_fields,
    validate_filter_fields,
)

# ---------------------------------------------------------------------------
# Field allowlist
# ---------------------------------------------------------------------------


def test_known_fields_includes_the_documented_hunting_surface() -> None:
    fields = known_fields()
    for expected in ("hostname", "source_ip", "user.name", "process.cmd_line", "hash.md5"):
        assert expected in fields


def test_an_unknown_field_is_refused_with_a_pointer_to_the_fields_endpoint() -> None:
    condition = Condition(field="not_a_real_field", operator="equals", value="x")
    with pytest.raises(InvalidHuntQuery, match="not_a_real_field.*GET /hunting/fields"):
        validate_filter_fields(condition)


def test_an_unknown_field_nested_inside_a_group_is_still_caught() -> None:
    group = ConditionGroup(
        all_of=[
            Condition(field="hostname", operator="equals", value="dc01"),
            Condition(field="bogus.nested.field", operator="equals", value="x"),
        ]
    )
    with pytest.raises(InvalidHuntQuery, match="bogus.nested.field"):
        validate_filter_fields(group)


# ---------------------------------------------------------------------------
# One test per operator compile_filters supports
# ---------------------------------------------------------------------------


def test_equals_compiles_to_a_case_insensitive_term() -> None:
    query = compile_filters(Condition(field="hostname", operator="equals", value="DC01"))
    assert query == {"term": {"hostname": {"value": "DC01", "case_insensitive": True}}}


def test_equals_on_an_ip_field_is_not_case_insensitive() -> None:
    query = compile_filters(Condition(field="source_ip", operator="equals", value="10.1.1.5"))
    assert query["term"]["source_ip"]["case_insensitive"] is False


def test_not_equals_requires_the_field_to_exist_and_not_match() -> None:
    query = compile_filters(Condition(field="hostname", operator="not_equals", value="dc01"))
    assert query["bool"]["must"] == [{"exists": {"field": "hostname"}}]
    assert query["bool"]["must_not"][0]["term"]["hostname"]["value"] == "dc01"


def test_contains_compiles_to_a_wrapped_wildcard() -> None:
    query = compile_filters(Condition(field="hostname", operator="contains", value="dc"))
    assert query["wildcard"]["hostname"]["value"] == "*dc*"


def test_starts_with_compiles_to_a_prefix_query() -> None:
    query = compile_filters(Condition(field="hostname", operator="starts_with", value="dc"))
    assert query == {"prefix": {"hostname": {"value": "dc", "case_insensitive": True}}}


def test_ends_with_compiles_to_a_leading_wildcard() -> None:
    query = compile_filters(Condition(field="hostname", operator="ends_with", value="01"))
    assert query["wildcard"]["hostname"]["value"] == "*01"


def test_in_compiles_to_a_should_of_terms() -> None:
    query = compile_filters(Condition(field="hostname", operator="in", value=["dc01", "dc02"]))
    values = [clause["term"]["hostname"]["value"] for clause in query["bool"]["should"]]
    assert values == ["dc01", "dc02"]


def test_not_in_requires_existence_and_excludes_every_value() -> None:
    query = compile_filters(Condition(field="hostname", operator="not_in", value=["dc01"]))
    assert query["bool"]["must"] == [{"exists": {"field": "hostname"}}]


def test_gt_gte_lt_lte_compile_to_range_clauses() -> None:
    assert compile_filters(Condition(field="process.pid", operator="gt", value=100)) == {
        "range": {"process.pid": {"gt": 100}}
    }
    assert compile_filters(Condition(field="process.pid", operator="gte", value=100)) == {
        "range": {"process.pid": {"gte": 100}}
    }
    assert compile_filters(Condition(field="process.pid", operator="lt", value=100)) == {
        "range": {"process.pid": {"lt": 100}}
    }
    assert compile_filters(Condition(field="process.pid", operator="lte", value=100)) == {
        "range": {"process.pid": {"lte": 100}}
    }


def test_exists_true_and_false() -> None:
    present = compile_filters(Condition(field="domain", operator="exists", value=True))
    assert present == {"exists": {"field": "domain"}}
    absent = compile_filters(Condition(field="domain", operator="exists", value=False))
    assert absent == {"bool": {"must_not": [{"exists": {"field": "domain"}}]}}


def test_cidr_matches_directly_against_an_ip_typed_field() -> None:
    query = compile_filters(Condition(field="source_ip", operator="cidr", value="10.0.0.0/8"))
    assert query == {
        "bool": {
            "should": [{"term": {"source_ip": "10.0.0.0/8"}}],
            "minimum_should_match": 1,
        }
    }


def test_matches_operator_is_refused_with_an_explanation() -> None:
    condition = Condition(field="hostname", operator="matches", value="dc.*")
    with pytest.raises(InvalidHuntQuery, match="no per-query timeout"):
        compile_filters(condition)


def test_a_group_of_conditions_compiles_to_the_matching_boolean_combinator() -> None:
    all_of = ConditionGroup(
        all_of=[
            Condition(field="hostname", operator="equals", value="dc01"),
            Condition(field="source_ip", operator="cidr", value="10.0.0.0/8"),
        ]
    )
    assert "filter" in compile_filters(all_of)["bool"]

    any_of = ConditionGroup(
        any_of=[
            Condition(field="hostname", operator="equals", value="dc01"),
            Condition(field="hostname", operator="equals", value="dc02"),
        ]
    )
    assert "should" in compile_filters(any_of)["bool"]

    not_of = ConditionGroup(not_of=Condition(field="hostname", operator="equals", value="dc01"))
    assert "must_not" in compile_filters(not_of)["bool"]


# ---------------------------------------------------------------------------
# Free text
# ---------------------------------------------------------------------------


def test_free_text_searches_every_documented_field_except_ip_and_command_line() -> None:
    query = compile_free_text("carol")
    searched = {
        field
        for clause in query["bool"]["should"]
        for field in (clause.get("wildcard") or clause.get("match") or {})
    }
    assert searched == set(FREE_TEXT_FIELDS) - {"source_ip", "destination_ip"}


def test_free_text_does_not_query_ip_typed_fields() -> None:
    # OpenSearch rejects `wildcard` outright on an `ip`-typed field
    # ("Can only use wildcard queries on keyword and text fields") — a
    # regression test for the bug this exact case caught during Phase 13
    # development (see the module docstring in app/hunting/query.py).
    query = compile_free_text("10.1.1.5")
    for clause in query["bool"]["should"]:
        assert "source_ip" not in clause.get("wildcard", {})
        assert "destination_ip" not in clause.get("wildcard", {})


def test_free_text_escapes_lucene_wildcard_metacharacters() -> None:
    query = compile_free_text("a*b?c")
    hostname_clause = next(c for c in query["bool"]["should"] if "hostname" in c.get("wildcard", {}))
    assert hostname_clause["wildcard"]["hostname"]["value"] == "*a\\*b\\?c*"


def test_command_line_is_matched_not_wildcarded() -> None:
    query = compile_free_text("powershell -enc")
    command_line_clause = next(c for c in query["bool"]["should"] if "command_line" in c.get("match", {}))
    assert command_line_clause["match"]["command_line"] == "powershell -enc"


def test_empty_free_text_is_rejected() -> None:
    with pytest.raises(InvalidHuntQuery, match="must not be empty"):
        compile_free_text("   ")


def test_overlong_free_text_is_rejected() -> None:
    with pytest.raises(InvalidHuntQuery, match="exceeds"):
        compile_free_text("x" * 513)


# ---------------------------------------------------------------------------
# Time range and full query composition
# ---------------------------------------------------------------------------


def test_time_range_with_only_since() -> None:
    since = datetime(2026, 1, 1, tzinfo=UTC)
    assert compile_time_range(since=since, until=None) == {
        "range": {"timestamp": {"gte": since.isoformat()}}
    }


def test_time_range_with_neither_bound_is_none() -> None:
    assert compile_time_range(since=None, until=None) is None


def test_build_query_always_scopes_to_tenant() -> None:
    query = build_query(
        tenant_id="11111111-1111-1111-1111-111111111111",
        free_text="carol",
        filters=None,
        since=None,
        until=None,
    )
    assert {"term": {"tenant_id": "11111111-1111-1111-1111-111111111111"}} in query["bool"]["filter"]


def test_build_query_with_nothing_but_a_tenant_scope() -> None:
    query = build_query(tenant_id="t1", free_text=None, filters=None, since=None, until=None)
    assert query == {"bool": {"filter": [{"term": {"tenant_id": "t1"}}]}}


def test_build_query_combines_free_text_filters_and_time_range() -> None:
    query = build_query(
        tenant_id="t1",
        free_text="carol",
        filters=Condition(field="hostname", operator="equals", value="dc01"),
        since=datetime(2026, 1, 1, tzinfo=UTC),
        until=datetime(2026, 1, 2, tzinfo=UTC),
    )
    assert len(query["bool"]["filter"]) == 4
