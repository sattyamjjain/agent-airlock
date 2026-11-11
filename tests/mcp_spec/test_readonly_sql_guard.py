"""Tests for the read-only SQL guard (CVE-2026-125322 + CVE-2026-61789, v0.10.34).

- CVE-2026-125322: pgEdge Postgres MCP Server below 1.1.0 let the ``where`` parameter of
  ``count_rows`` carry a subquery on other tables.
  https://nvd.nist.gov/vuln/detail/CVE-2026-125322
- CVE-2026-61789: bytebase DBHub below 0.22.6 took every ``--`` for a comment, while
  MySQL and MariaDB need whitespace after it, so a second statement ran.
  https://nvd.nist.gov/vuln/detail/CVE-2026-61789

The guard only tokenises strings. No test opens a database or a socket, and nothing here
depends on today's date.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from agent_airlock.mcp_spec.readonly_sql_guard import (
    DEFAULT_FRAGMENT_FIELDS,
    DEFAULT_STATEMENT_FIELDS,
    ReadOnlySQLDecision,
    ReadOnlySQLGuard,
    ReadOnlySQLVerdict,
)

V = ReadOnlySQLVerdict


def _verdict(args: Any, dialect: str = "generic") -> ReadOnlySQLVerdict:
    return ReadOnlySQLGuard(dialect=dialect).evaluate(args).verdict


class TestFragmentFields:
    """A fragment is spliced into a fixed query: CVE-2026-125322's ``where``."""

    @pytest.mark.parametrize(
        "fragment",
        [
            "status = 'active'",
            "name = 'a;b -- c'",
            "price > 10 AND category IN ('a', 'b')",
            "created_at >= '2026-01-01' AND (x = 1 OR y = 2)",
            "CAST(ts AS timestamp WITH TIME ZONE) > now()",
            "replace(name, 'a', 'b') = 'c'",
        ],
    )
    def test_plain_predicate_allowed(self, fragment: str) -> None:
        decision = ReadOnlySQLGuard().evaluate({"where": fragment})
        assert isinstance(decision, ReadOnlySQLDecision)
        assert decision.allowed is True
        assert decision.verdict is V.ALLOW
        assert decision.matched_field is None

    def test_cve_2026_125322_subquery_refused(self) -> None:
        decision = ReadOnlySQLGuard().evaluate(
            {"table": "orders", "where": "1=1 AND (SELECT count(*) FROM users) > 0"}
        )
        assert decision.allowed is False
        assert decision.verdict is V.DENY_SUBQUERY_IN_FRAGMENT
        assert decision.matched_field == "where"
        assert decision.matched_pattern == "SELECT"

    @pytest.mark.parametrize(
        "fragment",
        [
            "x IN (TABLE users)",  # PostgreSQL / MySQL 8 shorthand for SELECT * FROM users
            "table_to_xml('users', true, true, '')::text LIKE '%a%'",
            "pg_catalog.\"table_to_xml\"('users', true, true, '') IS NOT NULL",
        ],
    )
    def test_reading_another_table_without_select_refused(self, fragment: str) -> None:
        assert _verdict({"where": fragment}) is V.DENY_SUBQUERY_IN_FRAGMENT

    @pytest.mark.parametrize("fragment", ["id = 1 -- x", "id = 1 /* x */", "id = 1 #x"])
    def test_comment_refused(self, fragment: str) -> None:
        assert _verdict({"where": fragment}) is V.DENY_COMMENT_IN_FRAGMENT

    def test_hash_is_a_comment_only_on_mysql(self) -> None:
        assert _verdict({"where": "flags # 4 = 0"}, "mysql") is V.DENY_COMMENT_IN_FRAGMENT
        assert _verdict({"where": "flags # 4 = 0"}, "postgres") is V.ALLOW

    def test_union_refused(self) -> None:
        decision = ReadOnlySQLGuard().evaluate({"where": "id = 1 UNION SELECT 2"})
        assert decision.allowed is False
        assert decision.verdict in {V.DENY_SUBQUERY_IN_FRAGMENT, V.DENY_STACKED_STATEMENT}
        assert _verdict({"where": "id = 1 UNION VALUES (2)"}) is V.DENY_STACKED_STATEMENT

    @pytest.mark.parametrize(
        ("fragment", "token"),
        [
            ("id = 1; DELETE FROM t", ";"),
            ("1=1) OR (1=1", ")"),
            ("(id = 1", "("),
        ],
    )
    def test_ending_the_clause_refused(self, fragment: str, token: str) -> None:
        decision = ReadOnlySQLGuard().evaluate({"where": fragment})
        assert decision.verdict is V.DENY_STACKED_STATEMENT
        assert decision.matched_pattern == token

    def test_write_keyword_and_dangerous_function_refused(self) -> None:
        assert _verdict({"where": "id = 1 INTO OUTFILE '/tmp/x'"}) is (V.DENY_DANGEROUS_FUNCTION)
        assert _verdict({"having": "pg_ls_dir('.') IS NOT NULL"}) is V.DENY_DANGEROUS_FUNCTION
        assert _verdict({"condition": "x = 1 DO"}) is V.DENY_WRITE_STATEMENT

    def test_executable_comment_refused_in_fragment(self) -> None:
        decision = ReadOnlySQLGuard(dialect="mysql").evaluate({"where": "id = 1 /*!50000 OR 1=1*/"})
        assert decision.verdict is V.DENY_COMMENT_IN_FRAGMENT
        assert decision.matched_pattern == "/*!"


class TestStatementFields:
    """A statement field holds one whole statement, which must only read."""

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM t WHERE a = 'x;y'",
            "select 1;",
            "SELECT 1; -- done",
            "WITH c AS (SELECT 1 AS n) SELECT n FROM c",
            "(SELECT 1) UNION (SELECT 2)",
            "VALUES (1), (2)",
            "SHOW search_path",
            "EXPLAIN SELECT * FROM t",
            "SELECT replace(name, 'a', 'b'), insert('abc', 1, 1, 'z') FROM t",
            "",
            "-- only a comment",
        ],
    )
    def test_read_statement_allowed(self, sql: str) -> None:
        assert _verdict({"sql": sql}) is V.ALLOW

    def test_cve_2026_61789_comment_then_second_statement_refused(self) -> None:
        decision = ReadOnlySQLGuard(dialect="mysql").evaluate(
            {"sql": "SELECT 1 -- x\n; DROP TABLE t"}
        )
        assert decision.allowed is False
        assert decision.verdict is V.DENY_STACKED_STATEMENT
        assert decision.matched_pattern == ";"

    def test_cve_2026_61789_double_dash_without_space_is_code_on_mysql(self) -> None:
        # The advisory's own rule: MySQL reads '--1' as two minus signs, so the text
        # after it runs. A checker that skipped it as a comment saw one statement.
        sql = "SELECT 1 --1; DROP TABLE t"
        assert _verdict({"sql": sql}, "mysql") is V.DENY_STACKED_STATEMENT
        assert _verdict({"sql": sql}, "generic") is V.DENY_STACKED_STATEMENT
        assert _verdict({"sql": sql}, "postgres") is V.ALLOW  # a comment there

    def test_stacked_statement_refused(self) -> None:
        decision = ReadOnlySQLGuard().evaluate({"query": "SELECT * FROM t; DELETE FROM t"})
        assert decision.verdict is V.DENY_STACKED_STATEMENT
        assert decision.matched_field == "query"

    def test_data_modifying_cte_refused(self) -> None:
        decision = ReadOnlySQLGuard().evaluate(
            {"sql": "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d"}
        )
        assert decision.verdict is V.DENY_WRITE_STATEMENT
        assert decision.matched_pattern == "DELETE"

    def test_select_into_refused(self) -> None:
        decision = ReadOnlySQLGuard().evaluate({"sql": "SELECT * INTO new_t FROM t"})
        assert decision.verdict is V.DENY_WRITE_STATEMENT
        assert decision.matched_pattern == "INTO"

    @pytest.mark.parametrize(
        "sql",
        [
            "DELETE FROM t",
            "UPDATE t SET a = 1",
            "EXPLAIN ANALYZE DELETE FROM t",
            "SELECT * FROM t FOR UPDATE",
            "PRAGMA writable_schema = 1",
            "SET ROLE admin",
        ],
    )
    def test_non_read_statement_refused(self, sql: str) -> None:
        assert _verdict({"sql": sql}) is V.DENY_WRITE_STATEMENT

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT pg_read_file('/etc/passwd')",
            "SELECT pg_catalog.pg_read_file('x')",
            "SELECT \"pg_read_file\"('x')",
            "SELECT LOAD_FILE('x')",
            "SELECT a FROM t INTO DUMPFILE '/tmp/x'",
            "SELECT query_to_xml('DELETE FROM t RETURNING 1', true, true, '')",
            "SELECT load_extension('x')",
        ],
    )
    def test_dangerous_function_refused(self, sql: str) -> None:
        assert _verdict({"statement": sql}) is V.DENY_DANGEROUS_FUNCTION

    def test_mysql_executable_comment_body_is_code(self) -> None:
        decision = ReadOnlySQLGuard(dialect="mysql").evaluate(
            {"sql": "SELECT /*!50000 1; DROP TABLE t*/"}
        )
        assert decision.verdict is V.DENY_STACKED_STATEMENT
        assert _verdict({"sql": "SELECT /*M! 1; DROP TABLE t*/"}, "mysql") is (
            V.DENY_STACKED_STATEMENT
        )
        assert _verdict({"sql": "SELECT 1 /*!40101 , 2 */"}, "mysql") is V.ALLOW

    def test_backslash_outside_a_literal_is_a_client_command(self) -> None:
        assert _verdict({"sql": "SELECT 1 \\! touch x"}) is V.DENY_STACKED_STATEMENT


class TestDialectReadings:
    """Each dialect is tokenised the way that database reads it."""

    def test_postgres_dollar_quote_allowed(self) -> None:
        assert _verdict({"sql": "SELECT $$a;b$$"}, "postgres") is V.ALLOW
        assert _verdict({"sql": "SELECT $fn$it's -- fine$fn$"}, "postgres") is V.ALLOW
        assert _verdict({"sql": "SELECT a$$b FROM t WHERE x = $1"}, "postgres") is V.ALLOW

    def test_dollar_quote_is_not_a_quote_on_mysql(self) -> None:
        assert _verdict({"sql": "SELECT $$a;b$$"}, "mysql") is V.DENY_STACKED_STATEMENT
        assert _verdict({"sql": "SELECT $$a;b$$"}, "generic") is V.DENY_STACKED_STATEMENT

    @pytest.mark.parametrize("sql", ["SELECT 'abc", "SELECT $tag$abc", "SELECT /* x"])
    def test_unterminated_is_uninspectable(self, sql: str) -> None:
        decision = ReadOnlySQLGuard(dialect="postgres").evaluate({"sql": sql})
        assert decision.verdict is V.DENY_UNINSPECTABLE
        assert decision.matched_pattern == "uninspectable"

    def test_postgres_comments_nest(self) -> None:
        sql = "SELECT /* /* */ ' */ ; DROP TABLE t; --'"
        assert _verdict({"sql": sql}, "postgres") is V.DENY_STACKED_STATEMENT
        assert _verdict({"sql": sql}, "generic") is V.DENY_STACKED_STATEMENT

    def test_postgres_escape_string(self) -> None:
        assert _verdict({"sql": "SELECT E'\\'; DROP TABLE t; --'"}, "postgres") is V.ALLOW
        assert _verdict({"sql": "SELECT '\\'; DROP TABLE t; --'"}, "postgres") is (
            V.DENY_STACKED_STATEMENT
        )

    def test_backslash_escapes_on_mysql_only(self) -> None:
        sql = "SELECT 'it\\'s' FROM t"
        assert _verdict({"sql": sql}, "mysql") is V.ALLOW
        assert _verdict({"sql": sql}, "postgres") is V.DENY_UNINSPECTABLE
        assert _verdict({"sql": sql}, "generic") is V.DENY_UNINSPECTABLE

    def test_sqlite_bracket_names(self) -> None:
        sql = "SELECT [a'] ; DROP TABLE t; --']"
        assert _verdict({"sql": sql}, "sqlite") is V.DENY_STACKED_STATEMENT
        assert _verdict({"sql": sql}, "generic") is V.DENY_STACKED_STATEMENT

    def test_generic_refuses_when_any_reading_does(self) -> None:
        # MySQL reads '# 2; DROP TABLE t' as a comment; PostgreSQL reads '#' as XOR.
        sql = "SELECT 1 # 2; DROP TABLE t"
        assert _verdict({"sql": sql}, "mysql") is V.ALLOW
        decision = ReadOnlySQLGuard().evaluate({"sql": sql})
        assert decision.verdict is V.DENY_STACKED_STATEMENT
        assert "postgres" in decision.detail

    def test_unicode_escaped_name_is_uninspectable(self) -> None:
        sql = "SELECT U&\"pg\\005fread\\005ffile\"('x')"
        assert _verdict({"sql": sql}, "postgres") is V.DENY_UNINSPECTABLE

    @pytest.mark.parametrize("sql", ["SELECT 1\x00; DROP TABLE t", "SELECT 1 -- a\rb"])
    def test_text_databases_read_differently_is_uninspectable(self, sql: str) -> None:
        assert _verdict({"sql": sql}) is V.DENY_UNINSPECTABLE


class TestTraversal:
    """Values are walked at any depth, as FilterEvalRCEGuard walks them."""

    def test_nested_fragment_walked(self) -> None:
        decision = ReadOnlySQLGuard().evaluate({"params": {"where": "1=1 OR (SELECT 1) = 1"}})
        assert decision.verdict is V.DENY_SUBQUERY_IN_FRAGMENT
        assert decision.matched_field == "params.where"

    def test_list_of_queries_walked(self) -> None:
        decision = ReadOnlySQLGuard().evaluate({"sql": ["SELECT 1", "SELECT 2; DROP TABLE t"]})
        assert decision.verdict is V.DENY_STACKED_STATEMENT
        assert decision.matched_field == "sql[1]"

    def test_fragment_on_the_path_wins(self) -> None:
        assert _verdict({"where": {"sql": "SELECT 1"}}) is V.DENY_SUBQUERY_IN_FRAGMENT

    def test_bytes_decoded(self) -> None:
        assert _verdict({"sql": b"SELECT 1"}) is V.ALLOW
        assert _verdict({"sql": bytearray(b"SELECT 1; DROP TABLE t")}) is (V.DENY_STACKED_STATEMENT)
        assert _verdict({"where": memoryview(b"id = 1 -- x")}) is V.DENY_COMMENT_IN_FRAGMENT

    def test_non_utf8_bytes_refused(self) -> None:
        decision = ReadOnlySQLGuard().evaluate({"sql": b"SELECT \xff"})
        assert decision.verdict is V.DENY_UNINSPECTABLE
        assert decision.matched_field == "sql"

    def test_unread_field_not_inspected(self) -> None:
        assert _verdict({"note": "DROP TABLE t; --", "limit": 10}) is V.ALLOW

    def test_none_args_allowed(self) -> None:
        assert ReadOnlySQLGuard().evaluate(None).allowed is True

    @pytest.mark.parametrize("value", [10, 1.5, Decimal("2"), True, None])
    def test_numbers_in_a_read_field_allowed(self, value: object) -> None:
        assert _verdict({"where": value}) is V.ALLOW

    def test_other_object_in_a_read_field_refused(self) -> None:
        class Clause:
            def __str__(self) -> str:
                return "1=1; DROP TABLE t"

        assert _verdict({"where": Clause()}) is V.DENY_UNINSPECTABLE
        assert _verdict({"note": Clause()}) is V.ALLOW

    def test_non_mapping_args_refused(self) -> None:
        guard = ReadOnlySQLGuard()
        assert guard.evaluate(["SELECT 1"]).verdict is V.DENY_UNINSPECTABLE  # type: ignore[arg-type]

    def test_too_deep_and_self_containing_refused(self) -> None:
        deep: dict[str, Any] = {"where": "id = 1"}
        for _ in range(40):
            deep = {"x": deep}
        assert _verdict(deep) is V.DENY_UNINSPECTABLE
        loop: list[Any] = []
        loop.append(loop)
        assert _verdict({"sql": loop}) is V.DENY_UNINSPECTABLE

    def test_detail_names_field_and_token_never_the_value(self) -> None:
        secret_tail = "zz_value_marker_zz"
        decision = ReadOnlySQLGuard().evaluate({"sql": f"SELECT 1; DROP TABLE t -- {secret_tail}"})
        assert "'sql'" in decision.detail
        assert "deny_stacked_statement" in decision.detail
        assert "';'" in decision.detail
        assert secret_tail not in decision.detail

    def test_custom_field_names(self) -> None:
        guard = ReadOnlySQLGuard(
            statement_fields=frozenset({"q"}), fragment_fields=frozenset({"predicate"})
        )
        assert guard.evaluate({"q": "DELETE FROM t"}).verdict is V.DENY_WRITE_STATEMENT
        assert guard.evaluate({"predicate": "(SELECT 1) = 1"}).verdict is (
            V.DENY_SUBQUERY_IN_FRAGMENT
        )
        assert guard.evaluate({"sql": "DELETE FROM t"}).verdict is V.ALLOW


class TestConstructor:
    def test_defaults(self) -> None:
        assert frozenset({"sql", "query", "statement"}) == DEFAULT_STATEMENT_FIELDS
        assert (
            frozenset({"where", "filter", "condition", "having", "order_by"})
            == DEFAULT_FRAGMENT_FIELDS
        )

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"statement_fields": {"sql"}},
            {"fragment_fields": ["where"]},
            {"statement_fields": frozenset({1})},
            {"dialect": 3},
        ],
    )
    def test_wrong_types_raise_type_error(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(TypeError):
            ReadOnlySQLGuard(**kwargs)

    def test_unknown_dialect_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="dialect"):
            ReadOnlySQLGuard(dialect="oracle")

    def test_field_in_both_sets_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="both"):
            ReadOnlySQLGuard(
                statement_fields=frozenset({"sql"}), fragment_fields=frozenset({"sql"})
            )


class TestPreset:
    """``policy_presets.readonly_sql_tool_args_2026_125322_defaults``."""

    def test_default_dict(self) -> None:
        from agent_airlock.policy_presets import readonly_sql_tool_args_2026_125322_defaults

        config = readonly_sql_tool_args_2026_125322_defaults()
        assert config == {
            "preset_id": "readonly_sql_tool_args_2026_125322",
            "severity": "medium",
            "default_action": "deny",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-125322",
            "cves": ("CVE-2026-125322", "CVE-2026-61789"),
            "statement_fields": DEFAULT_STATEMENT_FIELDS,
            "fragment_fields": DEFAULT_FRAGMENT_FIELDS,
            "dialect": "generic",
        }

    def test_overrides_and_validation(self) -> None:
        from agent_airlock.policy_presets import readonly_sql_tool_args_2026_125322_defaults

        config = readonly_sql_tool_args_2026_125322_defaults(
            statement_fields=frozenset({"q"}), dialect="postgres"
        )
        assert config["statement_fields"] == frozenset({"q"})
        assert config["dialect"] == "postgres"
        guard = ReadOnlySQLGuard(
            statement_fields=config["statement_fields"],
            fragment_fields=config["fragment_fields"],
            dialect=config["dialect"],
        )
        assert guard.evaluate({"q": "SELECT $$a;b$$"}).allowed is True
        with pytest.raises(ValueError):
            readonly_sql_tool_args_2026_125322_defaults(dialect="oracle")

    def test_registered_and_exported(self) -> None:
        import agent_airlock
        from agent_airlock import policy_presets

        names = {m.factory_name for m in policy_presets.list_active()}
        assert "readonly_sql_tool_args_2026_125322_defaults" in names
        assert "readonly_sql_tool_args_2026_125322_defaults" in policy_presets.__all__
        for name in ("ReadOnlySQLGuard", "ReadOnlySQLDecision", "ReadOnlySQLVerdict"):
            assert name in agent_airlock.__all__
            assert getattr(agent_airlock, name) is globals()[name]
