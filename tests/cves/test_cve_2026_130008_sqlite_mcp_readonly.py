"""CVE-2026-130008 — sqlite-mcp's read-only mode is bypassed by a second statement.

Vulnerability (from NVD and GHSA-q433-mp6c-8v4f):
    sqlite-mcp before 0.1.2, read-only mode (the default): ``execute_query`` checks only that
    its ``query`` starts with ``SELECT``, and the driver runs every ``;``-separated
    statement; ``describe_table`` splices ``table_name`` into ``PRAGMA table_info(...)``.
    Either path reaches ``ATTACH DATABASE``, which opens a file read-write whatever the main
    connection's ``mode=ro``: the protected database becomes writable, and other SQLite files
    are read or created.

Advisory: https://github.com/StacklokLabs/sqlite-mcp/security/advisories/GHSA-q433-mp6c-8v4f
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-130008
CVSS:     8.2 (HIGH) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N, CWE-89, CWE-863

Airlock fit: partial.
    Both payloads are tool-call arguments, and
    :class:`~agent_airlock.mcp_spec.readonly_sql_guard.ReadOnlySQLGuard` refuses both: a
    second statement in ``query`` and anything but a name in ``table_name``. The server
    listening on all interfaces with no authentication is its own. A second-defence fixture
    against an existing guard, not a new guard.
"""

from __future__ import annotations

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock.mcp_spec.readonly_sql_guard import ReadOnlySQLGuard, ReadOnlySQLVerdict
from agent_airlock.policy_presets import readonly_sql_tool_args_2026_125322_defaults

CVE = "CVE-2026-130008"

#: NVD's description, verbatim, so the classifier assertions read the real record.
NVD_DESCRIPTION = (
    "sqlite-mcp is a Model Context Protocol server for SQLite. Prior to 0.1.2, the "
    "default read-only mode can be bypassed through execute_query, which accepts a "
    "leading SELECT while the SQLite driver executes trailing statements, and through "
    "describe_table, which interpolates the caller-controlled table_name into PRAGMA "
    "table_info. Either path can issue ATTACH DATABASE, which opens an attached file "
    "read-write despite mode=ro and can make the protected database writable, read other "
    "SQLite database files, or create a SQLite-format file at a path writable by the "
    "server process. Existing non-empty files that are not SQLite databases are refused "
    "and left unchanged. The server has no built-in authentication and listens on all "
    "interfaces at :8080 by default, so any client that can reach the port can invoke "
    "these tools unless an authenticating proxy is in place. This issue is fixed in "
    "version 0.1.2."
)

NVD_CWES = ["CWE-89", "CWE-863"]


class TestExecuteQuery:
    @pytest.mark.parametrize(
        "query",
        [
            "SELECT 1; ATTACH DATABASE '/data/app.db' AS rw; DELETE FROM rw.users",
            "select 1 ;\n attach database '/tmp/new.db' as n",
            "SELECT 1/**/;ATTACH '/data/app.db' AS rw",
        ],
    )
    @pytest.mark.parametrize("dialect", ["sqlite", "generic"])
    def test_a_second_statement_is_refused(self, query: str, dialect: str) -> None:
        decision = ReadOnlySQLGuard(dialect=dialect).evaluate({"query": query})
        assert decision.allowed is False
        assert decision.verdict in (
            ReadOnlySQLVerdict.DENY_STACKED_STATEMENT,
            ReadOnlySQLVerdict.DENY_WRITE_STATEMENT,
        )
        assert decision.matched_field == "query"

    def test_attach_alone_is_refused(self) -> None:
        decision = ReadOnlySQLGuard(dialect="sqlite").evaluate(
            {"query": "ATTACH DATABASE '/data/app.db' AS rw"}
        )
        assert decision.verdict is ReadOnlySQLVerdict.DENY_WRITE_STATEMENT

    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM users",
            "SELECT ';ATTACH' AS note",
            "SELECT 1;",
            "WITH t AS (SELECT 1) SELECT * FROM t",
        ],
    )
    def test_a_read_passes(self, query: str) -> None:
        assert ReadOnlySQLGuard(dialect="sqlite").evaluate({"query": query}).allowed


class TestDescribeTable:
    @pytest.mark.parametrize(
        "table_name",
        [
            "users); ATTACH DATABASE '/tmp/x.db' AS y; --",
            "users) UNION SELECT 1",
            "users;ATTACH '/tmp/x.db' AS y",
        ],
    )
    def test_what_is_not_a_name_is_refused(self, table_name: str) -> None:
        decision = ReadOnlySQLGuard(dialect="sqlite").evaluate({"table_name": table_name})
        assert decision.verdict is ReadOnlySQLVerdict.DENY_NOT_AN_IDENTIFIER
        assert decision.matched_field == "table_name"

    def test_a_table_name_passes(self) -> None:
        guard = ReadOnlySQLGuard(dialect="sqlite")
        assert guard.evaluate({"table_name": "users"}).allowed
        assert guard.evaluate({"table_name": '"Order Details"'}).allowed


class TestScopeBoundary:
    def test_the_guard_cannot_see_who_connects(self) -> None:
        guard = ReadOnlySQLGuard(dialect="sqlite")
        for caller in ("127.0.0.1", "203.0.113.9"):
            assert guard.evaluate({"query": "SELECT 1", "caller": caller}).allowed

    def test_preset_does_not_claim_this_cve(self) -> None:
        assert CVE not in readonly_sql_tool_args_2026_125322_defaults()["cves"]


class TestWatcherAdmittedThisOnTheDescription:
    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_cwe_alone_would_not_have_filed_it(self) -> None:
        # CWE-89 is not on the watcher's argument-shaped list; the description's sink is.
        assert classify_shape("", ["CWE-89"]) == "triage-required"
