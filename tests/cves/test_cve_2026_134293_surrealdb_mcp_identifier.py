"""CVE-2026-134293 — SurrealDB's MCP server lets an escaped backtick close a quoted identifier.

Vulnerability (from NVD and GHSA-cr79-9p8r-p5wx):
    SurrealDB 3.1.0 before 4.0.0: ``consume_backtick_ident`` in ``surrealdb/mcp/src/tools/mod.rs``
    ends a quoted identifier at the first backtick, while the SurrealQL parser reads ``\\``` as an
    escaped one. The ``target`` / ``table`` argument of the CRUD tools passes validation and then
    breaks out of the identifier into a statement of the caller's.

Advisory: https://github.com/surrealdb/surrealdb/security/advisories/GHSA-cr79-9p8r-p5wx
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-134293
CVSS:     8.2 (HIGH) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N, CWE-89

Airlock fit: partial.
    The payload is a tool-call argument, and
    :class:`~agent_airlock.mcp_spec.readonly_sql_guard.ReadOnlySQLGuard` refuses a backslash, a
    quote of any style and a ``;`` inside a quoted name whatever the dialect, so it does not
    depend on agreeing with SurrealQL's lexer about where the name ends. ``table`` is an
    identifier field by default and ``target`` has to be named. Partial, because a record id
    (``person:john``), which those tools also take, is not a name to the guard: a tool that
    needs one declares its own shape. A second-defence fixture, not a new guard.
"""

from __future__ import annotations

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock.mcp_spec.readonly_sql_guard import (
    DEFAULT_IDENTIFIER_FIELDS,
    ReadOnlySQLGuard,
    ReadOnlySQLVerdict,
)
from agent_airlock.policy_presets import readonly_sql_tool_args_2026_125322_defaults

CVE = "CVE-2026-134293"

#: NVD's description, verbatim, so the classifier assertions read the real record.
NVD_DESCRIPTION = (
    "SurrealDB 3.1.0 before 4.0.0 contains an SQL injection vulnerability in its Model "
    "Context Protocol (MCP) server because the identifier validator "
    "(consume_backtick_ident and validate_identifier) treats the first backtick as the "
    "closing delimiter, ignoring escape characters that the SurrealQL parser honors. "
    "Attackers can supply MCP tool arguments containing an escaped backtick to break out "
    "of the quoted identifier and execute arbitrary SurrealQL statements."
)

NVD_CWES = ["CWE-89"]

_BREAKOUT = "`person\\`; REMOVE TABLE person; --`"


def _first_backtick_validator(text: str) -> bool:
    """What ``consume_backtick_ident`` accepted: any body up to the first backtick."""
    if not text.startswith("`"):
        return False
    close = text.find("`", 1)
    return close > 1 and not set(text[1:close]) & set("\n\r\0")


class TestTheBreakoutIsRefused:
    def test_the_vulnerable_check_accepts_its_first_identifier(self) -> None:
        assert _first_backtick_validator(_BREAKOUT)

    @pytest.mark.parametrize("field", ["table", "target", "from", "with"])
    @pytest.mark.parametrize(
        "value",
        [
            _BREAKOUT,
            "`a\\`",
            "`a\\\\`; DELETE person",
            "person; REMOVE TABLE person",
            "`a`; DELETE person",
        ],
    )
    @pytest.mark.parametrize("dialect", ["generic", "mysql", "sqlite", "postgres"])
    def test_every_spelling(self, field: str, value: str, dialect: str) -> None:
        guard = ReadOnlySQLGuard(
            identifier_fields=DEFAULT_IDENTIFIER_FIELDS | {"target", "from", "with"},
            dialect=dialect,
        )
        decision = guard.evaluate({field: value})
        assert decision.verdict is ReadOnlySQLVerdict.DENY_NOT_AN_IDENTIFIER
        assert decision.matched_field == field
        assert "REMOVE" not in decision.detail

    def test_an_ordinary_table_passes(self) -> None:
        guard = ReadOnlySQLGuard(identifier_fields=DEFAULT_IDENTIFIER_FIELDS | {"target"})
        for value in ("person", "`my table`"):
            assert guard.evaluate({"target": value}).allowed, value


class TestScopeBoundary:
    def test_a_record_id_is_not_a_name(self) -> None:
        guard = ReadOnlySQLGuard(identifier_fields=DEFAULT_IDENTIFIER_FIELDS | {"target"})
        decision = guard.evaluate({"target": "person:john"})
        assert decision.verdict is ReadOnlySQLVerdict.DENY_NOT_AN_IDENTIFIER

    def test_target_is_not_read_until_it_is_named(self) -> None:
        assert ReadOnlySQLGuard().evaluate({"target": _BREAKOUT}).allowed
        assert not ReadOnlySQLGuard().evaluate({"table": _BREAKOUT}).allowed

    def test_preset_does_not_claim_this_cve(self) -> None:
        assert CVE not in readonly_sql_tool_args_2026_125322_defaults()["cves"]


class TestWatcherAdmittedThisOnTheDescription:
    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_cwe_alone_would_not_have_filed_it(self) -> None:
        # CWE-89 is not on the watcher's argument-shaped list; the description's sink is.
        assert classify_shape("", ["CWE-89"]) == "triage-required"
