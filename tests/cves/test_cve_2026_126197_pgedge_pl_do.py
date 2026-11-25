"""CVE-2026-126197 — pgEdge Postgres MCP splices pl-do tool arguments between fixed dollar quotes.

Vulnerability (from NVD and GHSA-r5pp-jx86-r6r9):
    pgEdge Postgres MCP Server before 1.1.0: a custom ``pl-do`` tool's JSON arguments are
    interpolated into a ``DO`` block delimited by the fixed tag ``$mcp_custom_tool$`` (and
    ``$mcp_args$`` for plpgsql), which nothing checked the values against. A string holding the
    tag closes the block, and the rest runs over the simple query protocol as statements of the
    caller's, transaction control included, so ``read_only`` is bypassed. ``sql`` and
    ``pl-func`` tools bind their arguments and are not affected.

Advisory: https://github.com/pgEdge/pgedge-postgres-mcp/security/advisories/GHSA-r5pp-jx86-r6r9
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-126197
CVSS:     8.8 (HIGH) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-89

Airlock fit: partial.
    The payload is a tool-call argument. After the closing tag PostgreSQL needs a ``;`` before
    the next statement, and a plpgsql argument needs one to end the assignment it lands in, so
    :class:`~agent_airlock.tool_arg_sink_guard.ToolArgSinkGuard` with ``screen_all_str_args``
    refuses every payload that runs something. Partial, because the arguments of a custom tool
    are free text: text with a ``;`` in it is refused too, and a tool that needs one declares
    the shape it takes instead (``TestATypedArgument``). A second-defence fixture, not a new
    guard.
"""

from __future__ import annotations

from typing import Annotated, Any

import pytest
from pydantic import StringConstraints
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy
from agent_airlock.policy_presets import tool_arg_sink_defaults
from agent_airlock.tool_arg_sink_guard import ToolArgSinkGuard

CVE = "CVE-2026-126197"

#: NVD's description, verbatim, so the classifier assertions read the real record.
NVD_DESCRIPTION = (
    "pgEdge Postgres MCP Server enables SQL queries against PostgreSQL databases through "
    "Model Context Protocol compatible clients. Prior to 1.1.0, custom pl-do tools "
    "interpolated JSON arguments into a PostgreSQL DO block delimited by fixed "
    "dollar-quote tags. An argument containing $mcp_custom_tool$ could terminate the "
    "block and inject arbitrary SQL statements, while $mcp_args$ could inject procedural "
    "code into a plpgsql block. Because the statement used the simple query protocol, "
    "injected text could include additional statements and transaction control, bypassing "
    "read_only and accessing data or modifying resources available to the connecting "
    "role. The issue requires at least one pl-do custom tool; sql and pl-func tools pass "
    "arguments as bind parameters and are not affected by this injection mechanism. This "
    "issue is fixed in 1.1.0."
)

NVD_CWES = ["CWE-89"]

_PAYLOADS = [
    "x$mcp_custom_tool$; COMMIT; BEGIN READ WRITE; DELETE FROM accounts; --",
    "x$mcp_custom_tool$ LANGUAGE plpgsql; SELECT pg_read_file('/etc/passwd'); --",
    "x$mcp_args$::json; PERFORM pg_sleep(1); v := $mcp_args$y",
]


def _do_block(argument: str) -> str:
    """The statement the server built: the JSON between two fixed tags."""
    return (
        f"DO $mcp_custom_tool$ DECLARE a json := $mcp_args${argument}$mcp_args$; $mcp_custom_tool$"
    )


def _statement_count(sql: str, tag: str) -> int:
    """How many times the fixed tag appears: two delimit one block, more break it."""
    return sql.count(tag)


class TestTheTagBreaksTheBlock:
    @pytest.mark.parametrize("payload", _PAYLOADS)
    def test_the_payload_carries_a_delimiter_of_the_block(self, payload: str) -> None:
        sql = _do_block(payload)
        counts = [_statement_count(sql, tag) for tag in ("$mcp_custom_tool$", "$mcp_args$")]
        assert counts != [2, 2]

    def test_an_ordinary_value_does_not(self) -> None:
        sql = _do_block("widgets")
        assert [_statement_count(sql, t) for t in ("$mcp_custom_tool$", "$mcp_args$")] == [2, 2]


def _tool(**policy: Any) -> Any:
    @Airlock(policy=SecurityPolicy(**policy), config=AirlockConfig(enable_audit_log=False))
    def custom_report(name: str = "", filters: dict[str, Any] | None = None) -> str:
        return "ran"

    return custom_report


class TestScreeningEveryStringArgument:
    @pytest.mark.parametrize("payload", _PAYLOADS)
    @pytest.mark.parametrize("nested", [False, True])
    def test_the_call_is_blocked(self, payload: str, nested: bool) -> None:
        tool = _tool(tool_arg_sink_guard=ToolArgSinkGuard(screen_all_str_args=True))
        refused = tool(filters={"region": payload}) if nested else tool(name=payload)
        assert refused["success"] is False
        assert refused["block_reason"] == "tool_arg_sink"

    def test_an_ordinary_call_runs(self) -> None:
        tool = _tool(tool_arg_sink_guard=ToolArgSinkGuard(screen_all_str_args=True))
        assert tool(name="O'Brien and sons", filters={"region": "EMEA", "year": 2026}) == "ran"


class TestATypedArgument:
    def test_a_declared_shape_refuses_the_tag_on_its_own(self) -> None:
        @Airlock(config=AirlockConfig(enable_audit_log=False), return_dict=True)
        def custom_report(
            name: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9 _.-]+$")],
        ) -> str:
            return "ran"

        for payload in _PAYLOADS:
            assert custom_report(name=payload)["block_reason"] == "validation_error"
        assert custom_report(name="Q3 revenue")["success"] is True

    def test_a_bare_string_with_no_guard_admits_it(self) -> None:
        assert _tool()(name=_PAYLOADS[0]) == "ran"


class TestScopeBoundary:
    def test_preset_does_not_claim_this_cve(self) -> None:
        assert CVE not in tool_arg_sink_defaults()["cves"]


class TestWatcherAdmittedThisOnTheDescription:
    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_cwe_alone_would_not_have_filed_it(self) -> None:
        # CWE-89 is not on the watcher's argument-shaped list; the description's sink is.
        assert classify_shape("", ["CWE-89"]) == "triage-required"
