"""CVE-2026-117561 — Codefriar sf-mcp: Salesforce CLI flag values reach ``execSync`` past ``escapeValue()``.

Vulnerability (from NVD, CNA VulnCheck):
    "Codefriar sf-mcp through 1.3.2 contains an OS command injection vulnerability that
    allows attackers to execute shell commands by supplying crafted Salesforce CLI tool flag
    values. Because escapeValue() in src/utils.ts fails to neutralize backticks, $()
    substitution, and other shell metacharacters, these values reach execSync in
    executeSfCommand and run as the MCP server user." NVD names no fixed release (its range
    is "through 1.3.2"), and this module cites no upstream fix.

Advisory: https://www.vulncheck.com/advisories/sf-mcp-through-1.3.2-os-command-injection-via-salesforce-cli-flag-values
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-117561
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: strong.
    **In scope:** shell syntax in flag values a server splices into a command line, the
    "Command / argument injection into a spawn" shape in ``docs/cve-triage.md``. sf-mcp's
    tools take the CLI's own flag names (``target-org``, ``query``, ...) and build
    ``--<flag>=<value>``, so the set of arguments is open-ended:
    ``ToolArgSinkGuard(screen_all_str_args=True)`` screens every value, and every
    ``**kwargs`` name too, for ``DEFAULT_SHELL_METACHARS`` at step 2.75, before the tool runs.
    ``tool_arg_sink_defaults(mode="deny")`` is that configuration and claims this CVE.
    **Out of scope:** ``escapeValue()`` and the ``execSync`` string, which are upstream's to
    fix. ``sf_data_query`` is a placeholder tool.

    The default set leaves out quotes and ``$NAME`` expansion (the guard's ``Honest scope``),
    so a double-quoted SOQL literal and ``$SF_ORG`` pass; ``TestDocumentedLimit`` pins both.
    An existing guard (0.10.28) already refuses the shape, so this is a second-defence
    fixture, not a new guard. Triage: #387.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import TOOL_ARG_SINK_CVES, list_active, tool_arg_sink_defaults

CVE = "CVE-2026-117561"

NVD_DESCRIPTION = (
    "Codefriar sf-mcp through 1.3.2 contains an OS command injection vulnerability that allows "
    "attackers to execute shell commands by supplying crafted Salesforce CLI tool flag values. "
    "Because escapeValue() in src/utils.ts fails to neutralize backticks, $() substitution, and "
    "other shell metacharacters, these values reach execSync in executeSfCommand and run as "
    "the MCP server user."
)
NVD_CWES = ["CWE-78"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_117561_sf_mcp_flag_values.json").read_text(
        encoding="utf-8"
    )
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign"]]
PASSES_BY_DESIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["passes_by_design"]]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]

#: Every flag screened, since the flag names are the CLI's. ``allowed_tools`` is explicit so
#: the policy states it admits every tool rather than warning that it does.
GUARDED = SecurityPolicy(
    allowed_tools=["*"], tool_arg_sink_guard=ToolArgSinkGuard(screen_all_str_args=True)
)


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """A placeholder sf-mcp tool taking CLI flags by name; it records that it ran."""

    @Airlock(policy=policy)
    def sf_data_query(**flags: str) -> str:
        ran.append("sf_data_query")
        return "ran"

    return {"sf_data_query": sf_data_query}


def _call(policy: SecurityPolicy, entry: dict[str, Any]) -> tuple[Any, list[str]]:
    ran: list[str] = []
    return _tools(policy, ran)[entry["tool"]](**entry["arguments"]), ran


def _assert_refused(result: Any, entry: dict[str, Any]) -> None:
    assert isinstance(result, dict), f"the call ran and returned {result!r}"
    assert result["success"] is False
    assert result["status"] == "blocked"
    assert result["block_reason"] == "tool_arg_sink"
    assert result["error"].startswith("AIRLOCK_BLOCK")
    assert result["fix_hints"], "a refusal must say what to send instead"
    assert result["metadata"]["verdict"] == entry["verdict"]
    assert result["metadata"]["argument"] == entry["argument"]
    assert result["metadata"]["token"] == entry["token"]


class TestTheFlagValueIsRefused:
    @pytest.mark.parametrize("entry", PAYLOADS)
    def test_it_is_refused_before_the_tool_runs(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED, entry)
        _assert_refused(result, entry)
        assert ran == []

    @pytest.mark.parametrize("entry", PAYLOADS)
    def test_the_refusal_names_the_token_never_the_value(self, entry: dict[str, Any]) -> None:
        result, _ = _call(GUARDED, entry)
        value = entry["arguments"][entry["argument"]]
        assert value not in result["error"]
        assert not any(value in hint for hint in result["fix_hints"])

    def test_a_flag_name_is_on_the_command_line_too(self) -> None:
        # sf-mcp builds --<flag>=<value>, so the name is model-written text as well. It is
        # refused without being echoed back.
        result, ran = _call(
            GUARDED,
            {
                "tool": "sf_data_query",
                "arguments": {"query": "SELECT Id FROM Account", "x;id": "1"},
            },
        )
        assert isinstance(result, dict)
        assert result["block_reason"] == "tool_arg_sink"
        assert result["metadata"]["argument"] is None
        assert result["metadata"]["token"] == ";"
        assert "x;id" not in result["error"]
        assert ran == []


class TestBenignCallsRun:
    @pytest.mark.parametrize("entry", BENIGN)
    def test_it_runs(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED, entry)
        assert result == "ran"
        assert ran == [entry["tool"]]


class TestThePreset:
    def test_deny_mode_refuses_the_disclosed_shape(self) -> None:
        result, ran = _call(tool_arg_sink_defaults(mode="deny")["policy"], DISCLOSED)
        _assert_refused(result, DISCLOSED)
        assert ran == []

    def test_the_default_warn_mode_logs_and_runs_the_call(self) -> None:
        # Warn mode is the preset's day-one default and is not a refusal.
        result, ran = _call(tool_arg_sink_defaults()["policy"], DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]

    def test_the_preset_claims_this_cve(self) -> None:
        assert CVE in TOOL_ARG_SINK_CVES
        assert CVE in tool_arg_sink_defaults()["cves"]
        assert "tool_arg_sink_defaults" in {meta.factory_name for meta in list_active()}


class TestDocumentedLimit:
    @pytest.mark.parametrize("entry", PASSES_BY_DESIGN)
    def test_it_passes_the_default_set(self, entry: dict[str, Any]) -> None:
        result, _ = _call(GUARDED, entry)
        assert result == "ran", entry["why"]

    def test_an_operator_can_refuse_the_double_quote(self) -> None:
        quoted = next(e for e in _FIXTURE["passes_by_design"] if e["id"] == "double-quote")
        policy = SecurityPolicy(
            allowed_tools=["*"],
            tool_arg_sink_guard=ToolArgSinkGuard(screen_all_str_args=True, extra_metachars={'"'}),
        )
        result, ran = _call(policy, quoted)
        _assert_refused(
            result, {"verdict": "deny_shell_metachar", "argument": "query", "token": '"'}
        )
        assert ran == []


class TestScopeBoundary:
    def test_without_the_guard_nothing_else_on_the_call_path_refuses_it(self) -> None:
        result, ran = _call(SecurityPolicy(allowed_tools=["*"]), DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]


class TestWatcherAdmittedThisOnBothSignals:
    """Filed as #387: the text matches ``shell`` and ``metachar``, and CWE-78 is
    argument-shaped, so either signal alone would have filed it."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_files_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
