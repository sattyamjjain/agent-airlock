"""CVE-2026-117569 — Kali-GPT: scanner parameters of ``execute_tool()`` run through ``subprocess.run`` with ``shell=True``.

Vulnerability (from NVD, CNA VulnCheck):
    "Kali-GPT through commit a608c74 contains an OS command injection vulnerability in
    execute_tool() in kali_gpt/tools/mcp_server.py that allows MCP clients to run commands
    via unsanitized scanner parameters. Attackers or prompt-injected agents can embed shell
    metacharacters in parameters like target, ports, domain, wordlist, or url, executed via
    subprocess.run with shell=True as the MCP server user." NVD names no fixed release (its
    range is "through commit a608c74"), and this module cites no upstream fix.

Advisory: https://www.vulncheck.com/advisories/kali-gpt-through-commit-a608c74-os-command-injection-via-mcp-scanner-tool-parameters
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-117569
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: strong.
    **In scope:** shell syntax in the five scanner parameters NVD names, the "Command /
    argument injection into a spawn" shape in ``docs/cve-triage.md``.
    ``ToolArgSinkGuard(shell_args={"target", "ports", "domain", "wordlist", "url"})`` refuses
    every ``DEFAULT_SHELL_METACHARS`` token at step 2.75, before ``execute_tool`` runs, and
    so does ``tool_arg_sink_defaults(mode="deny")``, which claims this CVE. **Out of
    scope:** the ``shell=True`` command line Kali-GPT builds, which is upstream's to fix, and
    which scanner a call may select.

    Under ``shell=True`` an unquoted ``&`` is a separator, so a well-formed URL with a query
    string is refused too (``TestTheUrlParameter``): the cost of screening a URL that reaches
    a shell. A target starting with ``-`` is option injection (CWE-88), not shell syntax, and
    passes (``TestDocumentedLimit``). An existing guard (0.10.28) already refuses the shape,
    so this is a second-defence fixture, not a new guard. Triage: #390.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import TOOL_ARG_SINK_CVES, list_active, tool_arg_sink_defaults

CVE = "CVE-2026-117569"

NVD_DESCRIPTION = (
    "Kali-GPT through commit a608c74 contains an OS command injection vulnerability in "
    "execute_tool() in kali_gpt/tools/mcp_server.py that allows MCP clients to run commands via "
    "unsanitized scanner parameters. Attackers or prompt-injected agents can embed shell "
    "metacharacters in parameters like target, ports, domain, wordlist, or url, executed via "
    "subprocess.run with shell=True as the MCP server user."
)
NVD_CWES = ["CWE-78"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_117569_kali_gpt_scanner_params.json").read_text(
        encoding="utf-8"
    )
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign"]]
WELL_FORMED_REFUSED = [
    pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["refused_although_well_formed"]
]
PASSES_BY_DESIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["passes_by_design"]]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]

_NAMED = {"target", "ports", "domain", "wordlist", "url"}

#: The guard on the five parameters NVD names. ``allowed_tools`` is explicit so the policy
#: states it admits every tool rather than warning that it does.
GUARDED = SecurityPolicy(
    allowed_tools=["*"], tool_arg_sink_guard=ToolArgSinkGuard(shell_args=_NAMED)
)


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """A stub of ``execute_tool()``: it records that it ran and scans nothing."""

    @Airlock(policy=policy)
    def execute_tool(
        tool: str,
        target: str = "",
        ports: str = "",
        domain: str = "",
        wordlist: str = "",
        url: str = "",
    ) -> str:
        ran.append("execute_tool")
        return "ran"

    return {"execute_tool": execute_tool}


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


class TestEveryScannerParameterIsScreened:
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

    def test_the_five_parameters_nvd_names_are_all_covered(self) -> None:
        assert {entry["argument"] for entry in _FIXTURE["payloads"]} == _NAMED


class TestTheUrlParameter:
    @pytest.mark.parametrize("entry", WELL_FORMED_REFUSED)
    def test_a_query_string_ampersand_is_refused(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED, entry)
        _assert_refused(result, entry)
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
    def test_it_passes(self, entry: dict[str, Any]) -> None:
        result, _ = _call(GUARDED, entry)
        assert result == "ran", entry["why"]


class TestScopeBoundary:
    def test_without_the_guard_nothing_else_on_the_call_path_refuses_it(self) -> None:
        result, ran = _call(SecurityPolicy(allowed_tools=["*"]), DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]


class TestWatcherAdmittedThisOnBothSignals:
    """Filed as #390: the text matches ``shell``, ``metachar`` and ``subprocess``, and CWE-78
    is argument-shaped, so either signal alone would have filed it."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_files_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
