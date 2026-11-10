"""CVE-2026-117567 — esp-mcp: ``target``, ``port``, ``project_path`` and ``project_name`` reach ``asyncio.create_subprocess_shell``.

Vulnerability (from NVD, CNA VulnCheck):
    "esp-mcp through commit 28afddf contains an OS command injection vulnerability that
    allows attackers to run arbitrary commands by supplying shell metacharacters in MCP tool
    parameters. Attackers influencing agent tool calls through prompt injection can inject
    metacharacters into target, port, project_path, or project_name values passed to
    asyncio.create_subprocess_shell, executing commands as the MCP server user." NVD names
    no fixed release (its range is "through commit 28afddf"), and this module cites no
    upstream fix.

Advisory: https://www.vulncheck.com/advisories/esp-mcp-through-commit-28afddf-os-command-injection-via-mcp-tool-parameters
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-117567
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: strong.
    **In scope:** shell syntax in the four string arguments NVD names, which reach a shell
    through ``asyncio.create_subprocess_shell``: the "Command / argument injection into a
    spawn" shape in ``docs/cve-triage.md``. ``ToolArgSinkGuard(shell_args={"target", "port",
    "project_path", "project_name"})`` refuses every ``DEFAULT_SHELL_METACHARS`` token at
    step 2.75, before the tool runs, and so does ``tool_arg_sink_defaults(mode="deny")``,
    which claims this CVE. NVD names the parameters, not the tools, so ``build_project`` is
    a placeholder. **Out of scope:** the shell command line esp-mcp builds, which is
    upstream's to fix: a call through ``create_subprocess_exec`` with an argv list would not
    be exposed to these characters at all.

    ``TestDocumentedLimit`` pins what the guard's ``Honest scope`` says passes: a value
    starting with ``-`` (option injection) and a bare ``$NAME``. An existing guard (0.10.28)
    already refuses the shape, so this is a second-defence fixture, not a new guard.
    Triage: #388.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import TOOL_ARG_SINK_CVES, list_active, tool_arg_sink_defaults

CVE = "CVE-2026-117567"

NVD_DESCRIPTION = (
    "esp-mcp through commit 28afddf contains an OS command injection vulnerability that allows "
    "attackers to run arbitrary commands by supplying shell metacharacters in MCP tool "
    "parameters. Attackers influencing agent tool calls through prompt injection can inject "
    "metacharacters into target, port, project_path, or project_name values passed to "
    "asyncio.create_subprocess_shell, executing commands as the MCP server user."
)
NVD_CWES = ["CWE-78"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_117567_esp_mcp_build_params.json").read_text(
        encoding="utf-8"
    )
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign"]]
PASSES_BY_DESIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["passes_by_design"]]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]

#: The guard on the four arguments NVD names. ``allowed_tools`` is explicit so the policy
#: states it admits every tool rather than warning that it does.
GUARDED = SecurityPolicy(
    allowed_tools=["*"],
    tool_arg_sink_guard=ToolArgSinkGuard(
        shell_args={"target", "port", "project_path", "project_name"}
    ),
)


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """A placeholder esp-mcp tool holding the four parameters; it records that it ran."""

    @Airlock(policy=policy)
    def build_project(project_path: str, project_name: str, target: str, port: str) -> str:
        ran.append("build_project")
        return "ran"

    return {"build_project": build_project}


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


class TestEveryNamedParameterIsScreened:
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

    def test_the_four_parameters_nvd_names_are_all_covered(self) -> None:
        refused = {entry["argument"] for entry in _FIXTURE["payloads"]}
        assert refused == {"target", "port", "project_path", "project_name"}


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
    """Filed as #388: the text matches ``shell``, ``metachar`` and ``subprocess``, and CWE-78
    is argument-shaped, so either signal alone would have filed it."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_files_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
