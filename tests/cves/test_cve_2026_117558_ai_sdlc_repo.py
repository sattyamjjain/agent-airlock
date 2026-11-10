"""CVE-2026-117558 — ai-sdlc plugin MCP server: ``repo`` interpolated into ``gh issue view`` and ``gh pr view``.

Vulnerability (from NVD, CNA VulnCheck):
    "The ai-sdlc plugin MCP server through 0.31.2 contains an OS command injection
    vulnerability that allows attackers to execute commands by supplying shell metacharacters
    in the repo argument. The unvalidated repo value is interpolated into gh issue view or gh
    pr view commands run via execSync(), letting prompt-injected agents execute commands as
    the MCP server user." NVD names no fixed release (its range is "through 0.31.2"), and
    this module cites no upstream fix.

Advisory: https://www.vulncheck.com/advisories/ai-sdlc-mcp-server-through-0.31.2-command-injection-via-check-issue-and-check-pr-status
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-117558
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: strong.
    **In scope:** shell syntax in a string argument a server splices into a command line,
    the "Command / argument injection into a spawn" shape in ``docs/cve-triage.md``.
    ``ToolArgSinkGuard(shell_args={"repo"})`` reads ``repo`` at step 2.75 of ``@Airlock`` and
    refuses every token of ``DEFAULT_SHELL_METACHARS`` before the tool runs, and so does
    ``tool_arg_sink_defaults(mode="deny")``, which claims this CVE. **Out of scope:** the
    ``execSync`` string ai-sdlc builds, which is upstream's to fix: the guard reads the
    argument, not the command line. The guard is off until a policy sets it, and the preset
    starts in ``warn`` mode, which logs the finding and runs the call.

    An existing guard (0.10.28) already refuses the shape, so this is a second-defence
    fixture, not a new guard. ``TestDocumentedLimit`` pins what the guard's own docstring
    says passes: a value starting with ``-`` (option injection) and a bare ``$NAME``.
    Triage: #384.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import TOOL_ARG_SINK_CVES, list_active, tool_arg_sink_defaults

CVE = "CVE-2026-117558"

NVD_DESCRIPTION = (
    "The ai-sdlc plugin MCP server through 0.31.2 contains an OS command injection "
    "vulnerability that allows attackers to execute commands by supplying shell metacharacters "
    "in the repo argument. The unvalidated repo value is interpolated into gh issue view or gh "
    "pr view commands run via execSync(), letting prompt-injected agents execute commands as "
    "the MCP server user."
)
NVD_CWES = ["CWE-78"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_117558_ai_sdlc_repo.json").read_text(
        encoding="utf-8"
    )
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign"]]
PASSES_BY_DESIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["passes_by_design"]]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]

#: The guard as the docstring configures it: the argument NVD names. ``allowed_tools`` is
#: explicit so the policy states it admits every tool rather than warning that it does.
GUARDED = SecurityPolicy(
    allowed_tools=["*"], tool_arg_sink_guard=ToolArgSinkGuard(shell_args={"repo"})
)


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """Stubs of ai-sdlc's two tools: each records that it ran and builds nothing."""

    @Airlock(policy=policy)
    def check_issue(repo: str, number: int) -> str:
        ran.append("check_issue")
        return "ran"

    @Airlock(policy=policy)
    def check_pr_status(repo: str, number: int) -> str:
        ran.append("check_pr_status")
        return "ran"

    return {"check_issue": check_issue, "check_pr_status": check_pr_status}


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


class TestTheDisclosedShapeIsRefused:
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

    def test_a_positional_repo_is_read_under_its_parameter_name(self) -> None:
        ran: list[str] = []
        result = _tools(GUARDED, ran)["check_issue"]("owner/name; id", 1970)
        _assert_refused(result, DISCLOSED)
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

    def test_deny_mode_runs_a_benign_call(self) -> None:
        result, _ = _call(tool_arg_sink_defaults(mode="deny")["policy"], _FIXTURE["benign"][0])
        assert result == "ran"

    def test_the_default_warn_mode_logs_and_runs_the_call(self) -> None:
        # Day-one adoption cannot break a host, so warn mode is not a refusal: it is
        # pinned here so nobody reads the preset's default as protection.
        result, ran = _call(tool_arg_sink_defaults()["policy"], DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]

    def test_the_preset_claims_this_cve(self) -> None:
        assert CVE in TOOL_ARG_SINK_CVES
        assert CVE in tool_arg_sink_defaults()["cves"]
        assert "tool_arg_sink_defaults" in {meta.factory_name for meta in list_active()}


class TestDocumentedLimit:
    """The guard's ``Honest scope`` names these; they pass, and a reader must not infer more."""

    @pytest.mark.parametrize("entry", PASSES_BY_DESIGN)
    def test_it_passes(self, entry: dict[str, Any]) -> None:
        result, _ = _call(GUARDED, entry)
        assert result == "ran", entry["why"]


class TestScopeBoundary:
    def test_without_the_guard_nothing_else_on_the_call_path_refuses_it(self) -> None:
        # The refusal is the opt-in guard's. A plain policy admits the payload, which is the
        # vulnerable server's own behaviour; the quoting fix is upstream's.
        result, ran = _call(SecurityPolicy(allowed_tools=["*"]), DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]


class TestWatcherAdmittedThisOnBothSignals:
    """Filed as #384: the text matches sink words (``shell``, ``metachar``, ``interpolat``)
    and CWE-78 is argument-shaped, so either signal alone would have filed it."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_files_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
