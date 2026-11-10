"""CVE-2026-117560 — ATXP Gemini CLI extension: ``$()`` or backticks in ``message_id``, ``subject`` or ``query`` reach ``runAtxp()``.

Vulnerability (from NVD, CNA VulnCheck):
    "ATXP Gemini CLI extension through 1.0.0 contains an OS command injection vulnerability
    in runAtxp() that allows attackers to execute shell commands through unsanitized MCP tool
    parameters. Attackers can plant instructions in email or SMS content to inject $() or
    backtick substitutions into parameters like message_id, subject, or query, running
    commands as the user." NVD names no fixed release (its range is "through 1.0.0"), and
    this module cites no upstream fix.

Advisory: https://www.vulncheck.com/advisories/atxp-gemini-cli-extension-through-1.0.0-os-command-injection-via-mcp-tools
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-117560
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: strong.
    **In scope:** substitution syntax in the string arguments NVD names, which reach a
    shell through ``runAtxp()``: the "Command / argument injection into a spawn" shape in
    ``docs/cve-triage.md``. ``ToolArgSinkGuard(shell_args={"message_id", "subject",
    "query"})`` refuses ``$(``, a backtick and the other ``DEFAULT_SHELL_METACHARS`` tokens at
    step 2.75, before the tool runs, and so does ``tool_arg_sink_defaults(mode="deny")``,
    which claims this CVE. NVD names the parameters, not the tools, so ``atxp_tool`` here is a
    placeholder. **Out of scope:** the email or SMS content that steers the agent, which no
    tool argument carries until the agent writes it into one, and ``runAtxp()``'s command
    string, which is upstream's to fix.

    ``subject`` and ``query`` look like free text, and with ``screen_all_str_args`` an
    operator opts free text out by name. ``TestDocumentedLimit`` pins that an opted-out
    ``subject`` admits the payload: on this server it must be screened, not exempted.
    An existing guard (0.10.28) already refuses the shape, so this is a second-defence
    fixture, not a new guard. Triage: #386.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import TOOL_ARG_SINK_CVES, list_active, tool_arg_sink_defaults

CVE = "CVE-2026-117560"

NVD_DESCRIPTION = (
    "ATXP Gemini CLI extension through 1.0.0 contains an OS command injection vulnerability in "
    "runAtxp() that allows attackers to execute shell commands through unsanitized MCP tool "
    "parameters. Attackers can plant instructions in email or SMS content to inject $() or "
    "backtick substitutions into parameters like message_id, subject, or query, running "
    "commands as the user."
)
NVD_CWES = ["CWE-78"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_117560_atxp_tool_params.json").read_text(
        encoding="utf-8"
    )
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign"]]
PASSES_BY_DESIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["passes_by_design"]]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]
SUBJECT_PAYLOAD: dict[str, Any] = next(
    entry for entry in _FIXTURE["payloads"] if entry["argument"] == "subject"
)

#: The guard on the three parameters NVD names. ``allowed_tools`` is explicit so the policy
#: states it admits every tool rather than warning that it does.
GUARDED = SecurityPolicy(
    allowed_tools=["*"],
    tool_arg_sink_guard=ToolArgSinkGuard(shell_args={"message_id", "subject", "query"}),
)


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """A placeholder tool holding the three parameters; it records that it ran."""

    @Airlock(policy=policy)
    def atxp_tool(message_id: str = "", subject: str = "", query: str = "") -> str:
        ran.append("atxp_tool")
        return "ran"

    return {"atxp_tool": atxp_tool}


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


class TestTheSubstitutionIsRefused:
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


class TestBenignCallsRun:
    @pytest.mark.parametrize("entry", BENIGN)
    def test_it_runs(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED, entry)
        assert result == "ran"
        assert ran == [entry["tool"]]


class TestThePreset:
    def test_deny_mode_refuses_every_named_parameter(self) -> None:
        policy = tool_arg_sink_defaults(mode="deny")["policy"]
        for entry in _FIXTURE["payloads"]:
            result, ran = _call(policy, entry)
            _assert_refused(result, entry)
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

    def test_a_subject_opted_out_as_free_text_admits_the_payload(self) -> None:
        # The exemption is the operator's to grant, and on this server it must not be:
        # runAtxp() puts subject into a shell. The preset takes the same free_text_args.
        policy = tool_arg_sink_defaults(free_text_args={"subject"}, mode="deny")["policy"]
        result, ran = _call(policy, SUBJECT_PAYLOAD)
        assert result == "ran"
        assert ran == ["atxp_tool"]


class TestScopeBoundary:
    def test_without_the_guard_nothing_else_on_the_call_path_refuses_it(self) -> None:
        result, ran = _call(SecurityPolicy(allowed_tools=["*"]), DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]


class TestWatcherAdmittedThisOnBothSignals:
    """Filed as #386: the text matches ``shell`` and CWE-78 is argument-shaped, so either
    signal alone would have filed it."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_files_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
