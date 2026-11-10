"""CVE-2026-117559 — DroidMind: shell command allowlist bypassed with ``$(...)`` or backtick substitution.

Vulnerability (from NVD, CNA VulnCheck):
    "DroidMind through 0.4.0 contains a command injection vulnerability that allows MCP
    clients to bypass the shell command allowlist by using $(...) or backtick substitution.
    Attackers, including prompt-injected agents, can inject commands through parameters
    interpolated into Device.run_shell() or unvalidated Device.list_directory() to run
    blocked commands such as reboot on connected Android devices." NVD names no fixed
    release (its range is "through 0.4.0"), and this module cites no upstream fix.

Advisory: https://www.vulncheck.com/advisories/droidmind-through-0.4.0-command-injection-via-shell-allowlist-bypass
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-117559
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: strong.
    **In scope:** substitution syntax in a string argument that reaches a device shell, the
    "Command / argument injection into a spawn" shape in ``docs/cve-triage.md``. NVD names
    no argument; ``android-shell``'s ``command`` and ``list_directory``'s ``path`` are the
    server's own (``docs/guide/shell-and-installer-arguments.md``).
    ``ToolArgSinkGuard(shell_args={"command", "path"})`` refuses ``$(``, a backtick and every
    other ``DEFAULT_SHELL_METACHARS`` token at step 2.75, before the tool runs, and so does
    ``tool_arg_sink_defaults(mode="deny")``, which claims this CVE. **Out of scope:** which
    commands DroidMind's allowlist admits. A blocked command sent on its own, ``reboot``,
    carries no shell syntax and passes this guard; refusing it is the allowlist's job (or a
    ``ShellCommandPolicy`` rule's), and the substitution that smuggled it past the allowlist
    is what this guard refuses.

    An existing guard (0.10.28) already refuses the shape, so this is a second-defence
    fixture, not a new guard. Triage: #385.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import TOOL_ARG_SINK_CVES, list_active, tool_arg_sink_defaults

CVE = "CVE-2026-117559"

NVD_DESCRIPTION = (
    "DroidMind through 0.4.0 contains a command injection vulnerability that allows MCP "
    "clients to bypass the shell command allowlist by using $(...) or backtick substitution. "
    "Attackers, including prompt-injected agents, can inject commands through parameters "
    "interpolated into Device.run_shell() or unvalidated Device.list_directory() to run "
    "blocked commands such as reboot on connected Android devices."
)
NVD_CWES = ["CWE-78"]

_FIXTURE: dict[str, Any] = json.loads(
    (
        Path(__file__).parent / "fixtures" / "cve_2026_117559_droidmind_shell_allowlist.json"
    ).read_text(encoding="utf-8")
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign"]]
PASSES_BY_DESIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["passes_by_design"]]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]

#: The guard on the server's two shell-bound arguments. ``allowed_tools`` is explicit so the
#: policy states it admits every tool rather than warning that it does.
GUARDED = SecurityPolicy(
    allowed_tools=["*"], tool_arg_sink_guard=ToolArgSinkGuard(shell_args={"command", "path"})
)


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """Stubs of DroidMind's two tools: each records that it ran and reaches no device."""

    @Airlock(policy=policy)
    def android_shell(serial: str, command: str) -> str:
        ran.append("android_shell")
        return "ran"

    @Airlock(policy=policy)
    def list_directory(serial: str, path: str) -> str:
        ran.append("list_directory")
        return "ran"

    return {"android_shell": android_shell, "list_directory": list_directory}


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
    """What this guard does not decide: which command runs, and ``$NAME`` expansion."""

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
    """Filed as #385: the text matches ``shell`` and ``interpolat``, and CWE-78 is
    argument-shaped, so either signal alone would have filed it."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_files_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
