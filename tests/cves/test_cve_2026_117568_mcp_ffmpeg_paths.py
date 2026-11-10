"""CVE-2026-117568 — mcp-ffmpeg: ``videoPath`` and ``outputDir`` break out of the ``child_process.exec`` string.

Vulnerability (from NVD, CNA VulnCheck):
    "mcp-ffmpeg through 1.0.5 contains an OS command injection vulnerability that allows
    attackers to run shell commands by supplying crafted videoPath or outputDir values to
    the resize-video, extract-audio and get-video-info tools. Attackers can embed $(),
    backticks or a closing double quote in an existing file or directory name to break out
    of the child_process.exec command string and execute commands as the MCP server user."
    NVD names no fixed release (its range is "through 1.0.5"), and this module cites no
    upstream fix. No triage issue exists for this record, although the watcher reads it as
    a candidate (pinned in this module).

Advisory: https://www.vulncheck.com/advisories/mcp-ffmpeg-through-1.0.5-os-command-injection-via-videopath-and-outputdir
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-117568
CVSS:     7.0 (HIGH) — CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: partial.
    **In scope:** shell syntax in the two path arguments NVD names, the "Command / argument
    injection into a spawn" shape in ``docs/cve-triage.md``.
    ``ToolArgSinkGuard(shell_args={"videoPath", "outputDir"})`` refuses ``$(`` and a
    backtick at step 2.75, before any of the three tools runs, and so does
    ``tool_arg_sink_defaults(mode="deny")``, which claims this CVE.

    **Why partial:** the third form NVD names, a closing double quote, is not in
    ``DEFAULT_SHELL_METACHARS``. The guard's ``Honest scope`` says a quote that only closes
    the server's own quoting injects arguments (here ``-y`` and a second output path) rather
    than commands, and leaves quotes to the operator: ``extra_metachars={'"'}`` refuses it,
    and ``TestTheClosingQuote`` pins both halves. The preset takes no ``extra_metachars``, so in
    ``deny`` mode it still admits the quote. **Out of scope:** the ``child_process.exec``
    string, which is upstream's to fix.

    An existing guard (0.10.28) already refuses the substitution forms, so this is a
    second-defence fixture, not a new guard.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import TOOL_ARG_SINK_CVES, list_active, tool_arg_sink_defaults

CVE = "CVE-2026-117568"

NVD_DESCRIPTION = (
    "mcp-ffmpeg through 1.0.5 contains an OS command injection vulnerability that allows "
    "attackers to run shell commands by supplying crafted videoPath or outputDir values to the "
    "resize-video, extract-audio and get-video-info tools. Attackers can embed $(), backticks "
    "or a closing double quote in an existing file or directory name to break out of the "
    "child_process.exec command string and execute commands as the MCP server user."
)
NVD_CWES = ["CWE-78"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_117568_mcp_ffmpeg_paths.json").read_text(
        encoding="utf-8"
    )
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
QUOTE_BREAKOUTS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["quote_breakouts"]]
BENIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign"]]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]

_SHELL_ARGS = {"videoPath", "outputDir"}

#: The default set on the two arguments NVD names. ``allowed_tools`` is explicit so the
#: policy states it admits every tool rather than warning that it does.
GUARDED = SecurityPolicy(
    allowed_tools=["*"], tool_arg_sink_guard=ToolArgSinkGuard(shell_args=_SHELL_ARGS)
)
#: The same, with the double quote the operator of a quoting server adds.
GUARDED_WITH_QUOTE = SecurityPolicy(
    allowed_tools=["*"],
    tool_arg_sink_guard=ToolArgSinkGuard(shell_args=_SHELL_ARGS, extra_metachars={'"'}),
)


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """Stubs of mcp-ffmpeg's three tools: each records that it ran and transcodes nothing."""

    @Airlock(policy=policy)
    def resize_video(videoPath: str, outputDir: str) -> str:  # noqa: N803
        ran.append("resize_video")
        return "ran"

    @Airlock(policy=policy)
    def extract_audio(videoPath: str, outputDir: str) -> str:  # noqa: N803
        ran.append("extract_audio")
        return "ran"

    @Airlock(policy=policy)
    def get_video_info(videoPath: str) -> str:  # noqa: N803
        ran.append("get_video_info")
        return "ran"

    return {
        "resize_video": resize_video,
        "extract_audio": extract_audio,
        "get_video_info": get_video_info,
    }


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

    def test_all_three_tools_nvd_names_are_covered(self) -> None:
        assert {entry["tool"] for entry in _FIXTURE["payloads"]} == {
            "resize_video",
            "extract_audio",
            "get_video_info",
        }


class TestTheClosingQuote:
    """NVD's third form. The default set admits it; the operator's ``'"'`` refuses it."""

    @pytest.mark.parametrize("entry", QUOTE_BREAKOUTS)
    def test_the_default_set_admits_it(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED, entry)
        assert result == "ran"
        assert ran == [entry["tool"]]

    @pytest.mark.parametrize("entry", QUOTE_BREAKOUTS)
    def test_the_preset_in_deny_mode_admits_it(self, entry: dict[str, Any]) -> None:
        result, _ = _call(tool_arg_sink_defaults(mode="deny")["policy"], entry)
        assert result == "ran"

    @pytest.mark.parametrize("entry", QUOTE_BREAKOUTS)
    def test_extra_metachars_refuses_it(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED_WITH_QUOTE, entry)
        _assert_refused(result, entry)
        assert ran == []

    @pytest.mark.parametrize("entry", BENIGN)
    def test_the_quote_rule_still_runs_benign_calls(self, entry: dict[str, Any]) -> None:
        result, _ = _call(GUARDED_WITH_QUOTE, entry)
        assert result == "ran"


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


class TestScopeBoundary:
    def test_without_the_guard_nothing_else_on_the_call_path_refuses_it(self) -> None:
        result, ran = _call(SecurityPolicy(allowed_tools=["*"]), DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]


class TestWatcherReadsThisAsACandidate:
    """No triage issue was filed, but the record is argument-shaped on both signals: the
    text matches ``child_process``, ``exec`` and ``shell``, and CWE-78 is in the set."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_would_file_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_would_file_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
