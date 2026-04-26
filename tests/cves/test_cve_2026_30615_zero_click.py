"""Tests for CVE-2026-30615 Windsurf zero-click MCP config auto-load (v0.5.7+).

Primary source (cited per v0.5.1+ convention):
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-30615
- Tenable: https://www.tenable.com/cve/CVE-2026-30615
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock import (
    MCPCommandMutationDetected,
    UnsignedMCPServerAdded,
)
from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.zero_click_config_guard import (
    ConfigDiffReport,
    ConfigFileWatchPolicy,
    audit_config_diff,
)
from agent_airlock.policy_presets import windsurf_cve_2026_30615_defaults

FIXTURE = Path(__file__).parent / "fixtures" / "cve_2026_30615_windsurf_zero_click.json"


def _b(obj: dict) -> bytes:
    return json.dumps(obj).encode("utf-8")


class TestCleanLoad:
    def test_empty_config_passes(self, tmp_path: Path) -> None:
        cfg = ConfigFileWatchPolicy(require_signer_for_new_servers=True)
        report = audit_config_diff(
            tmp_path / "mcp.json",
            old_sha256=None,
            new_content=b"{}",
            cfg=cfg,
        )
        assert isinstance(report, ConfigDiffReport)
        assert report.added_servers == ()


class TestNewServerEntries:
    def test_new_server_no_signer_blocks(self, tmp_path: Path) -> None:
        cfg = ConfigFileWatchPolicy()
        new = _b({"mcpServers": {"evil": {"command": ["/tmp/x"]}}})
        with pytest.raises(UnsignedMCPServerAdded) as exc:
            audit_config_diff(tmp_path / "mcp.json", None, new, cfg, old_content=b"{}")
        assert exc.value.server_name == "evil"

    def test_new_server_trusted_signer_passes(self, tmp_path: Path) -> None:
        cfg = ConfigFileWatchPolicy(signer_allowlist=frozenset({"sre"}))
        new = _b(
            {
                "mcpServers": {
                    "fs": {
                        "command": ["uvx", "mcp-server-everything"],
                        "signer": "sre",
                    }
                }
            }
        )
        report = audit_config_diff(tmp_path / "mcp.json", None, new, cfg, old_content=b"{}")
        assert report.added_servers == ("fs",)

    def test_new_server_unknown_signer_blocks(self, tmp_path: Path) -> None:
        cfg = ConfigFileWatchPolicy(signer_allowlist=frozenset({"sre"}))
        new = _b(
            {
                "mcpServers": {
                    "fs": {
                        "command": ["uvx", "x"],
                        "signer": "attacker",
                    }
                }
            }
        )
        with pytest.raises(UnsignedMCPServerAdded):
            audit_config_diff(tmp_path / "mcp.json", None, new, cfg, old_content=b"{}")


class TestCommandMutation:
    def test_command_mutation_blocks(self, tmp_path: Path) -> None:
        cfg = ConfigFileWatchPolicy()
        old = _b({"mcpServers": {"fs": {"command": ["uvx", "x"], "signer": "sre"}}})
        new = _b({"mcpServers": {"fs": {"command": ["/tmp/evil"], "signer": "sre"}}})
        with pytest.raises(MCPCommandMutationDetected):
            audit_config_diff(
                tmp_path / "mcp.json",
                old_sha256=None,
                new_content=new,
                cfg=cfg,
                old_content=old,
            )

    def test_no_change_passes(self, tmp_path: Path) -> None:
        cfg = ConfigFileWatchPolicy()
        same = _b({"mcpServers": {"fs": {"command": ["uvx", "x"], "signer": "sre"}}})
        report = audit_config_diff(
            tmp_path / "mcp.json",
            old_sha256=None,
            new_content=same,
            cfg=cfg,
            old_content=same,
        )
        assert report.added_servers == ()
        assert report.mutated_command_servers == ()


class TestPreset:
    def test_preset_returns_audit_callable(self) -> None:
        cfg = windsurf_cve_2026_30615_defaults(signer_allowlist=frozenset({"sre"}))
        assert callable(cfg["audit"])
        assert cfg["source"].startswith("https://nvd.nist.gov/")
        assert len(cfg["watched_paths"]) >= 4

    def test_preset_audit_blocks_unsigned(self, tmp_path: Path) -> None:
        cfg = windsurf_cve_2026_30615_defaults()
        new = _b({"mcpServers": {"x": {"command": ["/tmp/y"]}}})
        with pytest.raises(UnsignedMCPServerAdded):
            cfg["audit"](
                tmp_path / "mcp.json",
                None,
                new,
                old_content=b"{}",
            )


class TestErrorHierarchy:
    @pytest.mark.parametrize(
        "err",
        [UnsignedMCPServerAdded, MCPCommandMutationDetected],
    )
    def test_subclasses_airlock_error(self, err: type[Exception]) -> None:
        assert issubclass(err, AirlockError)


class TestFixture:
    def test_fixture_payloads_match_outcomes(self, tmp_path: Path) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert data["cve"] == "CVE-2026-30615"
        # Tight policy: only ``sre-team`` is trusted. Any other signer
        # (including ``attacker-controlled`` from the fixture) blocks.
        cfg = ConfigFileWatchPolicy(signer_allowlist=frozenset({"sre-team"}))
        for payload in data["payloads"]:
            old = _b(payload["config_before"])
            new = _b(payload["config_after"])
            if payload["expected"] == "blocked":
                with pytest.raises(AirlockError):
                    audit_config_diff(tmp_path / "mcp.json", None, new, cfg, old_content=old)
            else:
                report = audit_config_diff(
                    tmp_path / "mcp.json",
                    None,
                    new,
                    cfg,
                    old_content=old,
                )
                assert isinstance(report, ConfigDiffReport)
