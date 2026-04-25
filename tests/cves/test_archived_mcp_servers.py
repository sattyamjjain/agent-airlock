"""Tests for the archived-MCP-server advisory gate (v0.5.6+).

Primary source (cited per v0.5.1+ convention):
- GitHub modelcontextprotocol/servers issue #3662 — Puppeteer SSRF /
  IPI / sandbox bypass:
  <https://github.com/modelcontextprotocol/servers/issues/3662>
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock import ArchivedMcpServerBlocked
from agent_airlock.exceptions import AirlockError
from agent_airlock.policy_presets import archived_mcp_server_advisory_defaults

FIXTURE = Path(__file__).parent / "fixtures" / "archived_mcp_servers_2026_04.json"


class TestDefaultBlockList:
    """The shipped fixture seeds three archived packages."""

    def test_puppeteer_blocks(self) -> None:
        cfg = archived_mcp_server_advisory_defaults()
        with pytest.raises(ArchivedMcpServerBlocked) as exc:
            cfg["check"]({"package_origin": "@modelcontextprotocol/server-puppeteer"})
        assert "puppeteer" in str(exc.value).lower()

    def test_brave_search_blocks(self) -> None:
        cfg = archived_mcp_server_advisory_defaults()
        with pytest.raises(ArchivedMcpServerBlocked):
            cfg["check"]({"package_origin": "@modelcontextprotocol/server-brave-search"})

    def test_unknown_package_passes(self) -> None:
        cfg = archived_mcp_server_advisory_defaults()
        cfg["check"]({"package_origin": "@example/safe-mcp-server"})

    def test_missing_package_origin_passes(self) -> None:
        """Manifests without a package_origin key are not in scope."""
        cfg = archived_mcp_server_advisory_defaults()
        cfg["check"]({"name": "some_tool"})


class TestAllowList:
    """Caller can opt in to a specific archived package."""

    def test_allow_list_unblocks(self) -> None:
        cfg = archived_mcp_server_advisory_defaults(
            allow_list=["@modelcontextprotocol/server-puppeteer"],
        )
        cfg["check"]({"package_origin": "@modelcontextprotocol/server-puppeteer"})

    def test_allow_list_does_not_unblock_other_archived(self) -> None:
        cfg = archived_mcp_server_advisory_defaults(
            allow_list=["@modelcontextprotocol/server-puppeteer"],
        )
        with pytest.raises(ArchivedMcpServerBlocked):
            cfg["check"]({"package_origin": "@modelcontextprotocol/server-everart"})


class TestCustomBlockList:
    """Caller can supply their own block-list."""

    def test_custom_block_list(self) -> None:
        cfg = archived_mcp_server_advisory_defaults(
            block_list=[
                {
                    "package": "internal/legacy-mcp",
                    "archived_at": "2026-01",
                    "monthly_downloads": 7,
                    "advisory_url": "https://example.com",
                }
            ],
        )
        with pytest.raises(ArchivedMcpServerBlocked):
            cfg["check"]({"package_origin": "internal/legacy-mcp"})


class TestFixture:
    def test_fixture_parses_with_disclosed_at(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert data["disclosed_at"]
        assert data["airlock_preset"] == "archived_mcp_server_advisory_defaults"
        assert len(data["packages"]) == 3
        for pkg in data["packages"]:
            assert pkg["disclosed_at"]
            assert pkg["advisory_url"].startswith("https://")
            assert isinstance(pkg["disclosed_classes"], list)


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(ArchivedMcpServerBlocked, AirlockError)
