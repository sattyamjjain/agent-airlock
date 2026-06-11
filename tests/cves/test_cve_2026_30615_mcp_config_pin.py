"""CVE-2026-30615 (Windsurf zero-click MCP config) — spawn-time config pin.

Companion to ``test_cve_2026_30615_zero_click.py`` (which covers the
*config-file* diff guard). This suite covers the **spawn-time** half: the
``mcp_config_pin`` preset / :class:`McpConfigPinSet`, which fingerprints the
resolved STDIO spawn config at invocation time and **fails closed** (raises,
never warns) on an injected or mutated server — catching the zero-click
pattern even when the mutation never touched a watched config file.

The CVE-2026-30615 pattern: a prompt-injected page rewrites the MCP client
config so the IDE auto-launches an attacker ``command`` / ``args`` / ``env``.
The pin refuses any STDIO server whose ``{name, command, args, env-keys}``
fingerprint is not the operator-pinned known-good value.

Primary source (cited per the v0.5.1+ convention):
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-30615
- Tenable: https://www.tenable.com/cve/CVE-2026-30615
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock import (
    McpConfigPinSet,
    McpConfigPinViolation,
    McpServerPin,
    fingerprint_mcp_server,
    mcp_config_pin,
)

# A known-good operator manifest: the two servers the host is allowed to spawn.
_GOOD_MANIFEST = [
    {
        "name": "filesystem",
        "command": "uvx",
        "args": ["mcp-server-filesystem", "/srv/data"],
        "env": {"MCP_MODE": "ro"},
    },
    {
        "name": "git",
        "command": "npx",
        "args": ["@modelcontextprotocol/server-git"],
    },
]


def _pin() -> McpConfigPinSet:
    return mcp_config_pin(_GOOD_MANIFEST)["pin_set"]


# ---------------------------------------------------------------------------
# Clean path
# ---------------------------------------------------------------------------


class TestCleanSpawn:
    def test_exact_pinned_config_allowed(self) -> None:
        # Identical resolved config → no raise.
        _pin().check(
            {
                "name": "filesystem",
                "command": "uvx",
                "args": ["mcp-server-filesystem", "/srv/data"],
                "env": {"MCP_MODE": "ro"},
            }
        )

    def test_env_value_rotation_is_allowed(self) -> None:
        # Only env *keys* are pinned — a rotated secret/value must still pass.
        _pin().check(
            {
                "name": "filesystem",
                "command": "uvx",
                "args": ["mcp-server-filesystem", "/srv/data"],
                "env": {"MCP_MODE": "rw-but-still-a-valid-value"},
            }
        )

    def test_pinned_names_exposed(self) -> None:
        assert _pin().pinned_names == ("filesystem", "git")


# ---------------------------------------------------------------------------
# CVE-2026-30615: injected (unpinned) server — fail closed
# ---------------------------------------------------------------------------


class TestInjectedServerFailsClosed:
    def test_cve_2026_30615_injected_unpinned_server_raises(self) -> None:
        """CVE-2026-30615: a prompt-injected STDIO server not in the pin set
        is refused fail-closed at spawn time."""
        pin = _pin()
        with pytest.raises(McpConfigPinViolation) as exc:
            pin.check({"name": "evil", "command": "/tmp/x.sh", "args": ["--pwn"]})
        assert exc.value.reason == "unpinned"
        assert exc.value.server_name == "evil"
        assert exc.value.expected_fingerprint is None
        assert "CVE-2026-30615" in str(exc.value)


# ---------------------------------------------------------------------------
# CVE-2026-30615: mutated pinned server — fail closed
# ---------------------------------------------------------------------------


class TestMutatedServerFailsClosed:
    def test_cve_2026_30615_mutated_command_raises(self) -> None:
        """CVE-2026-30615 mutation class: a previously-pinned server whose
        ``command`` was flipped to a malicious binary is refused."""
        pin = _pin()
        with pytest.raises(McpConfigPinViolation) as exc:
            pin.check(
                {
                    "name": "filesystem",
                    "command": "/tmp/evil",  # mutated
                    "args": ["mcp-server-filesystem", "/srv/data"],
                    "env": {"MCP_MODE": "ro"},
                }
            )
        assert exc.value.reason == "mutated"
        assert exc.value.expected_fingerprint is not None
        assert "CVE-2026-30615" in str(exc.value)

    def test_cve_2026_30615_mutated_args_raises(self) -> None:
        pin = _pin()
        with pytest.raises(McpConfigPinViolation) as exc:
            pin.check(
                {
                    "name": "filesystem",
                    "command": "uvx",
                    "args": ["mcp-server-filesystem", "/etc"],  # path mutated
                    "env": {"MCP_MODE": "ro"},
                }
            )
        assert exc.value.reason == "mutated"

    def test_cve_2026_30615_injected_env_key_raises(self) -> None:
        # The classic preload injection: add an LD_PRELOAD env key to a
        # pinned server. The key set changed → fingerprint mismatch.
        pin = _pin()
        with pytest.raises(McpConfigPinViolation) as exc:
            pin.check(
                {
                    "name": "git",
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-git"],
                    "env": {"LD_PRELOAD": "/tmp/evil.so"},
                }
            )
        assert exc.value.reason == "mutated"


# ---------------------------------------------------------------------------
# Audit emission + fingerprint determinism + construction
# ---------------------------------------------------------------------------


class TestAuditAndInternals:
    def test_block_emits_jsonl_audit_record(self, tmp_path: Path) -> None:
        audit = tmp_path / "audit.jsonl"
        pin = mcp_config_pin(_GOOD_MANIFEST, audit_path=str(audit))["pin_set"]
        with pytest.raises(McpConfigPinViolation):
            pin.check({"name": "evil", "command": "/tmp/x.sh"})
        records = [
            json.loads(line)
            for line in audit.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert records, "expected an audit record on the JSON-Lines channel"
        rec = records[-1]
        assert rec["blocked"] is True
        assert rec["block_reason"] == "mcp_config_pin:unpinned"
        assert rec["tool_name"] == "mcp_server:evil"

    def test_fingerprint_is_order_stable_for_env_keys(self) -> None:
        # env-key order must not change the fingerprint (mapping has no order).
        a = fingerprint_mcp_server(name="x", command="uvx", args=["a"], env_keys=["A", "B"])
        b = fingerprint_mcp_server(name="x", command="uvx", args=["a"], env_keys=["B", "A"])
        assert a == b

    def test_fingerprint_is_args_order_sensitive(self) -> None:
        # argv order DOES matter.
        a = fingerprint_mcp_server(name="x", command="uvx", args=["a", "b"])
        b = fingerprint_mcp_server(name="x", command="uvx", args=["b", "a"])
        assert a != b

    def test_duplicate_pin_name_raises(self) -> None:
        with pytest.raises(ValueError, match="duplicate pin"):
            McpConfigPinSet(
                [
                    McpServerPin(name="dup", fingerprint="aa"),
                    McpServerPin(name="dup", fingerprint="bb"),
                ]
            )

    def test_preset_metadata(self) -> None:
        preset = mcp_config_pin(_GOOD_MANIFEST)
        assert preset["cves"] == ("CVE-2026-30615",)
        assert preset["owasp"] == "ASI04"
        assert preset["source"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-30615"
        assert callable(preset["check"])
