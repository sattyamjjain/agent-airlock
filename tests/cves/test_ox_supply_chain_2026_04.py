"""OX Security 'Mother of All AI Supply Chains' umbrella regression (v0.5.3+).

On 2026-04-20 OX Security published a dossier of 10+ coordinated MCP-
ecosystem CVEs. Anthropic publicly declined to patch four of the six
Claude Desktop tool-definition tampering CVEs. This suite covers the
three CVE classes not already codified elsewhere in ``tests/cves/``:

- Tool-definition tampering (CVE-2026-30615/30617/30618/30623/30624/30625)
- OpenAI MCP Bridge SSRF (CVE-2026-26015)
- LlamaIndex MCP adapter unsafe deserialization (CVE-2026-33224)

Plus pass/fail pairs for the two existing primitives the umbrella
re-uses — MCPwn destructive-tool auth (CVE-2026-33032) and Flowise
``eval()`` token ban (CVE-2025-59528).

Primary sources
---------------
- OX dossier: https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
- Per-CVE NVD URLs carried in ``tests/cves/fixtures/ox_supply_chain_2026_04.json``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.supply_chain import (
    MCPBridgeSSRFBlocked,
    ToolDefinitionRegistry,
    ToolDefinitionTamperedError,
    UnsafeDeserializationError,
    check_mcp_bridge_target,
    check_tool_response_content_type,
    compute_tool_manifest_digest,
)
from agent_airlock.policy_presets import (
    FlowiseEvalTokenError,
    UnauthenticatedDestructiveToolError,
    ox_mcp_supply_chain_2026_04_defaults,
)

FIXTURE = Path(__file__).parent / "fixtures" / "ox_supply_chain_2026_04.json"


class TestToolDefinitionTamper:
    """Pair 1: CVE-2026-30615/30617/30618/30623/30624/30625."""

    def test_01_unchanged_manifest_passes(self) -> None:
        reg = ToolDefinitionRegistry()
        manifest = {"name": "read_file", "params": {"path": "string"}}
        reg.register("read_file", manifest)
        reg.verify("read_file", manifest)  # must not raise

    def test_02_mutated_manifest_raises(self) -> None:
        reg = ToolDefinitionRegistry()
        reg.register("read_file", {"name": "read_file", "params": {"path": "string"}})
        with pytest.raises(ToolDefinitionTamperedError) as exc:
            reg.verify(
                "read_file",
                {"name": "read_file", "params": {"path": "string", "extra": "shell=True"}},
            )
        assert exc.value.tool_name == "read_file"

    def test_digest_is_deterministic_under_key_reordering(self) -> None:
        """JSON key order should not change the digest."""
        a = {"b": 1, "a": 2}
        b = {"a": 2, "b": 1}
        assert compute_tool_manifest_digest(a) == compute_tool_manifest_digest(b)


class TestMCPBridgeSSRF:
    """Pair 2: CVE-2026-26015 (OpenAI MCP Bridge)."""

    def test_01_public_host_passes(self) -> None:
        check_mcp_bridge_target("https://example.com/api")

    def test_02_rfc1918_raises(self) -> None:
        with patch(
            "agent_airlock.mcp_spec.supply_chain.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("10.0.0.5", 0))],
        ):
            with pytest.raises(MCPBridgeSSRFBlocked) as exc:
                check_mcp_bridge_target("https://internal.example.com/admin")
            assert "RFC1918" in exc.value.reason

    def test_03_aws_imds_hostname_blocked(self) -> None:
        with pytest.raises(MCPBridgeSSRFBlocked) as exc:
            check_mcp_bridge_target("http://169.254.169.254/latest/meta-data/")
        assert "metadata" in exc.value.reason or "link-local" in exc.value.reason

    def test_04_loopback_blocked(self) -> None:
        with patch(
            "agent_airlock.mcp_spec.supply_chain.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 0))],
        ):
            with pytest.raises(MCPBridgeSSRFBlocked):
                check_mcp_bridge_target("https://localhost/")


class TestUnsafeDeserialization:
    """Pair 3: CVE-2026-33224 (LlamaIndex MCP adapter)."""

    def test_01_json_content_type_passes(self) -> None:
        check_tool_response_content_type("application/json", tool_name="read_file")

    def test_02_pickle_content_type_raises(self) -> None:
        with pytest.raises(UnsafeDeserializationError) as exc:
            check_tool_response_content_type(
                "application/x-python-pickle",
                tool_name="llama_search",
            )
        assert exc.value.tool_name == "llama_search"

    def test_03_explicit_allowlist_bypasses(self) -> None:
        check_tool_response_content_type(
            "application/octet-stream",
            tool_name="binary_blob",
            allowed_content_types=frozenset({"application/octet-stream"}),
        )


class TestReusedPrimitives:
    """Pairs 4 and 5: the umbrella re-uses MCPwn + Flowise checks
    exported via ``policy_presets``. Smoke test that routing through
    the umbrella still fires the same errors."""

    def test_mcpwn_check_via_umbrella(self) -> None:
        cfg = ox_mcp_supply_chain_2026_04_defaults()
        with pytest.raises(UnauthenticatedDestructiveToolError):
            cfg["destructive_tool_check"]([{"name": "delete_site", "middlewares": []}])

    def test_flowise_check_via_umbrella(self) -> None:
        cfg = ox_mcp_supply_chain_2026_04_defaults()
        with pytest.raises(FlowiseEvalTokenError):
            cfg["eval_token_check"]([{"name": "evil", "handler": "return eval(userInput)"}])


class TestFixture:
    """Every CVE in the fixture must carry a primary-source URL AND
    a known class label the umbrella knows how to dispatch on."""

    KNOWN_CLASSES = {
        "path_traversal",
        "tool_definition_tamper",
        "mcp_bridge_ssrf",
        "unsafe_deserialization",
        "auth_header_leak",
    }

    def test_fixture_shape_and_coverage(self) -> None:
        data = json.loads(FIXTURE.read_text())
        assert len(data["cves"]) == 10
        for entry in data["cves"]:
            assert entry["id"].startswith("CVE-")
            assert entry["source"].startswith("https://")
            assert entry["class"] in self.KNOWN_CLASSES, (
                f"{entry['id']} class {entry['class']!r} is not dispatched by the umbrella preset"
            )


class TestErrorHierarchy:
    """All three new errors must subclass ``AirlockError`` for one-clause catch."""

    def test_tamper_is_airlock_error(self) -> None:
        reg = ToolDefinitionRegistry()
        reg.register("x", {"a": 1})
        with pytest.raises(AirlockError):
            reg.verify("x", {"a": 2})

    def test_ssrf_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            check_mcp_bridge_target("http://169.254.169.254/")

    def test_deserialization_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            check_tool_response_content_type("application/x-python-pickle")
