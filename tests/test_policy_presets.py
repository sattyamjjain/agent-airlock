"""Tests for the 2026 policy presets (Phase 1.4).

Each preset gets a pair of asserting tests:

- a *blocking* scenario that reproduces the canonical offending pattern and
  asserts the preset stops it;
- an *allowing* scenario that performs the canonical compliant call and
  asserts the preset lets it through.

These tests exercise the SecurityPolicy layer only. CapabilityPolicy is
covered in `test_capabilities.py` and the E2E policy wiring is covered in
`test_policy.py`.
"""

from __future__ import annotations

import pytest

from agent_airlock.policy import AgentIdentity, PolicyViolation
from agent_airlock.policy_presets import (
    EU_AI_ACT_ARTICLE_15,
    GTG_1002_DEFENSE,
    INDIA_DPDP_2023,
    MEX_GOV_2026,
    OWASP_MCP_TOP_10_2026,
    eu_ai_act_article_15_policy,
    gtg_1002_defense_policy,
    india_dpdp_2023_policy,
    mex_gov_2026_policy,
    owasp_mcp_top_10_2026_policy,
)


@pytest.fixture
def agent() -> AgentIdentity:
    """A canonical authenticated agent identity usable across presets."""
    return AgentIdentity(
        agent_id="test-agent-1",
        session_id="session-1",
        roles=["developer"],
    )


# -----------------------------------------------------------------------------
# GTG-1002 defense
# -----------------------------------------------------------------------------


class TestGTG1002Defense:
    """GTG-1002 blocks the autonomous-cyber-espionage tool-call pattern."""

    def test_blocks_shell_exec(self, agent: AgentIdentity) -> None:
        """Canonical offending call: shell command execution."""
        policy = GTG_1002_DEFENSE
        with pytest.raises(PolicyViolation):
            policy.check("run_shell", agent=agent)

    def test_blocks_exec_glob(self, agent: AgentIdentity) -> None:
        """`exec_*` variants are all denied."""
        policy = gtg_1002_defense_policy()
        for tool in ("exec_python", "exec_node", "exec_bash"):
            with pytest.raises(PolicyViolation):
                policy.check(tool, agent=agent)

    def test_blocks_anonymous_call(self) -> None:
        """`require_agent_id=True` rejects unauthenticated invocations."""
        policy = gtg_1002_defense_policy()
        with pytest.raises(PolicyViolation):
            policy.check("read_file", agent=None)

    def test_allows_read_file(self, agent: AgentIdentity) -> None:
        """Canonical compliant call: authenticated read of a single file."""
        policy = GTG_1002_DEFENSE
        policy.check("read_file", agent=agent)  # must not raise


# -----------------------------------------------------------------------------
# Mexican-government-2026 defense
# -----------------------------------------------------------------------------


class TestMexGov2026:
    """MEX_GOV_2026 blocks the bulk-exfil pattern via tool allow/deny lists."""

    def test_blocks_bulk_export(self, agent: AgentIdentity) -> None:
        policy = MEX_GOV_2026
        with pytest.raises(PolicyViolation):
            policy.check("bulk_export_users", agent=agent)

    def test_blocks_write_tools_via_allowlist(self, agent: AgentIdentity) -> None:
        """Write operations are not in the allow-list (read-only shape)."""
        policy = mex_gov_2026_policy()
        with pytest.raises(PolicyViolation):
            policy.check("write_record", agent=agent)

    def test_allows_read(self, agent: AgentIdentity) -> None:
        policy = MEX_GOV_2026
        policy.check("read_record", agent=agent)

    def test_allows_search(self, agent: AgentIdentity) -> None:
        policy = MEX_GOV_2026
        policy.check("search_documents", agent=agent)


# -----------------------------------------------------------------------------
# OWASP MCP Top 10 (2026 beta)
# -----------------------------------------------------------------------------


class TestOwaspMcpTop10:
    """Covers MCP02 (permissions), MCP03/MCP04 (supply chain), MCP05 (injection)."""

    def test_blocks_command_injection_pattern(self, agent: AgentIdentity) -> None:
        """MCP05: tool names shaped like shell entrypoints are denied."""
        policy = OWASP_MCP_TOP_10_2026
        for tool in ("exec_sql", "run_plugin", "system_call"):
            with pytest.raises(PolicyViolation):
                policy.check(tool, agent=agent)

    def test_blocks_supply_chain_tool(self, agent: AgentIdentity) -> None:
        """MCP03 / MCP04: install_* / download_plugin_* are denied."""
        policy = owasp_mcp_top_10_2026_policy()
        for tool in ("install_package", "download_plugin_x", "load_extension_foo"):
            with pytest.raises(PolicyViolation):
                policy.check(tool, agent=agent)

    def test_blocks_destructive_verbs(self, agent: AgentIdentity) -> None:
        """MCP02: delete_all_*, drop_*, truncate_* are denied."""
        policy = OWASP_MCP_TOP_10_2026
        for tool in ("delete_all_users", "drop_table_orders", "truncate_log"):
            with pytest.raises(PolicyViolation):
                policy.check(tool, agent=agent)

    def test_allows_benign_read(self, agent: AgentIdentity) -> None:
        policy = OWASP_MCP_TOP_10_2026
        policy.check("get_document", agent=agent)


# -----------------------------------------------------------------------------
# EU AI Act Article 15
# -----------------------------------------------------------------------------


class TestEUAIActArticle15:
    """Cybersecurity preset for high-risk AI systems (applies 2026-08-02)."""

    def test_requires_agent_identity(self) -> None:
        """Article 15(4) monitoring requires attributability."""
        policy = EU_AI_ACT_ARTICLE_15
        with pytest.raises(PolicyViolation):
            policy.check("fetch_document", agent=None)

    def test_allows_authenticated_call(self, agent: AgentIdentity) -> None:
        """Authenticated call passes the base policy check."""
        policy = eu_ai_act_article_15_policy()
        policy.check("fetch_document", agent=agent)

    def test_rate_limit_configured(self) -> None:
        """A '*' rate limit is wired so bursts can't escape resilience bounds."""
        policy = EU_AI_ACT_ARTICLE_15
        assert "*" in policy.rate_limits
        assert policy.rate_limits["*"] == "500/hour"

    def test_capability_policy_denies_network_arbitrary(self) -> None:
        """Confidentiality (15(5)): arbitrary raw-socket egress is denied."""
        from agent_airlock.capabilities import Capability

        policy = EU_AI_ACT_ARTICLE_15
        assert policy.capability_policy is not None
        assert bool(policy.capability_policy.denied & Capability.NETWORK_ARBITRARY)


# -----------------------------------------------------------------------------
# India DPDP 2023
# -----------------------------------------------------------------------------


class TestIndiaDPDP2023:
    """India Digital Personal Data Protection Act 2023 alignment."""

    def test_blocks_bulk_export_of_personal_data(self, agent: AgentIdentity) -> None:
        """Purpose limitation: bulk_export_* denied."""
        policy = INDIA_DPDP_2023
        with pytest.raises(PolicyViolation):
            policy.check("bulk_export_customers", agent=agent)

    def test_blocks_download_personal_data(self, agent: AgentIdentity) -> None:
        """Data minimization: download_personal_data_* denied."""
        policy = india_dpdp_2023_policy()
        with pytest.raises(PolicyViolation):
            policy.check("download_personal_data_full", agent=agent)

    def test_allows_read(self, agent: AgentIdentity) -> None:
        policy = INDIA_DPDP_2023
        policy.check("read_record", agent=agent)

    def test_capability_policy_denies_pii_access(self) -> None:
        """Capability gating denies unscoped PII/secret handling."""
        from agent_airlock.capabilities import Capability

        policy = INDIA_DPDP_2023
        assert policy.capability_policy is not None
        assert bool(policy.capability_policy.denied & Capability.DATA_PII)
        assert bool(policy.capability_policy.denied & Capability.DATA_SECRETS)


# -----------------------------------------------------------------------------
# Factory vs constant equivalence
# -----------------------------------------------------------------------------


class TestFactoryConsistency:
    """Each eager constant should be equivalent to a fresh factory call."""

    def test_gtg1002_fresh_equivalent(self, agent: AgentIdentity) -> None:
        fresh = gtg_1002_defense_policy()
        assert fresh.require_agent_id == GTG_1002_DEFENSE.require_agent_id
        assert fresh.denied_tools == GTG_1002_DEFENSE.denied_tools
        assert fresh.rate_limits == GTG_1002_DEFENSE.rate_limits

    def test_mex_gov_fresh_equivalent(self) -> None:
        fresh = mex_gov_2026_policy()
        assert fresh.allowed_tools == MEX_GOV_2026.allowed_tools
        assert fresh.denied_tools == MEX_GOV_2026.denied_tools

    def test_owasp_mcp_fresh_equivalent(self) -> None:
        fresh = owasp_mcp_top_10_2026_policy()
        assert fresh.denied_tools == OWASP_MCP_TOP_10_2026.denied_tools

    def test_eu_ai_act_fresh_equivalent(self) -> None:
        fresh = eu_ai_act_article_15_policy()
        assert fresh.rate_limits == EU_AI_ACT_ARTICLE_15.rate_limits

    def test_india_dpdp_fresh_equivalent(self) -> None:
        fresh = india_dpdp_2023_policy()
        assert fresh.allowed_tools == INDIA_DPDP_2023.allowed_tools
