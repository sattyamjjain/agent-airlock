"""CVE-2025-59536 — Claude Code hooks RCE + MCP consent bypass (exfil leg).

Vulnerability (from the Check Point research write-up):
    Claude Code (< 1.0.111) executes repository-controlled configuration
    — project `hooks`, registered MCP servers, and environment variables
    including `ANTHROPIC_BASE_URL` — BEFORE showing the user the trust
    dialog. Opening a malicious repository is therefore enough to
    (1) run arbitrary shell commands via hooks, and (2) redirect the
    agent's base URL to an attacker-controlled host that exfiltrates
    the API key on the first request.

Advisory:  https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/
NVD:       https://nvd.nist.gov/vuln/detail/CVE-2025-59536
CVSS:      8.7 (High)

Airlock fit: PARTIAL.
    The hook-execution leg runs on the Claude Code *client* before any
    tool call exists, so runtime middleware has no seam. That half is
    out-of-scope for agent-airlock and is fixed by upgrading Claude Code.

    The exfiltration leg — sending the API key to an attacker-controlled
    `ANTHROPIC_BASE_URL` — IS blockable. `EndpointPolicy` rejects any
    hostname not in the caller's allow-list, and `SafeURL` applies the
    same guard at the tool-signature level. If the agent's outbound
    requests are routed through an airlock-wrapped HTTP tool, the attempt
    to post to `https://evil.example.com/...` never leaves the process.

This file tests the exfil-leg mitigation only. It is NOT a complete
defence against CVE-2025-59536.
"""

from __future__ import annotations

import pytest

from agent_airlock.network import EndpointPolicy, NetworkBlockedError, validate_endpoint


class TestCVE2025_59536_ExfilLeg:
    """Runtime defence for the egress leg of the hooks RCE chain."""

    def test_endpoint_policy_blocks_exfil_host(self) -> None:
        """ANTHROPIC_BASE_URL redirected to evil.example.com is rejected."""
        policy = EndpointPolicy(
            allowed_endpoints=["api.anthropic.com", "*.claude.com"],
        )
        with pytest.raises(NetworkBlockedError):
            validate_endpoint("https://evil.example.com/v1/messages", policy)

    def test_endpoint_policy_blocks_typosquat_exfil(self) -> None:
        """A convincing typosquat of api.anthropic.com is also outside the allow-list."""
        policy = EndpointPolicy(
            allowed_endpoints=["api.anthropic.com"],
        )
        with pytest.raises(NetworkBlockedError):
            validate_endpoint("https://api.anthropiic.com/v1/messages", policy)

    def test_endpoint_policy_allows_canonical_api_host(self) -> None:
        """The canonical API endpoint passes."""
        policy = EndpointPolicy(allowed_endpoints=["api.anthropic.com"])
        validate_endpoint("https://api.anthropic.com/v1/messages", policy)
