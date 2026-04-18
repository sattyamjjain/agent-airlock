"""CVE-2026-27826 — mcp-atlassian SSRF via `X-Atlassian-*-Url` headers.

Vulnerability (from the GitLab advisory):
    mcp-atlassian (< 0.17.0) uses unvalidated `X-Atlassian-Jira-Url` and
    `X-Atlassian-Confluence-Url` request headers to decide where to send
    upstream API calls. An attacker can redirect outbound requests to the
    IMDS endpoint or to an internal host to steal credentials or
    fingerprint the internal network.

Advisory: https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27826/
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-27826
CVSS:     7.5 (High, AV:A/PR:N/UI:N, C:H)

Airlock fit: partial.
    The vulnerability is at the HTTP-transport layer — headers aren't
    tool-call arguments. Runtime middleware cannot validate a header on
    an incoming request that never invokes a decorated tool.

    BUT: when an MCP server is fronted by agent-airlock and the base
    URL is surfaced as a tool parameter (the common operator pattern
    these days — per-call URL selection instead of a static config),
    the same `SafeURL` + `EndpointPolicy` primitives that block
    CVE-2026-26118 block this too. That narrower case is what we
    assert here.

    For the transport-header path, operators should (a) upgrade
    mcp-atlassian to ≥ 0.17.0 and (b) front their MCP server with an
    HTTP reverse proxy that strips or validates these headers before
    they reach application code.
"""

from __future__ import annotations

import pytest

from agent_airlock.network import EndpointPolicy, NetworkBlockedError, validate_endpoint


class TestCVE2026_27826:
    """Covered only when the base URL is surfaced as a tool argument."""

    def test_endpoint_policy_blocks_internal_ip(self) -> None:
        """Attacker-supplied URL pointing at an internal host is blocked."""
        policy = EndpointPolicy()
        with pytest.raises(NetworkBlockedError):
            validate_endpoint("http://10.0.0.5:8080/api/2/issue", policy)

    def test_endpoint_policy_blocks_localhost_override(self) -> None:
        policy = EndpointPolicy()
        with pytest.raises(NetworkBlockedError):
            validate_endpoint("http://127.0.0.1:8080/wiki/api", policy)

    def test_endpoint_policy_with_allowlist_blocks_unlisted_host(self) -> None:
        """Even if private IPs were allowed, an unlisted host is rejected."""
        policy = EndpointPolicy(
            allowed_endpoints=["*.atlassian.net"],
            blocked_patterns=["169.254.169.254"],
        )
        with pytest.raises(NetworkBlockedError):
            validate_endpoint("https://evil.example.com/api", policy)

    def test_endpoint_policy_allows_legitimate_atlassian_host(self) -> None:
        policy = EndpointPolicy(allowed_endpoints=["*.atlassian.net"])
        validate_endpoint(
            "https://example-corp.atlassian.net/rest/api/2/issue/ENG-1",
            policy,
        )
