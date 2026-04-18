"""CVE-2026-26118 — Microsoft Azure MCP Server SSRF (IMDS token theft).

Vulnerability (from the MSRC advisory and the Blueinfy write-up):
    Azure MCP Server Tools (< 2.0.0-beta.17) fetch URLs passed through
    tool arguments without validating the destination. A crafted argument
    of `http://169.254.169.254/metadata/identity/oauth2/token?...` causes
    the server process to hit the Azure Instance Metadata Service and
    return the managed-identity access token to the caller — trivially
    escalating any prompt-injection bug into full Azure resource takeover.

Advisory: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26118
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-26118
CVSS:     8.8 (High)

Airlock fit: strong — this is what v0.4.1's `EndpointPolicy` was built for.
    `validate_endpoint(...)` rejects:
    - all four cloud-metadata hosts in `_METADATA_HOSTS`
      (169.254.169.254 / 253 / fd00:ec2::254 / metadata.google.internal),
    - any hostname that resolves to a private / loopback / link-local IP
      when `allow_private_ips=False` (the default),
    - any hostname matching a caller-supplied blocklist pattern.

Additionally `SafeURL` (via Pydantic) performs the same check at the
type-annotation layer, so a tool signature `def fetch(url: SafeURL)`
raises `SafeURLValidationError` before the request ever fires.
"""

from __future__ import annotations

import pytest

from agent_airlock.network import EndpointPolicy, NetworkBlockedError, validate_endpoint
from agent_airlock.safe_types import SafeURLValidationError, SafeURLValidator


class TestCVE2026_26118:
    """Azure-style SSRF against IMDS must be blocked at the URL layer."""

    def test_endpoint_policy_blocks_aws_imds(self) -> None:
        """AWS IMDS — same address and the poster-child metadata URL."""
        policy = EndpointPolicy()  # default denies metadata + private IPs
        with pytest.raises(NetworkBlockedError):
            validate_endpoint(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                policy,
            )

    def test_endpoint_policy_blocks_gcp_metadata(self) -> None:
        policy = EndpointPolicy()
        with pytest.raises(NetworkBlockedError):
            validate_endpoint(
                "http://metadata.google.internal/computeMetadata/v1/",
                policy,
            )

    def test_endpoint_policy_blocks_azure_imds_style(self) -> None:
        """The Azure IMDS endpoint is the same 169.254.169.254 host."""
        policy = EndpointPolicy()
        with pytest.raises(NetworkBlockedError):
            validate_endpoint(
                "http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://management.azure.com/",
                policy,
            )

    def test_safeurl_validator_also_blocks_imds(self) -> None:
        """The type-level defence. A tool signature with `SafeURL` never sees the URL."""
        validator = SafeURLValidator()
        with pytest.raises(SafeURLValidationError):
            validator("http://169.254.169.254/metadata/identity/oauth2/token")

    def test_endpoint_policy_allows_legitimate_azure_resource_url(self) -> None:
        """A legitimate Azure Resource Manager URL is not flagged by default."""
        policy = EndpointPolicy(allowed_endpoints=["management.azure.com"])
        validate_endpoint(
            "https://management.azure.com/subscriptions/abc/resourceGroups?api-version=2024-01-01",
            policy,
        )
