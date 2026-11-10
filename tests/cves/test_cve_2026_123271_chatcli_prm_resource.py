"""CVE-2026-123271 — ChatCLI MCP OAuth: a server-supplied resource used as the resource indicator.

Vulnerability (from NVD, CNA VulnCheck):
    "ChatCLI before v1.215.2 contains an improper validation vulnerability in the MCP OAuth
    login flow that uses server-supplied Protected Resource Metadata as the resource indicator
    without checking it matches the configured server URL. A malicious MCP server can declare
    another resource on the same authorization server, obtain the user's bearer token for it,
    and replay that token against the other resource." Fixed in v1.215.2 by commit 951fe24b,
    which refuses metadata that names another resource and always requests the token for the
    configured server.

Advisory: https://github.com/diillson/chatcli/security/advisories/GHSA-95vg-3r9c-2v5q
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-123271
CVSS:     8.0 (HIGH) — AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N, CWE-346

Airlock fit: partial.
    The same class as CVE-2026-123272 in mcp-go, which has its own module. RFC 9728 section 3.3
    says a protected resource metadata document whose ``resource`` is not the identifier the
    client built the metadata URL from must not be used, and
    ``ProtectedResourceMetadata.from_discovery`` refuses it. **Out of reach:** ChatCLI's own
    login flow, which does not call airlock, and the client's choice of RFC 8707 ``resource``
    parameter. ChatCLI's fix sends the configured server URL whatever the metadata says, and a
    client using airlock should do the same.

    Observed against ``v0.10.31`` while writing this module: ``ProtectedResourceMetadata``
    parsed the malicious document with no error, and there was no ``from_discovery``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock.mcp_spec import (
    ProtectedResourceMetadata,
    ResourceMismatchError,
    validate_protected_resource,
)
from agent_airlock.mcp_spec.oauth import TokenAudienceError, validate_access_token_audience
from agent_airlock.policy_presets import mcp_spec_2026_07_defaults

CVE = "CVE-2026-123271"

NVD_DESCRIPTION = (
    "ChatCLI before v1.215.2 contains an improper validation vulnerability in the MCP OAuth "
    "login flow that uses server-supplied Protected Resource Metadata as the resource indicator "
    "without checking it matches the configured server URL. A malicious MCP server can declare "
    "another resource on the same authorization server, obtain the user's bearer token for it, "
    "and replay that token against the other resource."
)
NVD_CWES = ["CWE-346"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_123271_chatcli_prm_resource.json").read_text(
        encoding="utf-8"
    )
)
CONFIGURED_URL: str = _FIXTURE["resource_url"]
MALICIOUS: dict[str, Any] = _FIXTURE["malicious_document"]
HONEST: dict[str, Any] = _FIXTURE["honest_document"]
VARIANTS = [pytest.param(value, id=value) for value in _FIXTURE["variants"]]


class TestTheMaliciousDocumentIsRefused:
    def test_from_discovery_refuses_another_resource_on_the_same_authorization_server(
        self,
    ) -> None:
        with pytest.raises(ResourceMismatchError, match="RFC 9728 section 3.3") as exc:
            ProtectedResourceMetadata.from_discovery(MALICIOUS, resource_url=CONFIGURED_URL)
        text = f"{exc.value} {exc.value!r}"
        assert "tools" not in text
        assert "billing" not in text

    @pytest.mark.parametrize("resource", VARIANTS)
    def test_every_other_resource_a_server_could_declare_is_refused(self, resource: str) -> None:
        metadata = ProtectedResourceMetadata.model_validate({**MALICIOUS, "resource": resource})
        with pytest.raises(ResourceMismatchError):
            validate_protected_resource(metadata, resource_url=CONFIGURED_URL)


class TestTheHonestDocumentPasses:
    def test_the_configured_server_naming_itself_is_read(self) -> None:
        # The honest document writes a trailing slash, which the token audience check forgives
        # too, so the two checks agree on it.
        metadata = ProtectedResourceMetadata.from_discovery(HONEST, resource_url=CONFIGURED_URL)
        assert metadata.resource == HONEST["resource"]
        validate_access_token_audience(
            {"aud": HONEST["resource"]}, expected_audience=CONFIGURED_URL
        )


class TestWhyTheBindingMatters:
    def test_a_token_minted_for_the_other_resource_does_not_fit_the_configured_server(
        self,
    ) -> None:
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience(
                {"aud": MALICIOUS["resource"]}, expected_audience=CONFIGURED_URL
            )


class TestDocumentedLimit:
    def test_the_plain_constructor_still_parses_it(self) -> None:
        assert ProtectedResourceMetadata.model_validate(MALICIOUS).resource == MALICIOUS["resource"]


class TestScopeBoundary:
    def test_the_preset_does_not_claim_this_cve(self) -> None:
        preset = mcp_spec_2026_07_defaults(expected_issuer="https://auth.example.com")
        assert CVE not in preset.get("cves", ())
        assert preset["spec"] == "SEP-2468"


class TestWatcherSignals:
    """Observed: the watcher asks for triage on this record rather than filing it."""

    def test_the_full_record_needs_triage(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "triage-required"

    def test_the_text_alone_needs_triage(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "triage-required"

    def test_the_cwe_alone_needs_triage(self) -> None:
        assert classify_shape("", NVD_CWES) == "triage-required"
