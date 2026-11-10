"""CVE-2026-123272 — mcp-go OAuth: protected resource metadata names another server's resource.

Vulnerability (from NVD, CNA VulnCheck):
    "Mark3labs mcp-go before v1.2.1 contains an improper validation vulnerability in
    OAuthHandler.fetchServerMetadata that allows malicious MCP servers to obtain tokens for other
    resources by declaring arbitrary resources in well-known metadata. Attackers can declare a
    different MCP server as the RFC 8707 resource indicator, causing the authorization server to
    mint tokens the attacker replays against that resource." Fixed in v1.2.1 by commit 90d247ed
    (mark3labs/mcp-go#1053), which checks the declared resource against the server the client
    addressed. On the well-known path it also accepts a resource that is a segment-aware prefix
    of that URL; the check below accepts only the same server.

Advisory: https://github.com/mark3labs/mcp-go/security/advisories/GHSA-xf6j-693p-wqxx
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-123272
CVSS:     8.0 (HIGH) — AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N, CWE-346

Airlock fit: partial.
    RFC 9728 section 3.3: the ``resource`` a protected resource metadata document returns must
    be the resource identifier the client built the metadata URL from, or the document must not
    be used. ``ProtectedResourceMetadata.from_discovery`` and ``validate_protected_resource``
    are that check, so a client that reads the document through them refuses this one. **Out of
    reach:** mcp-go's own OAuth handler, which does not call airlock, and the client's choice of
    RFC 8707 ``resource`` parameter: send the MCP server's own URL there whatever the document
    says. The plain constructor still parses any ``resource``, which ``TestDocumentedLimit``
    pins.

    Observed against ``v0.10.31`` while writing this module: ``ProtectedResourceMetadata``
    parsed the malicious document with no error, and there was no ``from_discovery``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from scripts.cve_watcher import classify_shape

from agent_airlock.mcp_spec import (
    ProtectedResourceMetadata,
    ResourceMismatchError,
    validate_protected_resource,
)
from agent_airlock.mcp_spec.oauth import TokenAudienceError, validate_access_token_audience
from agent_airlock.policy_presets import mcp_spec_2026_07_defaults

CVE = "CVE-2026-123272"

NVD_DESCRIPTION = (
    "Mark3labs mcp-go before v1.2.1 contains an improper validation vulnerability in "
    "OAuthHandler.fetchServerMetadata that allows malicious MCP servers to obtain tokens for "
    "other resources by declaring arbitrary resources in well-known metadata. Attackers can "
    "declare a different MCP server as the RFC 8707 resource indicator, causing the "
    "authorization server to mint tokens the attacker replays against that resource."
)
NVD_CWES = ["CWE-346"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_123272_mcp_go_prm_resource.json").read_text(
        encoding="utf-8"
    )
)
RESOURCE_URL: str = _FIXTURE["resource_url"]
MALICIOUS: dict[str, Any] = _FIXTURE["malicious_document"]
HONEST: dict[str, Any] = _FIXTURE["honest_document"]
VARIANTS = [pytest.param(value, id=value) for value in _FIXTURE["variants"]]


def _hosts_in(text: str) -> bool:
    return "mcp-a" in text or "mcp-b" in text or "attacker" in text


class TestTheMaliciousDocumentIsRefused:
    def test_from_discovery_refuses_it(self) -> None:
        with pytest.raises(ResourceMismatchError, match="RFC 9728 section 3.3"):
            ProtectedResourceMetadata.from_discovery(MALICIOUS, resource_url=RESOURCE_URL)

    def test_validate_protected_resource_refuses_it_after_a_plain_parse(self) -> None:
        metadata = ProtectedResourceMetadata.model_validate(MALICIOUS)
        with pytest.raises(ResourceMismatchError):
            validate_protected_resource(metadata, resource_url=RESOURCE_URL)

    @pytest.mark.parametrize("resource", VARIANTS)
    def test_every_other_resource_a_server_could_declare_is_refused(self, resource: str) -> None:
        document = {**MALICIOUS, "resource": resource}
        with pytest.raises(ResourceMismatchError):
            ProtectedResourceMetadata.from_discovery(document, resource_url=RESOURCE_URL)

    def test_the_refusal_repeats_neither_url(self) -> None:
        with pytest.raises(ResourceMismatchError) as exc:
            ProtectedResourceMetadata.from_discovery(MALICIOUS, resource_url=RESOURCE_URL)
        assert not _hosts_in(f"{exc.value} {exc.value!r}")


class TestTheHonestDocumentPasses:
    def test_the_server_that_names_itself_is_read(self) -> None:
        metadata = ProtectedResourceMetadata.from_discovery(HONEST, resource_url=RESOURCE_URL)
        assert metadata.resource == RESOURCE_URL
        assert metadata.authorization_servers == MALICIOUS["authorization_servers"]


class TestWhyTheBindingMatters:
    """The token the vulnerable flow mints works only at the server the document named."""

    def test_the_server_the_client_asked_for_refuses_that_token(self) -> None:
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience(
                {"aud": MALICIOUS["resource"]}, expected_audience=RESOURCE_URL
            )

    def test_the_server_the_document_named_accepts_it(self) -> None:
        validate_access_token_audience(
            {"aud": MALICIOUS["resource"]}, expected_audience=MALICIOUS["resource"]
        )


class TestDocumentedLimit:
    """A client that skips ``from_discovery`` is not protected, and the docs say so."""

    def test_the_plain_constructor_still_parses_it(self) -> None:
        metadata = ProtectedResourceMetadata.model_validate(MALICIOUS)
        assert metadata.resource == MALICIOUS["resource"]

    def test_a_document_that_does_not_parse_is_refused_before_the_resource_check(self) -> None:
        with pytest.raises(ValidationError):
            ProtectedResourceMetadata.from_discovery(
                {"resource": 7, "authorization_servers": MALICIOUS["authorization_servers"]},
                resource_url=RESOURCE_URL,
            )


class TestScopeBoundary:
    def test_the_preset_does_not_claim_this_cve(self) -> None:
        # mcp_spec_2026_07_defaults checks the authorization response's iss (SEP-2468). It does
        # not read protected resource metadata.
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
