"""CVE-2026-119025 — open on Windows and WSL: a discovery-metadata ``authorization_endpoint`` with ``$(...)`` run through PowerShell.

Vulnerability (from NVD, CNA VulnCheck):
    "open 7.2.0 before 11.0.0 contains an OS command injection vulnerability that allows
    attackers to execute PowerShell code by supplying crafted URLs on Windows and WSL.
    Attackers can embed $(...) subexpressions in URLs, such as OAuth authorization_endpoint
    values from malicious MCP servers, which execute when index.js passes them unescaped to
    powershell -EncodedCommand." Fixed in open 11.0.0. NVD's references include the MCP
    Inspector advisory GHSA-q978-78c7-phqw, the MCP client that opened such an endpoint.

Advisory: https://www.vulncheck.com/advisories/open-7.2.0-before-11.0.0-os-command-injection-via-powershell-on-windows
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-119025
CVSS:     7.5 (HIGH) — CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H, CWE-78

Airlock fit: partial.
    **In scope:** the URL a malicious MCP server hands a client in its discovery metadata,
    before the client opens it. ``AuthorizationServerMetadata`` screens ``issuer`` and the
    authorization, token and registration endpoints as it parses them, and
    ``ProtectedResourceMetadata`` screens each of its ``authorization_servers``
    (``mcp_spec/oauth.py``, ``_screen_metadata_url``, 0.10.29): ``$(`` and every character
    RFC 3986 never allows unencoded (a double quote, a backtick, a space, ...) are refused
    with a ``ValidationError`` that names the field and the character's class, never the
    URL. ``from_discovery`` parses through the same screen. On the ``@Airlock`` call path, a
    tool that takes the URL as an argument typed ``SafeURL`` refuses it at strict validation
    (``validation_error``).

    **Why partial, and what is out of scope:** ``open`` is a Node package and MCP Inspector
    a TypeScript client; neither calls airlock, and the fix is ``open`` 11.0.0. The screen
    covers only a document parsed through these models, and only the fields above: an
    extra field the model keeps (``extra="allow"``), such as RFC 8414's
    ``service_documentation``, is not screened (``TestDocumentedLimit``). No preset claims
    this CVE: the screen needs none, it runs on every parse. An existing primitive already
    refuses the shape, so this is a second-defence fixture, not a new guard. Triage: #399.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from scripts.cve_watcher import classify_shape

import agent_airlock.policy_presets as policy_presets
from agent_airlock import Airlock, SafeURL
from agent_airlock.mcp_spec.oauth import AuthorizationServerMetadata, ProtectedResourceMetadata

CVE = "CVE-2026-119025"

NVD_DESCRIPTION = (
    "open 7.2.0 before 11.0.0 contains an OS command injection vulnerability that allows "
    "attackers to execute PowerShell code by supplying crafted URLs on Windows and WSL. "
    "Attackers can embed $(...) subexpressions in URLs, such as OAuth authorization_endpoint "
    "values from malicious MCP servers, which execute when index.js passes them unescaped to "
    "powershell -EncodedCommand."
)
NVD_CWES = ["CWE-78"]

_FIXTURE: dict[str, Any] = json.loads(
    (
        Path(__file__).parent / "fixtures" / "cve_2026_119025_open_authorization_endpoint.json"
    ).read_text(encoding="utf-8")
)
DOCUMENT: dict[str, Any] = _FIXTURE["document"]
DISCOVERY_URL: str = _FIXTURE["discovery_url"]
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(url, id=url) for url in _FIXTURE["benign"]]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]


def _refusal(document: dict[str, Any]) -> str:
    with pytest.raises(ValidationError) as caught:
        AuthorizationServerMetadata.model_validate(document)
    return str(caught.value)


def _open_authorization_url(ran: list[str]) -> Any:
    """A tool an agent might call to open the endpoint; it records that it ran."""

    @Airlock(return_dict=True)
    def open_authorization_url(url: SafeURL) -> str:
        ran.append("open_authorization_url")
        return "ran"

    return open_authorization_url


class TestTheMetadataScreenRefusesIt:
    @pytest.mark.parametrize("entry", PAYLOADS)
    def test_the_document_does_not_parse(self, entry: dict[str, Any]) -> None:
        text = _refusal({**DOCUMENT, entry["field"]: entry["value"]})
        assert f"{entry['field']} holds {entry['named']}" in text

    @pytest.mark.parametrize("entry", PAYLOADS)
    def test_the_refusal_never_repeats_the_url(self, entry: dict[str, Any]) -> None:
        text = _refusal({**DOCUMENT, entry["field"]: entry["value"]})
        assert entry["value"] not in text
        assert "calc" not in text

    def test_from_discovery_refuses_it_before_the_issuer_check(self) -> None:
        document = {**DOCUMENT, DISCLOSED["field"]: DISCLOSED["value"]}
        with pytest.raises(ValidationError, match="shell command substitution"):
            AuthorizationServerMetadata.from_discovery(document, discovery_url=DISCOVERY_URL)

    def test_a_document_read_from_json_is_refused(self) -> None:
        body = json.dumps({**DOCUMENT, DISCLOSED["field"]: DISCLOSED["value"]})
        with pytest.raises(ValidationError, match="shell command substitution"):
            AuthorizationServerMetadata.model_validate_json(body)

    def test_an_authorization_server_list_with_one_such_url_is_refused(self) -> None:
        bad = _FIXTURE["authorization_server_payload"]
        with pytest.raises(ValidationError) as caught:
            ProtectedResourceMetadata.model_validate(
                {
                    "resource": "https://mcp.example.test/mcp",
                    "authorization_servers": [DOCUMENT["issuer"], bad],
                }
            )
        text = str(caught.value)
        assert "authorization_servers[1] holds a shell command substitution" in text
        assert bad not in text


class TestTheCallPathRefusesItAsAnArgument:
    def test_a_safe_url_argument_is_refused_at_strict_validation(self) -> None:
        ran: list[str] = []
        result = _open_authorization_url(ran)(url=DISCLOSED["value"])
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["status"] == "blocked"
        assert result["block_reason"] == "validation_error"
        assert "shell command substitution" in result["error"]
        assert ran == []

    def test_a_benign_endpoint_runs(self) -> None:
        ran: list[str] = []
        result = _open_authorization_url(ran)(url=DOCUMENT["authorization_endpoint"])
        assert isinstance(result, dict)
        assert result["success"] is True
        assert ran == ["open_authorization_url"]


class TestBenignDocumentsParse:
    @pytest.mark.parametrize("url", BENIGN)
    def test_the_endpoint_is_accepted(self, url: str) -> None:
        metadata = AuthorizationServerMetadata.model_validate(
            {**DOCUMENT, "authorization_endpoint": url}
        )
        assert metadata.authorization_endpoint == url

    def test_from_discovery_reads_the_honest_document(self) -> None:
        metadata = AuthorizationServerMetadata.from_discovery(DOCUMENT, discovery_url=DISCOVERY_URL)
        assert metadata.authorization_endpoint == DOCUMENT["authorization_endpoint"]


class TestDocumentedLimit:
    def test_an_extra_field_is_kept_and_not_screened(self) -> None:
        extras: dict[str, str] = _FIXTURE["unscreened_extra_fields"]
        metadata = AuthorizationServerMetadata.model_validate({**DOCUMENT, **extras})
        assert metadata.model_extra == extras

    def test_the_percent_encoded_form_is_url_syntax_and_passes(self) -> None:
        # The refusal's own advice for a literal: %24( is no subexpression.
        url = "https://auth.example.test/authorize?x=%24(calc)"
        metadata = AuthorizationServerMetadata.model_validate(
            {**DOCUMENT, "authorization_endpoint": url}
        )
        assert metadata.authorization_endpoint == url


class TestScopeBoundary:
    def test_no_preset_claims_this_cve(self) -> None:
        # The screen runs on every parse, so no preset turns it on or names it.
        assert CVE not in Path(policy_presets.__file__).read_text(encoding="utf-8")

    def test_a_bare_str_argument_is_not_screened_on_the_call_path(self) -> None:
        # The URL type is what refuses it; a tool that declares a plain str gets no screen.
        @Airlock(return_dict=True)
        def open_any(url: str) -> str:
            return "ran"

        result = open_any(url=DISCLOSED["value"])
        assert isinstance(result, dict)
        assert result["success"] is True


class TestWatcherAdmittedThisOnTheCwe:
    """Filed as #399 on CWE-78 alone: the text names PowerShell, which is not a sink word."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_would_only_ask_for_triage(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "triage-required"

    def test_the_cwe_alone_files_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
