"""0.10.33: the checks noticed during 0.10.29 to 0.10.32 that read less than they were handed.

Each class is one place a guard admitted something its own contract refuses, or a helper
crashed or misled on an input the package allows:

* a redirect URI with no host (``https:///cb``) passed ``validate_redirect_uri``;
* the auto-memory scope check read paths only as written, so ``%2e%2e`` traversed in a store
  that percent-decodes, and tenant ids such as ``a.`` named another tenant's directory;
* CIMD pinned whatever ``redirect_uris`` a document held, valid or not;
* ``create_secure_mcp_server(pin_guard=)`` raised ``AttributeError`` on FastMCP 2.x;
* ``Mcp-Param-{Name}`` headers were never compared with the arguments they mirror;
* the ``iss`` check took any issuer string, so metadata built without ``from_discovery``
  could feed it an unchecked one;
* ``EvalRCEGuard``'s ``getattr`` sink missed ``__getattribute__``, ``attrgetter`` and
  ``getattr_static``;
* ``CodeSandboxBridgeGuard`` read only the text as written, so ``from ｊｓ import`` ran;
* the gateway benchmark recorded a run whose benign controls were refused.

Defensive only: every input here is a string handed to a guard.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent_airlock.integrations.claude_auto_memory import (
    AutoMemoryAccessPolicy,
    AutoMemoryCrossTenantError,
    AutoMemoryTenantIdError,
    guarded_read,
)
from agent_airlock.mcp.cimd import (
    CIMDGuard,
    CIMDTrustAnchorError,
    CIMDVerdict,
    FetchResult,
    InMemoryCIMDPinStore,
)
from agent_airlock.mcp_spec.code_sandbox_bridge_guard import CodeSandboxBridgeGuard
from agent_airlock.mcp_spec.eval_rce_guard import EvalRCEGuard
from agent_airlock.mcp_spec.header_integrity import (
    HeaderBodyMismatchError,
    validate_header_body_integrity,
)
from agent_airlock.mcp_spec.oauth import (
    AuthorizationServerMetadata,
    IssuerMismatchError,
    RedirectURIError,
    validate_authorization_response_iss,
    validate_redirect_uri,
)

# =============================================================================
# Redirect URIs name a host
# =============================================================================


class TestARedirectUriNamesAHost:
    @pytest.mark.parametrize(
        "uri", ["https:///cb", "https:cb", "https://:443/cb", "http:///cb", "https://?x=1"]
    )
    def test_a_uri_with_no_host_is_refused(self, uri: str) -> None:
        with pytest.raises(RedirectURIError, match="must name a host"):
            validate_redirect_uri(uri)

    @pytest.mark.parametrize(
        "uri",
        [
            "https://client.example.com/callback",
            "http://localhost:8080/callback",
            "http://127.0.0.1/cb",
            "http://[::1]:9000/cb",
        ],
    )
    def test_a_uri_with_a_host_is_allowed_as_before(self, uri: str) -> None:
        assert validate_redirect_uri(uri) is None


# =============================================================================
# Auto-memory: encoded traversal and tenant ids a store can rename
# =============================================================================


def _read(tenant: str, path: str) -> bytes:
    return guarded_read(AutoMemoryAccessPolicy(tenant_id=tenant), path, lambda _p: b"ok")


class TestAutoMemoryReadsEveryDecodedForm:
    @pytest.mark.parametrize(
        "path",
        [
            "/memory/a/%2e%2e/b/notes.md",
            "/memory/a/%2E%2E/b/notes.md",
            "/memory/a/.%2e/b/notes.md",
            "/memory/a/%252e%252e/b/notes.md",
            "/memory/a/b%2fc.md",
            "/memory/a/b%5Cc.md",
            # Still decoding after four rounds: refused rather than read further.
            "/memory/a/%25252525252e%25252525252e/b/x.md",
        ],
    )
    def test_an_encoded_escape_is_refused(self, path: str) -> None:
        with pytest.raises(AutoMemoryCrossTenantError):
            _read("a", path)

    @pytest.mark.parametrize(
        "path", ["/memory/a/notes.md", "/memory/a/%41.md", "/memory/a/50%25.md", "/memory/a/.x"]
    )
    def test_an_ordinary_path_is_allowed(self, path: str) -> None:
        assert _read("a", path) == b"ok"


class TestATenantIdAStoreCanRenameIsRefused:
    @pytest.mark.parametrize("tenant", ["a.", "a..", "a ", " a", "a\t", "a%2fb", "a%", "a\x01b"])
    def test_it_is_refused(self, tenant: str) -> None:
        with pytest.raises(AutoMemoryTenantIdError):
            AutoMemoryAccessPolicy(tenant_id=tenant)

    @pytest.mark.parametrize("tenant", ["acct-42", "a.b", "..a", "acct 42", "ACME_1"])
    def test_an_ordinary_id_is_allowed(self, tenant: str) -> None:
        assert _read(tenant, f"/memory/{tenant}/x.md") == b"ok"


# =============================================================================
# CIMD validates redirect_uris before it pins them
# =============================================================================

_CLIENT_ID = "https://client.example.com/.well-known/oauth-client"


def _cimd(redirect_uris: object) -> CIMDGuard:
    import json

    body = json.dumps(
        {"client_id": _CLIENT_ID, "client_name": "Example", "redirect_uris": redirect_uris}
    )

    def fetch(url: str) -> FetchResult:
        return FetchResult(status=200, body=body, url_chain=(url,))

    return CIMDGuard(
        store=InMemoryCIMDPinStore(),
        fetcher=fetch,
        resolver=lambda _host: ["93.184.216.34"],
    )


class TestCimdValidatesRedirectUris:
    @pytest.mark.parametrize(
        "redirect_uris",
        [
            ["http://attacker.example/cb"],
            ["https://client.example.com/cb#frag"],
            ["https:///cb"],
            ["https://client.example.com/cb", "ftp://client.example.com/cb"],
            [],
            "https://client.example.com/cb",
            [42],
        ],
    )
    def test_a_document_with_an_invalid_one_is_not_pinned(self, redirect_uris: object) -> None:
        guard = _cimd(redirect_uris)
        with pytest.raises(CIMDTrustAnchorError) as exc:
            guard.approve(_CLIENT_ID, approved_by="secops")
        assert exc.value.decision.verdict is CIMDVerdict.DENY_MALFORMED
        assert "redirect_uris" in exc.value.decision.reason
        assert guard.store.get(_CLIENT_ID) is None

    def test_valid_ones_are_pinned_as_before(self) -> None:
        guard = _cimd(["https://client.example.com/cb", "http://localhost:8080/cb"])
        assert guard.approve(_CLIENT_ID, approved_by="secops").allowed
        assert guard.check(_CLIENT_ID).allowed


# =============================================================================
# FastMCP 2.x: list tools through get_tools, an unknown name raises NotFoundError
# =============================================================================


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _FastMcp2Server:
    """FastMCP 2's server surface: ``get_tools()`` and a ``get_tool`` that raises."""

    def __init__(self, names: list[str]) -> None:
        self._tools = {name: _Tool(name) for name in names}

    async def get_tools(self) -> dict[str, _Tool]:
        return dict(self._tools)

    async def get_tool(self, key: str) -> _Tool:
        from fastmcp.exceptions import NotFoundError

        if key not in self._tools:
            raise NotFoundError(f"Unknown tool: {key}")
        return self._tools[key]


class _FastMcp4Server:
    """FastMCP 3+: ``list_tools(run_middleware=...)`` and a ``get_tool`` that returns None."""

    def __init__(self, names: list[str]) -> None:
        self._tools = {name: _Tool(name) for name in names}

    async def list_tools(self, *, run_middleware: bool = True) -> list[_Tool]:
        assert run_middleware is False
        return list(self._tools.values())

    async def get_tool(self, key: str) -> _Tool | None:
        return self._tools.get(key)


class TestTheServerToolsAreReadOnEveryFastMcpThePinAllows:
    @pytest.mark.parametrize("server_type", [_FastMcp2Server, _FastMcp4Server])
    def test_both_shapes_list_and_resolve(self, server_type: type[Any]) -> None:
        pytest.importorskip("fastmcp")
        from agent_airlock.mcp import _server_tool, _server_tools

        server = server_type(["b", "a"])
        names = sorted(tool.name for tool in asyncio.run(_server_tools(server)))
        assert names == ["a", "b"]
        assert asyncio.run(_server_tool(server, "a")).name == "a"
        assert asyncio.run(_server_tool(server, "missing")) is None

    def test_a_server_with_neither_is_refused_by_name(self) -> None:
        pytest.importorskip("fastmcp")
        from agent_airlock.mcp import _server_tools

        with pytest.raises(TypeError, match="neither list_tools nor get_tools"):
            asyncio.run(_server_tools(object()))


# =============================================================================
# Mcp-Param-{Name} headers carry the arguments they mirror
# =============================================================================

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "region": {"type": "string", "x-mcp-header": "Region"},
        "limit": {"type": "integer", "x-mcp-header": "Limit"},
        "dry_run": {"type": "boolean", "x-mcp-header": "DryRun"},
        "scope": {
            "type": "object",
            "properties": {"tenant": {"type": ["string", "null"], "x-mcp-header": "Tenant"}},
        },
        "query": {"type": "string"},
    },
}


def _call(arguments: dict[str, Any], **headers: str) -> dict[str, Any]:
    return {
        "method": "tools/call",
        "params": {"name": "execute_sql", "arguments": arguments},
        "headers": {"Mcp-Method": "tools/call", "Mcp-Name": "execute_sql", **headers},
    }


def _refused(request: dict[str, Any], schema: Any = None) -> dict[str, Any]:
    with pytest.raises(HeaderBodyMismatchError) as exc:
        validate_header_body_integrity(request, input_schema=_SCHEMA if schema is None else schema)
    return exc.value.audit_event


class TestParamHeadersMatchTheArguments:
    def test_the_specs_example_passes(self) -> None:
        request = _call(
            {"region": "us-west1", "query": "SELECT 1"}, **{"Mcp-Param-Region": "us-west1"}
        )
        assert validate_header_body_integrity(request, input_schema=_SCHEMA) is None

    def test_every_type_and_a_nested_property_pass_when_they_agree(self) -> None:
        request = _call(
            {"region": "us", "limit": 42, "dry_run": False, "scope": {"tenant": "t1"}},
            **{
                "mcp-param-region": "us",
                "Mcp-Param-Limit": "42.0",
                "Mcp-Param-DryRun": "false",
                "Mcp-Param-Tenant": "t1",
            },
        )
        assert validate_header_body_integrity(request, input_schema=_SCHEMA) is None

    def test_an_encoded_value_is_decoded_first(self) -> None:
        request = _call(
            {"region": "Hello, 世界"}, **{"Mcp-Param-Region": "=?base64?SGVsbG8sIOS4lueVjA==?="}
        )
        assert validate_header_body_integrity(request, input_schema=_SCHEMA) is None

    @pytest.mark.parametrize(
        ("arguments", "headers"),
        [
            ({"region": "us-west1"}, {"Mcp-Param-Region": "eu-west1"}),
            ({"limit": 42}, {"Mcp-Param-Limit": "43"}),
            ({"limit": True}, {"Mcp-Param-Limit": "1"}),
            ({"dry_run": True}, {"Mcp-Param-DryRun": "True"}),
            ({"region": 7}, {"Mcp-Param-Region": "7"}),
            ({}, {"Mcp-Param-Region": "us-west1"}),
            ({"region": None}, {"Mcp-Param-Region": "us-west1"}),
        ],
    )
    def test_a_disagreement_is_refused(
        self, arguments: dict[str, Any], headers: dict[str, str]
    ) -> None:
        event = _refused(_call(arguments, **headers))
        assert event["reason"] == "param_mismatch"
        assert event["param_header"].startswith("Mcp-Param-")

    def test_a_value_with_no_header_is_refused(self) -> None:
        event = _refused(_call({"region": "us-west1"}))
        assert event["reason"] == "missing_param_header"
        assert event["param_header"] == "Mcp-Param-Region"

    @pytest.mark.parametrize("arguments", [{}, {"region": None}, {"query": "x"}])
    def test_no_value_expects_no_header(self, arguments: dict[str, Any]) -> None:
        assert validate_header_body_integrity(_call(arguments), input_schema=_SCHEMA) is None

    @pytest.mark.parametrize("value", ["é", " us", "=?base64?!!!?="])
    def test_a_value_a_header_cannot_carry_is_malformed(self, value: str) -> None:
        event = _refused(_call({"region": value}, **{"Mcp-Param-Region": value}))
        assert event["reason"] == "malformed_param_header"
        assert event["param_header"] == "Mcp-Param-Region"

    def test_the_audit_event_never_holds_the_value(self) -> None:
        event = _refused(_call({"region": "secret-ish"}, **{"Mcp-Param-Region": "other"}))
        assert "secret-ish" not in repr(event)
        assert "other" not in repr(event)

    def test_an_unrecognised_param_header_is_ignored(self) -> None:
        request = _call({}, **{"Mcp-Param-Unknown": "x"})
        assert validate_header_body_integrity(request, input_schema=_SCHEMA) is None

    def test_without_a_schema_nothing_changes(self) -> None:
        request = _call({"region": "us-west1"}, **{"Mcp-Param-Region": "eu-west1"})
        assert validate_header_body_integrity(request) is None

    @pytest.mark.parametrize(
        "schema",
        [
            {"properties": {"a": {"type": "number", "x-mcp-header": "A"}}},
            {"properties": {"a": {"type": "object", "x-mcp-header": "A"}}},
            {"properties": {"a": {"type": "string", "x-mcp-header": ""}}},
            {"properties": {"a": {"type": "string", "x-mcp-header": "A B"}}},
            {"properties": {"a": {"type": "string", "x-mcp-header": "A\r\nX"}}},
            {
                "properties": {
                    "a": {"type": "string", "x-mcp-header": "Dup"},
                    "b": {"type": "string", "x-mcp-header": "dup"},
                }
            },
            {
                "properties": {
                    "a": {"type": "array", "items": {"type": "string", "x-mcp-header": "A"}}
                }
            },
            {"properties": {"a": {"anyOf": [{"type": "string", "x-mcp-header": "A"}]}}},
            {"$defs": {"x": {"type": "string", "x-mcp-header": "A"}}, "properties": {}},
            ["not", "a", "mapping"],
        ],
    )
    def test_a_schema_the_spec_makes_invalid_is_refused(self, schema: Any) -> None:
        event = _refused(_call({}), schema)
        assert event["reason"] == "invalid_param_schema"

    def test_only_tools_call_reads_the_schema(self) -> None:
        request = {
            "method": "prompts/get",
            "params": {"name": "p"},
            "headers": {"Mcp-Method": "prompts/get", "Mcp-Name": "p"},
        }
        assert validate_header_body_integrity(request, input_schema=["not", "a", "mapping"]) is None

    def test_the_preset_passes_the_schema_through(self) -> None:
        from agent_airlock.policy_presets import mcp_spec_2026_07_header_integrity_defaults

        check = mcp_spec_2026_07_header_integrity_defaults()["check_request"]
        with pytest.raises(HeaderBodyMismatchError):
            check(_call({"region": "us"}), _SCHEMA)
        assert check(_call({"region": "us"}, **{"Mcp-Param-Region": "us"}), _SCHEMA) is None


# =============================================================================
# The iss check refuses metadata nothing bound to a URL
# =============================================================================

_AS = "https://as.example"
_DOCUMENT = {
    "issuer": _AS,
    "authorization_endpoint": f"{_AS}/authorize",
    "token_endpoint": f"{_AS}/token",
    "code_challenge_methods_supported": ["S256"],
}


class TestTheIssCheckTakesBoundMetadata:
    def test_metadata_from_discovery_is_accepted_and_records_its_url(self) -> None:
        url = f"{_AS}/.well-known/oauth-authorization-server"
        metadata = AuthorizationServerMetadata.from_discovery(_DOCUMENT, discovery_url=url)
        assert metadata.discovery_url == url
        assert validate_authorization_response_iss({"iss": _AS}, expected_issuer=metadata) is None

    def test_constructed_metadata_is_refused(self) -> None:
        metadata = AuthorizationServerMetadata(**_DOCUMENT)
        assert metadata.discovery_url is None
        with pytest.raises(IssuerMismatchError, match="without from_discovery"):
            validate_authorization_response_iss({"iss": _AS}, expected_issuer=metadata)

    def test_a_string_is_read_as_before(self) -> None:
        assert validate_authorization_response_iss({"iss": _AS}, expected_issuer=_AS) is None
        with pytest.raises(IssuerMismatchError):
            validate_authorization_response_iss(
                {"iss": "https://decoy.example.net"}, expected_issuer=_AS
            )


# =============================================================================
# EvalRCEGuard: the getattr family
# =============================================================================


class TestTheGetattrFamily:
    @pytest.mark.parametrize(
        "payload",
        [
            'f.__getattribute__("__co" + "de__")',
            'object.__getattribute__(f, "x")',
            'operator.attrgetter("__co" + "de__")(f)',
            'from operator import attrgetter\nattrgetter("a")(f)',
            'inspect.getattr_static(f, "__co" + "de__")',
        ],
    )
    def test_each_spelling_is_refused_as_getattr(self, payload: str) -> None:
        decision = EvalRCEGuard().evaluate({"code": payload})
        assert decision.allowed is False
        assert decision.matched_sink == "getattr"

    @pytest.mark.parametrize(
        "text", ["see operator.attrgetter in the docs", "getattribute is a word", "attrgetter_x(1)"]
    )
    def test_the_names_without_a_call_pass(self, text: str) -> None:
        assert EvalRCEGuard().evaluate({"note": text}).allowed is True


# =============================================================================
# CodeSandboxBridgeGuard reads the NFKC form too
# =============================================================================


class TestTheBridgeGuardReadsWhatPythonReads:
    @pytest.mark.parametrize(
        "code",
        [
            "from ｊｓ import window\n",
            "import ｊｓ\nprint(1)\n",
            "from ｐｙｏｄｉｄｅ.ｆｆｉ import to_js\n",
        ],
    )
    def test_fullwidth_identifiers_are_refused(self, code: str) -> None:
        assert CodeSandboxBridgeGuard().evaluate({"code": code}).allowed is False

    @pytest.mark.parametrize("code", ['print("ｊｓ")\n', "x = 'ｆｕｌｌｗｉｄｔｈ'\n"])
    def test_fullwidth_text_that_names_no_bridge_passes(self, code: str) -> None:
        assert CodeSandboxBridgeGuard().evaluate({"code": code}).allowed is True


# =============================================================================
# The gateway benchmark refuses a run whose benign controls were refused
# =============================================================================


class TestTheGatewayRunNeedsItsBenignControls:
    def test_a_refused_benign_control_is_named(self) -> None:
        from benchmarks.vs_gateway.gateway_harness.regen import benign_controls_refused

        records = {
            "benign_echo": {"gateway_decision": "BLOCK"},
            "benign_read": {"gateway_decision": "PASS"},
            "ghost_arg": {"gateway_decision": "BLOCK"},
        }
        assert benign_controls_refused(records) == ["benign_echo"]

    def test_the_published_measurement_has_none(self) -> None:
        import json
        from pathlib import Path

        from benchmarks.vs_gateway.gateway_harness.regen import benign_controls_refused

        fixture = (
            Path(__file__).resolve().parents[1] / "benchmarks/vs_gateway/gateway_measurement.json"
        )
        records = json.loads(fixture.read_text(encoding="utf-8"))["records"]
        assert any(item.startswith("benign") for item in records)
        assert benign_controls_refused(records) == []
