"""MCP 2026-07-28 SEP-2243 request header-integrity preset (v0.8.45+).

One contract check, composed from existing airlock primitives (no new engine):
the ``Mcp-Method`` / ``Mcp-Name`` routing headers are required and must agree
with the request body — "Servers reject requests where the headers and body
disagree" (SEP-2243). A mismatch fails closed (deny) and carries a structured
audit event.
"""

from __future__ import annotations

import base64
import inspect
from typing import Any

import pytest

from agent_airlock.mcp_spec.header_integrity import (
    HeaderBodyMismatchError,
    validate_header_body_integrity,
)
from agent_airlock.policy_presets import (
    MCP_SPEC_2026_07_HEADER_INTEGRITY,
    list_active,
    mcp_spec_2026_07_defaults,
    mcp_spec_2026_07_header_integrity_defaults,
    mcp_stateless_conformance_2026_07_defaults,
)


def _matching_request() -> dict:
    """A well-formed tools/call whose routing headers agree with the body."""
    return {
        "method": "tools/call",
        "params": {"name": "get_balance", "arguments": {}},
        "headers": {"Mcp-Method": "tools/call", "Mcp-Name": "get_balance"},
    }


class TestMatchingRequestPasses:
    def test_matching_header_body_passes(self) -> None:
        preset = mcp_spec_2026_07_header_integrity_defaults()
        assert preset["check_request"](_matching_request()) is None

    def test_matching_top_level_headers_pass(self) -> None:
        # Flattened top-level header form is accepted too.
        req = {
            "method": "tools/call",
            "name": "get_balance",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "get_balance",
        }
        assert validate_header_body_integrity(req) is None

    def test_header_lookup_is_case_insensitive(self) -> None:
        req = {
            "method": "resources/read",
            "params": {"name": "doc://a"},
            "headers": {"mcp-method": "resources/read", "MCP-NAME": "doc://a"},
        }
        assert validate_header_body_integrity(req) is None


class TestMismatchIsBlocked:
    def test_method_mismatch_blocked_with_audit_event(self) -> None:
        preset = mcp_spec_2026_07_header_integrity_defaults()
        req = _matching_request()
        req["headers"]["Mcp-Method"] = "resources/read"  # disagrees with body
        with pytest.raises(HeaderBodyMismatchError) as exc_info:
            preset["check_request"](req)
        event = exc_info.value.audit_event
        assert event["event"] == "mcp.header_integrity.reject"
        assert event["reason"] == "method_mismatch"
        assert event["spec"] == "SEP-2243"
        assert event["header_method"] == "resources/read"
        assert event["body_method"] == "tools/call"

    def test_name_mismatch_blocked_with_audit_event(self) -> None:
        req = _matching_request()
        req["headers"]["Mcp-Name"] = "drain_account"  # header routes a different op
        with pytest.raises(HeaderBodyMismatchError) as exc_info:
            validate_header_body_integrity(req)
        event = exc_info.value.audit_event
        assert event["reason"] == "name_mismatch"
        assert event["header_name"] == "drain_account"
        assert event["body_name"] == "get_balance"

    def test_missing_method_header_blocked(self) -> None:
        # SEP-2243 makes the routing headers REQUIRED — absence is a rejection.
        req = _matching_request()
        del req["headers"]["Mcp-Method"]
        with pytest.raises(HeaderBodyMismatchError) as exc_info:
            validate_header_body_integrity(req)
        assert exc_info.value.audit_event["reason"] == "missing_method_header"

    def test_missing_name_header_blocked(self) -> None:
        req = _matching_request()
        del req["headers"]["Mcp-Name"]
        with pytest.raises(HeaderBodyMismatchError) as exc_info:
            validate_header_body_integrity(req)
        assert exc_info.value.audit_event["reason"] == "missing_name_header"

    def test_empty_header_value_is_missing(self) -> None:
        req = _matching_request()
        req["headers"]["Mcp-Method"] = ""
        with pytest.raises(HeaderBodyMismatchError):
            validate_header_body_integrity(req)


class TestNameHeaderScopedToNameBearingMethods:
    """SEP-2243: Mcp-Name is required only for tools/call, resources/read, prompts/get.

    Requiring it on every request (the historical D-PING-NAME divergence, #127) was
    stricter than the ratified header table and a benign-request false positive.
    """

    def test_operation_less_method_without_name_accepted(self) -> None:
        # tools/list carries Mcp-Method but no Mcp-Name (no params.name/uri).
        req = {"method": "tools/list", "headers": {"Mcp-Method": "tools/list"}}
        assert validate_header_body_integrity(req) is None

    def test_second_operation_less_method_accepted(self) -> None:
        req = {
            "method": "completion/complete",
            "headers": {"Mcp-Method": "completion/complete"},
        }
        assert validate_header_body_integrity(req) is None

    def test_tools_call_still_requires_name(self) -> None:
        req = {
            "method": "tools/call",
            "params": {"name": "search"},
            "headers": {"Mcp-Method": "tools/call"},
        }
        with pytest.raises(HeaderBodyMismatchError) as exc:
            validate_header_body_integrity(req)
        assert exc.value.audit_event["reason"] == "missing_name_header"

    def test_resources_read_name_sourced_from_uri(self) -> None:
        req = {
            "method": "resources/read",
            "params": {"uri": "file:///a"},
            "headers": {"Mcp-Method": "resources/read", "Mcp-Name": "file:///a"},
        }
        assert validate_header_body_integrity(req) is None

    def test_resources_read_missing_name_rejected(self) -> None:
        req = {
            "method": "resources/read",
            "params": {"uri": "file:///a"},
            "headers": {"Mcp-Method": "resources/read"},
        }
        with pytest.raises(HeaderBodyMismatchError):
            validate_header_body_integrity(req)


def _call_named(body_name: Any, header: Any) -> dict[str, Any]:
    """A tools/call for ``body_name`` whose ``Mcp-Name`` header carries ``header``."""
    return {
        "method": "tools/call",
        "params": {"name": body_name, "arguments": {}},
        "headers": {"Mcp-Method": "tools/call", "Mcp-Name": header},
    }


def _encoded(text: str) -> str:
    return "=?base64?" + base64.b64encode(text.encode("utf-8")).decode("ascii") + "?="


def _refused(request: Any, **kwargs: Any) -> dict[str, Any]:
    """The audit event of the refusal ``request`` must get."""
    with pytest.raises(HeaderBodyMismatchError) as exc:
        validate_header_body_integrity(request, **kwargs)
    return exc.value.audit_event


class TestEncodedNameHeader:
    """The spec's "Value Encoding": a server decodes an encoded Mcp-Name, then compares it.

    python-sdk #3817 opened on the malformed side of this. On 0.10.31 a valid client was
    refused as `name_mismatch`, and a malformed one got that same reason.
    """

    def test_a_plain_name_is_still_allowed(self) -> None:
        assert validate_header_body_integrity(_call_named("echo", "echo")) is None

    def test_the_encoded_form_of_the_body_name_is_allowed(self) -> None:
        assert validate_header_body_integrity(_call_named("echo", "=?base64?ZWNobw==?=")) is None

    def test_a_non_ascii_name_is_allowed_encoded(self) -> None:
        assert validate_header_body_integrity(_call_named("écho", _encoded("écho"))) is None

    def test_the_encoded_form_of_another_name_is_a_mismatch(self) -> None:
        event = _refused(_call_named("other", "=?base64?ZWNobw==?="))
        assert event["reason"] == "name_mismatch"

    @pytest.mark.parametrize(
        ("name", "header"),
        [
            ("Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="),
            (" padded ", "=?base64?IHBhZGRlZCA=?="),
            ("line1\nline2", "=?base64?bGluZTEKbGluZTI=?="),
            ("=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="),
        ],
    )
    def test_the_specs_encoding_examples_are_allowed(self, name: str, header: str) -> None:
        assert validate_header_body_integrity(_call_named(name, header)) is None

    @pytest.mark.parametrize(
        ("method", "params"),
        [
            ("resources/read", {"uri": "file:///ré sumé.txt"}),
            ("prompts/get", {"name": "résumé"}),
        ],
    )
    def test_each_name_bearing_method_decodes(self, method: str, params: dict[str, str]) -> None:
        name = next(iter(params.values()))
        request = {
            "method": method,
            "params": params,
            "headers": {"Mcp-Method": method, "Mcp-Name": _encoded(name)},
        }
        assert validate_header_body_integrity(request) is None

    def test_a_plain_value_shaped_like_the_form_is_read_as_encoded(self) -> None:
        """A client must encode such a value. On 0.10.31 this pair matched as raw strings."""
        literal = "=?base64?ZWNobw==?="
        event = _refused(_call_named(literal, literal))
        assert event["reason"] == "name_mismatch"
        assert event["header_name_decoded"] == "echo"

    def test_that_literal_name_is_allowed_once_encoded(self) -> None:
        literal = "=?base64?ZWNobw==?="
        assert validate_header_body_integrity(_call_named(literal, _encoded(literal))) is None

    @pytest.mark.parametrize(
        "header", ["=?BASE64?ZWNobw==?=", "=?base64?ZWNobw==", "base64?ZWNobw==?="]
    )
    def test_markers_that_are_not_exact_are_not_the_form(self, header: str) -> None:
        """They are case-sensitive and must appear exactly, so this is a plain value."""
        event = _refused(_call_named("echo", header))
        assert event["reason"] == "name_mismatch"
        assert event["header_name_decoded"] == header

    def test_comparison_is_by_code_point(self) -> None:
        """No Unicode normalization: é composed and decomposed are different names."""
        event = _refused(_call_named("écho", _encoded("écho")))
        assert event["reason"] == "name_mismatch"

    def test_mcp_method_has_no_encoded_form(self) -> None:
        """Only Mcp-Name and Mcp-Param-* permit the encoding."""
        request = _call_named("echo", "echo")
        request["headers"]["Mcp-Method"] = _encoded("tools/call")
        assert _refused(request)["reason"] == "method_mismatch"

    def test_an_encoded_header_on_a_method_with_no_name_is_not_compared(self) -> None:
        request = {
            "method": "tools/list",
            "headers": {"Mcp-Method": "tools/list", "Mcp-Name": "=?base64?ZWNobw==?="},
        }
        assert validate_header_body_integrity(request) is None

    def test_a_flattened_request_decodes(self) -> None:
        request = {
            "method": "tools/call",
            "name": "echo",
            "Mcp-Method": "tools/call",
            "Mcp-Name": "=?base64?ZWNobw==?=",
        }
        assert validate_header_body_integrity(request) is None

    def test_an_asgi_pair_list_decodes(self) -> None:
        request = {
            "method": "tools/call",
            "params": {"name": "echo"},
            "headers": [(b"mcp-method", b"tools/call"), (b"mcp-name", b"=?base64?ZWNobw==?=")],
        }
        assert validate_header_body_integrity(request) is None

    def test_a_renamed_header_decodes_too(self) -> None:
        request = {
            "method": "tools/call",
            "params": {"name": "echo"},
            "headers": {"Mcp-Method": "tools/call", "X-Op": "=?base64?ZWNobw==?="},
        }
        assert validate_header_body_integrity(request, name_header="X-Op") is None

    def test_the_preset_decodes(self) -> None:
        check = mcp_spec_2026_07_header_integrity_defaults()["check_request"]
        assert check(_call_named("echo", "=?base64?ZWNobw==?=")) is None
        with pytest.raises(HeaderBodyMismatchError) as exc:
            check(_call_named("echo", "=?base64?\xe9?="))
        assert exc.value.audit_event["reason"] == "malformed_name_header"


class TestMalformedNameHeader:
    @pytest.mark.parametrize(
        "header",
        [
            pytest.param("=?base64?\xe9?=", id="non-ascii-payload"),
            pytest.param("=?base64?ZWNobw=?=", id="short-padding"),
            pytest.param("=?base64?ZWNobw?=", id="no-padding"),
            pytest.param("=?base64?ZWNobw===?=", id="extra-padding"),
            pytest.param("=?base64?ZWNobx==?=", id="non-canonical-trailing-bits"),
            pytest.param("=?base64?/w==?=", id="bytes-not-utf8"),
            pytest.param("=?base64?7aCA?=", id="utf8-surrogate"),
            pytest.param("=?base64?wK8=?=", id="utf8-overlong"),
            pytest.param("=?base64?ZWN obw==?=", id="space-in-payload"),
            pytest.param("=?base64?ZWNo\nbw==?=", id="newline-in-payload"),
            pytest.param("=?base64?-_-_?=", id="urlsafe-alphabet"),
            pytest.param("=?base64?====?=", id="only-padding"),
            pytest.param("=?base64?ZWNobw==?=?=", id="suffix-twice"),
            pytest.param("=?base64?=", id="markers-overlap"),
        ],
    )
    def test_it_is_refused_with_its_own_reason(self, header: str) -> None:
        event = _refused(_call_named("echo", header))
        assert event["reason"] == "malformed_name_header"
        assert event["header_name"] == header
        assert event["header_name_decoded"] is None

    def test_a_header_given_as_bytes_gets_the_same_reason(self) -> None:
        """#3817: on the SDK the same corrupt header is a 400 or a 500 by argument type."""
        request = {
            "method": "tools/call",
            "params": {"name": "echo"},
            "headers": [(b"mcp-method", b"tools/call"), (b"mcp-name", b"=?base64?\xe9?=")],
        }
        assert _refused(request)["reason"] == "malformed_name_header"

    def test_it_is_refused_on_a_method_that_needs_no_name(self) -> None:
        """An edge may route on the header whatever the method, so it is never read past."""
        request = {
            "method": "tools/list",
            "headers": {"Mcp-Method": "tools/list", "Mcp-Name": "=?base64?\xe9?="},
        }
        assert _refused(request)["reason"] == "malformed_name_header"

    @pytest.mark.parametrize("body_name", ["", "echo"])
    def test_an_encoded_empty_name_is_a_missing_name(self, body_name: str) -> None:
        """As a plain empty header is: equality with an empty body name must not admit it."""
        event = _refused(_call_named(body_name, "=?base64??="))
        assert event["reason"] == "missing_name_header"
        assert event["header_name"] == "=?base64??="
        assert event["header_name_decoded"] == ""

    def test_two_spellings_are_compared_raw(self) -> None:
        request = _call_named("echo", "echo")
        request["headers"]["mcp-name"] = "=?base64?ZWNobw==?="
        assert _refused(request)["reason"] == "conflicting_name_header"

    def test_a_body_member_cannot_shadow_an_encoded_header(self) -> None:
        request = _call_named("echo", "=?base64?ZWNobw==?=")
        request["mcp-name"] = "echo"
        assert _refused(request)["reason"] == "conflicting_name_header"


class TestPlainNameHeaderValue:
    """The spec lists a value holding invalid characters as a validation failure."""

    @pytest.mark.parametrize(
        "name",
        [
            pytest.param("écho", id="non-ascii"),
            pytest.param("日本語", id="non-latin"),
            pytest.param("echo\x00", id="nul"),
            pytest.param("echo\nX-Other: 1", id="newline"),
            pytest.param("echo\x7f", id="del"),
            pytest.param(" echo", id="leading-space"),
            pytest.param("echo ", id="trailing-space"),
            pytest.param("\techo", id="leading-tab"),
        ],
    )
    def test_a_value_a_client_must_encode_is_refused_even_when_it_matches(self, name: str) -> None:
        event = _refused(_call_named(name, name))
        assert event["reason"] == "malformed_name_header"
        assert event["header_name"] == name

    @pytest.mark.parametrize("name", ["a b", "a\tb", "file:///a b.txt", "~!@#$%^&*()", "a=?b"])
    def test_a_value_a_header_can_carry_is_allowed(self, name: str) -> None:
        assert validate_header_body_integrity(_call_named(name, name)) is None

    @pytest.mark.parametrize("value", [["echo"], 7, {"name": "echo"}])
    def test_a_value_that_is_not_a_string_is_a_mismatch(self, value: Any) -> None:
        event = _refused(_call_named("echo", value))
        assert event["reason"] == "name_mismatch"
        assert event["header_name"] == value
        assert event["header_name_decoded"] == value


class TestNameHeaderAuditEvent:
    def test_the_raw_value_sits_beside_the_decoded_one(self) -> None:
        with pytest.raises(HeaderBodyMismatchError) as exc:
            validate_header_body_integrity(_call_named("other", "=?base64?ZWNobw==?="))
        event = exc.value.audit_event
        assert event["header_name"] == "=?base64?ZWNobw==?="
        assert event["header_name_decoded"] == "echo"
        assert event["body_name"] == "other"
        assert "=?base64?ZWNobw==?=" in str(exc.value)
        assert "decoded 'echo'" in str(exc.value)

    def test_a_plain_mismatch_reads_as_it_did(self) -> None:
        with pytest.raises(HeaderBodyMismatchError) as exc:
            validate_header_body_integrity(_call_named("other", "echo"))
        assert exc.value.audit_event["header_name"] == "echo"
        assert exc.value.audit_event["header_name_decoded"] == "echo"
        assert "decoded" not in str(exc.value)
        assert str(exc.value) == ("'Mcp-Name'='echo' disagrees with body name 'other' (SEP-2243)")

    def test_a_refusal_after_decoding_keeps_the_decoded_name(self) -> None:
        request = {
            "method": "resources/read",
            "params": {"uri": "file:///a", "name": "file:///b"},
            "headers": {"Mcp-Method": "resources/read", "Mcp-Name": _encoded("file:///a")},
        }
        event = _refused(request)
        assert event["reason"] == "ambiguous_body_name"
        assert event["header_name_decoded"] == "file:///a"

    def test_an_absent_header_decodes_to_nothing(self) -> None:
        request = _call_named("echo", "echo")
        del request["headers"]["Mcp-Name"]
        event = _refused(request)
        assert event["header_name"] is None
        assert event["header_name_decoded"] is None


class TestPresetMetadata:
    def test_canonical_metadata(self) -> None:
        p = mcp_spec_2026_07_header_integrity_defaults()
        assert p["preset_id"] == "mcp_spec_2026_07_header_integrity"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-2243"  # a spec proposal id, NOT a CVE
        assert callable(p["check_request"])
        assert p["header_error"] is HeaderBodyMismatchError

    def test_named_constant_matches_factory(self) -> None:
        assert MCP_SPEC_2026_07_HEADER_INTEGRITY["preset_id"] == "mcp_spec_2026_07_header_integrity"

    def test_no_cve_id_in_preset(self) -> None:
        src = inspect.getsource(mcp_spec_2026_07_header_integrity_defaults)
        assert "CVE-" not in src


class TestNoRegression:
    def test_new_preset_discoverable_via_list_active(self) -> None:
        ids = {m.preset_id for m in list_active()}
        assert "mcp_spec_2026_07_header_integrity_defaults" in ids

    def test_sibling_mcp_spec_presets_unaffected(self) -> None:
        ids = {m.preset_id for m in list_active()}
        # The SEP-2468 and SEP-2567/2575 presets still discover + construct.
        assert "mcp_spec_2026_07_defaults" in ids
        assert "mcp_stateless_conformance_2026_07_defaults" in ids
        sep2468 = mcp_spec_2026_07_defaults(expected_issuer="https://as.example.com")
        assert callable(sep2468["check_oauth_response"])
        stateless = mcp_stateless_conformance_2026_07_defaults()
        assert callable(stateless["check_request"])
