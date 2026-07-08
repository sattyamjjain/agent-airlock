"""MCP 2026-07-28 SEP-2243 request header-integrity preset (v0.8.45+).

One contract check, composed from existing airlock primitives (no new engine):
the ``Mcp-Method`` / ``Mcp-Name`` routing headers are required and must agree
with the request body — "Servers reject requests where the headers and body
disagree" (SEP-2243). A mismatch fails closed (deny) and carries a structured
audit event.
"""

from __future__ import annotations

import inspect

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


class TestPresetMetadata:
    def test_canonical_metadata(self) -> None:
        p = mcp_spec_2026_07_header_integrity_defaults()
        assert p["preset_id"] == "mcp_spec_2026_07_header_integrity"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-2243"  # a spec proposal id, NOT a CVE
        assert callable(p["check_request"])
        assert p["header_error"] is HeaderBodyMismatchError

    def test_named_constant_matches_factory(self) -> None:
        assert (
            MCP_SPEC_2026_07_HEADER_INTEGRITY["preset_id"] == "mcp_spec_2026_07_header_integrity"
        )

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
