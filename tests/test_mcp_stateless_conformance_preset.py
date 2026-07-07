"""MCP 2026-07-28 statelessness conformance preset (SEP-2567 / SEP-2575, v0.8.44+).

Two contract checks, composed from existing airlock primitives (no new engine):

1. SEP-2575 — reject a call that still carries ``Mcp-Session-Id`` or invokes the
   removed ``initialize`` → session handshake.
2. SEP-2567 — a state handle passed as a tool argument must be an explicit declared
   contract parameter (reuses the shipped ghost-argument primitive).
"""

from __future__ import annotations

import inspect

import pytest

from agent_airlock.mcp_spec.statelessness import (
    StatefulSessionError,
    validate_state_handle_declared,
    validate_stateless_request,
)
from agent_airlock.policy_presets import (
    MCP_STATELESS_CONFORMANCE_2026_07,
    list_active,
    mcp_spec_2026_07_defaults,
    mcp_stateless_conformance_2026_07_defaults,
)
from agent_airlock.validator import GhostArgumentError


# A stateless-conformant tool: the state handle is an explicit, typed parameter.
def paginate(cursor: str, limit: int = 20) -> dict:
    return {"cursor": cursor, "limit": limit}


# A session-lifecycle-dependent tool: state is absorbed implicitly via **kwargs.
def legacy_session_tool(**kwargs: object) -> dict:
    return dict(kwargs)


class TestStatelessRequest:
    def test_clean_stateless_call_passes(self) -> None:
        preset = mcp_stateless_conformance_2026_07_defaults()
        assert preset["check_request"]({"method": "tools/call", "headers": {}}) is None

    def test_mcp_session_id_header_blocked(self) -> None:
        preset = mcp_stateless_conformance_2026_07_defaults()
        with pytest.raises(StatefulSessionError):
            preset["check_request"]({"headers": {"Mcp-Session-Id": "sess-123"}})

    def test_session_header_is_case_insensitive(self) -> None:
        with pytest.raises(StatefulSessionError):
            validate_stateless_request({"headers": {"mcp-session-id": "x"}})

    def test_session_header_at_top_level(self) -> None:
        with pytest.raises(StatefulSessionError):
            validate_stateless_request({"Mcp-Session-Id": "x"})

    def test_initialize_handshake_blocked(self) -> None:
        with pytest.raises(StatefulSessionError):
            validate_stateless_request({}, method="initialize")

    def test_empty_session_header_is_not_carrying(self) -> None:
        # An empty/absent value is not "carrying" a session.
        assert validate_stateless_request({"headers": {"Mcp-Session-Id": ""}}) is None


class TestStateHandleContract:
    def test_declared_state_handle_passes(self) -> None:
        preset = mcp_stateless_conformance_2026_07_defaults()
        assert preset["check_tool_call"](paginate, {"cursor": "pg2"}) is None

    def test_kwargs_absorbed_state_handle_blocked(self) -> None:
        # The implicit-state anti-pattern SEP-2567 removes.
        preset = mcp_stateless_conformance_2026_07_defaults()
        with pytest.raises(GhostArgumentError):
            preset["check_tool_call"](legacy_session_tool, {"cursor": "pg2"})

    def test_ghost_state_handle_blocked(self) -> None:
        with pytest.raises(GhostArgumentError):
            validate_state_handle_declared(paginate, {"state_handle": "x"})

    def test_non_state_arg_is_not_this_presets_job(self) -> None:
        # A general ghost arg is @Airlock's job; the stateless preset only polices
        # state handles, so a non-state extra does not trip it.
        assert validate_state_handle_declared(paginate, {"cursor": "pg2", "foo": 1}) is None


class TestPresetMetadata:
    def test_canonical_metadata(self) -> None:
        p = mcp_stateless_conformance_2026_07_defaults()
        assert p["preset_id"] == "mcp_stateless_conformance_2026_07"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-2567/SEP-2575"  # spec proposal ids, NOT CVEs
        assert callable(p["check_request"])
        assert callable(p["check_tool_call"])

    def test_named_constant_matches_factory(self) -> None:
        assert MCP_STATELESS_CONFORMANCE_2026_07["preset_id"] == "mcp_stateless_conformance_2026_07"

    def test_no_cve_id_in_preset(self) -> None:
        src = inspect.getsource(mcp_stateless_conformance_2026_07_defaults)
        assert "CVE-" not in src


class TestNoRegression:
    def test_new_preset_discoverable_via_list_active(self) -> None:
        ids = {m.preset_id for m in list_active()}
        assert "mcp_stateless_conformance_2026_07_defaults" in ids

    def test_existing_sep_2468_preset_unaffected(self) -> None:
        ids = {m.preset_id for m in list_active()}
        assert "mcp_spec_2026_07_defaults" in ids
        # The SEP-2468 preset still constructs and exposes its checks.
        sep2468 = mcp_spec_2026_07_defaults(expected_issuer="https://as.example.com")
        assert callable(sep2468["check_oauth_response"])
        assert callable(sep2468["check_server_card"])
