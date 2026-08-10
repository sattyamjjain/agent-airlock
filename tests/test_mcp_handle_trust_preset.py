"""MCP 2026-07-28 stateless handle-channel trust preset (SEP-2567 + SEP-2243).

Deny-by-default for the channel the stateless rewrite created: server-minted state handles
and x-mcp-header-sourced headers now ride the same tool-argument channel as attacker-shaped
inputs. Covers the three behaviours — declared handle, reserved-header override rejection,
and unminted-handle deny.
"""

from __future__ import annotations

import inspect

import pytest

from agent_airlock import mcp_spec_2026_07_28_handle_trust_defaults
from agent_airlock.mcp_spec.handle_trust import (
    RESERVED_DECISION_HEADERS,
    HandleTrustError,
    validate_handle_minted,
    validate_no_reserved_header_override,
)
from agent_airlock.policy_presets import list_active
from agent_airlock.validator import GhostArgumentError


def _tool_with_handle(state_handle: str | None = None, query: str = "") -> str:  # noqa: ARG001
    """A tool that declares ``state_handle`` as an explicit contract parameter."""
    return "ok"


def _tool_no_handle(query: str = "") -> str:  # noqa: ARG001
    """A tool that declares no handle parameter."""
    return "ok"


class TestDeclaredHandle:
    """Requirement 1: a handle must be a declared parameter, not inferred."""

    def test_declared_handle_allowed(self) -> None:
        preset = mcp_spec_2026_07_28_handle_trust_defaults()
        assert preset["check_tool_call"](_tool_with_handle, {"state_handle": "h1"}) is None

    def test_undeclared_handle_denied(self) -> None:
        preset = mcp_spec_2026_07_28_handle_trust_defaults()
        with pytest.raises(GhostArgumentError):
            preset["check_tool_call"](_tool_no_handle, {"state_handle": "h1"})


class TestReservedHeaderOverride:
    """Requirement 2: an x-mcp-header must not set/override a policy-decision header."""

    def test_benign_param_headers_allowed(self) -> None:
        preset = mcp_spec_2026_07_28_handle_trust_defaults()
        assert preset["check_headers"](["Mcp-Param-Region", "Mcp-Param-Tenant"]) is None

    def test_authorization_override_rejected(self) -> None:
        preset = mcp_spec_2026_07_28_handle_trust_defaults()
        with pytest.raises(HandleTrustError) as exc:
            preset["check_headers"](["Mcp-Param-Region", "Authorization"])
        assert exc.value.audit_event["reason"] == "reserved_header_override"
        assert exc.value.audit_event["spec"] == "SEP-2567/SEP-2243"

    def test_mcp_name_override_case_insensitive_rejected(self) -> None:
        with pytest.raises(HandleTrustError):
            validate_no_reserved_header_override(["mcp-name"])

    def test_reserved_set_is_explicit_not_prefix(self) -> None:
        # Enumerated decision headers; a namespaced Mcp-Param-* header is NOT reserved.
        assert "authorization" in RESERVED_DECISION_HEADERS
        assert "mcp-name" in RESERVED_DECISION_HEADERS
        assert "mcp-protocol-version" in RESERVED_DECISION_HEADERS
        assert "mcp-param-region" not in RESERVED_DECISION_HEADERS


class TestMintedHandle:
    """Requirement 3: a handle not minted within the current policy scope is denied."""

    def test_minted_handle_allowed(self) -> None:
        preset = mcp_spec_2026_07_28_handle_trust_defaults()
        assert preset["check_handle"]("h1", minted={"h1", "h2"}) is None

    def test_unminted_handle_denied(self) -> None:
        preset = mcp_spec_2026_07_28_handle_trust_defaults()
        with pytest.raises(HandleTrustError) as exc:
            preset["check_handle"]("evil", minted={"h1"})
        assert exc.value.audit_event["reason"] == "unminted_handle"

    def test_empty_scope_denies_by_default(self) -> None:
        with pytest.raises(HandleTrustError):
            validate_handle_minted("h1", minted=set())


class TestPresetMetadata:
    def test_canonical_metadata(self) -> None:
        p = mcp_spec_2026_07_28_handle_trust_defaults()
        assert p["preset_id"] == "mcp_spec_2026_07_28_handle_trust"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-2567/SEP-2243"  # spec proposal ids, NOT CVEs
        assert callable(p["check_tool_call"])
        assert callable(p["check_headers"])
        assert callable(p["check_handle"])
        assert p["handle_error"] is HandleTrustError

    def test_no_cve_id_in_preset(self) -> None:
        src = inspect.getsource(mcp_spec_2026_07_28_handle_trust_defaults)
        assert "CVE-" not in src

    def test_discoverable_via_list_active(self) -> None:
        ids = {m.preset_id for m in list_active()}
        assert "mcp_spec_2026_07_28_handle_trust_defaults" in ids
