"""MCP 2026-07-28 step-up scope-accumulation guard preset (SEP-2350 / SEP-2352, v0.8.52+).

Refuses a tool call whose authorising scope set (or its issuer) changed between admission
and execution. Broadening — a step-up granting new scopes after admission — is the primary
attack shape and is denied; narrowing is also refused; a live issuer that differs from the
admitted one is always refused (RFC 9207 / SEP-2468). Deny-by-default with an explicit
opt-out that still logs the decision. **SEP-2350 / SEP-2352 are spec ids, not CVEs.**
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from agent_airlock import observability
from agent_airlock.mcp_spec.step_up_scope_guard import (
    AdmissionScopeSnapshot,
    ScopeAccumulationError,
    capture_admission_snapshot,
    verify_scope_unchanged,
)
from agent_airlock.observability import NoOpProvider
from agent_airlock.policy_presets import (
    MCP_STEP_UP_SCOPE_2026_07,
    list_active,
    mcp_meta_trust_2026_07_defaults,
    mcp_spec_2026_07_header_integrity_defaults,
    mcp_step_up_scope_2026_07_defaults,
)

_ISS = "https://as.example.com"
_OTHER_ISS = "https://evil-as.example.com"


def _snapshot() -> AdmissionScopeSnapshot:
    return capture_admission_snapshot(
        "transfer_funds", scopes=["payments.read", "payments.write"], issuer=_ISS
    )


class _CapturingProvider(NoOpProvider):
    """Records track_event calls so tests can assert the decision flowed through OTel."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def track_event(self, event_name: str, properties: dict[str, Any] | None = None) -> None:
        self.events.append((event_name, properties or {}))


@pytest.fixture
def capture_events():
    provider = _CapturingProvider()
    observability.configure(provider)
    try:
        yield provider
    finally:
        observability._reset_provider()


class TestBenignUnaffected:
    def test_matching_scope_and_issuer_passes(self) -> None:
        preset = mcp_step_up_scope_2026_07_defaults()
        snap = preset["capture_admission"](
            "transfer_funds", scopes="payments.read payments.write", issuer=_ISS
        )
        # Same scope set (space-delimited form) + same issuer → admitted call executes.
        assert (
            preset["check_execution"](
                snap, live_scopes=["payments.write", "payments.read"], live_issuer=_ISS
            )
            is None
        )

    def test_step_up_before_admission_is_unaffected(self) -> None:
        # A step-up that happens BEFORE the call is admitted is benign: the call is
        # admitted at the broader scope and executes at exactly that scope. Only a
        # step-up BETWEEN admission and execution is an accumulation.
        snap = capture_admission_snapshot(
            "transfer_funds", scopes=["payments.read", "payments.write", "admin.all"], issuer=_ISS
        )
        assert (
            verify_scope_unchanged(
                snap, live_scopes=["payments.read", "payments.write", "admin.all"], live_issuer=_ISS
            )
            is None
        )


class TestScopeBroadenedRefused:
    def test_broadened_between_admission_and_execution_refused(self) -> None:
        with pytest.raises(ScopeAccumulationError) as exc:
            verify_scope_unchanged(
                _snapshot(),
                live_scopes=["payments.read", "payments.write", "admin.all"],
                live_issuer=_ISS,
            )
        event = exc.value.audit_event
        assert event["event"] == "mcp.scope_accumulation.refuse"
        assert event["reason"] == "scope_broadened"
        assert event["tool"] == "transfer_funds"
        assert event["broadened"] == ["admin.all"]
        assert event["admitted_issuer"] == _ISS and event["live_issuer"] == _ISS

    def test_narrowed_also_refused(self) -> None:
        with pytest.raises(ScopeAccumulationError) as exc:
            verify_scope_unchanged(_snapshot(), live_scopes=["payments.read"], live_issuer=_ISS)
        assert exc.value.audit_event["reason"] == "scope_narrowed"


class TestIssuerBinding:
    def test_same_scopes_different_issuer_refused(self) -> None:
        with pytest.raises(ScopeAccumulationError) as exc:
            verify_scope_unchanged(
                _snapshot(),
                live_scopes=["payments.read", "payments.write"],
                live_issuer=_OTHER_ISS,
            )
        assert exc.value.audit_event["reason"] == "issuer_mismatch"

    def test_opt_out_does_not_relax_issuer_binding(self) -> None:
        # allow_scope_change relaxes a scope-set change, NEVER a cross-authority issuer.
        with pytest.raises(ScopeAccumulationError) as exc:
            verify_scope_unchanged(
                _snapshot(),
                live_scopes=["payments.read", "payments.write"],
                live_issuer=_OTHER_ISS,
                allow_scope_change=True,
            )
        assert exc.value.audit_event["reason"] == "issuer_mismatch"


class TestOptOutPermitsAndLogs:
    def test_opt_out_permits_broadening(self) -> None:
        assert (
            verify_scope_unchanged(
                _snapshot(),
                live_scopes=["payments.read", "payments.write", "admin.all"],
                live_issuer=_ISS,
                allow_scope_change=True,
            )
            is None
        )

    def test_opt_out_still_emits_decision(self, capture_events: _CapturingProvider) -> None:
        verify_scope_unchanged(
            _snapshot(),
            live_scopes=["payments.read", "payments.write", "admin.all"],
            live_issuer=_ISS,
            allow_scope_change=True,
        )
        assert capture_events.events, "opt-out must still emit the decision (never silent)"
        name, props = capture_events.events[-1]
        assert name == "mcp.scope_accumulation.decision"
        assert props["event"] == "mcp.scope_accumulation.allow"
        assert props["reason"] == "scope_broadened"
        assert props["opted_out"] is True

    def test_refusal_also_emits_decision(self, capture_events: _CapturingProvider) -> None:
        with pytest.raises(ScopeAccumulationError):
            verify_scope_unchanged(
                _snapshot(),
                live_scopes=["payments.read", "payments.write", "admin.all"],
                live_issuer=_ISS,
            )
        assert capture_events.events[-1][1]["event"] == "mcp.scope_accumulation.refuse"


class TestCompositionWithMetaTrust:
    def test_meta_trust_at_admission_then_step_up_refused_at_execution(self) -> None:
        # Admission: a request with benign _meta passes the untrusted-_meta guard.
        meta = mcp_meta_trust_2026_07_defaults()
        admission_request = {"_meta": {"traceparent": "00-abc-def-01", "progressToken": 7}}
        assert meta["check_request"](admission_request) is None

        step_up = mcp_step_up_scope_2026_07_defaults()
        snap = step_up["capture_admission"](
            "transfer_funds", scopes=["payments.write"], issuer=_ISS
        )

        # Execution: the scope set broadened → the step-up guard refuses, independently
        # of (and composing with) the _meta guard.
        with pytest.raises(step_up["scope_error"]):
            step_up["check_execution"](
                snap, live_scopes=["payments.write", "admin.all"], live_issuer=_ISS
            )

    def test_guards_use_distinct_error_types(self) -> None:
        from agent_airlock.mcp_spec.meta_trust import MetaTrustError

        assert MCP_STEP_UP_SCOPE_2026_07["scope_error"] is ScopeAccumulationError
        assert ScopeAccumulationError is not MetaTrustError


class TestPresetMetadata:
    def test_canonical_metadata(self) -> None:
        p = mcp_step_up_scope_2026_07_defaults()
        assert p["preset_id"] == "mcp_step_up_scope_2026_07"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-2350/SEP-2352"
        assert p["owasp"] == "MCP07"
        assert callable(p["capture_admission"]) and callable(p["check_execution"])
        assert p["scope_error"] is ScopeAccumulationError
        assert p["snapshot_type"] is AdmissionScopeSnapshot

    def test_named_constant_matches_factory(self) -> None:
        assert MCP_STEP_UP_SCOPE_2026_07["preset_id"] == "mcp_step_up_scope_2026_07"

    def test_cites_seps_not_cves(self) -> None:
        src = inspect.getsource(mcp_step_up_scope_2026_07_defaults)
        assert "SEP-2350" in src and "SEP-2352" in src
        assert "CVE-" not in src

    def test_factory_opt_out_default_flows_to_check(self) -> None:
        # A factory-level opt-out is the default for check_execution.
        p = mcp_step_up_scope_2026_07_defaults(allow_scope_change=True)
        snap = p["capture_admission"]("t", scopes=["a"], issuer=_ISS)
        assert p["check_execution"](snap, live_scopes=["a", "b"], live_issuer=_ISS) is None


class TestNoRegression:
    def test_discoverable_via_list_active(self) -> None:
        assert "mcp_step_up_scope_2026_07_defaults" in {m.preset_id for m in list_active()}

    def test_sibling_presets_unaffected(self) -> None:
        assert callable(mcp_meta_trust_2026_07_defaults()["check_request"])
        assert callable(mcp_spec_2026_07_header_integrity_defaults()["check_request"])
