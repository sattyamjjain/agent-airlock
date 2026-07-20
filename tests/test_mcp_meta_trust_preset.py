"""MCP 2026-07-28 ``_meta`` trust-boundary preset (v0.8.50+).

The 2026-07-28 final spec moves protocol version, client info, and capabilities into
an **unsigned** ``_meta`` object on every request. A server that keys an authorization
or routing decision off those fields trusts attacker-controlled data (Akamai,
2026-06-25). This preset treats ``_meta`` as untrusted input: with a ``MetaPin`` it
fails closed on disagreement; with no pin it denies capability/role-shaped escalation;
and it enforces type/shape discipline (mapping-only, scalar identity values, no
case/unicode-colliding keys, a size cap). A benign ``_meta`` (traceparent /
progressToken / ordinary annotations) passes untouched.

This is a **trust-boundary reading of the 2026-07-28 spec — not a SEP id, not a CVE.**
"""

from __future__ import annotations

import inspect

import pytest

from agent_airlock.mcp_spec.meta_trust import (
    MetaPin,
    MetaTrustError,
    validate_meta_trust,
)
from agent_airlock.policy_presets import (
    MCP_META_TRUST_2026_07,
    list_active,
    mcp_meta_trust_2026_07_defaults,
    mcp_spec_2026_07_defaults,
    mcp_spec_2026_07_header_integrity_defaults,
    mcp_stateless_conformance_2026_07_defaults,
)


def _pin() -> MetaPin:
    return MetaPin(
        protocol_version="2026-07-28",
        client_name="acme-agent",
        capabilities=frozenset({"tools", "logging"}),
    )


def _entitled_request() -> dict:
    """A request whose ``_meta`` agrees with :func:`_pin`."""
    return {
        "method": "tools/call",
        "params": {"name": "get_balance"},
        "_meta": {
            "protocolVersion": "2026-07-28",
            "clientInfo": {"name": "acme-agent", "version": "1.4.0"},
            "capabilities": {"tools": {}, "logging": {}},
        },
    }


class TestPinAgreementPasses:
    def test_pin_agreement_passes(self) -> None:
        preset = mcp_meta_trust_2026_07_defaults(pinned=_pin())
        assert preset["check_request"](_entitled_request()) is None

    def test_per_call_pin_overrides_factory(self) -> None:
        preset = mcp_meta_trust_2026_07_defaults()
        assert preset["check_request"](_entitled_request(), pinned=_pin()) is None

    def test_absent_meta_passes(self) -> None:
        assert validate_meta_trust({"method": "tools/call"}) is None

    def test_meta_field_not_pinned_and_not_asserted_passes(self) -> None:
        # A pinned client_version left unset in _meta is not a disagreement.
        req = {"_meta": {"protocolVersion": "2026-07-28"}}
        assert validate_meta_trust(req, pinned=_pin()) is None


class TestPinDisagreementDenies:
    def test_protocol_version_disagreement_denies_with_audit_event(self) -> None:
        preset = mcp_meta_trust_2026_07_defaults(pinned=_pin())
        req = _entitled_request()
        req["_meta"]["protocolVersion"] = "2020-01-01"
        with pytest.raises(MetaTrustError) as exc:
            preset["check_request"](req)
        event = exc.value.audit_event
        assert event["event"] == "mcp.meta_trust.reject"
        assert event["reason"] == "meta_pin_disagreement"
        assert event["field"] == "protocolVersion"
        assert event["meta_value"] == "2020-01-01"
        assert event["pin_value"] == "2026-07-28"

    def test_client_name_disagreement_denies(self) -> None:
        req = _entitled_request()
        req["_meta"]["clientInfo"]["name"] = "evil-client"
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust(req, pinned=_pin())
        assert exc.value.audit_event["reason"] == "meta_pin_disagreement"

    def test_capability_beyond_pin_denies(self) -> None:
        req = _entitled_request()
        req["_meta"]["capabilities"]["admin"] = True
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust(req, pinned=_pin())
        event = exc.value.audit_event
        assert event["reason"] == "meta_capability_escalation"
        assert "admin" in event["offending_capabilities"]

    def test_pinned_field_disagreement_denies(self) -> None:
        pin = MetaPin(fields={"tenant": "tenant-a"})
        req = {"_meta": {"tenant": "tenant-b"}}
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust(req, pinned=pin)
        assert exc.value.audit_event["reason"] == "meta_pin_disagreement"

    def test_pinned_field_agreement_passes(self) -> None:
        pin = MetaPin(fields={"tenant": "tenant-a"})
        assert validate_meta_trust({"_meta": {"tenant": "tenant-a"}}, pinned=pin) is None


class TestEscalationWithoutPinDenies:
    def test_capabilities_without_pin_denies(self) -> None:
        preset = mcp_meta_trust_2026_07_defaults()
        with pytest.raises(MetaTrustError) as exc:
            preset["check_request"]({"_meta": {"capabilities": {"admin": True}}})
        assert exc.value.audit_event["reason"] == "meta_capability_escalation"

    def test_role_without_pin_denies(self) -> None:
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust({"_meta": {"role": "admin"}})
        assert exc.value.audit_event["reason"] == "meta_role_escalation"

    def test_tenant_shaped_key_without_pin_denies(self) -> None:
        with pytest.raises(MetaTrustError):
            validate_meta_trust({"_meta": {"tenantId": "other-tenant"}})

    def test_meta_under_params_is_checked(self) -> None:
        with pytest.raises(MetaTrustError):
            validate_meta_trust({"params": {"_meta": {"scope": "admin:*"}}})

    def test_empty_capability_value_does_not_broaden(self) -> None:
        # An empty capabilities placeholder asserts no privilege → allowed.
        assert validate_meta_trust({"_meta": {"capabilities": {}}}) is None


class TestBenignMetaPassesUntouched:
    """MANDATORY: a guard that breaks normal traffic is worse than no guard."""

    def test_traceparent_progress_token_annotations_pass(self) -> None:
        benign = {
            "_meta": {
                "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
                "progressToken": 42,
                "annotations": {"audience": ["user"], "priority": 0.3},
            }
        }
        assert validate_meta_trust(benign) is None
        # And through the preset, no pin.
        assert mcp_meta_trust_2026_07_defaults()["check_request"](benign) is None

    def test_ordinary_string_meta_passes(self) -> None:
        assert validate_meta_trust({"_meta": {"requestId": "req-123", "locale": "en-US"}}) is None


class TestTypeAndShapeDiscipline:
    def test_case_duplicate_keys_deny(self) -> None:
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust({"_meta": {"Role": "x", "role": "y"}})
        assert exc.value.audit_event["reason"] == "meta_ambiguous_key"

    def test_unicode_duplicate_keys_deny(self) -> None:
        # Fullwidth 'ｒｏｌｅ' normalizes (NFKC) to 'role'.
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust({"_meta": {"role": "x", "ｒｏｌｅ": "y"}})
        assert exc.value.audit_event["reason"] == "meta_ambiguous_key"

    def test_oversized_meta_denies(self) -> None:
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust({"_meta": {"note": "A" * 20000}})
        event = exc.value.audit_event
        assert event["reason"] == "meta_too_large"
        assert event["limit_bytes"] == 16384

    def test_nonscalar_identity_value_denies(self) -> None:
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust({"_meta": {"role": {"$gt": ""}}}, pinned=_pin())
        assert exc.value.audit_event["reason"] == "meta_nonscalar_identity"

    def test_meta_not_a_mapping_denies(self) -> None:
        with pytest.raises(MetaTrustError) as exc:
            validate_meta_trust({"_meta": ["a", "b"]})
        assert exc.value.audit_event["reason"] == "meta_not_mapping"

    def test_narrowed_escalation_tokens_allow_opted_out_key(self) -> None:
        # Operator opts into a narrower set that excludes 'role'.
        from agent_airlock.mcp_spec.meta_trust import MetaTrustConfig

        cfg = MetaTrustConfig(escalation_tokens=frozenset({"admin"}))
        assert validate_meta_trust({"_meta": {"role": "reader"}}, config=cfg) is None


class TestPresetMetadata:
    def test_canonical_metadata(self) -> None:
        p = mcp_meta_trust_2026_07_defaults()
        assert p["preset_id"] == "mcp_meta_trust_2026_07"
        assert p["default_action"] == "deny"
        assert callable(p["check_request"])
        assert p["meta_error"] is MetaTrustError

    def test_named_constant_matches_factory(self) -> None:
        assert MCP_META_TRUST_2026_07["preset_id"] == "mcp_meta_trust_2026_07"

    def test_not_a_sep_and_not_a_cve(self) -> None:
        p = mcp_meta_trust_2026_07_defaults()
        # It carries a 'basis', NOT a 'spec' (SEP id), and no CVE.
        assert "spec" not in p
        assert "not a SEP" in p["basis"]
        src = inspect.getsource(mcp_meta_trust_2026_07_defaults)
        assert "CVE-" not in src
        assert "SEP-" not in src


class TestNoRegression:
    def test_new_preset_discoverable_via_list_active(self) -> None:
        ids = {m.preset_id for m in list_active()}
        assert "mcp_meta_trust_2026_07_defaults" in ids

    def test_sibling_mcp_spec_presets_unaffected(self) -> None:
        ids = {m.preset_id for m in list_active()}
        assert "mcp_spec_2026_07_header_integrity_defaults" in ids
        assert "mcp_stateless_conformance_2026_07_defaults" in ids
        assert "mcp_spec_2026_07_defaults" in ids
        assert callable(mcp_spec_2026_07_header_integrity_defaults()["check_request"])
        assert callable(mcp_stateless_conformance_2026_07_defaults()["check_request"])
        assert callable(
            mcp_spec_2026_07_defaults(expected_issuer="https://as.example.com")[
                "check_oauth_response"
            ]
        )
