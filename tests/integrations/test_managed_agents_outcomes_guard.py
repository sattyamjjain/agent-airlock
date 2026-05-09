"""Tests for the v0.7.4 Managed Agents Outcomes-rubric guard (ADD-1, 2026-05-09).

Anthropic's 2026-05-06 SF Code event shipped Managed Agents with a
structured Outcomes rubric (beta). The rubric produces a verdict
identifier that downstream tool calls should carry as a provenance
anchor. The guard fails-closed on missing / mismatched anchors so
operators can require all managed-agents-originated tool calls to
prove they passed through a rubric-verified plan.

Primary sources
---------------
- https://platform.claude.com/docs/en/managed-agents/dreams (2026-05-06)
- https://code.claude.com/docs/en/routines (2026-05-06)
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock.integrations.managed_agents_outcomes_guard import (
    MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD,
    ManagedAgentsOutcomesGuard,
    OutcomesRubricDecision,
    OutcomesRubricVerdict,
)


class TestManagedAgentsOutcomesGuardDenyAllDefault:
    """Empty allowlist (default) denies every call — operators must opt in."""

    def test_empty_allowlist_denies_known_id(self) -> None:
        guard = ManagedAgentsOutcomesGuard()
        decision = guard.evaluate({MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD: "rub-42"})
        assert isinstance(decision, OutcomesRubricDecision)
        assert decision.allowed is False
        assert decision.verdict == OutcomesRubricVerdict.DENY_RUBRIC_ID_NOT_ALLOWED
        assert decision.rubric_id == "rub-42"


class TestManagedAgentsOutcomesGuardAllowlistedPermit:
    """Allowlisted rubric IDs are permitted with verdict=ALLOW."""

    def test_allowlisted_id_permitted(self) -> None:
        guard = ManagedAgentsOutcomesGuard(allowlist=frozenset({"rub-1", "rub-42"}))
        decision = guard.evaluate({MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD: "rub-42"})
        assert decision.allowed is True
        assert decision.verdict == OutcomesRubricVerdict.ALLOW
        assert decision.rubric_id == "rub-42"


class TestManagedAgentsOutcomesGuardMismatchedRubricDeny:
    """A rubric ID outside the allowlist is denied with a dedicated reason."""

    def test_mismatched_rubric_id_denied(self) -> None:
        guard = ManagedAgentsOutcomesGuard(allowlist=frozenset({"rub-1"}))
        decision = guard.evaluate({MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD: "rub-99"})
        assert decision.allowed is False
        assert decision.verdict == OutcomesRubricVerdict.DENY_RUBRIC_ID_NOT_ALLOWED
        assert decision.rubric_id == "rub-99"


class TestManagedAgentsOutcomesGuardAbsentProvenance:
    """``None`` provenance (no rubric envelope at all) is denied."""

    def test_none_provenance_denied(self) -> None:
        guard = ManagedAgentsOutcomesGuard(allowlist=frozenset({"rub-1"}))
        decision = guard.evaluate(None)
        assert decision.allowed is False
        assert decision.verdict == OutcomesRubricVerdict.DENY_MISSING_PROVENANCE
        assert decision.rubric_id is None


class TestManagedAgentsOutcomesGuardAbsentKey:
    """Provenance dict present but lacking the rubric ID key is denied."""

    def test_absent_rubric_id_key_denied(self) -> None:
        guard = ManagedAgentsOutcomesGuard(allowlist=frozenset({"rub-1"}))
        decision = guard.evaluate({"some_other_field": "value"})
        assert decision.allowed is False
        assert decision.verdict == OutcomesRubricVerdict.DENY_RUBRIC_ID_MISSING
        assert decision.rubric_id is None

    def test_empty_string_rubric_id_treated_as_missing(self) -> None:
        """Empty-string rubric IDs are denied (no allowlisting via empty bypass)."""
        guard = ManagedAgentsOutcomesGuard(allowlist=frozenset({""}))
        decision = guard.evaluate({MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD: ""})
        assert decision.allowed is False
        assert decision.verdict == OutcomesRubricVerdict.DENY_RUBRIC_ID_MISSING

    def test_non_string_rubric_id_treated_as_missing(self) -> None:
        """Integer / object rubric IDs are denied — operator allowlist is string-typed."""
        guard = ManagedAgentsOutcomesGuard(allowlist=frozenset({"42"}))
        decision = guard.evaluate({MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD: 42})
        assert decision.allowed is False
        assert decision.verdict == OutcomesRubricVerdict.DENY_RUBRIC_ID_MISSING


class TestManagedAgentsOutcomesGuardCustomField:
    """Operators can override the provenance field name."""

    def test_custom_field_name_respected(self) -> None:
        guard = ManagedAgentsOutcomesGuard(
            allowlist=frozenset({"rub-1"}),
            provenance_field="our_internal_rubric_id",
        )
        decision = guard.evaluate({"our_internal_rubric_id": "rub-1"})
        assert decision.allowed is True
        assert decision.rubric_id == "rub-1"

    def test_custom_field_default_field_no_longer_consulted(self) -> None:
        """When the field name is overridden, the default field is ignored."""
        guard = ManagedAgentsOutcomesGuard(
            allowlist=frozenset({"rub-1"}),
            provenance_field="our_internal_rubric_id",
        )
        decision = guard.evaluate({MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD: "rub-1"})
        assert decision.allowed is False
        assert decision.verdict == OutcomesRubricVerdict.DENY_RUBRIC_ID_MISSING


class TestManagedAgentsOutcomesGuardComposability:
    """The decision shape mirrors AllowlistVerdict for chain-friendly composition."""

    def test_decision_has_allowed_field_for_chain_composition(self) -> None:
        """An integrator can chain this guard with manifest_only_allowlist's verdict.

        Both decision types carry an ``allowed: bool`` field, so an
        integrator can short-circuit on the first deny without
        introspecting type-specific fields.
        """
        guard = ManagedAgentsOutcomesGuard(allowlist=frozenset({"rub-1"}))
        decisions: list[Any] = [
            guard.evaluate({MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD: "rub-1"}),
            guard.evaluate({MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD: "rub-99"}),
        ]
        # First allowed, second denied — chain semantics work.
        assert decisions[0].allowed is True
        assert decisions[1].allowed is False
        # Cross-module sanity: AllowlistVerdict from manifest_only_allowlist
        # also carries an `allowed` field with identical truthiness semantics.
        from agent_airlock.runtime.manifest_only_allowlist import AllowlistVerdict

        assert hasattr(AllowlistVerdict, "__dataclass_fields__")
        assert "allowed" in AllowlistVerdict.__dataclass_fields__


class TestManagedAgentsOutcomesGuardRejectsBadAllowlist:
    """Construction-time validation rejects nonsense allowlists."""

    def test_non_frozenset_allowlist_rejected(self) -> None:
        with pytest.raises(TypeError, match="frozenset"):
            ManagedAgentsOutcomesGuard(allowlist=["rub-1"])  # type: ignore[arg-type]

    def test_non_string_member_rejected(self) -> None:
        with pytest.raises(TypeError, match="str"):
            ManagedAgentsOutcomesGuard(allowlist=frozenset({42}))  # type: ignore[arg-type]


class TestManagedAgentsOutcomesPresetFactory:
    """`policy_presets.managed_agents_outcomes_2026_05_06_defaults()` factory."""

    def test_factory_returns_expected_config_shape(self) -> None:
        from agent_airlock.policy_presets import managed_agents_outcomes_2026_05_06_defaults

        config = managed_agents_outcomes_2026_05_06_defaults(
            allowlist=frozenset({"rub-1", "rub-42"})
        )
        assert config["preset_id"] == "managed_agents_outcomes_2026_05_06"
        assert config["severity"] == "high"
        assert config["default_action"] == "deny"
        assert "platform.claude.com" in config["advisory_url"]
        assert config["allowlist"] == frozenset({"rub-1", "rub-42"})
        assert config["provenance_field"] == MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD

    def test_factory_default_allowlist_is_empty_frozenset(self) -> None:
        from agent_airlock.policy_presets import managed_agents_outcomes_2026_05_06_defaults

        config = managed_agents_outcomes_2026_05_06_defaults()
        assert config["allowlist"] == frozenset()

    def test_factory_provenance_field_overridable(self) -> None:
        from agent_airlock.policy_presets import managed_agents_outcomes_2026_05_06_defaults

        config = managed_agents_outcomes_2026_05_06_defaults(
            provenance_field="our_internal_rubric_id",
        )
        assert config["provenance_field"] == "our_internal_rubric_id"
