"""Tests for ModelCapabilityTier classification (v0.5.5+).

Primary sources (cited per v0.5.1+ convention):
- Anthropic Mythos Preview — InfoQ, 2026-04-23:
  <https://www.infoq.com/news/2026/04/anthropic-claude-mythos/>
- Unit 42 MCP attack-vector catalog — 2026-04-24:
  <https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/>
"""

from __future__ import annotations

import pytest

from agent_airlock import Capability, CapabilityPolicy, ModelCapabilityTier
from agent_airlock.integrations.model_tier import classify_model
from agent_airlock.policy_presets import offensive_cyber_model_defaults


class TestClassification:
    """classify_model picks the right tier from the prefix table."""

    @pytest.mark.parametrize(
        ("model_id", "expected"),
        [
            ("claude-opus-4-7", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
            ("claude-opus-4-7[1m]", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
            ("claude-opus-4-6", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
            ("gpt-5-2-codex", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
            ("claude-mythos-preview", ModelCapabilityTier.ZERO_DAY_CAPABLE),
            ("gpt-4", ModelCapabilityTier.STANDARD),
            ("claude-3-sonnet", ModelCapabilityTier.STANDARD),
            ("llama-2-70b", ModelCapabilityTier.STANDARD),
        ],
    )
    def test_known_models(self, model_id: str, expected: ModelCapabilityTier) -> None:
        assert classify_model(model_id) is expected

    def test_unknown_model_is_standard(self) -> None:
        assert classify_model("totally-made-up-model-xyz") is ModelCapabilityTier.STANDARD

    def test_empty_model_id_is_standard(self) -> None:
        assert classify_model("") is ModelCapabilityTier.STANDARD


class TestOffensiveCyberPresetBehavior:
    """The preset's deny set scales with the tier."""

    def test_standard_tier_unaffected(self) -> None:
        policy = offensive_cyber_model_defaults(model_id="gpt-4")
        assert policy.model_tier is ModelCapabilityTier.STANDARD
        assert policy.denied == Capability.NONE

    def test_offensive_cyber_blocks_shell_and_writes(self) -> None:
        policy = offensive_cyber_model_defaults(model_id="claude-opus-4-7")
        assert policy.model_tier is ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE
        # Each of these four must be in the denied set
        for cap in (
            Capability.PROCESS_SHELL,
            Capability.FILESYSTEM_WRITE,
            Capability.FILESYSTEM_DELETE,
            Capability.NETWORK_ARBITRARY,
        ):
            assert policy.denied & cap == cap, f"{cap!r} not denied"

    def test_zero_day_tier_also_blocks_network_all(self) -> None:
        policy = offensive_cyber_model_defaults(model_id="claude-mythos-preview")
        assert policy.model_tier is ModelCapabilityTier.ZERO_DAY_CAPABLE
        # NETWORK_ALL and PROCESS_EXEC additionally denied
        assert policy.denied & Capability.NETWORK_ALL == Capability.NETWORK_ALL
        assert policy.denied & Capability.PROCESS_EXEC == Capability.PROCESS_EXEC


class TestCapabilityPolicyFieldAccepted:
    """The new ``model_tier`` field on CapabilityPolicy is optional + round-trips."""

    def test_tier_field_defaults_to_none(self) -> None:
        policy = CapabilityPolicy()
        assert policy.model_tier is None

    def test_tier_field_round_trips(self) -> None:
        policy = CapabilityPolicy(
            model_tier=ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE,
        )
        assert policy.model_tier is ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE


class TestEscapeHatch:
    """Caller can layer a broader policy on top to unlock a capability."""

    def test_shell_can_be_reenabled_on_offensive_tier(self) -> None:
        baseline = offensive_cyber_model_defaults(model_id="claude-opus-4-7")
        relaxed = CapabilityPolicy(
            granted=baseline.granted | Capability.PROCESS_SHELL,
            denied=baseline.denied & ~Capability.PROCESS_SHELL,
            require_sandbox_for=baseline.require_sandbox_for,
            model_tier=baseline.model_tier,
        )
        # Tier tag preserved for audit logs even though SHELL now allowed
        assert relaxed.model_tier is ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE
        assert relaxed.denied & Capability.PROCESS_SHELL == Capability.NONE
