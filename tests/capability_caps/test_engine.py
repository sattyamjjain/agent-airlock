"""Tests for ``CapabilityCapEngine``."""

from __future__ import annotations

import threading

import pytest

from agent_airlock.capability_caps import (
    Capability,
    CapabilityCapEngine,
    CapabilityCapExceeded,
    CapabilityRule,
    CapabilityRulesConfig,
    SQLiteCapabilityLedgerStore,
)
from agent_airlock.exceptions import AirlockError
from agent_airlock.policy_presets import agent_capability_default_caps


@pytest.fixture
def engine() -> CapabilityCapEngine:
    cfg = CapabilityRulesConfig(
        rules=(
            CapabilityRule(
                capability=Capability.DELEGATE_TO_AGENT,
                amount=3,
                window="hour",
            ),
            CapabilityRule(
                capability=Capability.INVOKE_TOOL,
                amount=2,
                window="minute",
            ),
        )
    )
    return CapabilityCapEngine(cfg)


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(CapabilityCapExceeded, AirlockError)


class TestBasicSemantics:
    def test_within_cap_allows(self, engine: CapabilityCapEngine) -> None:
        d = engine.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        assert d.allowed
        assert d.event_id is not None

    def test_third_call_allowed_fourth_denied(self, engine: CapabilityCapEngine) -> None:
        for _ in range(3):
            assert engine.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b").allowed
        d = engine.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        assert not d.allowed
        assert "cap breach" in d.reason

    def test_no_match_invoke_tool_permissive(self) -> None:
        # No rule for ``INVOKE_TOOL`` against this capability => permissive.
        cfg = CapabilityRulesConfig(rules=())
        e = CapabilityCapEngine(cfg)
        assert e.check_and_use("a", Capability.INVOKE_TOOL, "tool").allowed

    def test_sign_contract_deny_by_default(self) -> None:
        cfg = CapabilityRulesConfig(rules=())
        e = CapabilityCapEngine(cfg)
        d = e.check_and_use("a", Capability.SIGN_CONTRACT, "deal-1")
        assert not d.allowed
        assert "deny-by-default" in d.reason

    def test_or_raise_raises_typed(self, engine: CapabilityCapEngine) -> None:
        for _ in range(3):
            engine.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        with pytest.raises(CapabilityCapExceeded) as excinfo:
            engine.check_and_use_or_raise("a", Capability.DELEGATE_TO_AGENT, "b")
        assert excinfo.value.capability == Capability.DELEGATE_TO_AGENT
        assert excinfo.value.cap_amount == 3


class TestRevocation:
    def test_revoke_blocks_subsequent_use(self) -> None:
        cfg = CapabilityRulesConfig(
            rules=(
                CapabilityRule(
                    capability=Capability.DELEGATE_TO_AGENT,
                    amount=10,
                    window="hour",
                ),
            )
        )
        e = CapabilityCapEngine(cfg)
        assert e.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b").allowed
        e.revoke("a", Capability.DELEGATE_TO_AGENT)
        d = e.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        assert not d.allowed
        assert "revoked" in d.reason


class TestConcurrency:
    """Concurrent uses against a 1-amount cap result in exactly 1 grant."""

    def test_one_grant_under_concurrency(self) -> None:
        cfg = CapabilityRulesConfig(
            rules=(
                CapabilityRule(
                    capability=Capability.DELEGATE_TO_AGENT,
                    amount=1,
                    window="hour",
                ),
            )
        )
        store = SQLiteCapabilityLedgerStore()
        e = CapabilityCapEngine(cfg, store=store)
        results: list[bool] = []

        def attempt() -> None:
            d = e.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
            results.append(d.allowed)

        threads = [threading.Thread(target=attempt) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(1 for r in results if r) == 1


class TestDurability:
    """SQLite WAL: dropping the engine without close() simulates SIGKILL."""

    def test_use_events_survive_engine_drop(self, tmp_path) -> None:
        db = tmp_path / "cap.db"
        cfg = CapabilityRulesConfig(
            rules=(
                CapabilityRule(
                    capability=Capability.DELEGATE_TO_AGENT,
                    amount=10,
                    window="hour",
                ),
            )
        )
        # Engine 1 — append 5 use events, do not close.
        e1 = CapabilityCapEngine(cfg, store=SQLiteCapabilityLedgerStore(path=db))
        for _ in range(5):
            e1.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        # Drop engine 1 entirely (simulates SIGKILL).
        del e1

        # Engine 2 — read the same DB.
        e2 = CapabilityCapEngine(cfg, store=SQLiteCapabilityLedgerStore(path=db))
        d = e2.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        assert d.allowed  # still under the cap of 10
        assert d.already_used == 5  # WAL flushed all 5 prior events


class TestPreset:
    def test_preset_constructs(self) -> None:
        preset = agent_capability_default_caps()
        assert preset["preset_id"] == "agent_capability_default_caps"
        rules = preset["rules_config"].rules
        capabilities = {r.capability for r in rules}
        assert Capability.DELEGATE_TO_AGENT in capabilities
        assert Capability.INVOKE_TOOL in capabilities

    def test_preset_engine_round_trip(self) -> None:
        preset = agent_capability_default_caps()
        engine = CapabilityCapEngine(preset["rules_config"])
        # Default config grants 3 delegations / hour.
        for _ in range(3):
            assert engine.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b").allowed
        d = engine.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        assert not d.allowed


class TestAgentCommerceCapsRegression:
    """Ensure the dollar-cap layer still works (no shared state regressions)."""

    def test_dollar_caps_independent(self) -> None:
        from agent_airlock.integrations.agent_commerce_caps import (
            AgentCommerceCaps,
            Cap,
            CapsConfig,
        )

        caps = AgentCommerceCaps(
            CapsConfig(caps=(Cap(amount_cents=500, window="day", scope="agent"),))
        )
        d = caps.check_and_debit(agent_id="a", counterparty="m", amount_cents=300)
        assert d.allowed

    def test_capability_caps_dont_affect_dollar_caps(self) -> None:
        # Burn through capability cap.
        cfg = CapabilityRulesConfig(
            rules=(
                CapabilityRule(
                    capability=Capability.DELEGATE_TO_AGENT,
                    amount=1,
                    window="hour",
                ),
            )
        )
        e = CapabilityCapEngine(cfg)
        e.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        d = e.check_and_use("a", Capability.DELEGATE_TO_AGENT, "b")
        assert not d.allowed
        # Dollar-cap engine is on its own table, must still work.
        from agent_airlock.integrations.agent_commerce_caps import (
            AgentCommerceCaps,
            Cap,
            CapsConfig,
        )

        caps = AgentCommerceCaps(
            CapsConfig(caps=(Cap(amount_cents=500, window="day", scope="agent"),))
        )
        decision = caps.check_and_debit(agent_id="a", counterparty="m", amount_cents=100)
        assert decision.allowed
