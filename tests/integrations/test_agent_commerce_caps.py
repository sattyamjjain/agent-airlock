"""Tests for the v0.5.8 agent-commerce caps engine.

Primary source:
- https://www.anthropic.com/features/project-deal
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from agent_airlock import AgentCommerceCapExceeded, AgentCommerceCaps
from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.adapters import (
    GenericWebhookAdapter,
    ProjectDealAdapter,
    StripeAgenticAdapter,
)
from agent_airlock.integrations.agent_commerce_caps import (
    Cap,
    CapsConfig,
    SQLiteLedgerStore,
)
from agent_airlock.policy_presets import agent_commerce_default_caps


def _build(*, db_path: str = ":memory:") -> AgentCommerceCaps:
    return AgentCommerceCaps(
        config=CapsConfig(
            caps=(
                Cap(amount_cents=500, window="day", scope="counterparty"),
                Cap(amount_cents=10_000, window="week", scope="agent"),
            )
        ),
        store=SQLiteLedgerStore(db_path),
    )


class TestBasicDebit:
    def test_clean_debit_within_caps(self) -> None:
        caps = _build()
        d = caps.check_and_debit("a1", "v1", 100)
        assert d.allowed
        assert d.debit_id is not None

    def test_negative_debit_refused(self) -> None:
        caps = _build()
        d = caps.check_and_debit("a1", "v1", -10)
        assert not d.allowed


class TestCapBreaches:
    def test_per_counterparty_day_cap_breach(self) -> None:
        caps = _build()
        caps.check_and_debit("a1", "v1", 400)
        d = caps.check_and_debit("a1", "v1", 200)
        assert not d.allowed
        assert d.matched_cap is not None
        assert d.matched_cap.scope == "counterparty"

    def test_per_agent_week_cap_breach(self) -> None:
        caps = _build()
        # Spread across counterparties so the per-counterparty day cap
        # doesn't trip first; the agent week cap fires.
        for i in range(20):
            caps.check_and_debit("a1", f"v{i}", 500)
        d = caps.check_and_debit("a1", "v999", 500)
        assert not d.allowed
        assert d.matched_cap is not None
        assert d.matched_cap.scope == "agent"

    def test_check_and_debit_or_raise(self) -> None:
        caps = _build()
        caps.check_and_debit("a1", "v1", 400)
        with pytest.raises(AgentCommerceCapExceeded):
            caps.check_and_debit_or_raise("a1", "v1", 200)


class TestConcurrency:
    """100 concurrent debit attempts against a $5 cap with $1 each.

    No over-spend permitted — the engine must hard-stop at the cap.
    """

    def test_no_overspend_under_concurrency(self) -> None:
        caps = AgentCommerceCaps(
            config=CapsConfig(caps=(Cap(amount_cents=500, window="day", scope="counterparty"),)),
            store=SQLiteLedgerStore(":memory:"),
        )
        approved = 0
        approved_lock = threading.Lock()

        def attempt() -> None:
            nonlocal approved
            d = caps.check_and_debit("a1", "v1", 100)
            if d.allowed:
                with approved_lock:
                    approved += 1

        threads = [threading.Thread(target=attempt) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Cap is $5 = 500 cents = exactly 5 debits of 100 cents.
        assert approved == 5, f"concurrent debit overspend: {approved} approved against cap of 5"


class TestRestartSurvival:
    """The ledger must survive a process restart (ledger file persists)."""

    def test_ledger_persists_across_processes(self, tmp_path: Path) -> None:
        db = tmp_path / "ledger.db"
        first = AgentCommerceCaps(
            config=CapsConfig(caps=(Cap(amount_cents=500, window="day", scope="counterparty"),)),
            store=SQLiteLedgerStore(db),
        )
        first.check_and_debit("a1", "v1", 300)
        first.store.close()

        # Simulate restart with a fresh engine pointing at the same DB.
        second = AgentCommerceCaps(
            config=CapsConfig(caps=(Cap(amount_cents=500, window="day", scope="counterparty"),)),
            store=SQLiteLedgerStore(db),
        )
        d = second.check_and_debit("a1", "v1", 300)
        assert not d.allowed, "ledger did not persist across SQLiteLedgerStore re-open"

    def test_ledger_survives_sigkill_emulation(self, tmp_path: Path) -> None:
        """Emulate SIGKILL by skipping store.close(); WAL should preserve commits."""
        db = tmp_path / "ledger.db"
        first = AgentCommerceCaps(
            config=CapsConfig(caps=(Cap(amount_cents=1000, window="day", scope="counterparty"),)),
            store=SQLiteLedgerStore(db),
        )
        for _ in range(5):
            first.check_and_debit("a1", "v1", 100)
        # No close() — simulate kill -9.
        del first

        # Recovery checkpoint runs implicitly when WAL file is present.
        # Open with raw sqlite3 to confirm 5 rows are durable.
        conn = sqlite3.connect(db)
        try:
            row = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(amount_cents), 0) FROM debits"
            ).fetchone()
            assert row[0] == 5
            assert row[1] == 500
        finally:
            conn.close()


class TestAdapters:
    """Adapter swap with no policy rewrite."""

    def test_project_deal_adapter(self) -> None:
        adapter = ProjectDealAdapter()
        agent, cp, cents = adapter.parse_request(
            {
                "deal_id": "deal-1",
                "buyer_agent_id": "agent-buyer",
                "seller_id": "vendor-x",
                "amount": {"currency": "USD", "minor_units": 4200},
            }
        )
        assert agent == "agent-buyer"
        assert cp == "vendor-x"
        assert cents == 4200

    def test_stripe_agentic_adapter(self) -> None:
        adapter = StripeAgenticAdapter()
        agent, cp, cents = adapter.parse_request(
            {
                "id": "pi_xx",
                "amount": 4200,
                "customer": "cus_vendor-x",
                "metadata": {"airlock_agent_id": "agent-buyer"},
            }
        )
        assert agent == "agent-buyer"
        assert cp == "cus_vendor-x"
        assert cents == 4200

    def test_generic_webhook_adapter(self) -> None:
        adapter = GenericWebhookAdapter()
        agent, cp, cents = adapter.parse_request(
            {"agent_id": "a1", "counterparty": "v1", "amount_cents": 250}
        )
        assert (agent, cp, cents) == ("a1", "v1", 250)

    def test_swap_adapter_without_policy_rewrite(self) -> None:
        caps = _build()
        for adapter in (
            ProjectDealAdapter(),
            StripeAgenticAdapter(),
            GenericWebhookAdapter(),
        ):
            caps.register_adapter(adapter)
            assert caps.adapter_name == adapter.name


class TestPreset:
    def test_default_preset(self) -> None:
        cfg = agent_commerce_default_caps()
        assert isinstance(cfg["caps"], AgentCommerceCaps)
        assert cfg["source"].startswith("https://")
        # Sane defaults: $10 = 1000 cents per counterparty per day
        cap_amounts = sorted(c.amount_cents for c in cfg["config"].caps)
        assert cap_amounts == [1_000, 20_000]


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(AgentCommerceCapExceeded, AirlockError)
