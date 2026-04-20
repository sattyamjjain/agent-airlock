"""High-value action preset regression tests (v0.5.2+).

Motivating incident: 2026-04-19 Kelp DAO LayerZero bridge exploit, $292M
stolen, ~$200M Aave bad debt.

Primary sources
---------------
- Bloomberg (2026-04-19):
  https://www.bloomberg.com/news/articles/2026-04-19/crypto-hack-worth-290-million-triggers-defi-contagion-shock
- The Defiant on Aave / KelpDAO:
  https://thedefiant.io/news/defi/aave-price-crash-kelpdao-exploit-whale-dump-rxi8o9
"""

from __future__ import annotations

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.policy_presets import (
    HighValueActionBlocked,
    high_value_action_deny_by_default,
)


class TestHighValueActionDenyByDefault:
    def test_01_banned_verb_blocked(self) -> None:
        """``transfer_funds`` must be refused without opt-in."""
        cfg = high_value_action_deny_by_default()
        with pytest.raises(HighValueActionBlocked):
            cfg["check"]("transfer_funds", allow_high_value=False)

    def test_02_banned_verb_allowed_with_flag(self) -> None:
        cfg = high_value_action_deny_by_default()
        cfg["check"]("transfer_funds", allow_high_value=True)

    def test_03_non_matching_tool_passes(self) -> None:
        cfg = high_value_action_deny_by_default()
        cfg["check"]("read_balance", allow_high_value=False)
        cfg["check"]("list_positions", allow_high_value=False)


class TestHighValueActionExtras:
    def test_all_nine_verbs_classified(self) -> None:
        cfg = high_value_action_deny_by_default()
        for verb in [
            "transfer_usdc",
            "bridge_rsETH",
            "approve_spender",
            "withdraw_collateral",
            "borrow_against",
            "liquidate_position",
            "swap_tokens",
            "mint_nft",
            "burn_token",
        ]:
            assert cfg["is_high_value"](verb), f"{verb!r} should be high-value"

    def test_source_cites_bloomberg(self) -> None:
        cfg = high_value_action_deny_by_default()
        assert "bloomberg" in cfg["source"].lower()

    def test_is_airlock_error(self) -> None:
        cfg = high_value_action_deny_by_default()
        with pytest.raises(AirlockError):
            cfg["check"]("bridge_assets", allow_high_value=False)
