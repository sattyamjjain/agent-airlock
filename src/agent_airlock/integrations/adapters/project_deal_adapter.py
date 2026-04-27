"""Anthropic Project Deal adapter (v0.5.8+).

Maps Project Deal payment-request payloads to the
``(agent_id, counterparty, amount_cents)`` shape the
``agent_commerce_caps`` engine expects.

Source: https://www.anthropic.com/features/project-deal
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ProjectDealAdapter:
    """Project Deal payload shape:

    .. code-block:: json

        {
          "deal_id": "...",
          "buyer_agent_id": "agent-buyer",
          "seller_id": "vendor-x",
          "amount": {"currency": "USD", "minor_units": 4200}
        }
    """

    name: str = "project-deal"

    def parse_request(self, raw: dict[str, Any]) -> tuple[str, str, int]:
        agent_id = str(raw.get("buyer_agent_id") or raw.get("agent_id") or "")
        counterparty = str(raw.get("seller_id") or raw.get("counterparty") or "")
        amount_block = raw.get("amount") or {}
        if isinstance(amount_block, dict):
            cents = int(amount_block.get("minor_units", 0))
        else:
            cents = int(amount_block)
        return agent_id, counterparty, cents


__all__ = ["ProjectDealAdapter"]
