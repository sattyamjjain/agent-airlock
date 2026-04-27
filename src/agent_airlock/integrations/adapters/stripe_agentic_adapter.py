"""Stripe Agentic adapter (v0.5.8+).

Maps Stripe Agentic API payment-intent payloads to the
``(agent_id, counterparty, amount_cents)`` shape the
``agent_commerce_caps`` engine expects.

Stripe's Agentic surface uses ``stripe_metadata.airlock_agent_id``
to carry the buyer's agent id; the ``application``/``customer``
field carries the counterparty.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class StripeAgenticAdapter:
    """Stripe Agentic payment-intent shape:

    .. code-block:: json

        {
          "id": "pi_...",
          "amount": 4200,
          "currency": "usd",
          "customer": "cus_vendor-x",
          "metadata": {"airlock_agent_id": "agent-buyer"}
        }
    """

    name: str = "stripe-agentic"

    def parse_request(self, raw: dict[str, Any]) -> tuple[str, str, int]:
        meta = raw.get("metadata") or {}
        agent_id = ""
        if isinstance(meta, dict):
            agent_id = str(meta.get("airlock_agent_id", ""))
        if not agent_id:
            agent_id = str(raw.get("agent_id") or "")
        counterparty = str(raw.get("customer") or raw.get("counterparty") or "")
        cents = int(raw.get("amount", 0))
        return agent_id, counterparty, cents


__all__ = ["StripeAgenticAdapter"]
