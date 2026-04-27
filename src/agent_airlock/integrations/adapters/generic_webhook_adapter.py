"""Generic webhook adapter (v0.5.8+).

Catch-all for in-house or unsupported payment surfaces. Expects the
upstream webhook to already deliver the canonical
``(agent_id, counterparty, amount_cents)`` triple — useful when the
caller writes a thin shim over their own commerce events.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class GenericWebhookAdapter:
    """Webhook payload shape:

    .. code-block:: json

        {
          "agent_id": "agent-buyer",
          "counterparty": "vendor-x",
          "amount_cents": 4200
        }
    """

    name: str = "generic-webhook"

    def parse_request(self, raw: dict[str, Any]) -> tuple[str, str, int]:
        return (
            str(raw.get("agent_id", "")),
            str(raw.get("counterparty", "")),
            int(raw.get("amount_cents", 0)),
        )


__all__ = ["GenericWebhookAdapter"]
