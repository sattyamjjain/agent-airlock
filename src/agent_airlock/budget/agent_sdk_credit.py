"""Agent SDK Credit pool budget (v0.8.0+).

Anthropic's 2026-06-15 billing split (Zed blog 2026-05-14): Claude
subscriptions decouple from Claude Code usage when routed through
tools like Zed / Agent SDK. Per-month credit pools:

- $20  — Claude Pro
- $100 — Claude Max 5x
- $200 — Claude Max 20x

This primitive tracks running spend in-process against a configurable
monthly credit pool and emits a decision when:

- **90% spend** — :attr:`AgentSDKCreditVerdict.NEAR_LIMIT` (still
  ``allowed=True``; operator policy may choose to convert to deny).
- **100% spend** — :attr:`AgentSDKCreditVerdict.EXHAUSTED` with
  ``allowed=False``.

Rates load from a packaged pricing table
(``data/anthropic_pricing_2026_06.json``) keyed by model id. Unknown
models raise :class:`ValueError` — fail-closed; we do **not**
synthesise prices for models we haven't curated.

Honest scope
------------
- In-process accumulation only. Cross-process / cross-restart
  persistence is out of scope for the v0.8.0 first cut — operators
  who need it should layer their own sink.
- The pricing table is a 2026-06 snapshot. Operators on enterprise
  / annual contracts should pass their own rate card via
  ``override_pricing=``.

Primary source
--------------
https://zed.dev/blog/anthropic-subscription-changes (2026-05-14)
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass
from importlib.resources import files

import structlog

logger = structlog.get_logger("agent-airlock.budget.agent_sdk_credit")


_PRICING_PACKAGE = "agent_airlock.data"
_PRICING_RESOURCE_NAME = "anthropic_pricing_2026_06.json"


# Anthropic 2026-06-15 billing-split tier USD caps. Operators reference
# by label and the primitive picks the right monthly_credit_usd.
AGENT_SDK_TIER_USD: dict[str, float] = {
    "pro": 20.0,
    "max5x": 100.0,
    "max20x": 200.0,
}


_NEAR_LIMIT_FRACTION = 0.90


class AgentSDKCreditVerdict(str, enum.Enum):
    """Stable reason codes for :class:`AgentSDKCreditDecision`."""

    ALLOW = "allow"
    NEAR_LIMIT = "near_limit"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class AgentSDKCreditDecision:
    """Outcome of a single :meth:`AgentSDKCreditBudget.register_call`.

    Mirrors the v0.7.x decision family — ``allowed: bool`` for
    chain-friendly composition. Carries USD-denominated state so
    OTel exporters can emit gauges without re-querying the budget.

    Attributes:
        allowed: True for ALLOW + NEAR_LIMIT; False for EXHAUSTED.
        verdict: Stable :class:`AgentSDKCreditVerdict` value.
        detail: Free-form explanation.
        spent_usd: Cumulative spend so far this month (including the
            just-registered call).
        remaining_usd: ``monthly_credit_usd - spent_usd`` (may go
            slightly negative on the EXHAUSTED transition call).
        last_call_usd: USD cost of the just-registered call only.
    """

    allowed: bool
    verdict: AgentSDKCreditVerdict
    detail: str
    spent_usd: float
    remaining_usd: float
    last_call_usd: float


def load_anthropic_pricing_2026_06() -> dict[str, dict[str, float]]:
    """Load the packaged 2026-06 Anthropic pricing table.

    Returns:
        Dict keyed by model id with ``input_usd_per_million`` /
        ``output_usd_per_million`` per model.

    Raises:
        FileNotFoundError: Pricing fixture missing (broken install).
        ValueError: Pricing fixture present but malformed.
    """
    raw = (files(_PRICING_PACKAGE) / _PRICING_RESOURCE_NAME).read_text(encoding="utf-8")
    payload = json.loads(raw)
    models = payload.get("models")
    if not isinstance(models, dict):
        raise ValueError(
            f"pricing fixture {_PRICING_RESOURCE_NAME} malformed: 'models' must be a dict"
        )
    out: dict[str, dict[str, float]] = {}
    for model_id, rates in models.items():
        if not isinstance(rates, dict):
            raise ValueError(f"pricing fixture malformed: rates for {model_id!r} must be a dict")
        out[str(model_id)] = {
            "input_usd_per_million": float(rates["input_usd_per_million"]),
            "output_usd_per_million": float(rates["output_usd_per_million"]),
        }
    return out


class AgentSDKCreditBudget:
    """Track per-month USD spend against an Anthropic Agent SDK credit pool.

    Args:
        monthly_credit_usd: Pool size in USD. Must be > 0.
        tier_label: Optional tier label (``pro`` / ``max5x`` /
            ``max20x``) for observability / OTel attribute. The
            primitive does not auto-resolve the pool from the label —
            pass ``monthly_credit_usd=AGENT_SDK_TIER_USD[tier_label]``
            if you want the canonical value.
        override_pricing: Optional pricing-table override. Defaults
            to the packaged 2026-06 fixture.

    Raises:
        ValueError: ``monthly_credit_usd`` ≤ 0.
    """

    def __init__(
        self,
        monthly_credit_usd: float,
        *,
        tier_label: str | None = None,
        override_pricing: dict[str, dict[str, float]] | None = None,
    ) -> None:
        if monthly_credit_usd <= 0:
            raise ValueError(f"monthly_credit_usd must be positive; got {monthly_credit_usd!r}")
        self._monthly_credit_usd = float(monthly_credit_usd)
        self._tier_label = tier_label
        self._pricing = (
            override_pricing if override_pricing is not None else load_anthropic_pricing_2026_06()
        )
        self._spent_usd = 0.0

    @property
    def monthly_credit_usd(self) -> float:
        return self._monthly_credit_usd

    @property
    def tier_label(self) -> str | None:
        return self._tier_label

    @property
    def spent_usd(self) -> float:
        return self._spent_usd

    @property
    def remaining_usd(self) -> float:
        return self._monthly_credit_usd - self._spent_usd

    def register_call(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> AgentSDKCreditDecision:
        """Debit one call against the pool, return the decision.

        Args:
            model: Anthropic model id (must appear in the pricing table).
            input_tokens: Prompt-side tokens for this call.
            output_tokens: Completion-side tokens for this call.

        Returns:
            :class:`AgentSDKCreditDecision`. ``allowed=False`` maps
            to a refusal at the Airlock decorator boundary.

        Raises:
            ValueError: ``model`` is not in the pricing table.
        """
        rates = self._pricing.get(model)
        if rates is None:
            raise ValueError(f"unknown Anthropic model id {model!r}; not in pricing table")

        call_usd = (input_tokens / 1_000_000.0) * rates["input_usd_per_million"] + (
            output_tokens / 1_000_000.0
        ) * rates["output_usd_per_million"]
        self._spent_usd += call_usd

        if self._spent_usd >= self._monthly_credit_usd:
            logger.warning(
                "agent_sdk_credit_exhausted",
                tier=self._tier_label,
                spent_usd=round(self._spent_usd, 4),
                cap_usd=self._monthly_credit_usd,
            )
            return AgentSDKCreditDecision(
                allowed=False,
                verdict=AgentSDKCreditVerdict.EXHAUSTED,
                detail=(
                    f"Agent SDK credit pool exhausted "
                    f"(spent ${self._spent_usd:.4f} / ${self._monthly_credit_usd:.2f})"
                ),
                spent_usd=self._spent_usd,
                remaining_usd=self.remaining_usd,
                last_call_usd=call_usd,
            )

        if self._spent_usd >= self._monthly_credit_usd * _NEAR_LIMIT_FRACTION:
            logger.info(
                "agent_sdk_credit_near_limit",
                tier=self._tier_label,
                spent_usd=round(self._spent_usd, 4),
                cap_usd=self._monthly_credit_usd,
                fraction=_NEAR_LIMIT_FRACTION,
            )
            return AgentSDKCreditDecision(
                allowed=True,
                verdict=AgentSDKCreditVerdict.NEAR_LIMIT,
                detail=(
                    f"Agent SDK credit pool ≥90% consumed "
                    f"(spent ${self._spent_usd:.4f} / ${self._monthly_credit_usd:.2f})"
                ),
                spent_usd=self._spent_usd,
                remaining_usd=self.remaining_usd,
                last_call_usd=call_usd,
            )

        return AgentSDKCreditDecision(
            allowed=True,
            verdict=AgentSDKCreditVerdict.ALLOW,
            detail=(
                f"under Agent SDK credit cap "
                f"(spent ${self._spent_usd:.4f} / ${self._monthly_credit_usd:.2f})"
            ),
            spent_usd=self._spent_usd,
            remaining_usd=self.remaining_usd,
            last_call_usd=call_usd,
        )


__all__ = [
    "AGENT_SDK_TIER_USD",
    "AgentSDKCreditBudget",
    "AgentSDKCreditDecision",
    "AgentSDKCreditVerdict",
    "load_anthropic_pricing_2026_06",
]
