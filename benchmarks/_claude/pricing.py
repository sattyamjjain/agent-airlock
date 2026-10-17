"""Price Claude API usage by exact model id, with every multiplier that applies.

Base input/output rates come from the dated snapshot the package ships
(``agent_airlock/data/anthropic_pricing_2026_10.json``, loaded by
:func:`agent_airlock.budget.agent_sdk_credit.load_anthropic_pricing`). That snapshot
deliberately encodes base rates only, so the multipliers that stack on top live here.
Each was read from https://platform.claude.com/docs/en/about-claude/pricing on
2026-10-12:

* cache reads: 0.025x base input on Fable 5.1, 0.05x on Opus 5.5 and Sonnet 5.5,
  0.1x elsewhere (Haiku 5.5: $0.01/MTok up to 100K prompt tokens);
* cache writes: 1.25x base input for the 5-minute TTL, 2x for the 1-hour TTL;
* Batch API: 50% off every token category;
* Haiku 5.5 prompts over 100,000 tokens (input + cache reads + cache writes) pay 5x on
  every category, the whole request.

Lookup is by **exact** id. The agentdojo harness's prefix table metered
``claude-opus-5-5`` at Opus 5's $5/$25 and ``claude-haiku-5-5`` at $0; this module raises
:class:`UnpricedModelError` instead of guessing.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

PRICING_SNAPSHOT = "anthropic_pricing_2026_10.json"
"""The dated snapshot every run is priced from; recorded in each run manifest."""

BATCH_MULTIPLIER = 0.5
CACHE_WRITE_5M_MULTIPLIER = 1.25
CACHE_WRITE_1H_MULTIPLIER = 2.0

_CACHE_READ_MULTIPLIER: dict[str, float] = {
    "claude-fable-5-1": 0.025,
    "claude-opus-5-5": 0.05,
    "claude-sonnet-5-5": 0.05,
}
_DEFAULT_CACHE_READ_MULTIPLIER = 0.1

_LONG_PROMPT: dict[str, tuple[int, float]] = {"claude-haiku-5-5": (100_000, 5.0)}
"""model -> (prompt-token threshold, multiplier on every category above it)."""


class UnpricedModelError(KeyError):
    """Raised for a model id the pricing snapshot does not list."""


@dataclass(frozen=True)
class Rates:
    """USD per million tokens for one request at one prompt size."""

    model: str
    input: float
    output: float
    cache_read: float
    cache_write_5m: float
    cache_write_1h: float


@lru_cache(maxsize=1)
def _base_rates() -> dict[str, tuple[float, float]]:
    from agent_airlock.budget.agent_sdk_credit import load_anthropic_pricing

    table = load_anthropic_pricing(PRICING_SNAPSHOT)
    return {
        model: (row["input_usd_per_million"], row["output_usd_per_million"])
        for model, row in table.items()
    }


def rates_for(model: str, prompt_tokens: int = 0) -> Rates:
    """Return the per-MTok rates for ``model`` at a request whose prompt is ``prompt_tokens``.

    Args:
        model: Exact model id, e.g. ``claude-opus-5-5``.
        prompt_tokens: Input + cache-read + cache-write tokens of the request. Only Haiku
            5.5 changes price with it.

    Raises:
        UnpricedModelError: The snapshot does not list ``model``.
    """
    base = _base_rates()
    if model not in base:
        raise UnpricedModelError(f"{model!r} is not in pricing snapshot {PRICING_SNAPSHOT}")
    base_in, base_out = base[model]
    multiplier = 1.0
    threshold = _LONG_PROMPT.get(model)
    if threshold is not None and prompt_tokens > threshold[0]:
        multiplier = threshold[1]
    read_mult = _CACHE_READ_MULTIPLIER.get(model, _DEFAULT_CACHE_READ_MULTIPLIER)
    return Rates(
        model=model,
        input=base_in * multiplier,
        output=base_out * multiplier,
        cache_read=base_in * read_mult * multiplier,
        cache_write_5m=base_in * CACHE_WRITE_5M_MULTIPLIER * multiplier,
        cache_write_1h=base_in * CACHE_WRITE_1H_MULTIPLIER * multiplier,
    )


def _get(usage: Mapping[str, Any] | Any, key: str) -> int:
    value = usage.get(key) if isinstance(usage, Mapping) else getattr(usage, key, None)
    return int(value or 0)


def _cache_write_split(usage: Mapping[str, Any] | Any) -> tuple[int, int]:
    """Return (5-minute, 1-hour) cache-write tokens; untyped writes count as 5-minute."""
    total = _get(usage, "cache_creation_input_tokens")
    detail = (
        usage.get("cache_creation")
        if isinstance(usage, Mapping)
        else getattr(usage, "cache_creation", None)
    )
    if detail is None:
        return total, 0
    five = _get(detail, "ephemeral_5m_input_tokens")
    hour = _get(detail, "ephemeral_1h_input_tokens")
    if five + hour == 0:
        return total, 0
    return five, hour


def price_usage(model: str, usage: Mapping[str, Any] | Any, *, batch: bool) -> float:
    """Return the USD cost of one response's ``usage`` (a dict or an SDK usage object).

    Thinking tokens are part of ``output_tokens`` on the wire and are priced as output.

    Raises:
        UnpricedModelError: The snapshot does not list ``model``.
    """
    input_tokens = _get(usage, "input_tokens")
    output_tokens = _get(usage, "output_tokens")
    cache_read = _get(usage, "cache_read_input_tokens")
    write_5m, write_1h = _cache_write_split(usage)
    prompt = input_tokens + cache_read + write_5m + write_1h
    r = rates_for(model, prompt)
    usd = (
        input_tokens * r.input
        + output_tokens * r.output
        + cache_read * r.cache_read
        + write_5m * r.cache_write_5m
        + write_1h * r.cache_write_1h
    ) / 1_000_000
    if batch:
        usd *= BATCH_MULTIPLIER
    return round(usd, 8)


def worst_case_usd(model: str, input_tokens: int, max_tokens: int, *, batch: bool) -> float:
    """Upper bound for one request: every input token uncached, ``max_tokens`` all spent."""
    return price_usage(
        model, {"input_tokens": input_tokens, "output_tokens": max_tokens}, batch=batch
    )


def estimate_usd(model: str, input_tokens: int, output_tokens: int, *, batch: bool) -> float:
    """Expected cost for one request at an assumed output size (visible + thinking)."""
    return price_usage(
        model, {"input_tokens": input_tokens, "output_tokens": output_tokens}, batch=batch
    )
