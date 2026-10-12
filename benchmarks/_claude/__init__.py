"""Shared plumbing for the benchmarks that spend Anthropic API credit.

Every benchmark that calls a Claude model through the API goes through this package, so
the rules that protect the credit live in one place:

* **The key comes only from the environment** (``ANTHROPIC_API_KEY``), is passed to the
  client explicitly, and is never logged, printed or written to disk (:mod:`.client`).
* **Every request is priced by exact model id** from the dated snapshot the package
  ships, plus the cache, Batch and Haiku long-prompt multipliers (:mod:`.pricing`). An
  unknown id raises; nothing is ever metered at ``$0``.
* **Every dollar lands in an append-only ledger** (:mod:`.ledger`), and a job is admitted
  only when its worst case fits under the cap (:mod:`.budget`).
* **Batch submission is idempotent**: the intent is written before the batch is
  created, so a crash mid-submit cannot double-spend (:mod:`.batch`, :mod:`.store`).

Nothing here runs a model on import, and nothing imports ``anthropic`` at module level:
the SDK is imported inside the function that needs it, so the unit tests and every dry
run work without it installed.
"""

from __future__ import annotations

from .budget import BudgetExceededError, BudgetGuard, hard_cap_usd
from .ledger import Ledger, default_data_dir, default_ledger_path
from .models import DEFAULT_EFFORT, MODELS, model_alias, resolve_model
from .pricing import (
    UnpricedModelError,
    estimate_usd,
    price_usage,
    rates_for,
    worst_case_usd,
)

__all__ = [
    "DEFAULT_EFFORT",
    "MODELS",
    "BudgetExceededError",
    "BudgetGuard",
    "Ledger",
    "UnpricedModelError",
    "default_data_dir",
    "default_ledger_path",
    "estimate_usd",
    "hard_cap_usd",
    "model_alias",
    "price_usage",
    "rates_for",
    "resolve_model",
    "worst_case_usd",
]
