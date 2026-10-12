"""Admit a credit-funded job only when its worst case fits under the cap.

Two caps apply and the smaller wins:

* the per-command ``--budget-usd`` the operator passes (required with ``--run``);
* the cumulative hard cap for the ledger, ``$AIRLOCK_BENCH_HARD_CAP_USD`` (default
  ``180``: the $200 cycle credit minus a $20 reserve that no run may touch).

A job is admitted when ``spent + reserved + worst_case`` stays at or under both. Its
worst case is reserved in the ledger until the job settles, so two concurrent jobs
cannot each see the same headroom.
"""

from __future__ import annotations

import os

from .ledger import Ledger

DEFAULT_HARD_CAP_USD = 180.0


class BudgetExceededError(RuntimeError):
    """Raised when admitting a job would exceed a cap. Exit code 3 in the CLIs."""

    exit_code = 3


def hard_cap_usd() -> float:
    """The cumulative cap for the current ledger."""
    raw = os.environ.get("AIRLOCK_BENCH_HARD_CAP_USD")
    if raw is None or not raw.strip():
        return DEFAULT_HARD_CAP_USD
    value = float(raw)
    if value <= 0:
        raise ValueError(f"AIRLOCK_BENCH_HARD_CAP_USD must be positive, got {raw!r}")
    return value


class BudgetGuard:
    """Gate jobs against the per-command cap and the ledger's cumulative cap.

    Args:
        cap_usd: The operator's per-command budget (``--budget-usd``). Must be positive.
        ledger: The ledger to read spend from and write reservations to.
    """

    def __init__(self, cap_usd: float, ledger: Ledger) -> None:
        if cap_usd <= 0:
            raise ValueError(f"--budget-usd must be positive, got {cap_usd}")
        self.cap_usd = float(cap_usd)
        self.ledger = ledger
        self._baseline = ledger.spent() + ledger.reserved()

    def headroom(self) -> float:
        """USD still admissible under both caps right now."""
        spent = self.ledger.spent()
        reserved = self.ledger.reserved()
        command_used = spent + reserved - self._baseline
        return round(min(self.cap_usd - command_used, hard_cap_usd() - (spent + reserved)), 6)

    def admit(self, job: str, worst_case_usd: float) -> None:
        """Reserve ``worst_case_usd`` for ``job`` or raise.

        Raises:
            BudgetExceededError: The job's worst case does not fit under a cap.
        """
        room = self.headroom()
        if worst_case_usd > room:
            raise BudgetExceededError(
                f"job {job!r} worst case ${worst_case_usd:.2f} exceeds remaining "
                f"budget ${room:.2f} (per-command cap ${self.cap_usd:.2f}, hard cap "
                f"${hard_cap_usd():.2f}, ledger spent ${self.ledger.spent():.2f}, "
                f"reserved ${self.ledger.reserved():.2f})"
            )
        self.ledger.reserve(job, worst_case_usd)

    def settle(self, job: str) -> None:
        """Free ``job``'s reservation once its usage has been recorded."""
        self.ledger.settle(job)
