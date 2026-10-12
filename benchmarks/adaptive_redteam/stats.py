"""Statistics for the campaign: rule-of-three bounds, histograms, queries-to-plateau.

No scipy. The rule of three gives a 95% upper bound on an unseen event rate when
``k=0`` successes were observed in ``n`` trials: ``p <= 3/n``. For ``k>0`` we fall
back to a Wilson upper bound so a non-null result still ships an interval. These
are the honest "we ran N probes and saw zero bypasses, so the bypass rate is at
most 3/N with 95% confidence" statements the plan's nulls require.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .oracle import Attempt, Outcome

# z for a 95% one-sided / 97.5% two-sided interval — the same constant the other
# benchmark harnesses use (power.Z_95), spelled here so this package stays
# import-light.
Z_95 = 1.959963984540054


@dataclass(frozen=True)
class RuleOfThree:
    """A 95% upper bound on an event rate from ``k`` events in ``n`` trials."""

    n: int
    k: int
    upper_bound: float
    method: str

    def as_text(self) -> str:
        if self.n == 0:
            return "n=0 (not measured)"
        if self.k == 0:
            return f"0/{self.n} (<= {self.upper_bound:.3%} at 95%, rule of three)"
        return f"{self.k}/{self.n} ({self.k / self.n:.1%}, Wilson upper {self.upper_bound:.3%})"


def rule_of_three(n: int, k: int = 0) -> RuleOfThree:
    """A 95% upper bound on the rate of an event seen ``k`` times in ``n`` trials."""
    if n <= 0:
        return RuleOfThree(n=0, k=k, upper_bound=1.0, method="none")
    if k == 0:
        return RuleOfThree(n=n, k=0, upper_bound=min(1.0, 3.0 / n), method="rule_of_three")
    return RuleOfThree(n=n, k=k, upper_bound=_wilson_upper(n, k), method="wilson")


def _wilson_upper(n: int, k: int) -> float:
    """Upper end of the Wilson score interval for ``k/n``."""
    if n == 0:
        return 1.0
    p = k / n
    z = Z_95
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return min(1.0, (centre + margin) / denom)


def outcome_histogram(attempts: Iterable[Attempt]) -> dict[str, int]:
    """Count attempts by outcome value, with every outcome present (zeros kept)."""
    counts: Counter[str] = Counter(a.outcome.value for a in attempts)
    return {o.value: counts.get(o.value, 0) for o in Outcome}


def bypasses(attempts: Iterable[Attempt]) -> list[Attempt]:
    return [a for a in attempts if a.outcome is Outcome.BYPASS]


def attack_attempts(attempts: Iterable[Attempt]) -> list[Attempt]:
    from .oracle import Intent

    return [a for a in attempts if a.candidate.intent is Intent.ATTACK]


def false_refusals(attempts: Iterable[Attempt]) -> list[Attempt]:
    """Benign controls the guard wrongly refused (hard_block under benign intent)."""
    from .oracle import Intent

    return [
        a
        for a in attempts
        if a.candidate.intent is Intent.BENIGN and a.outcome is Outcome.HARD_BLOCK
    ]


def queries_to_plateau(attempts: Sequence[Attempt], *, window: int = 10) -> int | None:
    """Index of the first attempt after which ``window`` consecutive non-novel ones ran.

    Returns the 1-based count of attempts up to and including the last novel one,
    or ``None`` if the plateau window was never reached.
    """
    run = 0
    last_novel = 0
    for i, attempt in enumerate(attempts, start=1):
        if attempt.novel:
            run = 0
            last_novel = i
        else:
            run += 1
            if run >= window:
                return last_novel
    return None


@dataclass(frozen=True)
class GuardSummary:
    """Aggregate for one guard's ledger."""

    guard: str
    seed: int | None
    attack_n: int
    bypass_k: int
    benign_n: int
    false_refusal_k: int
    histogram: dict[str, int]
    refusal_bound: RuleOfThree
    plateau_at: int | None

    def to_json(self) -> dict[str, object]:
        return {
            "guard": self.guard,
            "seed": self.seed,
            "attack_n": self.attack_n,
            "bypass_k": self.bypass_k,
            "benign_n": self.benign_n,
            "false_refusal_k": self.false_refusal_k,
            "histogram": self.histogram,
            "bypass_rate_bound_95": self.refusal_bound.upper_bound,
            "bypass_rate_text": self.refusal_bound.as_text(),
            "plateau_at": self.plateau_at,
        }


def summarize(guard: str, attempts: Sequence[Attempt], *, seed: int | None = None) -> GuardSummary:
    """Summarize a guard's attempts: histogram, bypass rate-of-three, plateau."""
    atk = attack_attempts(attempts)
    byp = bypasses(attempts)
    benign = [a for a in attempts if a not in atk]
    return GuardSummary(
        guard=guard,
        seed=seed,
        attack_n=len(atk),
        bypass_k=len(byp),
        benign_n=len(benign),
        false_refusal_k=len(false_refusals(attempts)),
        histogram=outcome_histogram(attempts),
        refusal_bound=rule_of_three(len(atk), len(byp)),
        plateau_at=queries_to_plateau(attempts),
    )
