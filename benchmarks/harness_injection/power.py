"""How much this benchmark can actually conclude at a given ``--trials``.

Why this module exists
----------------------
The published run is a **null**: 0 acted events out of 24 cells, n = 6 per harness per arm.
``docs/benchmarks/injection-multi-harness.md`` states the 95% Wilson interval on that zero
as **[0.0%, 39.0%]** and says plainly that it rules out a *high* action rate and not a low
one.

Those interval figures were computed by hand for the write-up. A number in a document that
nothing recomputes is the failure mode this repo already has machine gates for
(``check_benchmark_freshness.py`` for dates, ``test_numeric_claim_parity.py`` for counts), so
the arithmetic lives here, the doc quotes it, and a test asserts the two agree.

The practical use is deciding whether the next run is worth its API budget *before* spending
it: :func:`trials_for_upper_bound` answers "how many trials would I need for a zero to mean
something", and ``--trials N`` on the CLI prints what that N would buy.

Zero events, small n
--------------------
For an observed 0 out of n, the Wilson score interval collapses to a closed form. With
:math:`\\hat p = 0`, the centre and half-width are both :math:`z^2 / 2(n + z^2)`, so

.. math::

    \\text{upper} = \\frac{z^2}{n + z^2}

which is exact and needs no normal-approximation caveat, no ``scipy``, and no iteration.
The cruder *rule of three* (:math:`3/n`) is reported alongside it because it is the figure
most readers recognise; it is slightly optimistic at small n, and the table shows by how
much.

No new dependency: :mod:`math` and nothing else.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = [
    "AIRLOCK_MODES",
    "PowerRow",
    "Z_95",
    "describe",
    "power_table",
    "probability_of_observing_zero",
    "rule_of_three_upper_bound",
    "trials_for_upper_bound",
    "wilson_upper_bound_for_zero",
]

#: Two-sided 95% normal quantile, at the conventional 1.96 rather than the exact
#: 1.959963984540054. This is the value the published intervals in
#: ``docs/benchmarks/injection-multi-harness.md`` were computed with, and the code has to
#: reproduce what was published rather than quietly revise it. The exact quantile moves
#: exactly one of those rows — n = 12 goes 24.3% → 24.2% — which is a rounding artefact and
#: not a correction worth restating a benchmark figure over.
Z_95 = 1.96

#: Each (harness, arm, trial) is measured twice — airlock enabled and disabled. So one
#: ``--trials`` step buys two observations per harness per arm, and the sample size the
#: interval is computed on is ``2 * trials``, not ``trials``.
AIRLOCK_MODES = 2


def wilson_upper_bound_for_zero(n: int, z: float = Z_95) -> float:
    """Upper end of the Wilson score interval for 0 events in ``n`` trials.

    Args:
        n: Number of measured trials. Must be positive.
        z: Normal quantile; defaults to two-sided 95%.

    Returns:
        The upper bound as a proportion in ``[0, 1]``.

    Raises:
        ValueError: If ``n`` is not positive. A bound on zero observations is not a number.
    """
    if n <= 0:
        raise ValueError(f"n must be positive, got {n!r}")
    return z**2 / (n + z**2)


def rule_of_three_upper_bound(n: int) -> float:
    """The ``3/n`` approximation, capped at 1.0.

    Reported next to the Wilson bound because it is the figure most readers know. It is
    *optimistic* at small n — at n = 6 it claims 50% where Wilson says 39%, and the two
    converge as n grows.
    """
    if n <= 0:
        raise ValueError(f"n must be positive, got {n!r}")
    return min(1.0, 3.0 / n)


def trials_for_upper_bound(target: float, z: float = Z_95) -> int:
    """Smallest ``n`` whose zero-event Wilson upper bound is at or below ``target``.

    Inverts :func:`wilson_upper_bound_for_zero`: ``z^2/(n + z^2) <= target`` gives
    ``n >= z^2 (1 - target) / target``.

    Args:
        target: Desired upper bound as a proportion — ``0.10`` for the 10% figure the
            benchmark doc names.
        z: Normal quantile; defaults to two-sided 95%.

    Returns:
        The required number of measured trials (``n``, not ``--trials``; divide by
        :data:`AIRLOCK_MODES` for the CLI value).

    Raises:
        ValueError: If ``target`` is not in ``(0, 1]``.
    """
    if not 0 < target <= 1:
        raise ValueError(f"target must be in (0, 1], got {target!r}")
    exact = z**2 * (1 - target) / target
    n = math.ceil(exact)
    # Guard the boundary: ceil of an exactly-representable solution can still land a hair
    # above the target after floating-point division, and a table that overstates its own
    # power is the one error this module exists to prevent.
    while wilson_upper_bound_for_zero(n, z) > target:
        n += 1
    return n


def probability_of_observing_zero(true_rate: float, n: int) -> float:
    """``(1 - p)^n`` — the chance this benchmark sees another zero when the rate is not zero.

    This is the number that says whether a null is informative. At n = 6, a true 5% action
    rate still produces a zero about 74% of the time, so the observed zero is barely evidence
    against it. The bound answers "how high could it be"; this answers "would I have noticed".
    """
    if not 0 <= true_rate <= 1:
        raise ValueError(f"true_rate must be in [0, 1], got {true_rate!r}")
    if n < 0:
        raise ValueError(f"n must be non-negative, got {n!r}")
    return (1 - true_rate) ** n


@dataclass(frozen=True)
class PowerRow:
    """One ``--trials`` setting and what a zero at that setting would license."""

    trials: int
    n_per_cell: int
    """Measurements per harness per arm — ``trials * AIRLOCK_MODES``."""
    wilson_upper: float
    rule_of_three_upper: float
    total_cells: int
    miss_rate_at_5pct: float
    """Chance of seeing zero anyway if the true action rate were 5%."""

    def as_percent(self) -> tuple[str, str, str]:
        """``(wilson, rule-of-three, miss-rate)`` formatted as the doc prints them."""
        return (
            f"{self.wilson_upper * 100:.1f}%",
            f"{self.rule_of_three_upper * 100:.1f}%",
            f"{self.miss_rate_at_5pct * 100:.0f}%",
        )


def power_table(
    trials: list[int],
    *,
    harnesses: int = 2,
    arms: int = 2,
) -> list[PowerRow]:
    """Build the rows the benchmark doc publishes.

    Args:
        trials: The ``--trials`` values to describe.
        harnesses: Harnesses in the matrix (2 as published: ``claude-code``, ``codex``).
        arms: Fixture arms (2: injected and benign control).

    Returns:
        One :class:`PowerRow` per requested trial count.
    """
    rows = []
    for count in trials:
        n = count * AIRLOCK_MODES
        rows.append(
            PowerRow(
                trials=count,
                n_per_cell=n,
                wilson_upper=wilson_upper_bound_for_zero(n),
                rule_of_three_upper=rule_of_three_upper_bound(n),
                total_cells=harnesses * arms * AIRLOCK_MODES * count,
                miss_rate_at_5pct=probability_of_observing_zero(0.05, n),
            )
        )
    return rows


def describe(trials: int, *, harnesses: int = 2, arms: int = 2) -> str:
    """One-paragraph summary of what a run at ``trials`` would be able to conclude.

    Printed by the CLI's dry run so the operator sees the power *before* committing API
    budget, which is the decision this whole module exists to inform.
    """
    row = power_table([trials], harnesses=harnesses, arms=arms)[0]
    wilson, rule_of_three, miss = row.as_percent()
    needed = trials_for_upper_bound(0.10)
    return (
        f"Power at --trials {row.trials}: n = {row.n_per_cell} per harness per arm "
        f"({row.total_cells} cells total).\n"
        f"  A zero would bound the true action rate at {wilson} (95% Wilson; "
        f"rule of three says {rule_of_three}).\n"
        f"  If the true rate were 5%, this run would still see zero {miss} of the time.\n"
        f"  For a 10% upper bound you need n = {needed}, i.e. "
        f"--trials {math.ceil(needed / AIRLOCK_MODES)}."
    )
