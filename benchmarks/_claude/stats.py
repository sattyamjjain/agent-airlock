"""Interval and test helpers for the credit-funded benchmarks.

``wilson_interval`` is re-exported from :mod:`benchmarks.harness_injection.power`, which
the published intervals already use (do not change its ``Z_95``). The rest:

* :func:`newcombe_diff_ci` - 95% interval for a difference of two proportions (Newcombe's
  method 10, built from Wilson intervals), used for "influenced minus noise";
* :func:`mcnemar_exact_p` - exact two-sided McNemar test for paired outcomes (arm H vs
  arm N on the same scenarios);
* :func:`cluster_bootstrap_ci` - percentile bootstrap that resamples whole clusters
  (MCPTox cases cluster by server, so a Wilson interval alone understates uncertainty).
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

from benchmarks.harness_injection.power import Z_95, wilson_interval

T = TypeVar("T")

__all__ = [
    "Z_95",
    "cluster_bootstrap_ci",
    "format_rate",
    "mcnemar_exact_p",
    "newcombe_diff_ci",
    "wilson_interval",
]


def newcombe_diff_ci(k1: int, n1: int, k2: int, n2: int, z: float = Z_95) -> tuple[float, float]:
    """95% interval for ``k1/n1 - k2/n2`` (Newcombe 1998, method 10).

    Raises:
        ValueError: Either ``n`` is not positive.
    """
    p1, p2 = k1 / n1, k2 / n2
    l1, u1 = wilson_interval(k1, n1, z)
    l2, u2 = wilson_interval(k2, n2, z)
    diff = p1 - p2
    lower = diff - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    upper = diff + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return max(-1.0, lower), min(1.0, upper)


def mcnemar_exact_p(b: int, c: int) -> float:
    """Exact two-sided McNemar p-value from the discordant counts ``b`` and ``c``."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail: float = sum(math.comb(n, i) for i in range(k + 1)) / float(2**n)
    return min(1.0, 2.0 * tail)


def cluster_bootstrap_ci(
    clusters: Mapping[str, Sequence[T]],
    stat: Callable[[list[T]], float],
    *,
    iterations: int = 2000,
    seed: int = 20261012,
    alpha: float = 0.05,
) -> tuple[float, float]:
    """Percentile bootstrap interval for ``stat`` resampling whole clusters with replacement.

    Args:
        clusters: ``cluster id -> rows`` (e.g. MCPTox server -> per-response outcomes).
        stat: Maps a flat list of rows to the statistic (e.g. a refusal rate).
        iterations: Bootstrap resamples.
        seed: RNG seed, recorded with the published interval.
        alpha: Two-sided miss rate.
    """
    keys = sorted(clusters)
    if not keys:
        raise ValueError("no clusters")
    rng = random.Random(seed)
    values = []
    for _ in range(iterations):
        rows: list[T] = []
        for _ in range(len(keys)):
            rows.extend(clusters[rng.choice(keys)])
        if rows:
            values.append(stat(rows))
    values.sort()
    lo = values[int((alpha / 2) * (len(values) - 1))]
    hi = values[int((1 - alpha / 2) * (len(values) - 1))]
    return lo, hi


def format_rate(k: int, n: int) -> str:
    """``k/n (p%, 95% CI lo-hi%)``, or ``n=0 (not measured)``."""
    if n == 0:
        return "n=0 (not measured)"
    lo, hi = wilson_interval(k, n)
    return f"{k}/{n} ({100 * k / n:.1f}%, 95% CI {100 * lo:.1f}-{100 * hi:.1f}%)"
