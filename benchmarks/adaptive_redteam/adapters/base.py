"""The adapter contract every guard target plugs into.

An adapter knows three things about one guard: its ``name``, its ``mode`` (A =
``@Airlock`` policy field, B = config gate, C = standalone guard), and how to turn
a :class:`~benchmarks.adaptive_redteam.oracle.Candidate` into a
:class:`~benchmarks.adaptive_redteam.oracle.Canary` the oracle can classify.

``intent()`` names the forbidden effect the guard exists to prevent.
``build_canary()`` and ``run()`` do the work; ``known_blocked()`` and
``benign()`` return the two control candidates the wiring test drives (a shape the
guard's own tests prove is refused, and a benign shape it must admit).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

from ..oracle import Canary, Candidate, ForbiddenEffect


@runtime_checkable
class GuardAdapter(Protocol):
    """One guard target, uniform across modes A/B/C."""

    name: str
    mode: str  # "A" | "B" | "C"

    def intent(self) -> ForbiddenEffect:
        """The forbidden effect this guard exists to prevent."""
        ...

    def build_canary(self) -> Any:
        """Create the sentinel sink(s) for one run (a context manager)."""
        ...

    def run(self, candidate: Candidate) -> Canary:
        """Drive the candidate through the guard and observe a :class:`Canary`."""

    def known_blocked(self, seed: int) -> Candidate:
        """A candidate the guard's own tests prove is refused (expect hard_block)."""

    def benign(self, seed: int) -> Candidate:
        """A benign control the guard must admit (expect benign_pass)."""


def normalized_denial(
    *,
    denied: bool,
    verdict: str | None = None,
    fix_hints: list[str] | None = None,
    block_reason: str | None = None,
    honeypot: bool = False,
    detail: str | None = None,
) -> dict[str, Any]:
    """A uniform ``response`` mapping the oracle reads the same way every time."""
    return {
        "denied": denied,
        "verdict": verdict,
        "block_reason": block_reason or verdict,
        "fix_hints": list(fix_hints or []),
        "honeypot": honeypot,
        "detail": detail,
    }


def extract_fix_hints(response: Any) -> list[str]:
    """Best-effort fix_hints from a guard decision or airlock response."""
    hints = getattr(response, "fix_hints", None)
    if hints is None and isinstance(response, Mapping):
        hints = response.get("fix_hints")
    if not hints:
        return []
    return [str(h) for h in hints]
