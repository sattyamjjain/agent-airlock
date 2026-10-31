"""Halt a run after a hard stop, and catch a run that repeats itself (V0.10.29).

``@Airlock`` judges one call at a time, so what it bounds by itself is that call: its
arguments, its tool's rate limit, its cost. A run is many calls, and two failures only show
across them. After a hard stop (a frozen fleet, an approval nobody could read, a refused
irreversible action) the model keeps issuing calls; and a model stuck in a loop repeats the
same calls, each of which passes on its own. A ``RunGuard`` keeps a latch and a short
history on the run's ``AirlockContext``, the one ``_share_run_state`` shares between a run's
calls, so both are visible.

- A refusal whose block reason is in ``halt_on`` (``kill_switch`` and
  ``policy_indeterminate`` by default), or any refusal of a tool matching
  ``irreversible_tools``, halts the run: every later call in it is refused as
  ``run_halted``, whatever its own policy, until the host starts a new run
  (openai/openai-agents-python#5351).
- The same ``(tool, arguments digest)`` calls repeated ``loop_repeats`` times in a row, as a
  block of 1 to ``max_loop_period`` calls, refuse the call that completes the repeat with a
  nudge in its fix hints; the next repeat halts the run. A failure-count circuit breaker
  after dispatch cannot see this: each call in the loop succeeds
  (prime-radiant-inc/evener#94).
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass

from .self_heal import BlockReason

__all__ = ["DEFAULT_HALT_ON", "RunGuard", "RunState"]

#: The block reasons that halt a run by default: a fleet freeze, and an answer nobody could
#: read as consent or refusal.
DEFAULT_HALT_ON: frozenset[str] = frozenset(
    {BlockReason.KILL_SWITCH.value, BlockReason.POLICY_INDETERMINATE.value}
)

_KNOWN_REASONS = frozenset(reason.value for reason in BlockReason)


@dataclass(frozen=True)
class RunGuard:
    """What halts a run, and what counts as a loop.

    Attributes:
        halt_on: Block reasons (:class:`BlockReason` members or their values) whose refusal
            halts the run.
        irreversible_tools: Tool-name globs: any refusal of a matching call halts the run.
        detect_loops: Refuse, then halt on, calls that repeat as described below.
        loop_repeats: How many times in a row a block of calls must repeat to count as a
            loop (at least 2).
        max_loop_period: The longest block of calls looked for (1 to 10).
    """

    halt_on: frozenset[str] = DEFAULT_HALT_ON
    irreversible_tools: tuple[str, ...] = ()
    detect_loops: bool = True
    loop_repeats: int = 5
    max_loop_period: int = 5

    def __post_init__(self) -> None:
        """Refuse a setting the guard cannot apply.

        Raises:
            ValueError: An unknown block reason, a loop length out of range, or a tool glob
                that is not a non-empty string.
        """
        halt_on = frozenset(str(getattr(reason, "value", reason)) for reason in self.halt_on)
        unknown = sorted(halt_on - _KNOWN_REASONS)
        if unknown:
            raise ValueError(f"RunGuard.halt_on names unknown block reasons: {unknown}")
        object.__setattr__(self, "halt_on", halt_on)
        globs = tuple(self.irreversible_tools)
        if not all(isinstance(glob, str) and glob for glob in globs):
            raise ValueError("RunGuard.irreversible_tools must be non-empty tool-name globs")
        object.__setattr__(self, "irreversible_tools", globs)
        if not _int_in(self.loop_repeats, 2, 100):
            raise ValueError(f"RunGuard.loop_repeats must be 2 to 100, got {self.loop_repeats!r}")
        if not _int_in(self.max_loop_period, 1, 10):
            raise ValueError(
                f"RunGuard.max_loop_period must be 1 to 10, got {self.max_loop_period!r}"
            )

    def canonical(self) -> dict[str, object]:
        """The fields a policy digest covers."""
        return {
            "halt_on": sorted(self.halt_on),
            "irreversible_tools": list(self.irreversible_tools),
            "detect_loops": self.detect_loops,
            "loop_repeats": self.loop_repeats,
            "max_loop_period": self.max_loop_period,
        }


def _int_in(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _period(history: list[tuple[str, str]], repeats: int, max_period: int) -> int | None:
    """The shortest block length whose ``repeats`` copies end ``history``, if any."""
    for period in range(1, max_period + 1):
        span = period * repeats
        if len(history) < span:
            break
        tail = history[-span:]
        block = tail[-period:]
        if all(tail[i] == block[i % period] for i in range(span)):
            return period
    return None


class RunState:
    """One run's halt latch and recent calls, shared by every call of the run."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._halted: str | None = None
        self._history: deque[tuple[str, str]] = deque(maxlen=1000)
        self._trips = 0

    @property
    def halted(self) -> bool:
        with self._lock:
            return self._halted is not None

    @property
    def halt_reason(self) -> str | None:
        """Why the run was halted (the first reason wins), or None."""
        with self._lock:
            return self._halted

    def halt(self, reason: str) -> None:
        """Halt the run. A run already halted keeps its first reason."""
        with self._lock:
            if self._halted is None:
                self._halted = reason

    def record(self, key: tuple[str, str], guard: RunGuard) -> tuple[int, int] | None:
        """Add a call to the history; on a loop, return ``(its period, this run's trips)``."""
        with self._lock:
            self._history.append(key)
            window = list(self._history)[-guard.loop_repeats * guard.max_loop_period :]
            period = _period(window, guard.loop_repeats, guard.max_loop_period)
            if period is None:
                return None
            self._trips += 1
            return period, self._trips

    def recent(self) -> Iterable[tuple[str, str]]:
        """The run's calls as ``(tool, arguments digest)``, oldest first (a copy)."""
        with self._lock:
            return list(self._history)
