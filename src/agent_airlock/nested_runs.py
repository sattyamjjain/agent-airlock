"""Nested-run budget: how deep a run tree may nest, and how many turns it may take (V0.10.29).

An agent that runs another agent as a tool starts a new run, and each run counts its own
turns, so a parent run with ``max_turns=2`` can still let each nested agent take its
framework's default of 10 (openai/openai-agents-python#5453). ``run_budget()`` sets the
tree's budget at its root. Every ``nested_run()`` below takes one level of depth and draws
its turns from what its parent has left: a share it names (``max_turns``) is reserved and
what it did not spend goes back when it ends, and with none it spends from its parent's as
it goes. Neither nesting nor sibling runs can spend more than the root allowed.

Running out does not end the whole run. ``nested_run()`` and ``spend_turn()`` raise
:class:`RunBudgetExhausted`, and ``@Airlock`` hands it to the agent that called the tool as
a failed tool result (``run_budget_exhausted``), so that agent can finish with what it has:
the calls before it have already run. Only a root that set ``hard_stop=True`` gets the
exception raised out of the run.

The budget rides a ContextVar: a task or an ``asyncio.to_thread`` call started inside a
scope inherits it, a bare ``threading.Thread`` does not (run its target through
``contextvars.copy_context().run``).
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Literal

from ._log import structlog
from .exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.nested_runs")

__all__ = [
    "NestedRun",
    "RunBudgetExhausted",
    "current_run_budget",
    "nested_run",
    "run_budget",
    "spend_turn",
]

BudgetKind = Literal["depth", "turns"]


class RunBudgetExhausted(AirlockError):
    """The run tree's depth or turn budget is spent.

    Attributes:
        kind: ``"depth"`` (no level of nested run is left) or ``"turns"`` (no turn is left).
        hard_stop: Whether the root asked for the exception to end the run, rather than
            reach the agent that called the tool as a failed tool result.
    """

    def __init__(self, message: str, *, kind: BudgetKind, hard_stop: bool) -> None:
        self.kind = kind
        self.hard_stop = hard_stop
        super().__init__(message)


class _Turns:
    """The turns left to a run and the runs below it, taken and given back under a lock."""

    def __init__(self, left: int) -> None:
        self._left = left
        self._lock = threading.Lock()

    @property
    def left(self) -> int:
        with self._lock:
            return self._left

    def take(self, wanted: int | None) -> int:
        """Reserve up to ``wanted`` turns, all that are left when None; return how many."""
        with self._lock:
            got = self._left if wanted is None else min(wanted, self._left)
            self._left -= got
            return got

    def spend(self, turns: int) -> bool:
        """Spend ``turns`` when that many are left; spend none otherwise."""
        with self._lock:
            if turns > self._left:
                return False
            self._left -= turns
            return True

    def give_back(self, turns: int) -> None:
        with self._lock:
            self._left += turns


@dataclass(frozen=True)
class _Node:
    """One run's budget: the levels of nesting left below it, its turns, the root's choice."""

    depth_left: int | None
    turns: _Turns | None
    hard_stop: bool
    level: int


_current: ContextVar[_Node | None] = ContextVar("airlock_run_budget", default=None)


class NestedRun:
    """The budget the current run may still use, read live."""

    __slots__ = ("_node",)

    def __init__(self, node: _Node) -> None:
        self._node = node

    @property
    def depth_left(self) -> int | None:
        """How many more levels of nested run may start below this one; None for no limit."""
        return self._node.depth_left

    @property
    def turns_left(self) -> int | None:
        """The turns this run and the runs below it may still take; None for no limit.

        Pass it as the framework's own ``max_turns`` for the run.
        """
        return None if self._node.turns is None else self._node.turns.left

    @property
    def hard_stop(self) -> bool:
        """Whether running out raises out of the run rather than failing one tool call."""
        return self._node.hard_stop

    def spend_turns(self, turns: int = 1) -> None:
        """Count ``turns`` against this run's budget; see :func:`spend_turn`."""
        _spend(self._node, turns)


def _limit(name: str, value: int | None) -> int | None:
    """``value`` when it is a whole number of 0 or more, or None.

    Raises:
        ValueError: It is anything else; a bool is refused, not read as 0 or 1.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a whole number of 0 or more, or None; got {value!r}")
    return value


def _tighter(inherited: int | None, own: int | None) -> int | None:
    """The lower of two limits, None meaning no limit."""
    if inherited is None:
        return own
    return inherited if own is None else min(inherited, own)


def _exhausted(node: _Node, kind: BudgetKind) -> RunBudgetExhausted:
    what = (
        "no level of nested run is left in the run's depth budget"
        if kind == "depth"
        else "no turn is left in the run's turn budget"
    )
    logger.warning("run_budget_exhausted", kind=kind, level=node.level, hard_stop=node.hard_stop)
    return RunBudgetExhausted(what, kind=kind, hard_stop=node.hard_stop)


def _child(parent: _Node, max_depth: int | None, max_turns: int | None, *, step: int) -> _Node:
    """The budget of a run started under ``parent``: ``step`` levels down, its own limits
    no looser than what ``parent`` has left, its turns reserved from ``parent``'s."""
    depth = parent.depth_left
    if depth is not None and step:
        if depth == 0:
            raise _exhausted(parent, "depth")
        depth -= step
    turns: _Turns | None = None
    if parent.turns is None:
        turns = None if max_turns is None else _Turns(max_turns)
    elif max_turns is None:
        # No share of its own: it spends from its parent's turns as it goes, so concurrent
        # siblings draw on the same turns and none is starved by another's reservation.
        if parent.turns.left == 0:
            raise _exhausted(parent, "turns")
        turns = parent.turns
    else:
        reserved = parent.turns.take(max_turns)
        if reserved == 0:
            raise _exhausted(parent, "turns")
        turns = _Turns(reserved)
    return _Node(_tighter(depth, max_depth), turns, parent.hard_stop, parent.level + step)


@contextmanager
def _installed(node: _Node, pool: _Turns | None) -> Iterator[NestedRun]:
    """Make ``node`` the current budget. On the way out the turns it reserved and did not
    spend go back to ``pool``, its parent's, and none stay behind for a task that outlives
    the scope; a node spending from ``pool`` itself has none to give back."""
    token = _current.set(node)
    try:
        yield NestedRun(node)
    finally:
        _current.reset(token)
        if pool is not None and node.turns is not None and node.turns is not pool:
            pool.give_back(node.turns.take(None))


@contextmanager
def run_budget(
    *, max_depth: int | None = None, max_turns: int | None = None, hard_stop: bool = False
) -> Iterator[NestedRun]:
    """Set the budget of the run tree started here.

    Inside another budget it can only tighten what is left of that one.

    Args:
        max_depth: How many levels of nested run may start below this run: 1 lets its agent
            run agents as tools but not those agents run more. None for no limit.
        max_turns: The turns the whole tree may take, this run's own included. A nested
            run that names its own ``max_turns`` reserves that share of what is left and
            gives back what it does not spend; one that names none spends from what is
            left as it goes. None for no limit.
        hard_stop: Raise :class:`RunBudgetExhausted` out of the run when the budget runs
            out, rather than hand it to the agent that asked for more as a failed tool
            result. Only the root may set it.

    Raises:
        ValueError: A limit is not a whole number of 0 or more, or ``hard_stop`` is set
            inside another budget.
    """
    depth, turns = _limit("max_depth", max_depth), _limit("max_turns", max_turns)
    parent = _current.get()
    if parent is None:
        root = _Node(depth, None if turns is None else _Turns(turns), bool(hard_stop), 0)
        with _installed(root, None) as handle:
            yield handle
        return
    if hard_stop:
        raise ValueError("hard_stop is the root's to set, and this run is inside a budget")
    with _installed(_child(parent, depth, turns, step=0), parent.turns) as handle:
        yield handle


@contextmanager
def nested_run(
    *, max_depth: int | None = None, max_turns: int | None = None
) -> Iterator[NestedRun]:
    """Start a nested run: one level of the depth budget, and turns reserved from its
    parent's. Its own limits can only tighten the inherited ones; with no budget set, its
    own limits are the whole budget of the runs below it.

    Raises:
        RunBudgetExhausted: No level of depth or no turn is left, raised before the run
            starts.
        ValueError: A limit is not a whole number of 0 or more.
    """
    depth, turns = _limit("max_depth", max_depth), _limit("max_turns", max_turns)
    parent = _current.get() or _Node(None, None, False, 0)
    with _installed(_child(parent, depth, turns, step=1), parent.turns) as handle:
        yield handle


def _spend(node: _Node, turns: int) -> None:
    if isinstance(turns, bool) or not isinstance(turns, int) or turns < 1:
        raise ValueError(f"turns must be a whole number of 1 or more; got {turns!r}")
    if node.turns is not None and not node.turns.spend(turns):
        raise _exhausted(node, "turns")


def spend_turn(turns: int = 1) -> None:
    """Count ``turns`` against the current run's budget; nothing to count with none set.

    Raises:
        RunBudgetExhausted: Fewer turns are left than ``turns``; none are spent then.
        ValueError: ``turns`` is not a whole number of 1 or more.
    """
    node = _current.get()
    _spend(node if node is not None else _Node(None, None, False, 0), turns)


def current_run_budget() -> NestedRun | None:
    """The budget of the run this code runs in, or None when no budget is set."""
    node = _current.get()
    return None if node is None else NestedRun(node)
