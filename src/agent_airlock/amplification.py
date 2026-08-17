"""Per-run resource-amplification budget (v0.8.74, issue #142).

What this closes
----------------
Convergent Detour Hijacking (`arXiv:2608.12273 <https://arxiv.org/abs/2608.12273>`_,
2026-08-12) is an attack whose payload **is** the resource cost. A malicious skill
description wins tool selection, fabricates plausible dependencies, recruits benign skills
into a bounded detour, then re-enters the original route so the task still completes. On
DeepSeek-V4-Pro: token consumption +66.91%, execution time +92.45%, task completion
comparable.

Before v0.8.74 agent-airlock recorded every recruited call — six where two were needed —
but nothing in the layer said they were *extra*. That is the distance between visibility
and detection. ``tests/test_detour_hijacking.py`` pinned the gap down; this module closes
it, and that test now asserts the closure rather than the gap.

The unit is calls, and the field names say so
---------------------------------------------
The paper measures tokens and wall time. agent-airlock does not observe either
universally: ``duration_ms`` is tool execution time (it excludes model latency, which is
where a detour spends most of what it wastes), and token counts only exist when the caller
supplies ``_airlock_input_tokens``. Inventing a cost model to fill the gap would be worse
than naming the limit.

So the primary unit is the **call count per run** — the signal the layer genuinely has,
and the one that already separates the two trajectories two-to-six. Tokens ride along as
``run_input_tokens`` **only** when the caller supplies them, and are never estimated.

Deny-by-default
---------------
The guard is opt-in: ``SecurityPolicy.amplification_budget`` defaults to ``None`` and a
policy without one behaves exactly as v0.8.73 did. But **opting in without declaring a
budget fails closed**. An operator who wires up amplification checking and leaves every
threshold unset has expressed an intent the configuration cannot satisfy, and silently
never firing would reproduce issue #142 in a new location — a field nobody reads. That
case raises :attr:`AmplificationVerdict.UNCONFIGURED` and blocks.

Primary source
--------------
https://arxiv.org/abs/2608.12273
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass
from typing import Literal

from ._log import structlog

logger = structlog.get_logger("agent-airlock.amplification")

__all__ = [
    "AmplificationBudget",
    "AmplificationDecision",
    "AmplificationGuard",
    "AmplificationVerdict",
    "RunLedger",
]


class AmplificationVerdict(str, enum.Enum):
    """Stable verdict labels for one amplification check."""

    OK = "ok"
    OVER_BUDGET = "over_budget"
    #: The guard was enabled with no threshold set. Blocks — see module docstring.
    UNCONFIGURED = "unconfigured"


@dataclass(frozen=True)
class AmplificationBudget:
    """What the policy declares "normal" for one run.

    At least one of :attr:`max_calls_per_run` or :attr:`max_amplification_ratio` must be
    set, otherwise every check returns :attr:`AmplificationVerdict.UNCONFIGURED` and
    blocks.

    Attributes:
        baseline_calls_per_run: The declared normal call count for a run. Required to
            compute a ratio; on its own it records the comparison without enforcing it.
        max_calls_per_run: Absolute ceiling on calls in one run.
        max_amplification_ratio: Ceiling on ``observed / baseline``. ``1.5`` blocks a run
            that makes 50% more calls than declared. Needs ``baseline_calls_per_run``.
        action: ``"block"`` refuses the call; ``"warn"`` records the verdict and lets it
            through, for operators establishing a baseline before enforcing one.
    """

    baseline_calls_per_run: int | None = None
    max_calls_per_run: int | None = None
    max_amplification_ratio: float | None = None
    action: Literal["block", "warn"] = "block"

    def is_configured(self) -> bool:
        """True when at least one enforceable threshold is set."""
        if self.max_calls_per_run is not None:
            return True
        return self.max_amplification_ratio is not None and self.baseline_calls_per_run is not None


@dataclass
class RunLedger:
    """Accumulated, per-run counters. One per session key."""

    call_count: int = 0
    input_tokens: int = 0

    def record(self, input_tokens: int | None) -> None:
        self.call_count += 1
        if input_tokens:
            self.input_tokens += int(input_tokens)


@dataclass(frozen=True)
class AmplificationDecision:
    """The outcome of one check, and the numbers that produced it.

    Every field here is written onto the :class:`~agent_airlock.audit.AuditRecord`, so an
    operator reading the log sees the comparison, not just the conclusion.

    Attributes:
        verdict: Stable :class:`AmplificationVerdict` value.
        run_call_count: Calls recorded for this run **including** the current one.
        run_input_tokens: Accumulated caller-supplied input tokens, ``None`` when the
            caller never supplied any. Never estimated.
        baseline_calls: The policy's declared baseline, echoed for readability.
        amplification_ratio: ``run_call_count / baseline_calls``, ``None`` without a
            baseline.
        reason: Human-readable explanation, empty when :attr:`AmplificationVerdict.OK`.
    """

    verdict: AmplificationVerdict
    run_call_count: int
    run_input_tokens: int | None = None
    baseline_calls: int | None = None
    amplification_ratio: float | None = None
    reason: str = ""

    @property
    def is_over(self) -> bool:
        """True when this decision should stop the call under a ``block`` action."""
        return self.verdict is not AmplificationVerdict.OK


class AmplificationGuard:
    """Counts calls per run and compares them against the policy's declared budget.

    Thread-safe. Ledgers are keyed by session, so a harness that supplies no context gets
    one shared anonymous ledger — which is honest about the limitation rather than
    silently counting unrelated runs as one. See ``session_key=None`` handling in
    :meth:`record_and_check`.
    """

    def __init__(self, budget: AmplificationBudget) -> None:
        self.budget = budget
        self._ledgers: dict[str, RunLedger] = {}
        self._lock = threading.Lock()

    #: Ledger key used when the harness supplied no run identity.
    ANONYMOUS_KEY = "__anonymous__"

    def ledger_for(self, session_key: str | None) -> RunLedger:
        """Return (creating if needed) the ledger for one run."""
        key = session_key or self.ANONYMOUS_KEY
        with self._lock:
            return self._ledgers.setdefault(key, RunLedger())

    def reset(self, session_key: str | None = None) -> None:
        """Drop one run's counters, or all of them when ``session_key`` is ``None``."""
        with self._lock:
            if session_key is None:
                self._ledgers.clear()
            else:
                self._ledgers.pop(session_key, None)

    def record_and_check(
        self,
        *,
        session_key: str | None,
        tool_name: str,
        input_tokens: int | None = None,
    ) -> AmplificationDecision:
        """Record one call against the run and judge the run so far.

        Args:
            session_key: Run identity. ``None`` falls back to a shared anonymous ledger.
            tool_name: Name of the tool being called, for logging.
            input_tokens: Caller-supplied token count for this call, when known.

        Returns:
            An :class:`AmplificationDecision`. The caller decides whether to act on it
            based on :attr:`AmplificationBudget.action`.
        """
        ledger = self.ledger_for(session_key)
        with self._lock:
            ledger.record(input_tokens)
            count = ledger.call_count
            tokens = ledger.input_tokens or None

        budget = self.budget
        baseline = budget.baseline_calls_per_run
        ratio = round(count / baseline, 4) if baseline else None

        def _decide(verdict: AmplificationVerdict, reason: str) -> AmplificationDecision:
            return AmplificationDecision(
                verdict=verdict,
                run_call_count=count,
                run_input_tokens=tokens,
                baseline_calls=baseline,
                amplification_ratio=ratio,
                reason=reason,
            )

        if not budget.is_configured():
            logger.warning("amplification_unconfigured", tool=tool_name, run_call_count=count)
            return _decide(
                AmplificationVerdict.UNCONFIGURED,
                "amplification checking is enabled but no threshold is set "
                "(set max_calls_per_run, or max_amplification_ratio with "
                "baseline_calls_per_run); blocked deny-by-default",
            )

        if budget.max_calls_per_run is not None and count > budget.max_calls_per_run:
            return _decide(
                AmplificationVerdict.OVER_BUDGET,
                f"run made {count} calls, over the declared ceiling of {budget.max_calls_per_run}",
            )

        if (
            budget.max_amplification_ratio is not None
            and ratio is not None
            and ratio > budget.max_amplification_ratio
        ):
            return _decide(
                AmplificationVerdict.OVER_BUDGET,
                f"run made {count} calls against a declared baseline of {baseline} "
                f"(amplification {ratio}x, over {budget.max_amplification_ratio}x)",
            )

        return _decide(AmplificationVerdict.OK, "")


def detour_hijacking_defaults(
    *,
    baseline_calls_per_run: int,
    tolerance: float = 1.5,
) -> AmplificationBudget:
    """Preset factory for the CDH shape (arXiv:2608.12273).

    Args:
        baseline_calls_per_run: The declared normal call count for one run. There is no
            default: the paper's premise is that a skill-based agent's legitimate route is
            discovered at runtime, so only the operator can say what normal is for their
            task. Guessing here would be the invented cost model this module refuses.
        tolerance: Allowed amplification over the baseline. Defaults to ``1.5``, below the
            paper's reported +66.91% token rise, so a run of that shape trips it.

    Returns:
        A configured :class:`AmplificationBudget` with ``action="block"``.
    """
    return AmplificationBudget(
        baseline_calls_per_run=baseline_calls_per_run,
        max_amplification_ratio=tolerance,
        action="block",
    )
