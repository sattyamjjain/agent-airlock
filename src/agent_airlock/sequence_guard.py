"""Behavioral tool-call SEQUENCE anomaly guard (v0.8.12+).

Watches the ordered stream of tool calls within an agent session and flags
divergence from a declared expected ORDER. The guard is intentionally
behavior-only: it never reads the model's reasoning trace.

Why behavior-only
-----------------
Onyame, Zhou, Thopalli, Kailkhura & Agarwal — *The Fragility of
Chain-of-Thought Monitoring Across Typologically Diverse Languages*
(arXiv:2605.27901, May 2026) — report an average **95.9% chain-of-thought
unfaithfulness across 8B–120B-parameter models**, including answer-switching,
post-hoc rationalisation, and procedural exploitation of hints. Trusting the
model's stated *reasoning* to detect misbehavior is therefore not viable.
Trusting the model's *behavior* — the sequence of tools it actually invokes,
in the order it actually invokes them — is.

What this module is
-------------------
A per-session, in-process transition observer with two complementary modes:

- **DECLARED mode** — the operator supplies a permitted-transition DAG
  ``{from_tool: {allowed_next_tools}}`` (plus an entry-tool set keyed by the
  sentinel ``"__entry__"``). Any transition not in the DAG is a
  :class:`SequenceViolation`. This is the deny-by-default deployment
  posture and the easier mode to reason about.
- **BASELINE mode** — the guard maintains a per-session-key Markov transition
  profile in a local JSON file (no cloud, no PII — see below). On each call
  it computes ``P(curr | prev) = count(prev→curr) / Σ count(prev→*)`` for
  the observed transition and, once the sample has at least
  ``min_baseline_samples`` outbound observations from ``prev``, flags
  transitions with ``P < low_probability_threshold``.

What this module is NOT
-----------------------
Not :class:`agent_airlock.anomaly.AnomalyDetector` — which monitors call
**rate**, endpoint **diversity**, **error rate**, and **consecutive blocked**
counts over sliding windows. Those are aggregate per-window signals; this
module is a per-transition ORDER signal. The two are complementary: an
attacker who keeps the rate flat but reorders calls slips past
``AnomalyDetector``; an attacker who hammers a single permitted transition
slips past ``SequenceGuard``. Run both for layered coverage.

Not a chain-of-thought monitor. By construction.

Persisted-state privacy contract
--------------------------------
Only ``tool_name`` strings and SHA-256 *shape* hashes appear in the
baseline JSON. The shape hash is computed from positional-arg **types** and
keyword-arg **names** + **types** — never argument **values**. PII, secrets,
and otherwise sensitive payloads cannot end up on disk via this module.

Failure model
-------------
Deny-by-default. ``action="block"`` (the default) raises
:class:`SequenceViolation` on a flagged transition. ``action="warn"`` logs
via ``structlog``, emits an OTel attribute, and lets the call proceed —
useful for staging the enforcement turn-up against real traffic.

Reference
---------
- Onyame, E., Zhou, R., Thopalli, K., Kailkhura, B., & Agarwal, C.
  *The Fragility of Chain-of-Thought Monitoring Across Typologically
  Diverse Languages.* arXiv:2605.27901 (2026).
  https://arxiv.org/abs/2605.27901
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import structlog

from .policy import PolicyViolation, ViolationType

logger = structlog.get_logger("agent-airlock.sequence_guard")


SequenceGuardMode = Literal["declared", "baseline"]
SequenceGuardAction = Literal["block", "warn"]
SessionKeyKind = Literal["agent_id", "session_id"]

ENTRY_SENTINEL = "__entry__"
"""DAG key that lists tool names permitted as the first call in a session."""

PREV_NONE_SENTINEL = "__none__"
"""Baseline-JSON key used for the synthetic ``prev`` of a session's first
call. Without it, the first-call distribution cannot be learned.
"""


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SequenceViolation(PolicyViolation):
    """Raised when a tool-call transition is rejected by the SequenceGuard.

    Subclasses :class:`PolicyViolation` so the existing ``@Airlock`` error
    handler (which already routes ``PolicyViolation`` through
    ``handle_policy_violation``) picks it up unchanged.
    """

    def __init__(
        self,
        message: str,
        *,
        mode: SequenceGuardMode,
        from_tool: str | None,
        to_tool: str,
        session_key: str,
        observed_probability: float | None = None,
    ) -> None:
        super().__init__(
            message=message,
            violation_type=ViolationType.TOOL_DENIED,
            details={
                "guard": "sequence_guard",
                "mode": mode,
                "from_tool": from_tool,
                "to_tool": to_tool,
                "session_key": session_key,
                "observed_probability": observed_probability,
            },
        )
        self.mode = mode
        self.from_tool = from_tool
        self.to_tool = to_tool
        self.session_key = session_key
        self.observed_probability = observed_probability


# ---------------------------------------------------------------------------
# Argument-shape hashing (no values on disk)
# ---------------------------------------------------------------------------


def args_shape_hash(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> str:
    """Return a stable SHA-256 hex of the *shape* of ``(args, kwargs)``.

    Stability rules:

    - Positional args contribute their **type names** in order. Two calls
      with the same arity and matching argument types hash identically
      regardless of value.
    - Keyword args contribute ``(sorted_key, type_name)`` pairs. Two calls
      with the same keyword names and value-types hash identically
      regardless of value or insertion order.
    - Argument **values** are never hashed. This is a deliberate
      privacy guarantee — the baseline JSON cannot leak PII or secrets
      through the shape hash.

    The shape hash is recorded alongside ``tool_name`` in the per-session
    transition history. Operators can use it later (e.g. via
    ``airlock studio``) to spot a "same tool, different argument shape"
    deviation — but the SequenceGuard itself currently only enforces
    against ``tool_name`` transitions.
    """
    arg_types = [type(a).__name__ for a in args]
    kwarg_pairs = sorted((k, type(v).__name__) for k, v in kwargs.items())
    canonical = json.dumps([arg_types, kwarg_pairs], separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Per-session state
# ---------------------------------------------------------------------------


@dataclass
class _SessionTrace:
    """Per-session ordered list of (tool_name, shape_hash) tuples + last tool."""

    history: list[tuple[str, str]] = field(default_factory=list)
    last_tool: str | None = None


# ---------------------------------------------------------------------------
# SequenceGuard
# ---------------------------------------------------------------------------


@dataclass
class SequenceGuard:
    """Behavioral tool-call sequence anomaly guard.

    Attached to a :class:`SecurityPolicy` via the optional ``sequence_guard``
    field. The runtime calls :meth:`record_and_check` from the ``@Airlock``
    seam right after the standard policy check, so the new logic is
    additive and zero-impact for callers who don't set it.

    Attributes:
        mode: ``"declared"`` (DAG-based deny-by-default) or ``"baseline"``
            (Markov-profile low-probability flag).
        action: ``"block"`` (default — raise :class:`SequenceViolation`)
            or ``"warn"`` (log + emit OTel attribute, do not raise).
        dag: Required in ``"declared"`` mode. A mapping
            ``{from_tool: {allowed_next_tools}}``. The key ``ENTRY_SENTINEL``
            (``"__entry__"``) lists tool names permitted as the first call
            in a session. Any transition not listed is a violation.
        baseline_path: Required in ``"baseline"`` mode. Path to a local
            JSON file used to persist the Markov transition counts. The
            file is created with ``{}`` on first use. **Only tool names
            and shape hashes are written — never argument values.**
        low_probability_threshold: ``baseline`` mode only. Transitions
            with ``P(to|from) < threshold`` are flagged. Default ``0.05``.
        min_baseline_samples: ``baseline`` mode only. A transition is
            NOT flagged until the outbound count from ``from`` reaches
            this many samples. Default ``50`` — avoids flagging during
            the cold-start phase before the model has been observed
            enough to be statistically meaningful.
        session_key_kind: ``"agent_id"`` (default) or ``"session_id"``.
            Selects which field of :class:`AirlockContext` keys the
            per-session trace. Falls back to ``"__anonymous__"`` if both
            are absent — and emits a structlog warning so deployments
            without identity don't silently log everything to one bucket.
    """

    mode: SequenceGuardMode
    action: SequenceGuardAction = "block"
    dag: Mapping[str, Iterable[str]] | None = None
    baseline_path: Path | None = None
    low_probability_threshold: float = 0.05
    min_baseline_samples: int = 50
    session_key_kind: SessionKeyKind = "agent_id"

    # --- internal state ---------------------------------------------------

    _traces: dict[str, _SessionTrace] = field(default_factory=dict, repr=False)
    _baseline_cache: dict[str, dict[str, dict[str, int]]] | None = field(default=None, repr=False)
    _normalised_dag: dict[str, frozenset[str]] | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if self.mode == "declared":
            if self.dag is None:
                raise ValueError("SequenceGuard(mode='declared') requires a `dag` mapping")
            self._normalised_dag = {key: frozenset(values) for key, values in self.dag.items()}
            if ENTRY_SENTINEL not in self._normalised_dag:
                raise ValueError(
                    f"SequenceGuard.dag must include the {ENTRY_SENTINEL!r} "
                    "key listing tool names permitted as the first call"
                )
        elif self.mode == "baseline":
            if self.baseline_path is None:
                raise ValueError("SequenceGuard(mode='baseline') requires a `baseline_path`")
            if not (0.0 < self.low_probability_threshold <= 1.0):
                raise ValueError(
                    "low_probability_threshold must be in (0.0, 1.0]; "
                    f"got {self.low_probability_threshold!r}"
                )
            if self.min_baseline_samples < 1:
                raise ValueError(
                    f"min_baseline_samples must be >= 1; got {self.min_baseline_samples!r}"
                )
        else:
            raise ValueError(
                f"SequenceGuard.mode must be 'declared' or 'baseline'; got {self.mode!r}"
            )
        if self.action not in ("block", "warn"):
            raise ValueError(f"SequenceGuard.action must be 'block' or 'warn'; got {self.action!r}")

    # -- Public API -------------------------------------------------------

    def record_and_check(
        self,
        *,
        session_key: str,
        tool_name: str,
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
    ) -> None:
        """Append the call to its session trace and flag if it violates.

        Args:
            session_key: Identifier for this session — typically
                ``context.agent_id`` or ``context.session_id`` depending
                on :attr:`session_key_kind`. The caller resolves the
                identifier; this method does not consult
                ``AirlockContext`` directly so it stays trivially testable.
            tool_name: The tool about to be invoked.
            args: Positional arguments — used only for the shape hash.
                Values are never read.
            kwargs: Keyword arguments — same shape-only treatment.

        Raises:
            SequenceViolation: ``action="block"`` and the transition is
                flagged. ``action="warn"`` never raises.
        """
        shape = args_shape_hash(args, kwargs)
        with self._lock:
            trace = self._traces.setdefault(session_key, _SessionTrace())
            previous = trace.last_tool
            trace.history.append((tool_name, shape))
            trace.last_tool = tool_name

            if self.mode == "declared":
                self._check_declared(
                    session_key=session_key,
                    previous=previous,
                    tool_name=tool_name,
                )
            else:
                self._check_baseline(
                    session_key=session_key,
                    previous=previous,
                    tool_name=tool_name,
                )

    def reset(self, session_key: str | None = None) -> None:
        """Drop in-memory trace(s).

        Args:
            session_key: If supplied, only that session's trace is dropped.
                If ``None``, every in-memory trace is dropped. The
                persisted baseline JSON (if any) is NOT touched.
        """
        with self._lock:
            if session_key is None:
                self._traces.clear()
            else:
                self._traces.pop(session_key, None)

    def history(self, session_key: str) -> list[tuple[str, str]]:
        """Return a snapshot copy of ``session_key``'s ordered trace.

        Returned tuples are ``(tool_name, shape_hash)``. The list is a
        copy — mutating it does not affect the guard's state.
        """
        with self._lock:
            trace = self._traces.get(session_key)
            return list(trace.history) if trace is not None else []

    # -- Internals --------------------------------------------------------

    def _check_declared(self, *, session_key: str, previous: str | None, tool_name: str) -> None:
        assert self._normalised_dag is not None  # noqa: S101  # nosec B101 - guarded by __post_init__
        dag = self._normalised_dag

        if previous is None:
            permitted = dag.get(ENTRY_SENTINEL, frozenset())
            if tool_name not in permitted:
                self._raise_or_warn(
                    SequenceViolation(
                        message=(
                            f"sequence_guard: tool {tool_name!r} is not in the "
                            f"entry set {sorted(permitted)!r}"
                        ),
                        mode="declared",
                        from_tool=None,
                        to_tool=tool_name,
                        session_key=session_key,
                    ),
                )
            return

        permitted_next = dag.get(previous, frozenset())
        if tool_name not in permitted_next:
            self._raise_or_warn(
                SequenceViolation(
                    message=(
                        f"sequence_guard: transition {previous!r} -> "
                        f"{tool_name!r} is not in the declared DAG "
                        f"(permitted from {previous!r}: {sorted(permitted_next)!r})"
                    ),
                    mode="declared",
                    from_tool=previous,
                    to_tool=tool_name,
                    session_key=session_key,
                ),
            )

    def _check_baseline(self, *, session_key: str, previous: str | None, tool_name: str) -> None:
        baseline = self._load_baseline()
        per_key = baseline.setdefault(session_key, {})

        prev_key = previous if previous is not None else PREV_NONE_SENTINEL
        outbound = per_key.setdefault(prev_key, {})
        total_before = sum(outbound.values())
        count_curr_before = outbound.get(tool_name, 0)

        # Record the transition BEFORE evaluating — so a re-run with the
        # same ``baseline_path`` continues from a consistent state.
        outbound[tool_name] = count_curr_before + 1
        self._persist_baseline(baseline)

        if total_before < self.min_baseline_samples:
            # Cold-start: do not flag until enough outbound samples exist.
            return

        observed_p = count_curr_before / total_before
        if observed_p < self.low_probability_threshold:
            self._raise_or_warn(
                SequenceViolation(
                    message=(
                        f"sequence_guard: low-probability transition "
                        f"{previous!r} -> {tool_name!r} "
                        f"(observed P={observed_p:.4f}, threshold="
                        f"{self.low_probability_threshold:.4f}, "
                        f"samples_from_prev={total_before})"
                    ),
                    mode="baseline",
                    from_tool=previous,
                    to_tool=tool_name,
                    session_key=session_key,
                    observed_probability=observed_p,
                ),
            )

    def _load_baseline(self) -> dict[str, dict[str, dict[str, int]]]:
        """Load (or lazily initialise) the baseline JSON cache.

        Cached after the first read so repeat calls do not re-read disk.
        Caller is expected to hold ``self._lock`` when invoking this.
        """
        if self._baseline_cache is not None:
            return self._baseline_cache
        assert self.baseline_path is not None  # noqa: S101  # nosec B101 - guarded by __post_init__
        if self.baseline_path.exists():
            try:
                raw = json.loads(self.baseline_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning(
                    "sequence_guard.baseline_load_failed",
                    path=str(self.baseline_path),
                    error=str(exc),
                )
                raw = {}
        else:
            raw = {}
        # Defensive shape coercion: missing nested dicts become {} on read.
        coerced: dict[str, dict[str, dict[str, int]]] = {}
        if isinstance(raw, dict):
            for sk, prev_map in raw.items():
                if not isinstance(prev_map, dict):
                    continue
                coerced[sk] = {}
                for prev, next_map in prev_map.items():
                    if not isinstance(next_map, dict):
                        continue
                    coerced[sk][prev] = {
                        k: int(v) for k, v in next_map.items() if isinstance(v, int)
                    }
        self._baseline_cache = coerced
        return coerced

    def _persist_baseline(self, baseline: dict[str, dict[str, dict[str, int]]]) -> None:
        """Atomically rewrite the baseline JSON.

        Tempfile + rename to avoid leaving a partial file on disk if the
        process is killed mid-write. Caller is expected to hold
        ``self._lock``.
        """
        assert self.baseline_path is not None  # noqa: S101  # nosec B101 - guarded by __post_init__
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.baseline_path.with_suffix(self.baseline_path.suffix + ".tmp")
        tmp.write_text(json.dumps(baseline, separators=(",", ":")), encoding="utf-8")
        tmp.replace(self.baseline_path)

    def _raise_or_warn(self, exc: SequenceViolation) -> None:
        """Emit the OTel attribute, then either raise or log per ``action``.

        The OTel attribute path is best-effort: we only touch the
        provider if a current span exists, so importing this module
        doesn't force OpenTelemetry on environments that don't use it.
        """
        self._emit_otel(exc)
        if self.action == "block":
            logger.warning(
                "sequence_guard.violation_block",
                **{k: v for k, v in exc.details.items() if v is not None},
            )
            raise exc
        logger.warning(
            "sequence_guard.violation_warn",
            **{k: v for k, v in exc.details.items() if v is not None},
        )

    @staticmethod
    def _emit_otel(exc: SequenceViolation) -> None:
        """Best-effort OTel span attribute emission.

        Reuses the existing ``observability`` provider — does not import
        ``opentelemetry`` at module import time. Failures here are
        swallowed deliberately: telemetry must never break enforcement.
        """
        try:
            from .observability import get_provider

            provider = get_provider()
            tracer = getattr(provider, "_tracer", None)
            if tracer is None:
                return
            current_span_fn = getattr(tracer, "get_current_span", None)
            span = current_span_fn() if current_span_fn else None
            if span is None or not hasattr(span, "set_attribute"):
                return
            span.set_attribute("airlock.sequence_guard.mode", exc.mode)
            span.set_attribute(
                "airlock.sequence_guard.from_tool",
                exc.from_tool if exc.from_tool is not None else "__entry__",
            )
            span.set_attribute("airlock.sequence_guard.to_tool", exc.to_tool)
            span.set_attribute("airlock.sequence_guard.session_key", exc.session_key)
            if exc.observed_probability is not None:
                span.set_attribute(
                    "airlock.sequence_guard.observed_probability",
                    float(exc.observed_probability),
                )
        except Exception as inner:  # noqa: BLE001
            logger.debug("sequence_guard.otel_emit_failed", error=str(inner))


__all__ = [
    "ENTRY_SENTINEL",
    "PREV_NONE_SENTINEL",
    "SequenceGuard",
    "SequenceGuardAction",
    "SequenceGuardMode",
    "SequenceViolation",
    "SessionKeyKind",
    "args_shape_hash",
]
