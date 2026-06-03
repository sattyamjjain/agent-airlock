"""Action-time contradiction gate (v0.8.15+, arXiv:2605.27157).

Why a *separate* gate at action time
-------------------------------------
Yu et al., *Detecting Is Not Resolving: The Monitoring Control Gap in
Retrieval Augmented LLMs* (`arXiv:2605.27157`_, 2026), show that LLMs
**readily acknowledge contradictory evidence** in their reasoning trace
yet "this awareness fails to constrain their final recommendations".
The paper localises the deficit at *action selection*: the danger-
relevant information receives attention during generation but does not
gate the output behaviour. Single-turn diagnostics therefore
overestimate RAG safety, and detection alone is not a control.

agent-airlock already detects many things (sequence anomalies, ghost
args, schema mismatches, untrusted re-invocation). The thing it was
*not* doing before this module is: when the harness or the agent
itself signals that contradictory evidence has been seen, **gate the
privileged / irreversible action** that comes next. This module is
that gate.

What this module is
-------------------
``ActionContradictionGate`` — an opt-in, off-by-default policy hook
that wraps three **pluggable detectors** (any one trips the gate) and a
**privileged-sink glob set**. When a detector trips AND the dispatched
tool matches a privileged sink AND no explicit allow has been issued,
the gate raises :class:`ActionContradictionViolation` (a
:class:`PolicyViolation` subclass, so the existing
``handle_policy_violation`` chain in ``core.py`` picks it up unchanged).

The three detector slots are intentionally narrow — each is a single
field, single regex, or single callable — so the gate stays
auditable. Composing them is the operator's job.

The explicit-allow primitive is **not new**: this module reuses the
existing :meth:`AirlockContext.authorize_once` (introduced for the
v0.8.6 reauth flow). Same one-shot grant, same semantics.

What this module is NOT
-----------------------
- Not a "trust the model's reasoning trace" monitor. The paper's
  whole point is that the trace is unreliable; we read **operator-
  controlled signals** (a metadata field, an operator regex, an
  operator predicate) — never the model's own claim that it has or
  has not "noticed" a contradiction.
- Not :mod:`agent_airlock.sequence_guard` (v0.8.12) — that flags
  *unusual transitions* in the call ORDER. This gate flags
  *contradiction-acknowledged + privileged-action* coupling at a
  *single* call boundary. The two compose.
- Not :attr:`SecurityPolicy.reauth_on_untrusted_reinvocation` (v0.8.6)
  — that flags re-invocation past a threshold once any untrusted tool
  output has flowed back into context. This gate is signal-driven, not
  count-driven, and targets a specific privileged-sink glob set.

Failure model
-------------
Fail closed by default. ``action="block"`` (the default) raises on a
flagged action. ``action="warn"`` logs via structlog and lets the call
proceed — useful for staging.

Off-by-default invariant
------------------------
``SecurityPolicy.action_contradiction_gate`` defaults to ``None``. A
caller who never sets the field sees zero overhead in the seam — no
detector runs, no log lines, no metadata reads. Specifically: a non-
RAG flow that has no notion of "evidence" pays no false-positive tax.

.. _arXiv:2605.27157: https://arxiv.org/abs/2605.27157
"""

from __future__ import annotations

import fnmatch
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog

from .policy import PolicyViolation, ViolationType

logger = structlog.get_logger("agent-airlock.action_contradiction_gate")


ContradictionGateAction = Literal["block", "warn"]


# The deny-by-default privileged-sink corpus. These are the tool-name
# globs the brief calls out: privileged or irreversible actions
# (send / export / commit / transfer) — plus the family of agentic
# exfil sinks the project already targets in the Capsule v0.8.14
# preset, kept in sync deliberately so the two presets compose without
# the operator having to re-declare the universe of risky sinks.
DEFAULT_PRIVILEGED_SINKS: tuple[str, ...] = (
    # Send / publish / dispatch
    "send_*",
    "publish_*",
    "post_to_*",
    "webhook_*",
    "dispatch_*",
    # Export / share / upload
    "export_*",
    "share_*",
    "upload_*",
    # State-mutating commits and transfers
    "commit_*",
    "transfer_*",
    "wire_*",
    "pay_*",
    "create_payment_*",
    # Delete / overwrite — irreversible
    "delete_*",
    "drop_*",
    "destroy_*",
    "purge_*",
    # Specific outbound integrations already canonicalised in v0.8.14
    "outlook_*",
    "smtp_*",
    "salesforce_send_email",
    "create_case",
    "create_lead",
)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class ActionContradictionViolation(PolicyViolation):
    """Raised when a privileged action is blocked because contradictory
    evidence was acknowledged earlier in the session.

    Subclasses :class:`PolicyViolation` so the existing ``@Airlock``
    error handler (which routes ``PolicyViolation`` through
    ``handle_policy_violation``) picks it up unchanged.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: str,
        detector_kind: str,
        session_key: str | None,
    ) -> None:
        super().__init__(
            message=message,
            violation_type=ViolationType.TOOL_DENIED,
            details={
                "guard": "action_contradiction_gate",
                "tool_name": tool_name,
                "detector_kind": detector_kind,
                "session_key": session_key,
            },
        )
        self.tool_name = tool_name
        self.detector_kind = detector_kind
        self.session_key = session_key


# ---------------------------------------------------------------------------
# Per-session contradiction state
# ---------------------------------------------------------------------------


@dataclass
class _ContradictionState:
    """Per-session sticky flag: once tripped, stays tripped until an
    explicit ``authorize_once`` consumes a one-shot grant for the next
    privileged call. The flag stays set across the rest of the session
    so subsequent privileged calls (after the consumed grant) are
    re-blocked — the operator must mint a fresh ``authorize_once`` for
    each privileged action."""

    tripped: bool = False
    last_detector_kind: str | None = None


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


@dataclass
class ActionContradictionGate:
    """Gate that requires an explicit allow before a privileged action
    when the session has signalled acknowledged-contradiction evidence.

    Attach via :attr:`SecurityPolicy.action_contradiction_gate`. The
    ``@Airlock`` seam runs the gate as Step 2.6 of the pre-execution
    pipeline (right after the v0.8.12 sequence guard). When **all** of
    the following hold:

    1. At least one configured detector reports a contradiction
       (operator-controlled signal — never the model's own trace).
    2. The dispatched tool name matches one of
       :attr:`privileged_sinks` (glob).
    3. The :class:`AirlockContext` has not issued
       :meth:`authorize_once` for this tool.

    …then the gate raises :class:`ActionContradictionViolation` (or
    logs + admits if ``action="warn"``).

    All three detectors are optional and orthogonal. Set any one or
    any combination; "any detector trips" semantics. If **none** are
    set, the gate is inert (it will never raise) — useful when an
    operator wants to wire the gate but flip the actual detectors on
    later via :meth:`SecurityPolicy.with_metadata`-style overrides.

    Attributes:
        signal_field_key: Key the gate looks up in
            ``AirlockContext.metadata``. A truthy value at that key
            means "the harness has detected acknowledged contradictory
            evidence in this session". Typical usage: a RAG retrieval
            pipeline flips this on after it sees an evidence-vs-claim
            conflict the agent has discussed.
        marker_regex: Pre-compiled regex run against the value the
            gate finds at :attr:`signal_field_key` *when that value is
            a string*. Lets the operator key the gate on a textual
            marker (e.g. ``re.compile(r"\\b(however|but|conflict)\\b",
            re.I)``) without changing application code. The regex is
            **never** run against the model's full reasoning trace —
            only against operator-supplied marker strings.
        predicate: Fully pluggable detector. Receives the
            :class:`AirlockContext` and returns ``True`` to flag.
            Run last so a bug in the predicate cannot prevent the
            other two detectors from voting.
        privileged_sinks: Glob-matched (``fnmatch``) tool-name globs
            this gate covers. Defaults to
            :data:`DEFAULT_PRIVILEGED_SINKS` (send / export / commit /
            transfer / delete + the v0.8.14 outbound-integration set).
        action: ``"block"`` (default) → raise
            :class:`ActionContradictionViolation`. ``"warn"`` → log +
            admit, useful for staged turn-up.
        session_key_kind: ``"agent_id"`` (default) or ``"session_id"``
            — selects which field of :class:`AirlockContext` the
            per-session state is keyed on.

    Failure model: fail closed by default. ``action="warn"`` is
    explicitly off-policy in production and is only there for
    operators staging the gate against real traffic.

    Thread safety: per-session state lives behind ``threading.Lock``;
    concurrent detectors and ``authorize_once`` calls preserve the
    sticky-trip invariant.
    """

    signal_field_key: str | None = None
    marker_regex: re.Pattern[str] | None = None
    predicate: Callable[[Any], bool] | None = None
    privileged_sinks: tuple[str, ...] = DEFAULT_PRIVILEGED_SINKS
    action: ContradictionGateAction = "block"
    session_key_kind: Literal["agent_id", "session_id"] = "agent_id"

    # Internal sticky state, per session key.
    _states: dict[str, _ContradictionState] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if self.action not in ("block", "warn"):
            raise ValueError(f"action must be 'block' or 'warn'; got {self.action!r}")
        if not self.privileged_sinks:
            raise ValueError(
                "privileged_sinks must be non-empty; use the deny-by-default "
                "DEFAULT_PRIVILEGED_SINKS or pass your own glob tuple"
            )

    # -- Public API -------------------------------------------------------

    def reset(self, session_key: str | None = None) -> None:
        """Drop in-memory state. If ``session_key`` is None, drop all."""
        with self._lock:
            if session_key is None:
                self._states.clear()
            else:
                self._states.pop(session_key, None)

    def is_tripped(self, session_key: str) -> bool:
        """Return whether the gate is currently sticky-tripped for the
        given session. Public so the harness can inspect (e.g. to
        decide whether to issue an out-of-band approval prompt)."""
        with self._lock:
            return self._states.get(session_key, _ContradictionState()).tripped

    def check_action(
        self,
        *,
        context: Any,
        tool_name: str,
        session_key: str,
    ) -> None:
        """Run all configured detectors against the context; if any
        trips and the tool is a privileged sink, enforce the gate.

        Args:
            context: The :class:`AirlockContext` for the current call.
                Duck-typed (we read ``.metadata`` + ``._authorized_once``)
                so this module does not hard-import ``context.py``.
            tool_name: Tool being dispatched.
            session_key: Operator-resolved session identifier. The
                caller derives it from
                ``context.agent_id``/``session_id`` per
                :attr:`session_key_kind` to keep this method pure.

        Raises:
            ActionContradictionViolation: ``action="block"`` and the
                gate is enforced. ``action="warn"`` never raises.
        """
        # Detect — refresh state. We always run the detectors (even when
        # the tool is not a privileged sink) so that the sticky flag
        # accumulates across the session even if non-privileged tools
        # are called between the contradiction-signal moment and the
        # eventual privileged action.
        detector_kind = self._run_detectors(context)
        with self._lock:
            state = self._states.setdefault(session_key, _ContradictionState())
            if detector_kind is not None:
                state.tripped = True
                state.last_detector_kind = detector_kind
            tripped = state.tripped
            last_kind = state.last_detector_kind or "unknown"

        if not tripped:
            return
        if not self._is_privileged_sink(tool_name):
            return

        # Privileged sink + tripped session → check the one-shot grant.
        authorized: set[str] = getattr(context, "_authorized_once", set())
        if tool_name in authorized:
            # Consume the grant; do NOT clear the sticky flag — the
            # next privileged call must mint a fresh authorize_once.
            authorized.discard(tool_name)
            logger.info(
                "action_contradiction_gate.authorize_once_consumed",
                tool_name=tool_name,
                session_key=session_key,
                detector_kind=last_kind,
            )
            return

        violation = ActionContradictionViolation(
            message=(
                f"action_contradiction_gate: tool {tool_name!r} is a "
                f"privileged sink and the session has acknowledged "
                f"contradictory evidence (detector={last_kind!r}); "
                f"call context.authorize_once({tool_name!r}) to grant "
                f"a single privileged invocation. Rationale: "
                f"arXiv:2605.27157 — acknowledging a contradiction is "
                f"not the same as resolving it."
            ),
            tool_name=tool_name,
            detector_kind=last_kind,
            session_key=session_key,
        )
        if self.action == "warn":
            logger.warning(
                "action_contradiction_gate.violation_warn",
                **{k: v for k, v in violation.details.items() if v is not None},
            )
            return
        logger.warning(
            "action_contradiction_gate.violation_block",
            **{k: v for k, v in violation.details.items() if v is not None},
        )
        raise violation

    # -- Internals --------------------------------------------------------

    def _run_detectors(self, context: Any) -> str | None:
        """Return the name of the first detector that trips, or
        ``None`` if none do.

        Detector kinds are deliberately orthogonal on the SAME metadata
        key (``signal_field_key``) so an operator can use one
        well-known key for any detector shape they pick:

        - ``signal_field`` trips iff ``metadata[signal_field_key] is True``
          (strict boolean — booleans are the unambiguous "flag" shape).
        - ``marker_regex`` trips iff the value at the same key is a
          ``str`` AND ``marker_regex.search(value)`` is truthy
          (strings are the operator's narrative marker shape).
        - ``predicate`` is the catch-all — reads anything off context.

        This split means an operator who uses the same key for either
        a flag OR a marker string gets unambiguous detector_kind in
        the audit verdict.
        """
        metadata: dict[str, Any] = getattr(context, "metadata", {}) or {}

        if self.signal_field_key is not None:
            if metadata.get(self.signal_field_key) is True:
                return "signal_field"

        if self.marker_regex is not None and self.signal_field_key is not None:
            value = metadata.get(self.signal_field_key)
            if isinstance(value, str) and self.marker_regex.search(value):
                return "marker_regex"

        if self.predicate is not None:
            try:
                if self.predicate(context):
                    return "predicate"
            except Exception as exc:  # noqa: BLE001
                # A buggy predicate must not crash the gate — log and
                # treat as no-vote. Operators get the structlog event
                # so the bug is visible without breaking enforcement.
                logger.warning(
                    "action_contradiction_gate.predicate_error",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )

        return None

    def _is_privileged_sink(self, tool_name: str) -> bool:
        return any(fnmatch.fnmatch(tool_name, pattern) for pattern in self.privileged_sinks)


__all__ = [
    "DEFAULT_PRIVILEGED_SINKS",
    "ActionContradictionGate",
    "ActionContradictionViolation",
    "ContradictionGateAction",
]
