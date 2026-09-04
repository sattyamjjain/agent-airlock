"""Process-wide kill-switch registration (v0.8.86+).

Why this exists
---------------
Through v0.8.85 the kill switch shipped a correct broadcaster, a correct listener and a
correct quorum, and **nothing consulted them**. ``KillSwitchListener`` was never
constructed inside the library: the only references outside this package were the CLI and
the CLI dispatcher table, so triggering the switch halted nothing in an airlock-protected
process. The README called it a "cluster-wide freeze"; the code was a set of primitives
with no seam into the call path.

This module is that seam. A process installs one listener, and :func:`is_frozen` is
consulted by ``@Airlock`` before any other gate — including ghost-argument validation,
because a freeze means *stop*, not *stop after checking whether the arguments were
well-formed*.

Polling is bounded, not per-call
--------------------------------
A transport read on every tool call would put the kill switch on the hot path. The
listener therefore polls at most once per :attr:`KillSwitchListener.poll_interval_seconds`
(5 s by default, matching the interval the original feature spec named and never
implemented). The cost of that choice is stated plainly: a freeze takes effect within one
poll interval, not instantly, and a process that never makes a tool call never polls.

Fail-open on transport errors, on purpose
-----------------------------------------
If a poll raises — Redis down, malformed frame — the previous state is kept and the error
is logged. A kill switch that halts every agent when its own transport hiccups is an
outage generator, and the failure mode it protects against (an operator needing to stop a
fleet) is one where the operator is present and can escalate. That trade is the opposite
of the library's usual deny-by-default posture, so it is a deliberate exception rather
than an oversight, and ``strict=True`` on :func:`install` inverts it.
"""

from __future__ import annotations

import threading

from .._log import structlog
from .broadcast import KillSwitchListener, KillSwitchState

logger = structlog.get_logger("agent-airlock.kill_switch.registry")

_lock = threading.Lock()
_listener: KillSwitchListener | None = None
_strict = False


def install(listener: KillSwitchListener, *, strict: bool = False) -> None:
    """Register the process-wide kill-switch listener.

    Args:
        listener: The listener ``@Airlock`` will consult before each call. Installing
            moves a ``DISARMED`` listener to :attr:`KillSwitchState.ARMED`, which is what
            that state means: watching, not yet triggered.
        strict: When True, a transport error during a poll freezes the process instead of
            keeping the last known state. Use it where a stalled kill switch is worse than
            an outage.
    """
    global _listener, _strict
    with _lock:
        _listener = listener
        _strict = strict
        if listener.state is KillSwitchState.DISARMED:
            listener.state = KillSwitchState.ARMED
    logger.info(
        "kill_switch_installed",
        signers=len(listener.signers),
        quorum=f"{listener.reset_quorum_threshold}-of-{listener.reset_quorum_total}",
        poll_interval_seconds=listener.poll_interval_seconds,
        strict=strict,
    )


def get() -> KillSwitchListener | None:
    """The installed listener, or None when no kill switch is registered."""
    with _lock:
        return _listener


def clear() -> None:
    """Remove the installed listener. Primarily for tests and process teardown."""
    global _listener, _strict
    with _lock:
        _listener = None
        _strict = False


def is_frozen() -> bool:
    """Whether tool calls must be refused right now.

    Polls the transport at most once per poll interval, then reports the listener state.
    Returns False when no kill switch is installed, which is the state every process is in
    until it calls :func:`install` — the switch is opt-in, and this function is the only
    thing ``@Airlock`` needs to know about it.

    Returns:
        True when the switch is triggered and calls must be refused.
    """
    listener = get()
    if listener is None:
        return False
    try:
        listener.poll_if_due()
    except Exception as exc:  # noqa: BLE001 - transport errors must not crash the caller
        logger.warning("kill_switch_poll_failed", error=str(exc), strict=_strict)
        if _strict:
            return True
    return listener.is_frozen()


__all__ = ["clear", "get", "install", "is_frozen"]
