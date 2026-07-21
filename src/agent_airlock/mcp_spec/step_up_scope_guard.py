"""MCP 2026-07-28 step-up scope-accumulation guard (SEP-2350 / SEP-2352).

The attack this closes is a **temporal** one. Between the moment a tool call is
*admitted* — authorised by a specific scope set from a specific authorization
server — and the moment it *executes*, an agent can complete an OAuth **step-up**
that grants it broader scopes. A server that re-reads the live token at execution
time then runs the already-admitted call under the newly-broadened authority: a
confused-deputy **privilege escalation via scope accumulation**. The MCP 2026-07-28
spec proposals **SEP-2350** (step-up authorization) and **SEP-2352** (admission-time
scope binding) formalise binding the authorising scope set to the admission point.

The control is a deny-by-default **re-check at the execution seam** (an in-process
decorator check, not a proxy):

* :func:`capture_admission_snapshot` — at admission, snapshot the exact scope set
  that authorised the call, bound to the credential's issuing authorization server
  (``issuer`` / RFC 9207 ``iss``).
* :func:`verify_scope_unchanged` — at execution, refuse if the live scope set
  differs from the snapshot. **Broadening** (a step-up granted new scopes between
  admission and execution) is the primary attack shape and is denied; **narrowing**
  is also refused. A live **issuer** that differs from the admitted one is always
  refused — a scope granted by a *different* authorization server can never satisfy
  an admission snapshot from another (RFC 9207 / SEP-2468). Deny-by-default with an
  explicit ``allow_scope_change`` **opt-out** (never opt-in); even the opt-out path
  emits the decision.

On refusal it raises :class:`ScopeAccumulationError`, carrying a structured
``audit_event`` in the same shape
:class:`~agent_airlock.mcp_spec.header_integrity.HeaderBodyMismatchError` uses, and
emits the decision through the shipped observability hook
(:func:`agent_airlock.observability.track_event`) — no new observability engine.

Built only on stdlib set operations, Pydantic-only core, zero new runtime deps.

References:
    - MCP 2026-07-28 specification (final).
    - SEP-2350 — step-up authorization.
    - SEP-2352 — admission-time scope binding.
    - RFC 9207 / SEP-2468 — authorization-server issuer identification.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import structlog

from ..observability import track_event

logger = structlog.get_logger("agent-airlock.mcp_spec.step_up_scope_guard")

__all__ = [
    "AdmissionScopeSnapshot",
    "ScopeAccumulationError",
    "capture_admission_snapshot",
    "verify_scope_unchanged",
]

#: OTel event name for every scope-accumulation decision (refuse or opted-out allow).
_DECISION_EVENT = "mcp.scope_accumulation.decision"


@dataclass(frozen=True)
class AdmissionScopeSnapshot:
    """The exact scope set (bound to its issuer) that authorised a call at admission.

    Captured when a tool call is admitted and re-checked at execution. Bound to the
    credential's issuing authorization server (``issuer`` / RFC 9207 ``iss``) so a
    scope granted by a different server can never satisfy this snapshot (SEP-2352).

    Attributes:
        tool_name: The tool the snapshot authorises.
        scopes: The exact authorising scope set at admission (order-insensitive).
        issuer: The authorization server (``iss``) that granted the scopes.
    """

    tool_name: str
    scopes: frozenset[str]
    issuer: str


class ScopeAccumulationError(ValueError):
    """Raised when the authorising scope set (or its issuer) changed after admission.

    Carries a structured, machine-readable :attr:`audit_event` in the same shape
    :class:`~agent_airlock.mcp_spec.header_integrity.HeaderBodyMismatchError` uses, so
    the ``@Airlock`` seam can log a record of the refused call.
    """

    def __init__(self, message: str, audit_event: Mapping[str, Any]) -> None:
        super().__init__(message)
        #: Structured, machine-readable description of the refusal.
        self.audit_event: dict[str, Any] = dict(audit_event)


def _normalize_scopes(scopes: Iterable[str] | str) -> frozenset[str]:
    """Normalize a scope value to a set. An OAuth ``scope`` string is space-delimited."""
    if isinstance(scopes, str):
        return frozenset(part for part in scopes.split() if part)
    return frozenset(str(item) for item in scopes)


def capture_admission_snapshot(
    tool_name: str,
    *,
    scopes: Iterable[str] | str,
    issuer: str,
) -> AdmissionScopeSnapshot:
    """Snapshot the authorising scope set + issuer at the moment a call is admitted.

    Args:
        tool_name: The tool being admitted.
        scopes: The authorising scope set (an iterable of scope strings, or a single
            space-delimited OAuth ``scope`` string).
        issuer: The authorization server (``iss``) that granted the scopes.

    Returns:
        An :class:`AdmissionScopeSnapshot` to re-check at execution time.
    """
    return AdmissionScopeSnapshot(
        tool_name=tool_name,
        scopes=_normalize_scopes(scopes),
        issuer=issuer,
    )


def _decision_record(
    snapshot: AdmissionScopeSnapshot,
    live: frozenset[str],
    live_issuer: str,
    reason: str,
    *,
    refused: bool,
) -> dict[str, Any]:
    """The structured policy-decision record: admitted vs live scopes, delta, issuers."""
    return {
        "event": "mcp.scope_accumulation.refuse" if refused else "mcp.scope_accumulation.allow",
        "reason": reason,
        "tool": snapshot.tool_name,
        "admitted_scopes": sorted(snapshot.scopes),
        "live_scopes": sorted(live),
        "broadened": sorted(live - snapshot.scopes),
        "narrowed": sorted(snapshot.scopes - live),
        "admitted_issuer": snapshot.issuer,
        "live_issuer": live_issuer,
        "refused": refused,
    }


def _emit(record: Mapping[str, Any]) -> None:
    """Route the decision through the shipped OTel observability hook (list values joined)."""
    props: dict[str, Any] = {}
    for key, value in record.items():
        props[key] = ",".join(value) if isinstance(value, list) else value
    track_event(_DECISION_EVENT, props)


def verify_scope_unchanged(
    snapshot: AdmissionScopeSnapshot,
    *,
    live_scopes: Iterable[str] | str,
    live_issuer: str,
    allow_scope_change: bool = False,
) -> None:
    """Re-check the live scope set against the admission snapshot at execution time.

    Deny-by-default:

    - a live ``issuer`` that differs from the admitted issuer is **always refused**
      (RFC 9207 / SEP-2468) — the ``allow_scope_change`` opt-out does not apply, because
      a scope from a *different* authorization server can never satisfy this snapshot;
    - a live scope set that differs from the admitted set is **refused**. Broadening
      (a step-up granted new scopes between admission and execution) is the primary
      attack shape; narrowing is also refused.

    Args:
        snapshot: The admission-time snapshot from :func:`capture_admission_snapshot`.
        live_scopes: The scope set the credential carries at execution time.
        live_issuer: The authorization server (``iss``) of the live credential.
        allow_scope_change: Explicit opt-out — permit a *scope-set* change (not an
            issuer change) while still emitting the decision. Defaults to ``False``
            (deny). There is no opt-in.

    Raises:
        ScopeAccumulationError: on issuer mismatch, or on a scope-set change when
            ``allow_scope_change`` is False. The error carries a structured
            ``audit_event``.
    """
    live = _normalize_scopes(live_scopes)

    # (1) Issuer binding (RFC 9207 / SEP-2468) — cross-authority is never satisfiable;
    #     the opt-out does not relax it.
    if live_issuer != snapshot.issuer:
        record = _decision_record(snapshot, live, live_issuer, "issuer_mismatch", refused=True)
        _emit(record)
        logger.warning(
            "scope_accumulation_blocked",
            reason="issuer_mismatch",
            tool=snapshot.tool_name,
            admitted_issuer=snapshot.issuer,
            live_issuer=live_issuer,
        )
        raise ScopeAccumulationError(
            f"live issuer {live_issuer!r} differs from the admitted issuer "
            f"{snapshot.issuer!r} for tool {snapshot.tool_name!r} — a scope from a "
            "different authorization server cannot satisfy this admission "
            "(RFC 9207 / SEP-2468)",
            record,
        )

    # (2) Scope set unchanged → the admitted call executes under exactly the authority
    #     that admitted it.
    if live == snapshot.scopes:
        return

    # (3) Scope set changed. Broadening is the primary attack shape; narrowing also refused.
    reason = "scope_broadened" if (live - snapshot.scopes) else "scope_narrowed"

    if allow_scope_change:
        record = _decision_record(snapshot, live, live_issuer, reason, refused=False)
        record["opted_out"] = True
        _emit(record)
        logger.warning(
            "scope_accumulation_opt_out",
            reason=reason,
            tool=snapshot.tool_name,
            broadened=sorted(live - snapshot.scopes),
            narrowed=sorted(snapshot.scopes - live),
        )
        return

    record = _decision_record(snapshot, live, live_issuer, reason, refused=True)
    _emit(record)
    logger.warning(
        "scope_accumulation_blocked",
        reason=reason,
        tool=snapshot.tool_name,
        broadened=sorted(live - snapshot.scopes),
        narrowed=sorted(snapshot.scopes - live),
    )
    raise ScopeAccumulationError(
        f"authorising scope set for tool {snapshot.tool_name!r} changed after admission "
        f"({reason}; broadened={sorted(live - snapshot.scopes)}, "
        f"narrowed={sorted(snapshot.scopes - live)}) — refusing (SEP-2350 / SEP-2352)",
        record,
    )
