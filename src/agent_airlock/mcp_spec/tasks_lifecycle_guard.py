"""MCP 2026-07-28 Tasks-extension (SEP-1686) lifecycle guard.

The Tasks extension is a **call-now, fetch-later** pattern: a request MAY return a
task *handle*, and the client later polls ``tasks/get`` / ``tasks/update`` /
``tasks/cancel`` for state and results (the on-the-wire schema lives in
:mod:`agent_airlock.mcp_spec.tasks`). A long-lived handle creates two lifecycle
risks this guard closes, deny-by-default:

1. **Authority drift on a live handle.** A handle admitted under scope set *S* by
   principal *P* can be operated on *later*, after the caller's authority has changed:
   the scope *S* was dropped, the caller stepped up to a **different** authorization
   server, or the authorizing token expired. Executing the task op under the changed
   authority is a confused-deputy privilege problem. This guard **reuses** the
   SEP-2350 / SEP-2352 scope-change detector
   (:func:`agent_airlock.mcp_spec.step_up_scope_guard.verify_scope_unchanged`) — it does
   not re-implement scope logic — and adds principal binding + token-expiry.
2. **Cross-task enumeration.** ``tasks/list`` is **removed** in the 2026-07-28 spec, so
   a client must not be able to enumerate — or operate on — a task it never received a
   handle for. Any op on a handle this principal was not admitted for, and any
   ``tasks/list``, is refused (no cross-task listing).

Every refusal raises :class:`TaskLifecycleError` carrying a structured ``audit_event``
in the same shape :class:`~agent_airlock.mcp_spec.header_integrity.HeaderBodyMismatchError`
uses, and emits the decision through the shipped observability hook
(:func:`agent_airlock.observability.track_event`) — no new engine.

The admitted-handle registry is a plain ``dict`` the caller (one per server / session)
holds — an in-process check, not a proxy. Stdlib only, Pydantic-only core.

References:
    - MCP 2026-07-28 specification (final) — Tasks extension.
    - SEP-1686 — Tasks primitive (``tasks/get`` / ``tasks/update`` / ``tasks/cancel``).
    - SEP-2350 / SEP-2352 — step-up authorization + admission-time scope binding (reused).
    - RFC 9207 / SEP-2468 — authorization-server issuer identification (reused).
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import structlog

from ..observability import track_event
from .step_up_scope_guard import (
    AdmissionScopeSnapshot,
    ScopeAccumulationError,
    capture_admission_snapshot,
    verify_scope_unchanged,
)

logger = structlog.get_logger("agent-airlock.mcp_spec.tasks_lifecycle_guard")

__all__ = [
    "REMOVED_METHODS",
    "TASK_OP_METHODS",
    "TaskAdmission",
    "TaskLifecycleError",
    "TaskRegistry",
    "admit_task",
    "check_task_op",
    "new_registry",
]

#: OTel event name for every Tasks-lifecycle decision.
_DECISION_EVENT = "mcp.tasks_lifecycle.decision"

#: The ``tasks/*`` methods this guard gates.
TASK_OP_METHODS: frozenset[str] = frozenset({"tasks/get", "tasks/update", "tasks/cancel"})

#: Methods removed in MCP 2026-07-28 — enumerating tasks is no longer permitted.
REMOVED_METHODS: frozenset[str] = frozenset({"tasks/list"})


@dataclass(frozen=True)
class TaskAdmission:
    """A task handle bound, at admission, to the scope set + principal that authorised it.

    Attributes:
        task_id: The task handle.
        snapshot: The admission scope snapshot (scope set + issuer), reusing the
            SEP-2350 / SEP-2352 :class:`AdmissionScopeSnapshot`.
        principal: The identity (agent / user ``sub``) the handle was admitted to.
        expires_at: Epoch-seconds expiry of the authorizing token, or ``None`` if the
            authority does not expire.
    """

    task_id: str
    snapshot: AdmissionScopeSnapshot
    principal: str
    expires_at: float | None = None


#: The admitted-handle registry a caller (one per server / session) holds.
TaskRegistry = dict[str, TaskAdmission]


class TaskLifecycleError(ValueError):
    """Raised when a Tasks-extension lifecycle op is refused (fail-closed).

    Carries a structured, machine-readable :attr:`audit_event` in the same shape
    :class:`~agent_airlock.mcp_spec.header_integrity.HeaderBodyMismatchError` uses.
    """

    def __init__(self, message: str, audit_event: Mapping[str, Any]) -> None:
        super().__init__(message)
        #: Structured, machine-readable description of the refusal.
        self.audit_event: dict[str, Any] = dict(audit_event)


def new_registry() -> TaskRegistry:
    """Return a fresh per-server / per-session registry of admitted task handles."""
    return {}


def _emit(record: Mapping[str, Any]) -> None:
    """Route the decision through the shipped OTel hook (list values joined)."""
    props: dict[str, Any] = {}
    for key, value in record.items():
        props[key] = ",".join(value) if isinstance(value, list) else value
    track_event(_DECISION_EVENT, props)


def _refuse(reason: str, message: str, **specifics: Any) -> TaskLifecycleError:
    """Build + emit the structured refusal (mirrors the header-integrity audit shape)."""
    audit: dict[str, Any] = {"event": "mcp.tasks_lifecycle.refuse", "reason": reason}
    audit.update(specifics)
    _emit(audit)
    logger.warning(
        "tasks_lifecycle_blocked",
        reason=reason,
        method=specifics.get("method"),
        task=specifics.get("task"),
        principal=specifics.get("principal"),
    )
    return TaskLifecycleError(message, audit)


def admit_task(
    registry: TaskRegistry,
    task_id: str,
    *,
    scopes: Iterable[str] | str,
    issuer: str,
    principal: str,
    expires_at: float | None = None,
) -> TaskAdmission:
    """Bind a task handle at admission to the authorising scope set + principal.

    Args:
        registry: The caller-held admitted-handle registry (from :func:`new_registry`).
        task_id: The task handle returned to the client.
        scopes: The authorising scope set (iterable of scopes or a space-delimited
            OAuth ``scope`` string).
        issuer: The authorization server (``iss``) that granted the scopes.
        principal: The identity the handle is admitted to (agent / user ``sub``).
        expires_at: Epoch-seconds expiry of the authorizing token (optional).

    Returns:
        The :class:`TaskAdmission` recorded in ``registry`` under ``task_id``.
    """
    snapshot = capture_admission_snapshot(task_id, scopes=scopes, issuer=issuer)
    admission = TaskAdmission(
        task_id=task_id,
        snapshot=snapshot,
        principal=principal,
        expires_at=expires_at,
    )
    registry[task_id] = admission
    return admission


def check_task_op(
    registry: TaskRegistry,
    method: str,
    task_id: str,
    *,
    live_scopes: Iterable[str] | str,
    live_issuer: str,
    principal: str,
    allow_scope_change: bool = False,
    now: float | None = None,
) -> None:
    """Re-check a ``tasks/*`` op against the handle's admission, deny-by-default.

    Args:
        registry: The caller-held admitted-handle registry.
        method: The JSON-RPC method (``tasks/get`` / ``tasks/update`` / ``tasks/cancel``;
            ``tasks/list`` is removed and always refused).
        task_id: The handle the op targets.
        live_scopes: The scope set the caller's credential carries now.
        live_issuer: The authorization server (``iss``) of the live credential.
        principal: The identity making the request.
        allow_scope_change: Explicit opt-out for a *scope-set* change (never the issuer
            binding). Defaults to ``False`` (deny). There is no opt-in.
        now: Epoch-seconds clock override for the expiry check (defaults to ``time.time``).

    Raises:
        TaskLifecycleError: on a removed method, an unknown / cross-principal handle, an
            expired authorizing token, or a scope-set / issuer change (the latter reusing
            the SEP-2350 / SEP-2352 detector). The error carries a structured
            ``audit_event``.
    """
    # (c) tasks/list is removed — refuse enumeration outright.
    if method in REMOVED_METHODS:
        raise _refuse(
            "tasks_list_removed",
            f"{method!r} is removed in MCP 2026-07-28 — refusing task enumeration "
            "(no cross-task listing)",
            method=method,
            task=task_id,
            principal=principal,
        )
    if method not in TASK_OP_METHODS:
        raise _refuse(
            "unknown_task_method",
            f"{method!r} is not a gated Tasks-extension method — refusing (deny-by-default)",
            method=method,
            task=task_id,
            principal=principal,
        )

    # (c) deny-by-default: a handle the caller never received cannot be operated on —
    #     no cross-task enumeration by guessing / iterating task ids.
    admission = registry.get(task_id)
    if admission is None:
        raise _refuse(
            "unknown_task_handle",
            f"no admitted task handle {task_id!r} — refusing {method!r} "
            "(deny-by-default; a client may only act on handles it received)",
            method=method,
            task=task_id,
            principal=principal,
        )

    # (a) principal binding — the caller must be the principal the handle was admitted to.
    if principal != admission.principal:
        raise _refuse(
            "principal_mismatch",
            f"task {task_id!r} was admitted to a different principal — refusing "
            f"cross-principal {method!r}",
            method=method,
            task=task_id,
            principal=principal,
            admitted_principal=admission.principal,
        )

    # (b) authorizing-token expiry.
    if admission.expires_at is not None:
        resolved_now = now if now is not None else time.time()
        if resolved_now >= admission.expires_at:
            raise _refuse(
                "token_expired",
                f"the token that admitted task {task_id!r} has expired — refusing {method!r}",
                method=method,
                task=task_id,
                principal=principal,
                expires_at=admission.expires_at,
                now=resolved_now,
            )

    # (b) scope-set / issuer change — REUSE the SEP-2350 / SEP-2352 detector.
    try:
        verify_scope_unchanged(
            admission.snapshot,
            live_scopes=live_scopes,
            live_issuer=live_issuer,
            allow_scope_change=allow_scope_change,
        )
    except ScopeAccumulationError as exc:
        base = dict(exc.audit_event)
        raise _refuse(
            str(base.get("reason", "scope_change")),
            f"tasks op {method!r} on {task_id!r} refused: {exc}",
            method=method,
            task=task_id,
            principal=principal,
            admitted_scopes=base.get("admitted_scopes"),
            live_scopes=base.get("live_scopes"),
            broadened=base.get("broadened"),
            narrowed=base.get("narrowed"),
            admitted_issuer=base.get("admitted_issuer"),
            live_issuer=base.get("live_issuer"),
        ) from exc
