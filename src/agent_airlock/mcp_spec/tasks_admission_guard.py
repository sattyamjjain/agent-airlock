"""MCP 2026-07-28 Tasks extension (SEP-2663) deny-by-default admission guard.

SEP-2663 finalises Tasks as an official **extension**: a server may answer a
``tools/call`` with an asynchronous *task handle* instead of a final result, and —
unlike the earlier experimental primitive — it may return a task **unsolicited**
(https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2663). Two
consequences this guard closes, **deny-by-default**:

1. **A task is only legitimate if the client opted into the extension.** Because a
   server can now hand back a task handle on an ordinary request, a client that never
   advertised the Tasks extension must not have tasks created for it. This guard
   refuses any task op unless the client's capabilities advertise Tasks.
2. **Outstanding tasks are a hit-and-run DoS surface** (Akamai): a hostile or buggy
   server can spray task handles and never resolve them. This guard caps outstanding
   tasks **per principal** (``max_outstanding_tasks``) and expires them after a TTL
   (``task_ttl_seconds``) — over-quota / past-TTL is refused and logged.

This is an **admission-control** layer that **composes with** the shipped SEP-1686
lifecycle guard (:mod:`agent_airlock.mcp_spec.tasks_lifecycle_guard`) — it reuses that
guard's ``admit_task`` / ``check_task_op`` for the handle→principal/scope binding and
the unsolicited-handle / ``tasks/list``-removed / issuer checks, and the SEP-2350/2352
scope-change detector underneath. It does **not** re-implement any of them. Stdlib
only, Pydantic-only core, in-process (not a proxy).

References:
    - SEP-2663 — Tasks Extension (MCP 2026-07-28 final).
    - SEP-1686 — earlier Tasks primitive lifecycle binding (reused).
    - SEP-2350 / SEP-2352 — step-up scope binding (reused, transitively).
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import structlog

from ..observability import track_event
from .tasks_lifecycle_guard import (
    TaskAdmission,
    TaskLifecycleError,
    TaskRegistry,
    admit_task,
    check_task_op,
    new_registry,
)

logger = structlog.get_logger("agent-airlock.mcp_spec.tasks_admission_guard")

__all__ = [
    "TasksAdmissionConfig",
    "TasksAdmissionError",
    "TasksAdmissionState",
    "admit_task_gated",
    "check_task_op_gated",
    "new_admission_state",
]

_DECISION_EVENT = "mcp.tasks_admission.decision"

#: Keys under which a client advertises the SEP-2663 Tasks extension in its capabilities.
_TASKS_CAPABILITY_KEYS = ("tasks",)


@dataclass(frozen=True)
class TasksAdmissionConfig:
    """Deny-by-default admission-control tunables for the SEP-2663 Tasks extension."""

    #: Max outstanding (un-expired) tasks a single principal may hold at once.
    max_outstanding_tasks: int = 16
    #: Seconds after admission a task handle is considered expired and refused.
    task_ttl_seconds: float = 900.0
    #: Require the client to advertise the Tasks extension in its capabilities.
    require_tasks_capability: bool = True


@dataclass
class TasksAdmissionState:
    """Per-server / per-session admission state (the caller holds one).

    Bundles the SEP-1686 :data:`TaskRegistry` (reused verbatim) with per-handle
    admission timestamps for the TTL sweep.
    """

    registry: TaskRegistry = field(default_factory=new_registry)
    admitted_at: dict[str, float] = field(default_factory=dict)


class TasksAdmissionError(TaskLifecycleError):
    """Refusal from the SEP-2663 admission layer (capability / quota / TTL).

    Subclasses :class:`~agent_airlock.mcp_spec.tasks_lifecycle_guard.TaskLifecycleError`
    so a caller can catch every Tasks refusal (lifecycle + admission) as one type, and
    carries the same structured ``audit_event``.
    """


def new_admission_state() -> TasksAdmissionState:
    """Return a fresh per-server / per-session admission state."""
    return TasksAdmissionState()


def _advertises_tasks(capabilities: Any) -> bool:
    """Whether the client's advertised capabilities opt into the SEP-2663 Tasks extension.

    In MCP a capability is advertised by the **presence** of its key, whose value is an
    (often empty) object — ``{"tasks": {}}`` means "Tasks supported". Presence counts;
    only an explicit ``None`` / ``False`` value is treated as not-advertised.
    """

    def _present(container: Mapping[str, Any]) -> bool:
        return any(
            key in container and container.get(key) not in (None, False)
            for key in _TASKS_CAPABILITY_KEYS
        )

    if isinstance(capabilities, Mapping):
        if _present(capabilities):
            return True
        experimental = capabilities.get("experimental")
        return isinstance(experimental, Mapping) and _present(experimental)
    if isinstance(capabilities, (list, tuple, set, frozenset)):
        return any(str(item) in _TASKS_CAPABILITY_KEYS for item in capabilities)
    return False


def _emit(record: Mapping[str, Any]) -> None:
    track_event(_DECISION_EVENT, dict(record))


def _refuse(reason: str, message: str, **specifics: Any) -> TasksAdmissionError:
    audit: dict[str, Any] = {"event": "mcp.tasks_admission.refuse", "reason": reason}
    audit.update(specifics)
    _emit(audit)
    logger.warning(
        "tasks_admission_blocked",
        reason=reason,
        task=specifics.get("task"),
        principal=specifics.get("principal"),
    )
    return TasksAdmissionError(message, audit)


def _sweep_expired(state: TasksAdmissionState, config: TasksAdmissionConfig, now: float) -> None:
    """Drop handles admitted more than ``task_ttl_seconds`` ago (before quota counting)."""
    expired = [
        task_id
        for task_id, admitted in state.admitted_at.items()
        if now - admitted > config.task_ttl_seconds
    ]
    for task_id in expired:
        state.admitted_at.pop(task_id, None)
        state.registry.pop(task_id, None)


def admit_task_gated(
    state: TasksAdmissionState,
    task_id: str,
    *,
    client_capabilities: Any,
    scopes: Iterable[str] | str,
    issuer: str,
    principal: str,
    expires_at: float | None = None,
    config: TasksAdmissionConfig | None = None,
    now: float | None = None,
) -> TaskAdmission:
    """Admit a new task handle, deny-by-default (SEP-2663 create path).

    Enforces the capability-advertisement gate and the per-principal TTL/quota, then
    **reuses** :func:`~agent_airlock.mcp_spec.tasks_lifecycle_guard.admit_task` for the
    handle→principal/scope binding.

    Raises:
        TasksAdmissionError: if the client did not advertise the Tasks extension, or the
            principal is over its outstanding-task quota.
    """
    config = config or TasksAdmissionConfig()
    resolved_now = now if now is not None else time.time()

    # (1) capability-advertisement gate — a client that never opted into Tasks must not
    #     have tasks created for it (SEP-2663 makes tasks returnable unsolicited).
    if config.require_tasks_capability and not _advertises_tasks(client_capabilities):
        raise _refuse(
            "tasks_capability_not_advertised",
            f"client did not advertise the Tasks extension — refusing to create task "
            f"{task_id!r} (SEP-2663; deny-by-default)",
            task=task_id,
            principal=principal,
        )

    # (2) TTL sweep, then per-principal outstanding-task quota (Akamai hit-and-run DoS).
    _sweep_expired(state, config, resolved_now)
    outstanding = sum(1 for adm in state.registry.values() if adm.principal == principal)
    if outstanding >= config.max_outstanding_tasks:
        raise _refuse(
            "task_quota_exceeded",
            f"principal {principal!r} holds {outstanding} outstanding tasks "
            f"(max {config.max_outstanding_tasks}) — refusing to create {task_id!r}",
            task=task_id,
            principal=principal,
            outstanding=outstanding,
            max_outstanding=config.max_outstanding_tasks,
        )

    # Reuse the SEP-1686 binding verbatim; record the admission time for TTL.
    admission = admit_task(
        state.registry,
        task_id,
        scopes=scopes,
        issuer=issuer,
        principal=principal,
        expires_at=expires_at,
    )
    state.admitted_at[task_id] = resolved_now
    return admission


def check_task_op_gated(
    state: TasksAdmissionState,
    method: str,
    task_id: str,
    *,
    client_capabilities: Any,
    live_scopes: Iterable[str] | str,
    live_issuer: str,
    principal: str,
    config: TasksAdmissionConfig | None = None,
    allow_scope_change: bool = False,
    now: float | None = None,
) -> None:
    """Re-check a ``tasks/*`` continue/cancel op, deny-by-default (SEP-2663).

    Enforces the capability gate and the per-handle TTL, then **reuses**
    :func:`~agent_airlock.mcp_spec.tasks_lifecycle_guard.check_task_op` for the
    principal/scope binding, unsolicited-handle rejection, ``tasks/list`` removal, and
    issuer/scope-change detection (SEP-1686 + SEP-2350/2352).

    Raises:
        TasksAdmissionError: on a missing Tasks capability or a past-TTL handle.
        TaskLifecycleError: on the reused per-op checks.
    """
    config = config or TasksAdmissionConfig()
    resolved_now = now if now is not None else time.time()

    if config.require_tasks_capability and not _advertises_tasks(client_capabilities):
        raise _refuse(
            "tasks_capability_not_advertised",
            f"client did not advertise the Tasks extension — refusing {method!r} on "
            f"{task_id!r} (SEP-2663)",
            method=method,
            task=task_id,
            principal=principal,
        )

    admitted = state.admitted_at.get(task_id)
    if admitted is not None and resolved_now - admitted > config.task_ttl_seconds:
        state.admitted_at.pop(task_id, None)
        state.registry.pop(task_id, None)
        raise _refuse(
            "task_ttl_exceeded",
            f"task {task_id!r} exceeded its {config.task_ttl_seconds}s TTL — refusing {method!r}",
            method=method,
            task=task_id,
            principal=principal,
            age_seconds=resolved_now - admitted,
            ttl_seconds=config.task_ttl_seconds,
        )

    # Reuse the SEP-1686 lifecycle checks (principal / scope / unsolicited handle /
    # tasks-list-removed / issuer) verbatim.
    check_task_op(
        state.registry,
        method,
        task_id,
        live_scopes=live_scopes,
        live_issuer=live_issuer,
        principal=principal,
        allow_scope_change=allow_scope_change,
        now=now,
    )
