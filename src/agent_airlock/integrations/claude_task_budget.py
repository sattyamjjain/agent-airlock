"""Anthropic Claude ``task_budget`` beta adapter (v0.5.1+).

On 2026-03-13 Anthropic shipped the ``task-budgets-2026-03-13`` beta header.
When set, Claude Opus 4.7+ receives an in-loop token countdown and can
adapt its planning to the remaining budget instead of running blind and
hitting the context window unexpectedly.

This module is the glue: take an agent-airlock ``CostTracker``, render its
current usage as the ``task_budget`` payload the Messages API expects, and
provide a hard-stop exception (``TaskBudgetExhausted``) for callers that
want to terminate a run rather than letting the model overshoot.

Usage::

    from agent_airlock import CostTracker
    from agent_airlock.integrations.claude_task_budget import (
        build_task_budget_headers,
        build_output_config,
        TaskBudgetExhausted,
    )

    tracker = CostTracker()
    headers = build_task_budget_headers()
    body = {
        "model": "claude-opus-4-7",
        "messages": [...],
        **build_output_config(
            total=tracker.to_task_budget(total=100_000)["task_budget"]["total_tokens"],
            remaining=tracker.to_task_budget(total=100_000)["task_budget"]["remaining_tokens"],
            soft=True,
        ),
    }

Reference
---------
https://platform.claude.com/docs/en/build-with-claude/task-budgets
"""

from __future__ import annotations

from typing import Any

from ..exceptions import AirlockError

BETA_HEADER_VALUE = "task-budgets-2026-03-13"
"""The exact ``anthropic-beta`` header value for the current task-budgets beta.

Pinned to the 2026-03-13 schema. When Anthropic promotes a newer version,
update this constant and bump the library version — older Claude runtimes
ignore unknown beta flags, but newer schemas may rename fields."""


class TaskBudgetExhausted(AirlockError):
    """Raised when a hard-policy task budget has been fully consumed.

    Callers using ``build_output_config(..., soft=False)`` opt into this
    exception — the sanitizer layer refuses to forward a request whose
    remaining budget has reached zero, preventing the model from
    overshooting the cap.
    """

    def __init__(self, *, total: int, used: int) -> None:
        self.total = total
        self.used = used
        super().__init__(
            f"task budget exhausted: used {used} of {total} tokens"
        )


def build_task_budget_headers(
    total_tokens: int | None = None,
    soft: bool = True,
) -> dict[str, str]:
    """Return the ``anthropic-beta`` header dict for task-budgets.

    Args:
        total_tokens: Accepted for API symmetry with ``build_output_config``
            but not included in the header — Anthropic reads the budget
            from the request body, not from headers. Present so callers
            can pass both builders the same ``(total, soft)`` tuple.
        soft: Same note — reserved for API symmetry.

    Returns:
        ``{"anthropic-beta": "task-budgets-2026-03-13"}``.
    """
    del total_tokens, soft  # reserved for future header-side params
    return {"anthropic-beta": BETA_HEADER_VALUE}


def build_output_config(
    total: int,
    remaining: int,
    soft: bool = True,
) -> dict[str, Any]:
    """Build the ``task_budget`` request-body fragment.

    Args:
        total: Total tokens allocated for this task.
        remaining: Tokens still available.
        soft: If True, policy is ``"soft"`` (model receives a countdown
            but may overshoot). If False, ``"hard"``.

    Returns:
        ``{"task_budget": {"total_tokens", "remaining_tokens", "policy"}}``.

    Raises:
        TaskBudgetExhausted: If ``remaining <= 0`` and ``soft=False``.
    """
    if remaining <= 0 and not soft:
        raise TaskBudgetExhausted(total=total, used=total - remaining)
    return {
        "task_budget": {
            "total_tokens": total,
            "remaining_tokens": max(0, remaining),
            "policy": "soft" if soft else "hard",
        }
    }


__all__ = [
    "BETA_HEADER_VALUE",
    "TaskBudgetExhausted",
    "build_output_config",
    "build_task_budget_headers",
]
