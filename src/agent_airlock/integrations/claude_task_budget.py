"""Anthropic Messages API task budgets (beta ``task-budgets-2026-03-13``).

A task budget tells the model how many tokens it has for a whole agentic loop (thinking,
tool calls and final output), so it can pace itself and wrap up before the budget runs
out. It is advisory: the model sees the countdown and adapts, but nothing stops it.
``max_tokens`` remains the hard per-response cap.

The request shape::

    client.beta.messages.create(
        betas=["task-budgets-2026-03-13"],
        output_config={"task_budget": {"type": "tokens", "total": 128_000}},
        ...,
    )

``total`` is at least 20,000 tokens; ``remaining`` is optional and defaults to ``total``
server-side, so a client that compacts its own context passes what is left of the loop.
There is no ``policy`` field. Until 0.10.25 this module built
``{"task_budget": {"total_tokens", "remaining_tokens", "policy"}}`` at the top level of
the body, a shape the API does not accept.

Not the Managed Agents session budget. A Managed Agents session takes a hard,
dollar-denominated cap at creation,
``budget={"type": "limit", "max_list_cost": {"amount": "2500", "currency": "USD"}}``
(the amount in cents), which the platform enforces before each model request. The two do
not compose: a session is not a Messages API request.

Usage::

    from agent_airlock import CostTracker
    from agent_airlock.integrations.claude_task_budget import (
        BETA_HEADER_VALUE,
        build_output_config,
    )

    tracker = CostTracker()
    body = {
        "model": "claude-opus-5-5",
        "max_tokens": 16_000,
        "messages": [...],
        **build_output_config(total=128_000, remaining=128_000 - used_so_far),
    }
    client.beta.messages.create(betas=[BETA_HEADER_VALUE], **body)

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

MIN_TASK_BUDGET_TOKENS = 20_000
"""The smallest ``total`` the API accepts; a smaller one is rejected with a 400."""


class InvalidTaskBudgetError(AirlockError):
    """Raised for a task budget the API would reject, before it is sent.

    Attributes:
        total: The ``total`` that was given.
        remaining: The ``remaining`` that was given, or None.
    """

    def __init__(self, message: str, *, total: Any, remaining: Any = None) -> None:
        self.total = total
        self.remaining = remaining
        super().__init__(message)


class TaskBudgetExhausted(AirlockError):
    """Raised when a hard task budget has been fully consumed.

    The API has no hard mode: a task budget is advisory. ``soft=False`` on
    :func:`build_task_budget` (and the builders that call it) is a client-side stop,
    raising this before a request whose remaining budget is zero or less is built, so
    the loop ends instead of running on an empty budget.
    """

    def __init__(self, *, total: int, used: int) -> None:
        self.total = total
        self.used = used
        super().__init__(f"task budget exhausted: used {used} of {total} tokens")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def build_task_budget(
    total: int,
    remaining: int | None = None,
    *,
    soft: bool = True,
) -> dict[str, Any]:
    """Build the ``task_budget`` object the Messages API reads from ``output_config``.

    Args:
        total: Tokens for the whole agentic loop, at least
            :data:`MIN_TASK_BUDGET_TOKENS`.
        remaining: Tokens still available, or None to leave it out (the API then reads
            it as ``total``).
        soft: If True, a negative ``remaining`` is sent as 0 and the model sees an empty
            budget. If False, a ``remaining`` of 0 or less raises
            :class:`TaskBudgetExhausted` instead. Nothing about ``soft`` is sent: the
            API has no policy field.

    Returns:
        ``{"type": "tokens", "total": total}``, plus ``"remaining"`` when given.

    Raises:
        InvalidTaskBudgetError: ``total`` is not an int (a bool is not), is below the
            minimum, or ``remaining`` is not an int or exceeds ``total``.
        TaskBudgetExhausted: ``soft`` is False and ``remaining`` is 0 or less.
    """
    if not _is_int(total):
        raise InvalidTaskBudgetError(
            f"task budget total must be an int, got {type(total).__name__}",
            total=total,
            remaining=remaining,
        )
    if total < MIN_TASK_BUDGET_TOKENS:
        raise InvalidTaskBudgetError(
            f"task budget total {total} is below the API minimum of "
            f"{MIN_TASK_BUDGET_TOKENS} tokens",
            total=total,
            remaining=remaining,
        )
    budget: dict[str, Any] = {"type": "tokens", "total": total}
    if remaining is None:
        return budget
    if not _is_int(remaining):
        raise InvalidTaskBudgetError(
            f"task budget remaining must be an int, got {type(remaining).__name__}",
            total=total,
            remaining=remaining,
        )
    if remaining > total:
        raise InvalidTaskBudgetError(
            f"task budget remaining {remaining} exceeds total {total}",
            total=total,
            remaining=remaining,
        )
    if remaining <= 0 and not soft:
        raise TaskBudgetExhausted(total=total, used=total - remaining)
    budget["remaining"] = max(0, remaining)
    return budget


def build_output_config(
    total: int,
    remaining: int | None = None,
    soft: bool = True,
) -> dict[str, Any]:
    """Build the request-body fragment that carries a task budget.

    Args:
        total: Tokens for the whole agentic loop (see :func:`build_task_budget`).
        remaining: Tokens still available, or None.
        soft: See :func:`build_task_budget`.

    Returns:
        ``{"output_config": {"task_budget": {...}}}``, to merge into the keyword
        arguments of ``client.beta.messages.create``. A request that already sets
        ``output_config`` (``effort``, ``format``) needs the ``task_budget`` key merged
        into it instead.

    Raises:
        InvalidTaskBudgetError: See :func:`build_task_budget`.
        TaskBudgetExhausted: ``soft`` is False and ``remaining`` is 0 or less.
    """
    return {"output_config": {"task_budget": build_task_budget(total, remaining, soft=soft)}}


def build_task_budget_headers(
    total_tokens: int | None = None,
    soft: bool = True,
) -> dict[str, str]:
    """Return the ``anthropic-beta`` header dict for task-budgets.

    With the Python SDK, pass ``betas=[BETA_HEADER_VALUE]`` to
    ``client.beta.messages.create`` instead; it sets the header.

    Args:
        total_tokens: Accepted for API symmetry with ``build_output_config``
            but not included in the header — Anthropic reads the budget
            from the request body, not from headers.
        soft: Same note — reserved for API symmetry.

    Returns:
        ``{"anthropic-beta": "task-budgets-2026-03-13"}``.
    """
    del total_tokens, soft  # reserved for future header-side params
    return {"anthropic-beta": BETA_HEADER_VALUE}


__all__ = [
    "BETA_HEADER_VALUE",
    "MIN_TASK_BUDGET_TOKENS",
    "InvalidTaskBudgetError",
    "TaskBudgetExhausted",
    "build_output_config",
    "build_task_budget",
    "build_task_budget_headers",
]
