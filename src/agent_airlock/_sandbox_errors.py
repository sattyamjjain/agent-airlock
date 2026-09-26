"""Sandbox exception classes, shared by ``core`` and ``sandbox``.

They sit apart from both modules so ``core`` can raise them without importing
``agent_airlock.sandbox``: the decorator's one local fallback is for the case where that
import fails, and ``sandbox_required=True`` has to be able to refuse the call then. Both
modules and the package root re-export them, so each name is one class. Until 0.10.17
``core`` and ``sandbox`` each defined their own ``SandboxExecutionError``, and the one in
``agent_airlock.sandbox`` was never raised.
"""

from __future__ import annotations

from typing import Any

from .exceptions import AirlockError


class SandboxError(AirlockError):
    """Base class for sandbox failures."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)


class SandboxNotAvailableError(SandboxError):
    """The E2B SDK or cloudpickle is not installed."""


class SandboxExecutionError(SandboxError):
    """The sandbox could not run a call, or returned no result from it.

    The ``@Airlock`` decorator raises it internally and answers it with a ``sandbox_error``
    refusal. A tool that raised inside the sandbox is not this error: the decorator answers
    that exactly as it answers a tool that raised in-process.
    """


class SandboxUnavailableError(SandboxNotAvailableError):
    """``sandbox_required=True`` and ``agent_airlock.sandbox`` could not be imported.

    The decorator raises it internally instead of running the tool in-process, and answers
    it with a ``sandbox_error`` refusal.
    """
