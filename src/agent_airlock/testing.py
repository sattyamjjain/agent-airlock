"""Testing utilities for Agent-Airlock.

Provides cleanup functions for test isolation. Use these functions
in pytest fixtures or test teardown to ensure tests don't leak state.

Example usage with pytest:

    import pytest
    from agent_airlock.testing import reset_all

    @pytest.fixture(autouse=True)
    def isolate_tests():
        '''Ensure test isolation by resetting global state.'''
        yield
        reset_all()

Or for specific cleanup:

    from agent_airlock.testing import (
        reset_audit_logger,
        reset_network_interceptors,
    )

    def test_something():
        # ... test code ...
        reset_network_interceptors()  # cleanup after test
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from types import ModuleType
from typing import TYPE_CHECKING, Any, cast

from ._log import structlog

if TYPE_CHECKING:
    from .policy import SecurityPolicy
    from .policy_coverage import CoverageReport

logger = structlog.get_logger("agent-airlock.testing")


def reset_all() -> None:
    """Reset all global state for test isolation.

    Call this in pytest fixtures or test teardown to ensure
    tests don't interfere with each other.

    Resets:
        - Audit logger instances
        - Sandbox pool
        - Conversation tracker
        - Cost tracker
        - Observability provider
        - Network interceptors
        - Context state
        - Circuit breaker registry
        - The startup-hook walk and the hooks already logged (V0.10.27)
    """
    reset_audit_logger()
    reset_sandbox_pool()
    reset_conversation_tracker()
    reset_cost_tracker()
    reset_observability()
    reset_network_interceptors()
    reset_context()
    reset_circuit_breakers()
    reset_startup_hook_check()

    logger.debug("testing_reset_all_complete")


def reset_audit_logger() -> None:
    """Reset all audit logger instances.

    Closes file handles and clears the singleton registry.
    """
    from .audit import AuditLogger

    AuditLogger.close_all()


def reset_sandbox_pool() -> None:
    """Reset the global sandbox pool.

    Shuts down any existing pool and clears state.
    Does not fail if E2B is not installed.
    """
    try:
        from .sandbox import _reset_pool

        _reset_pool()
    except ImportError:
        pass  # E2B not installed


def reset_conversation_tracker() -> None:
    """Reset the global conversation tracker.

    Clears all tracked conversations and state.
    """
    from .conversation import reset_conversation_tracker as _reset

    _reset()


def reset_cost_tracker() -> None:
    """Reset the global cost tracker.

    Clears all tracked costs and resets state.
    """
    from .cost_tracking import _reset_tracker

    _reset_tracker()


def reset_observability() -> None:
    """Reset the global observability provider.

    Resets to no-op provider.
    """
    from .observability import _reset_provider

    _reset_provider()


def reset_network_interceptors() -> None:
    """Reset network socket interceptors.

    Restores original socket methods and clears state.
    """
    from .network import _reset_interceptors

    _reset_interceptors()


def reset_context() -> None:
    """Reset the context state.

    Clears any current context in the calling thread/task.
    """
    from .context import _reset_context

    _reset_context()


def reset_circuit_breakers() -> None:
    """Reset all circuit breakers.

    Resets all breakers to closed state and clears the registry.
    """
    from .circuit_breaker import _reset_circuit_breaker_registry

    _reset_circuit_breaker_registry()


def reset_startup_hook_check() -> None:
    """Forget this process's startup-hook walk, so the next guarded call walks again.

    ``startup_hook_check`` walks once per process; a test that changes ``site`` or
    ``sys.path`` and expects a fresh walk resets first.
    """
    from .runtime.startup_hooks import _reset_process_state

    _reset_process_state()


def assert_policy_covers(
    tools: ModuleType | Iterable[Callable[..., Any] | str], policy: SecurityPolicy
) -> CoverageReport:
    """Fail when ``policy`` admits one of ``tools`` only because its allowlist is empty.

    A policy with an empty ``allowed_tools`` and ``default_deny=False`` admits any tool it
    does not deny, so a tool added later is admitted without anyone deciding to admit it.
    Each tool must be allowed by name or pattern, denied, or escalated (V0.10.29).

    Args:
        tools: The tools: a module or package (its ``@Airlock`` tools, as
            ``airlock policy coverage`` finds them), or tools and tool names.
        policy: The policy the tools run under.

    Returns:
        The coverage report, every tool classified.

    Raises:
        AssertionError: A tool is admitted only by the empty-allowlist default.
        TypeError: ``policy`` is not a ``SecurityPolicy``, or a tool has no name.
    """
    from .policy import SecurityPolicy as _SecurityPolicy
    from .policy_coverage import _tool_name, airlock_tools, coverage_report

    if not isinstance(policy, _SecurityPolicy):
        raise TypeError(f"assert_policy_covers needs a SecurityPolicy, not {type(policy).__name__}")
    if isinstance(tools, ModuleType):
        names = list(airlock_tools(tools))
    else:
        names = [_named(tool, _tool_name) for tool in cast("Iterable[Any]", tools)]
    report = coverage_report(policy, names)
    if report.uncovered:
        raise AssertionError(
            "the policy admits these tools only because allowed_tools is empty: "
            f"{', '.join(report.uncovered)}. Name each in allowed_tools, deny it, or "
            "escalate it."
        )
    return report


def _named(tool: Any, tool_name: Callable[[Any], str | None]) -> str:
    """A tool's name: as given, the name ``@Airlock`` checks its calls by, or ``__name__``."""
    name = tool if isinstance(tool, str) else tool_name(tool) or getattr(tool, "__name__", None)
    if not isinstance(name, str) or not name:
        raise TypeError(f"cannot tell the name of tool {tool!r}")
    return name
