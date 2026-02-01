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

import structlog

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
    """
    reset_audit_logger()
    reset_sandbox_pool()
    reset_conversation_tracker()
    reset_cost_tracker()
    reset_observability()
    reset_network_interceptors()
    reset_context()
    reset_circuit_breakers()

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
