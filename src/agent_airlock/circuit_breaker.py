"""Circuit breaker pattern for Agent-Airlock.

Provides fault tolerance by preventing cascading failures when tools
repeatedly fail, allowing systems to recover gracefully.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.circuit_breaker")


class CircuitState(str, Enum):
    """State of the circuit breaker."""

    CLOSED = "closed"  # Normal operation, requests pass through
    OPEN = "open"  # Failures exceeded threshold, requests blocked
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""

    failure_threshold: int = 5  # Failures before opening circuit
    success_threshold: int = 2  # Successes in half-open to close
    timeout: float = 30.0  # Seconds before trying half-open
    excluded_exceptions: tuple[type[Exception], ...] = ()  # Don't count these as failures
    on_listener_error: Callable[[str, Exception], None] | None = (
        None  # Callback for listener errors
    )


@dataclass
class CircuitStats:
    """Statistics for circuit breaker."""

    total_calls: int = 0
    total_failures: int = 0
    total_successes: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    last_failure_time: float | None = None
    last_success_time: float | None = None
    times_opened: int = 0


class CircuitBreakerError(Exception):
    """Raised when circuit is open and call is blocked."""

    def __init__(
        self,
        message: str,
        circuit_name: str,
        state: CircuitState,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.circuit_name = circuit_name
        self.state = state
        self.retry_after = retry_after


class CircuitBreaker:
    """Circuit breaker for tool execution.

    Prevents cascading failures by tracking failures and temporarily
    blocking calls when a failure threshold is exceeded.

    Usage:
        breaker = CircuitBreaker("my-tool")

        @breaker
        def my_tool(arg: str) -> str:
            return external_service.call(arg)

        # Or manually:
        with breaker:
            result = external_service.call(arg)
    """

    def __init__(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None,
    ) -> None:
        """Initialize circuit breaker.

        Args:
            name: Name for this circuit (used in logging/errors).
            config: Circuit breaker configuration.
        """
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._last_state_change = time.time()
        self._lock = threading.RLock()
        self._listeners: list[Callable[[str, CircuitState, CircuitState], None]] = []

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            self._check_timeout()
            return self._state

    @property
    def stats(self) -> CircuitStats:
        """Get circuit statistics."""
        with self._lock:
            return CircuitStats(
                total_calls=self._stats.total_calls,
                total_failures=self._stats.total_failures,
                total_successes=self._stats.total_successes,
                consecutive_failures=self._stats.consecutive_failures,
                consecutive_successes=self._stats.consecutive_successes,
                last_failure_time=self._stats.last_failure_time,
                last_success_time=self._stats.last_success_time,
                times_opened=self._stats.times_opened,
            )

    def _check_timeout(self) -> None:
        """Check if timeout has elapsed to transition from OPEN to HALF_OPEN."""
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._last_state_change
            if elapsed >= self.config.timeout:
                self._transition_to(CircuitState.HALF_OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state."""
        old_state = self._state
        if old_state != new_state:
            self._state = new_state
            self._last_state_change = time.time()

            if new_state == CircuitState.OPEN:
                self._stats.times_opened += 1

            logger.info(
                "circuit_state_changed",
                circuit=self.name,
                old_state=old_state.value,
                new_state=new_state.value,
            )

            # Notify listeners
            for listener in self._listeners:
                try:
                    listener(self.name, old_state, new_state)
                except Exception as e:
                    listener_name = getattr(listener, "__name__", str(listener))
                    logger.warning(
                        "circuit_listener_error",
                        circuit=self.name,
                        listener=listener_name,
                        error=str(e),
                    )
                    # Invoke error callback if configured
                    if self.config.on_listener_error:
                        # Suppress exceptions to prevent infinite recursion
                        with contextlib.suppress(Exception):
                            self.config.on_listener_error(listener_name, e)

    def _record_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            self._stats.total_calls += 1
            self._stats.total_successes += 1
            self._stats.consecutive_successes += 1
            self._stats.consecutive_failures = 0
            self._stats.last_success_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                if self._stats.consecutive_successes >= self.config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)

    def _record_failure(self, exc: Exception) -> None:
        """Record a failed call."""
        # Check if this exception should be excluded
        if isinstance(exc, self.config.excluded_exceptions):
            return

        with self._lock:
            self._stats.total_calls += 1
            self._stats.total_failures += 1
            self._stats.consecutive_failures += 1
            self._stats.consecutive_successes = 0
            self._stats.last_failure_time = time.time()

            if self._state == CircuitState.CLOSED:
                if self._stats.consecutive_failures >= self.config.failure_threshold:
                    self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open goes back to open
                self._transition_to(CircuitState.OPEN)

    def _can_execute(self) -> bool:
        """Check if execution is allowed."""
        with self._lock:
            self._check_timeout()

            if self._state == CircuitState.CLOSED:
                return True
            elif self._state == CircuitState.HALF_OPEN:
                return True  # Allow test request
            else:  # OPEN
                return False

    def _get_retry_after(self) -> float | None:
        """Get seconds until retry is allowed."""
        if self._state == CircuitState.OPEN:
            elapsed = time.time() - self._last_state_change
            remaining = self.config.timeout - elapsed
            return max(0, remaining)
        return None

    def add_listener(
        self,
        listener: Callable[[str, CircuitState, CircuitState], None],
    ) -> None:
        """Add state change listener.

        Args:
            listener: Callback(circuit_name, old_state, new_state).
        """
        self._listeners.append(listener)

    def reset(self) -> None:
        """Reset circuit to closed state."""
        with self._lock:
            self._transition_to(CircuitState.CLOSED)
            self._stats = CircuitStats()

    def __call__(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator to wrap a function with circuit breaker."""
        import functools

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with self:
                return func(*args, **kwargs)

        return wrapper

    def __enter__(self) -> CircuitBreaker:
        """Context manager entry."""
        if not self._can_execute():
            retry_after = self._get_retry_after()
            raise CircuitBreakerError(
                f"Circuit '{self.name}' is {self._state.value}",
                circuit_name=self.name,
                state=self._state,
                retry_after=retry_after,
            )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> bool:
        """Context manager exit."""
        if exc_val is None:
            self._record_success()
        elif isinstance(exc_val, Exception):
            self._record_failure(exc_val)
        return False  # Don't suppress exceptions


# Global registry of circuit breakers
_circuit_breakers: dict[str, CircuitBreaker] = {}
_registry_lock = threading.Lock()


def get_circuit_breaker(
    name: str,
    config: CircuitBreakerConfig | None = None,
) -> CircuitBreaker:
    """Get or create a circuit breaker by name.

    Args:
        name: Circuit breaker name.
        config: Configuration (only used if creating new).

    Returns:
        Circuit breaker instance.
    """
    with _registry_lock:
        if name not in _circuit_breakers:
            _circuit_breakers[name] = CircuitBreaker(name, config)
        return _circuit_breakers[name]


def get_all_circuit_breakers() -> dict[str, CircuitBreaker]:
    """Get all registered circuit breakers."""
    with _registry_lock:
        return dict(_circuit_breakers)


def reset_all_circuit_breakers() -> None:
    """Reset all circuit breakers to closed state."""
    with _registry_lock:
        for breaker in _circuit_breakers.values():
            breaker.reset()


def _reset_circuit_breaker_registry() -> None:
    """Reset the global circuit breaker registry for testing.

    This function should only be used in tests to ensure isolation
    between test cases. Resets all breakers and clears the registry.
    """
    with _registry_lock:
        for breaker in _circuit_breakers.values():
            breaker.reset()
        _circuit_breakers.clear()


# Predefined configurations
AGGRESSIVE_BREAKER = CircuitBreakerConfig(
    failure_threshold=3,
    success_threshold=1,
    timeout=10.0,
)
"""Opens quickly (3 failures), recovers quickly (10s timeout)."""

CONSERVATIVE_BREAKER = CircuitBreakerConfig(
    failure_threshold=10,
    success_threshold=5,
    timeout=60.0,
)
"""Opens slowly (10 failures), recovers slowly (60s timeout)."""

DEFAULT_BREAKER = CircuitBreakerConfig()
"""Default configuration (5 failures, 30s timeout)."""
