"""Retry policies for Agent-Airlock.

Provides configurable retry logic with exponential backoff,
jitter, and customizable retry conditions.
"""

from __future__ import annotations

import asyncio
import functools
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import structlog

logger = structlog.get_logger("agent-airlock.retry")

T = TypeVar("T")


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_retries: int = 3
    base_delay: float = 1.0  # Base delay in seconds
    max_delay: float = 60.0  # Maximum delay cap
    exponential_base: float = 2.0  # Multiplier for exponential backoff
    jitter: bool = True  # Add randomness to prevent thundering herd
    jitter_factor: float = 0.1  # Jitter as percentage of delay
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,)
    non_retryable_exceptions: tuple[type[Exception], ...] = ()


@dataclass
class RetryState:
    """State of a retry operation."""

    attempt: int = 0
    total_delay: float = 0.0
    last_exception: Exception | None = None
    exceptions: list[Exception] = field(default_factory=list)


class RetryExhaustedError(Exception):
    """Raised when all retry attempts have been exhausted."""

    def __init__(
        self,
        message: str,
        attempts: int,
        last_exception: Exception | None = None,
        all_exceptions: list[Exception] | None = None,
    ) -> None:
        super().__init__(message)
        self.attempts = attempts
        self.last_exception = last_exception
        self.all_exceptions = all_exceptions or []


def calculate_delay(
    attempt: int,
    config: RetryConfig,
) -> float:
    """Calculate delay for a retry attempt.

    Args:
        attempt: Current attempt number (0-indexed).
        config: Retry configuration.

    Returns:
        Delay in seconds.
    """
    # Exponential backoff
    delay = config.base_delay * (config.exponential_base**attempt)

    # Apply max delay cap
    delay = min(delay, config.max_delay)

    # Add jitter if enabled
    if config.jitter:
        jitter_range = delay * config.jitter_factor
        delay = delay + random.uniform(-jitter_range, jitter_range)  # nosec B311 - jitter not security

    return max(0, delay)


def should_retry(
    exception: Exception,
    attempt: int,
    config: RetryConfig,
) -> bool:
    """Determine if an exception should trigger a retry.

    Args:
        exception: The exception that occurred.
        attempt: Current attempt number.
        config: Retry configuration.

    Returns:
        True if should retry, False otherwise.
    """
    # Check if attempts exhausted
    if attempt >= config.max_retries:
        return False

    # Check if explicitly non-retryable
    if isinstance(exception, config.non_retryable_exceptions):
        return False

    # Check if retryable
    return isinstance(exception, config.retryable_exceptions)


class RetryPolicy:
    """Retry policy for function execution.

    Usage:
        policy = RetryPolicy(max_retries=3)

        @policy
        def flaky_function():
            return external_api.call()

        # Or manually:
        result = policy.execute(flaky_function, arg1, arg2)
    """

    def __init__(self, config: RetryConfig | None = None, **kwargs: Any) -> None:
        """Initialize retry policy.

        Args:
            config: Retry configuration.
            **kwargs: Shorthand for config fields.
        """
        if config:
            self.config = config
        else:
            self.config = RetryConfig(**kwargs)

    def execute(
        self,
        func: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Execute function with retry logic.

        Args:
            func: Function to execute.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            Function result.

        Raises:
            RetryExhaustedError: When all retries exhausted.
        """
        state = RetryState()

        while True:
            try:
                result = func(*args, **kwargs)
                if state.attempt > 0:
                    logger.info(
                        "retry_succeeded",
                        function=func.__name__,
                        attempt=state.attempt + 1,
                        total_delay=state.total_delay,
                    )
                return result

            except Exception as e:
                state.last_exception = e
                state.exceptions.append(e)

                if not should_retry(e, state.attempt, self.config):
                    if state.attempt >= self.config.max_retries:
                        raise RetryExhaustedError(
                            f"Exhausted {self.config.max_retries} retries for {func.__name__}",
                            attempts=state.attempt + 1,
                            last_exception=e,
                            all_exceptions=state.exceptions,
                        ) from e
                    raise

                delay = calculate_delay(state.attempt, self.config)
                state.total_delay += delay
                state.attempt += 1

                logger.warning(
                    "retry_attempt",
                    function=func.__name__,
                    attempt=state.attempt,
                    delay=delay,
                    error=str(e),
                )

                time.sleep(delay)

    async def execute_async(
        self,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Execute async function with retry logic.

        Args:
            func: Async function to execute.
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            Function result.

        Raises:
            RetryExhaustedError: When all retries exhausted.
        """
        state = RetryState()

        while True:
            try:
                result = await func(*args, **kwargs)
                if state.attempt > 0:
                    logger.info(
                        "retry_succeeded_async",
                        function=func.__name__,
                        attempt=state.attempt + 1,
                        total_delay=state.total_delay,
                    )
                return result

            except Exception as e:
                state.last_exception = e
                state.exceptions.append(e)

                if not should_retry(e, state.attempt, self.config):
                    if state.attempt >= self.config.max_retries:
                        raise RetryExhaustedError(
                            f"Exhausted {self.config.max_retries} retries for {func.__name__}",
                            attempts=state.attempt + 1,
                            last_exception=e,
                            all_exceptions=state.exceptions,
                        ) from e
                    raise

                delay = calculate_delay(state.attempt, self.config)
                state.total_delay += delay
                state.attempt += 1

                logger.warning(
                    "retry_attempt_async",
                    function=func.__name__,
                    attempt=state.attempt,
                    delay=delay,
                    error=str(e),
                )

                await asyncio.sleep(delay)

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator to wrap a function with retry logic."""

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> T:
                return await self.execute_async(func, *args, **kwargs)

            return async_wrapper  # type: ignore[return-value]
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> T:
                return self.execute(func, *args, **kwargs)

            return sync_wrapper


# Convenience function for simple retry decorator
def retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,),
    non_retryable_exceptions: tuple[type[Exception], ...] = (),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator factory for retry logic.

    Args:
        max_retries: Maximum retry attempts.
        base_delay: Base delay in seconds.
        max_delay: Maximum delay cap.
        exponential_base: Backoff multiplier.
        jitter: Enable delay jitter.
        retryable_exceptions: Exceptions to retry on.
        non_retryable_exceptions: Exceptions to not retry on.

    Returns:
        Decorator function.

    Usage:
        @retry(max_retries=3, retryable_exceptions=(ConnectionError,))
        def api_call():
            return requests.get(url)
    """
    config = RetryConfig(
        max_retries=max_retries,
        base_delay=base_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter,
        retryable_exceptions=retryable_exceptions,
        non_retryable_exceptions=non_retryable_exceptions,
    )
    return RetryPolicy(config)


# Predefined retry policies
NO_RETRY = RetryConfig(max_retries=0)
"""No retries - fail immediately."""

FAST_RETRY = RetryConfig(
    max_retries=3,
    base_delay=0.1,
    max_delay=1.0,
)
"""Fast retries for transient errors (100ms base)."""

STANDARD_RETRY = RetryConfig(
    max_retries=3,
    base_delay=1.0,
    max_delay=30.0,
)
"""Standard retry policy (1s base, 30s max)."""

AGGRESSIVE_RETRY = RetryConfig(
    max_retries=5,
    base_delay=0.5,
    max_delay=60.0,
)
"""More attempts with moderate delays."""

PATIENT_RETRY = RetryConfig(
    max_retries=10,
    base_delay=2.0,
    max_delay=300.0,
)
"""Many attempts with longer delays for eventually-consistent systems."""


# Common exception sets
NETWORK_EXCEPTIONS: tuple[type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,
)
"""Common network-related exceptions to retry on."""

TRANSIENT_EXCEPTIONS: tuple[type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,
)
"""Transient exceptions that often resolve on retry."""
