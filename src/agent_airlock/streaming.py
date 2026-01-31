"""Streaming support for Agent-Airlock.

Provides validation and sanitization for generator functions that yield
data incrementally. Supports both sync and async generators.

Example:
    from agent_airlock import Airlock, AirlockConfig
    from agent_airlock.streaming import StreamingAirlock

    config = AirlockConfig(mask_pii=True, max_output_chars=5000)

    @Airlock(config=config, streaming=True)
    async def stream_data() -> AsyncGenerator[str, None]:
        async for chunk in data_source:
            yield chunk  # Each chunk sanitized, total truncated if needed
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from dataclasses import dataclass, field
from typing import Any, TypeVar

import structlog

from .config import AirlockConfig
from .sanitizer import sanitize_output

logger = structlog.get_logger("agent-airlock.streaming")

T = TypeVar("T")


@dataclass
class StreamingState:
    """Tracks state across streaming chunks."""

    total_chars: int = 0
    total_chunks: int = 0
    sanitized_count: int = 0
    truncated: bool = False
    started_at: float = field(default_factory=lambda: __import__("time").time())

    def add_chars(self, count: int) -> None:
        """Add to character count."""
        self.total_chars += count
        self.total_chunks += 1

    def should_truncate(self, max_chars: int | None) -> bool:
        """Check if we've exceeded the character limit."""
        if max_chars is None or max_chars <= 0:
            return False
        return self.total_chars >= max_chars

    def remaining_chars(self, max_chars: int | None) -> int | None:
        """Get remaining characters before truncation."""
        if max_chars is None or max_chars <= 0:
            return None
        return max(0, max_chars - self.total_chars)


class StreamingAirlock:
    """Wrapper for streaming validation and sanitization.

    Wraps generator functions to provide:
    - Per-chunk PII/secret sanitization
    - Cumulative output truncation
    - Streaming-aware audit logging

    Example:
        streamer = StreamingAirlock(config)

        @Airlock(config=config)
        def my_generator() -> Generator[str, None, None]:
            for item in items:
                yield item

        # Wrap the generator
        for chunk in streamer.wrap_generator(my_generator()):
            print(chunk)  # Each chunk is sanitized
    """

    def __init__(
        self,
        config: AirlockConfig | None = None,
        *,
        tool_name: str = "unknown",
    ) -> None:
        """Initialize streaming wrapper.

        Args:
            config: Airlock configuration for sanitization settings.
            tool_name: Name of the tool for logging purposes.
        """
        self.config = config or AirlockConfig()
        self.tool_name = tool_name
        self._state = StreamingState()

    @property
    def state(self) -> StreamingState:
        """Get current streaming state."""
        return self._state

    def reset(self) -> None:
        """Reset streaming state for a new stream."""
        self._state = StreamingState()

    def _get_max_chars(self) -> int | None:
        """Get max output chars from config."""
        if self.config.max_output_chars > 0:
            return self.config.max_output_chars
        return None

    def _sanitize_chunk(self, chunk: T) -> tuple[T, int]:
        """Sanitize a single chunk.

        Args:
            chunk: The chunk to sanitize.

        Returns:
            Tuple of (sanitized_chunk, detection_count).
        """
        if not isinstance(chunk, str):
            return chunk, 0

        if not self.config.sanitize_output:
            return chunk, 0

        result = sanitize_output(
            chunk,
            mask_pii=self.config.mask_pii,
            mask_secrets=self.config.mask_secrets,
            max_chars=None,  # Don't truncate individual chunks
        )

        self._state.sanitized_count += result.detection_count

        return result.content, result.detection_count  # type: ignore[return-value]

    def _apply_truncation(self, chunk: str) -> tuple[str, bool]:
        """Apply truncation if needed.

        Args:
            chunk: The chunk to potentially truncate.

        Returns:
            Tuple of (possibly_truncated_chunk, was_final).
        """
        max_chars = self._get_max_chars()
        if max_chars is None:
            return chunk, False

        remaining = self._state.remaining_chars(max_chars)
        if remaining is None:  # pragma: no cover - defensive check
            return chunk, False

        if remaining <= 0:
            # Already at limit, signal end
            self._state.truncated = True
            return "", True

        if len(chunk) <= remaining:
            return chunk, False

        # Need to truncate this chunk
        self._state.truncated = True
        truncated = chunk[:remaining]
        return truncated + "\n\n[OUTPUT TRUNCATED - limit reached]", True

    def wrap_generator(
        self,
        gen: Generator[T, None, None],
    ) -> Generator[T, None, None]:
        """Wrap a sync generator with sanitization and truncation.

        Args:
            gen: The generator to wrap.

        Yields:
            Sanitized and potentially truncated chunks.

        Example:
            def my_gen():
                yield "Hello john@example.com"
                yield "More data..."

            for chunk in streamer.wrap_generator(my_gen()):
                print(chunk)  # Emails masked, truncation applied
        """
        self.reset()

        for chunk in gen:
            # Check if already truncated
            if self._state.truncated:  # pragma: no cover - defensive early exit
                return

            # Sanitize the chunk
            sanitized, _ = self._sanitize_chunk(chunk)

            # Handle string chunks for truncation
            if isinstance(sanitized, str):
                result, is_final = self._apply_truncation(sanitized)
                self._state.add_chars(len(result))

                if result:  # Don't yield empty strings
                    yield result  # type: ignore[misc]

                if is_final:
                    logger.info(
                        "stream_truncated",
                        tool=self.tool_name,
                        total_chars=self._state.total_chars,
                        total_chunks=self._state.total_chunks,
                    )
                    return
            else:
                self._state.add_chars(len(str(sanitized)))
                yield sanitized

        logger.debug(
            "stream_complete",
            tool=self.tool_name,
            total_chars=self._state.total_chars,
            total_chunks=self._state.total_chunks,
            sanitized_count=self._state.sanitized_count,
        )

    async def wrap_async_generator(
        self,
        gen: AsyncGenerator[T, None],
    ) -> AsyncGenerator[T, None]:
        """Wrap an async generator with sanitization and truncation.

        Args:
            gen: The async generator to wrap.

        Yields:
            Sanitized and potentially truncated chunks.

        Example:
            async def my_async_gen():
                yield "Hello john@example.com"
                await asyncio.sleep(0.1)
                yield "More data..."

            async for chunk in streamer.wrap_async_generator(my_async_gen()):
                print(chunk)
        """
        self.reset()

        async for chunk in gen:
            # Check if already truncated
            if self._state.truncated:  # pragma: no cover - defensive early exit
                return

            # Sanitize the chunk
            sanitized, _ = self._sanitize_chunk(chunk)

            # Handle string chunks for truncation
            if isinstance(sanitized, str):
                result, is_final = self._apply_truncation(sanitized)
                self._state.add_chars(len(result))

                if result:
                    yield result  # type: ignore[misc]

                if is_final:
                    logger.info(
                        "stream_truncated",
                        tool=self.tool_name,
                        total_chars=self._state.total_chars,
                        total_chunks=self._state.total_chunks,
                    )
                    return
            else:
                self._state.add_chars(len(str(sanitized)))
                yield sanitized

        logger.debug(
            "stream_complete",
            tool=self.tool_name,
            total_chars=self._state.total_chars,
            total_chunks=self._state.total_chunks,
            sanitized_count=self._state.sanitized_count,
        )


def is_generator_function(func: Any) -> bool:
    """Check if a function is a generator function.

    Args:
        func: Function to check.

    Returns:
        True if the function is a sync generator function.
    """
    import inspect

    return inspect.isgeneratorfunction(func)


def is_async_generator_function(func: Any) -> bool:
    """Check if a function is an async generator function.

    Args:
        func: Function to check.

    Returns:
        True if the function is an async generator function.
    """
    import inspect

    return inspect.isasyncgenfunction(func)


def create_streaming_wrapper(
    func: Any,
    config: AirlockConfig | None = None,
) -> Any:
    """Create a wrapper for a generator function with Airlock protection.

    This is a convenience function that wraps generator functions
    with streaming sanitization.

    Args:
        func: The generator function to wrap.
        config: Airlock configuration.

    Returns:
        A wrapped function that yields sanitized chunks.

    Example:
        @create_streaming_wrapper
        def my_generator():
            yield "data with john@example.com"
            yield "more data"

        for chunk in my_generator():
            print(chunk)  # Emails masked
    """
    import functools

    streamer = StreamingAirlock(config, tool_name=func.__name__)

    if is_async_generator_function(func):

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> AsyncGenerator[Any, None]:
            async for chunk in streamer.wrap_async_generator(func(*args, **kwargs)):
                yield chunk

        return async_wrapper

    elif is_generator_function(func):

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Generator[Any, None, None]:
            yield from streamer.wrap_generator(func(*args, **kwargs))

        return sync_wrapper

    else:
        raise TypeError(
            f"create_streaming_wrapper requires a generator function, got {type(func).__name__}"
        )
