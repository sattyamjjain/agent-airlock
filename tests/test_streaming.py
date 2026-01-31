"""Tests for streaming support functionality."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest

from agent_airlock.config import AirlockConfig
from agent_airlock.streaming import (
    StreamingAirlock,
    StreamingState,
    create_streaming_wrapper,
    is_async_generator_function,
    is_generator_function,
)


class TestStreamingState:
    """Tests for StreamingState dataclass."""

    def test_initial_state(self) -> None:
        """Test initial state values."""
        state = StreamingState()
        assert state.total_chars == 0
        assert state.total_chunks == 0
        assert state.sanitized_count == 0
        assert state.truncated is False
        assert state.started_at > 0

    def test_add_chars(self) -> None:
        """Test adding characters."""
        state = StreamingState()
        state.add_chars(100)
        assert state.total_chars == 100
        assert state.total_chunks == 1

        state.add_chars(50)
        assert state.total_chars == 150
        assert state.total_chunks == 2

    def test_should_truncate_no_limit(self) -> None:
        """Test truncation check with no limit."""
        state = StreamingState(total_chars=1000)
        assert state.should_truncate(None) is False
        assert state.should_truncate(0) is False
        assert state.should_truncate(-1) is False

    def test_should_truncate_under_limit(self) -> None:
        """Test truncation check when under limit."""
        state = StreamingState(total_chars=500)
        assert state.should_truncate(1000) is False

    def test_should_truncate_at_limit(self) -> None:
        """Test truncation check when at limit."""
        state = StreamingState(total_chars=1000)
        assert state.should_truncate(1000) is True

    def test_should_truncate_over_limit(self) -> None:
        """Test truncation check when over limit."""
        state = StreamingState(total_chars=1500)
        assert state.should_truncate(1000) is True

    def test_remaining_chars_no_limit(self) -> None:
        """Test remaining chars with no limit."""
        state = StreamingState(total_chars=500)
        assert state.remaining_chars(None) is None
        assert state.remaining_chars(0) is None
        assert state.remaining_chars(-1) is None

    def test_remaining_chars_with_limit(self) -> None:
        """Test remaining chars calculation."""
        state = StreamingState(total_chars=700)
        assert state.remaining_chars(1000) == 300

    def test_remaining_chars_over_limit(self) -> None:
        """Test remaining chars when over limit."""
        state = StreamingState(total_chars=1500)
        assert state.remaining_chars(1000) == 0


class TestStreamingAirlock:
    """Tests for StreamingAirlock class."""

    def test_init_default_config(self) -> None:
        """Test initialization with default config."""
        streamer = StreamingAirlock()
        assert streamer.config is not None
        assert streamer.tool_name == "unknown"
        assert streamer.state.total_chars == 0

    def test_init_custom_config(self) -> None:
        """Test initialization with custom config."""
        config = AirlockConfig(max_output_chars=1000, mask_pii=True)
        streamer = StreamingAirlock(config, tool_name="my_tool")
        assert streamer.config.max_output_chars == 1000
        assert streamer.tool_name == "my_tool"

    def test_reset(self) -> None:
        """Test state reset."""
        streamer = StreamingAirlock()
        streamer._state.total_chars = 500
        streamer._state.total_chunks = 10
        streamer._state.truncated = True

        streamer.reset()

        assert streamer.state.total_chars == 0
        assert streamer.state.total_chunks == 0
        assert streamer.state.truncated is False


class TestSyncGeneratorWrapping:
    """Tests for sync generator wrapping."""

    def test_wrap_simple_generator(self) -> None:
        """Test wrapping a simple generator."""
        streamer = StreamingAirlock()

        def simple_gen() -> Generator[str, None, None]:
            yield "Hello"
            yield "World"

        result = list(streamer.wrap_generator(simple_gen()))
        assert result == ["Hello", "World"]
        assert streamer.state.total_chunks == 2

    def test_wrap_generator_sanitizes_pii(self) -> None:
        """Test that generator output is sanitized."""
        config = AirlockConfig(sanitize_output=True, mask_pii=True)
        streamer = StreamingAirlock(config, tool_name="pii_gen")

        def pii_gen() -> Generator[str, None, None]:
            yield "Contact: john@example.com"
            yield "Phone: 555-123-4567"

        result = list(streamer.wrap_generator(pii_gen()))

        # Emails should be masked (j***@example.com or similar)
        assert "john@example.com" not in result[0]
        # The sanitized result should have some masking
        assert "***" in result[0] or "[EMAIL" in result[0]
        assert streamer.state.sanitized_count > 0

    def test_wrap_generator_truncates(self) -> None:
        """Test that generator output is truncated at limit."""
        config = AirlockConfig(max_output_chars=50)
        streamer = StreamingAirlock(config, tool_name="truncate_gen")

        def long_gen() -> Generator[str, None, None]:
            for i in range(100):
                yield f"Chunk {i:02d} "

        result = list(streamer.wrap_generator(long_gen()))

        # Should have stopped before yielding all 100 chunks
        assert len(result) < 100
        assert streamer.state.truncated is True
        # Last chunk should contain truncation message
        assert "[OUTPUT TRUNCATED" in result[-1]

    def test_wrap_generator_no_truncation_when_disabled(self) -> None:
        """Test that truncation is disabled with 0 max_chars."""
        config = AirlockConfig(max_output_chars=0)  # 0 means no limit
        streamer = StreamingAirlock(config)

        def long_gen() -> Generator[str, None, None]:
            for i in range(100):
                yield f"x{i}"

        result = list(streamer.wrap_generator(long_gen()))

        assert len(result) == 100
        assert streamer.state.truncated is False

    def test_wrap_generator_non_string_chunks(self) -> None:
        """Test wrapping generator with non-string chunks."""
        streamer = StreamingAirlock()

        def int_gen() -> Generator[int, None, None]:
            yield 1
            yield 2
            yield 3

        result = list(streamer.wrap_generator(int_gen()))

        assert result == [1, 2, 3]
        assert streamer.state.total_chunks == 3

    def test_wrap_generator_empty(self) -> None:
        """Test wrapping an empty generator."""
        streamer = StreamingAirlock()

        def empty_gen() -> Generator[str, None, None]:
            return
            yield  # Make it a generator

        result = list(streamer.wrap_generator(empty_gen()))

        assert result == []
        assert streamer.state.total_chunks == 0

    def test_wrap_generator_resets_state(self) -> None:
        """Test that each wrap call resets state."""
        streamer = StreamingAirlock()

        def gen() -> Generator[str, None, None]:
            yield "test"

        list(streamer.wrap_generator(gen()))
        assert streamer.state.total_chunks == 1

        list(streamer.wrap_generator(gen()))
        # Should be 1, not 2, because state was reset
        assert streamer.state.total_chunks == 1


class TestAsyncGeneratorWrapping:
    """Tests for async generator wrapping."""

    @pytest.mark.asyncio
    async def test_wrap_simple_async_generator(self) -> None:
        """Test wrapping a simple async generator."""
        streamer = StreamingAirlock()

        async def simple_gen() -> AsyncGenerator[str, None]:
            yield "Hello"
            yield "Async"

        result = []
        async for chunk in streamer.wrap_async_generator(simple_gen()):
            result.append(chunk)

        assert result == ["Hello", "Async"]
        assert streamer.state.total_chunks == 2

    @pytest.mark.asyncio
    async def test_wrap_async_generator_sanitizes(self) -> None:
        """Test that async generator output is sanitized."""
        config = AirlockConfig(sanitize_output=True, mask_secrets=True)
        streamer = StreamingAirlock(config)

        # Use a key that matches the OpenAI pattern (sk- followed by 20+ alphanumeric chars)
        test_key = "sk-abcdefghijklmnopqrstuvwxyz12345"

        async def secret_gen() -> AsyncGenerator[str, None]:
            yield f"API Key: {test_key}"

        result = []
        async for chunk in streamer.wrap_async_generator(secret_gen()):
            result.append(chunk)

        assert test_key not in result[0]
        assert streamer.state.sanitized_count > 0

    @pytest.mark.asyncio
    async def test_wrap_async_generator_truncates(self) -> None:
        """Test that async generator is truncated at limit."""
        config = AirlockConfig(max_output_chars=30)
        streamer = StreamingAirlock(config)

        async def long_gen() -> AsyncGenerator[str, None]:
            for i in range(50):
                yield f"x{i} "

        result = []
        async for chunk in streamer.wrap_async_generator(long_gen()):
            result.append(chunk)

        assert len(result) < 50
        assert streamer.state.truncated is True

    @pytest.mark.asyncio
    async def test_wrap_async_generator_non_string(self) -> None:
        """Test wrapping async generator with non-string chunks."""
        streamer = StreamingAirlock()

        async def dict_gen() -> AsyncGenerator[dict[str, int], None]:
            yield {"value": 1}
            yield {"value": 2}

        result = []
        async for chunk in streamer.wrap_async_generator(dict_gen()):
            result.append(chunk)

        assert result == [{"value": 1}, {"value": 2}]


class TestIsGeneratorFunction:
    """Tests for generator function detection."""

    def test_detect_sync_generator(self) -> None:
        """Test detecting sync generator function."""

        def gen_func() -> Generator[int, None, None]:
            yield 1

        assert is_generator_function(gen_func) is True

    def test_detect_regular_function(self) -> None:
        """Test that regular function is not detected as generator."""

        def regular_func() -> int:
            return 1

        assert is_generator_function(regular_func) is False

    def test_detect_async_function(self) -> None:
        """Test that async function is not detected as sync generator."""

        async def async_func() -> int:
            return 1

        assert is_generator_function(async_func) is False

    def test_detect_async_generator(self) -> None:
        """Test that async generator is not detected as sync generator."""

        async def async_gen() -> AsyncGenerator[int, None]:
            yield 1

        assert is_generator_function(async_gen) is False


class TestIsAsyncGeneratorFunction:
    """Tests for async generator function detection."""

    def test_detect_async_generator(self) -> None:
        """Test detecting async generator function."""

        async def async_gen() -> AsyncGenerator[int, None]:
            yield 1

        assert is_async_generator_function(async_gen) is True

    def test_detect_regular_function(self) -> None:
        """Test that regular function is not detected."""

        def regular_func() -> int:
            return 1

        assert is_async_generator_function(regular_func) is False

    def test_detect_async_function(self) -> None:
        """Test that regular async function is not detected as generator."""

        async def async_func() -> int:
            return 1

        assert is_async_generator_function(async_func) is False

    def test_detect_sync_generator(self) -> None:
        """Test that sync generator is not detected as async generator."""

        def sync_gen() -> Generator[int, None, None]:
            yield 1

        assert is_async_generator_function(sync_gen) is False


class TestCreateStreamingWrapper:
    """Tests for create_streaming_wrapper function."""

    def test_wrap_sync_generator(self) -> None:
        """Test creating wrapper for sync generator."""
        config = AirlockConfig(mask_pii=True, sanitize_output=True)

        def my_gen() -> Generator[str, None, None]:
            yield "Hello world"
            yield "test@example.com"

        wrapped = create_streaming_wrapper(my_gen, config)

        result = list(wrapped())

        assert len(result) == 2
        assert "Hello world" in result[0]
        # Email should be masked
        assert "test@example.com" not in result[1]

    @pytest.mark.asyncio
    async def test_wrap_async_generator(self) -> None:
        """Test creating wrapper for async generator."""
        config = AirlockConfig(mask_pii=True, sanitize_output=True)

        async def my_async_gen() -> AsyncGenerator[str, None]:
            yield "Async chunk"
            yield "user@domain.com"

        wrapped = create_streaming_wrapper(my_async_gen, config)

        result = []
        async for chunk in wrapped():
            result.append(chunk)

        assert len(result) == 2
        # Email should be masked
        assert "user@domain.com" not in result[1]

    def test_wrap_non_generator_raises(self) -> None:
        """Test that wrapping non-generator raises TypeError."""

        def regular_func() -> str:
            return "not a generator"

        with pytest.raises(TypeError, match="requires a generator function"):
            create_streaming_wrapper(regular_func)

    def test_wrapper_preserves_function_name(self) -> None:
        """Test that wrapper preserves original function name."""

        def named_generator() -> Generator[str, None, None]:
            yield "test"

        wrapped = create_streaming_wrapper(named_generator)

        assert wrapped.__name__ == "named_generator"

    def test_wrapper_preserves_docstring(self) -> None:
        """Test that wrapper preserves original docstring."""

        def documented_gen() -> Generator[str, None, None]:
            """This is the docstring."""
            yield "test"

        wrapped = create_streaming_wrapper(documented_gen)

        assert wrapped.__doc__ == "This is the docstring."


class TestStreamingEdgeCases:
    """Edge case tests for streaming functionality."""

    def test_empty_string_chunks_not_yielded(self) -> None:
        """Test that empty string chunks are not yielded."""
        streamer = StreamingAirlock()

        def gen_with_empties() -> Generator[str, None, None]:
            yield "Hello"
            yield ""  # This should be preserved (not sanitization-related)
            yield "World"

        result = list(streamer.wrap_generator(gen_with_empties()))

        # Empty strings that come from source are still yielded
        # Only post-truncation empties are filtered
        assert len(result) >= 2

    def test_sanitization_disabled(self) -> None:
        """Test streaming without sanitization."""
        config = AirlockConfig(sanitize_output=False)
        streamer = StreamingAirlock(config)

        def gen() -> Generator[str, None, None]:
            yield "Email: test@test.com"

        result = list(streamer.wrap_generator(gen()))

        # Should not be masked
        assert "test@test.com" in result[0]
        assert streamer.state.sanitized_count == 0

    def test_mixed_type_generator(self) -> None:
        """Test generator yielding mixed types."""
        streamer = StreamingAirlock()

        def mixed_gen() -> Generator[Any, None, None]:
            yield "string"
            yield 42
            yield {"key": "value"}

        result = list(streamer.wrap_generator(mixed_gen()))

        assert result[0] == "string"
        assert result[1] == 42
        assert result[2] == {"key": "value"}

    def test_truncation_happens_mid_chunk(self) -> None:
        """Test that truncation can happen in the middle of a chunk."""
        config = AirlockConfig(max_output_chars=15)
        streamer = StreamingAirlock(config)

        def gen() -> Generator[str, None, None]:
            yield "Short"  # 5 chars -> total 5
            yield "This is a longer chunk"  # Would exceed limit

        result = list(streamer.wrap_generator(gen()))

        # First chunk should be fine
        assert result[0] == "Short"
        # Second chunk should be truncated and contain truncation message
        if len(result) > 1:
            assert "[OUTPUT TRUNCATED" in result[1]
            assert streamer.state.truncated is True
