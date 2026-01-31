"""Comprehensive tests for streaming module - targeting 100% coverage."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Generator

import pytest

from agent_airlock import AirlockConfig
from agent_airlock.streaming import StreamingAirlock, StreamingState


class TestStreamingState:
    """Tests for StreamingState dataclass."""

    def test_remaining_chars_with_limit(self) -> None:
        """Test remaining_chars with limit set."""
        state = StreamingState()
        state.total_chars = 500
        remaining = state.remaining_chars(1000)
        assert remaining == 500

    def test_remaining_chars_no_limit(self) -> None:
        """Test remaining_chars with no limit."""
        state = StreamingState()
        remaining = state.remaining_chars(None)
        assert remaining is None

    def test_add_chars(self) -> None:
        """Test add_chars method."""
        state = StreamingState()
        state.add_chars(100)
        assert state.total_chars == 100
        assert state.total_chunks == 1
        state.add_chars(50)
        assert state.total_chars == 150
        assert state.total_chunks == 2

    def test_should_truncate(self) -> None:
        """Test should_truncate method."""
        state = StreamingState()
        state.total_chars = 1000
        assert state.should_truncate(500) is True
        assert state.should_truncate(2000) is False
        assert state.should_truncate(None) is False


class TestStreamingAirlock:
    """Tests for StreamingAirlock class."""

    def test_init_default(self) -> None:
        """Test default initialization."""
        streamer = StreamingAirlock()
        assert streamer.config is not None
        assert streamer.tool_name == "unknown"  # Default value

    def test_init_with_config(self) -> None:
        """Test initialization with config."""
        config = AirlockConfig(mask_pii=True, max_output_chars=1000)
        streamer = StreamingAirlock(config=config, tool_name="test_tool")
        assert streamer.config is config
        assert streamer.tool_name == "test_tool"

    def test_reset(self) -> None:
        """Test reset method."""
        streamer = StreamingAirlock()
        streamer._state.total_chars = 100
        streamer._state.truncated = True
        streamer.reset()
        assert streamer._state.total_chars == 0
        assert streamer._state.truncated is False

    def test_state_property(self) -> None:
        """Test state property."""
        streamer = StreamingAirlock()
        assert isinstance(streamer.state, StreamingState)

    def test_truncated_state(self) -> None:
        """Test accessing truncated state."""
        streamer = StreamingAirlock()
        assert streamer._state.truncated is False
        streamer._state.truncated = True
        assert streamer._state.truncated is True

    def test_wrap_generator_simple(self) -> None:
        """Test wrapping a simple generator."""
        config = AirlockConfig(mask_pii=True)
        streamer = StreamingAirlock(config=config)

        def gen() -> Generator[str, None, None]:
            yield "Hello "
            yield "World"

        result = list(streamer.wrap_generator(gen()))
        assert "".join(result) == "Hello World"

    def test_wrap_generator_with_pii(self) -> None:
        """Test wrapping generator with PII masking."""
        config = AirlockConfig(mask_pii=True, sanitize_output=True)
        streamer = StreamingAirlock(config=config)

        def gen() -> Generator[str, None, None]:
            yield "Email: test@example.com"

        result = list(streamer.wrap_generator(gen()))
        output = "".join(result)
        assert "test@example.com" not in output

    def test_wrap_generator_with_truncation(self) -> None:
        """Test wrapping generator with truncation."""
        config = AirlockConfig(max_output_chars=50)
        streamer = StreamingAirlock(config=config)

        def gen() -> Generator[str, None, None]:
            for i in range(100):
                yield f"Chunk {i} "

        result = list(streamer.wrap_generator(gen()))
        output = "".join(result)
        assert len(output) <= 100  # Should be truncated
        assert streamer._state.truncated is True

    def test_wrap_generator_already_truncated(self) -> None:
        """Test generator stops after truncation."""
        config = AirlockConfig(max_output_chars=10)
        streamer = StreamingAirlock(config=config)

        chunks_yielded = []

        def gen() -> Generator[str, None, None]:
            for i in range(100):
                chunks_yielded.append(i)
                yield "x" * 20

        list(streamer.wrap_generator(gen()))
        # Should stop early due to truncation
        assert len(chunks_yielded) < 100

    def test_wrap_generator_non_string_chunks(self) -> None:
        """Test wrapping generator with non-string chunks."""
        streamer = StreamingAirlock()

        def gen() -> Generator[dict, None, None]:  # type: ignore
            yield {"key": "value1"}
            yield {"key": "value2"}

        result = list(streamer.wrap_generator(gen()))  # type: ignore
        assert len(result) == 2
        assert result[0] == {"key": "value1"}

    def test_wrap_generator_empty(self) -> None:
        """Test wrapping empty generator."""
        streamer = StreamingAirlock()

        def gen() -> Generator[str, None, None]:
            return
            yield  # Never reached

        result = list(streamer.wrap_generator(gen()))
        assert result == []

    @pytest.mark.asyncio
    async def test_wrap_async_generator_simple(self) -> None:
        """Test wrapping an async generator."""
        config = AirlockConfig(mask_pii=True)
        streamer = StreamingAirlock(config=config)

        async def gen() -> AsyncGenerator[str, None]:
            yield "Hello "
            await asyncio.sleep(0.01)
            yield "World"

        result = []
        async for chunk in streamer.wrap_async_generator(gen()):
            result.append(chunk)
        assert "".join(result) == "Hello World"

    @pytest.mark.asyncio
    async def test_wrap_async_generator_with_truncation(self) -> None:
        """Test async generator with truncation."""
        config = AirlockConfig(max_output_chars=50)
        streamer = StreamingAirlock(config=config)

        async def gen() -> AsyncGenerator[str, None]:
            for i in range(100):
                yield f"Chunk {i} "

        result = []
        async for chunk in streamer.wrap_async_generator(gen()):
            result.append(chunk)
        assert streamer._state.truncated is True

    @pytest.mark.asyncio
    async def test_wrap_async_generator_already_truncated(self) -> None:
        """Test async generator stops after truncation."""
        config = AirlockConfig(max_output_chars=10)
        streamer = StreamingAirlock(config=config)

        chunks_yielded = []

        async def gen() -> AsyncGenerator[str, None]:
            for i in range(100):
                chunks_yielded.append(i)
                yield "x" * 20

        async for _ in streamer.wrap_async_generator(gen()):
            pass
        # Should stop early
        assert len(chunks_yielded) < 100


class TestCreateStreamingWrapper:
    """Tests for create_streaming_wrapper function."""

    def test_create_wrapper(self) -> None:
        """Test creating a streaming wrapper."""
        from agent_airlock import create_streaming_wrapper

        config = AirlockConfig(mask_pii=True)

        def my_gen(count: int) -> Generator[str, None, None]:
            for i in range(count):
                yield f"Item {i}"

        wrapped = create_streaming_wrapper(my_gen, config)
        result = list(wrapped(count=3))
        assert len(result) == 3


class TestGeneratorDetection:
    """Tests for generator detection functions."""

    def test_is_generator_function_true(self) -> None:
        """Test detecting generator function."""
        from agent_airlock import is_generator_function

        def gen() -> Generator[int, None, None]:
            yield 1

        assert is_generator_function(gen) is True

    def test_is_generator_function_false(self) -> None:
        """Test detecting non-generator function."""
        from agent_airlock import is_generator_function

        def regular() -> int:
            return 1

        assert is_generator_function(regular) is False

    def test_is_async_generator_function_true(self) -> None:
        """Test detecting async generator function."""
        from agent_airlock import is_async_generator_function

        async def async_gen() -> AsyncGenerator[int, None]:
            yield 1

        assert is_async_generator_function(async_gen) is True

    def test_is_async_generator_function_false(self) -> None:
        """Test detecting non-async-generator function."""
        from agent_airlock import is_async_generator_function

        async def regular() -> int:
            return 1

        assert is_async_generator_function(regular) is False
