"""Tests for async function support in Airlock decorator."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy
from agent_airlock.core import airlock


class TestAsyncDetection:
    """Tests for async function detection."""

    def test_detects_sync_function(self) -> None:
        """Test that sync functions are detected correctly."""

        @Airlock()
        def sync_func(x: int) -> int:
            return x * 2

        # Wrapped function should be sync
        assert not asyncio.iscoroutinefunction(sync_func)

    def test_detects_async_function(self) -> None:
        """Test that async functions are detected correctly."""

        @Airlock()
        async def async_func(x: int) -> int:
            return x * 2

        # Wrapped function should still be async
        assert asyncio.iscoroutinefunction(async_func)

    def test_preserves_function_signature(self) -> None:
        """Test that function signature is preserved for both sync and async."""

        @Airlock()
        def sync_func(x: int, y: str = "default") -> str:
            return f"{x}-{y}"

        @Airlock()
        async def async_func(x: int, y: str = "default") -> str:
            return f"{x}-{y}"

        sync_sig = inspect.signature(sync_func)
        async_sig = inspect.signature(async_func)

        assert "x" in sync_sig.parameters
        assert "y" in sync_sig.parameters
        assert sync_sig.parameters["y"].default == "default"

        assert "x" in async_sig.parameters
        assert "y" in async_sig.parameters
        assert async_sig.parameters["y"].default == "default"


class TestAsyncExecution:
    """Tests for async function execution."""

    @pytest.mark.asyncio
    async def test_async_function_execution(self) -> None:
        """Test that async functions execute correctly."""

        @Airlock()
        async def async_add(a: int, b: int) -> int:
            await asyncio.sleep(0.01)
            return a + b

        result = await async_add(a=2, b=3)
        assert result == 5

    @pytest.mark.asyncio
    async def test_async_function_with_await(self) -> None:
        """Test async function that actually awaits something."""

        @Airlock()
        async def fetch_data(url: str) -> dict[str, Any]:
            await asyncio.sleep(0.01)  # Simulate async I/O
            return {"url": url, "status": 200}

        result = await fetch_data(url="https://example.com")
        assert result["url"] == "https://example.com"
        assert result["status"] == 200

    @pytest.mark.asyncio
    async def test_async_function_concurrent_execution(self) -> None:
        """Test that async functions can run concurrently."""
        call_order: list[int] = []

        @Airlock()
        async def slow_func(id: int, delay: float) -> int:
            await asyncio.sleep(delay)
            call_order.append(id)
            return id

        # Start multiple calls concurrently
        tasks = [
            asyncio.create_task(slow_func(id=1, delay=0.03)),
            asyncio.create_task(slow_func(id=2, delay=0.01)),
            asyncio.create_task(slow_func(id=3, delay=0.02)),
        ]
        results = await asyncio.gather(*tasks)

        assert results == [1, 2, 3]
        # Due to different delays, order should be 2, 3, 1
        assert call_order == [2, 3, 1]

    def test_sync_function_execution(self) -> None:
        """Test that sync functions still work correctly."""

        @Airlock()
        def sync_multiply(a: int, b: int) -> int:
            return a * b

        result = sync_multiply(a=4, b=5)
        assert result == 20


class TestAsyncValidation:
    """Tests for validation in async functions."""

    @pytest.mark.asyncio
    async def test_async_type_validation(self) -> None:
        """Test that type validation works for async functions."""

        @Airlock()
        async def typed_func(x: int, y: str) -> str:
            return f"{x}-{y}"

        # Valid call
        result = await typed_func(x=42, y="hello")
        assert result == "42-hello"

        # Invalid type - should return error dict
        result = await typed_func(x="not_an_int", y="hello")  # type: ignore
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"

    @pytest.mark.asyncio
    async def test_async_ghost_argument_handling(self) -> None:
        """Test ghost argument handling in async functions."""
        config = AirlockConfig(strict_mode=True)

        @Airlock(config=config)
        async def strict_func(x: int) -> int:
            return x * 2

        # Valid call
        result = await strict_func(x=10)
        assert result == 20

        # Ghost argument in strict mode should be rejected
        result = await strict_func(x=10, unknown_arg="ghost")  # type: ignore
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"
        assert "unknown_arg" in str(result.get("error", "")).lower()

    @pytest.mark.asyncio
    async def test_async_permissive_mode(self) -> None:
        """Test permissive mode with async functions."""
        config = AirlockConfig(strict_mode=False)

        @Airlock(config=config)
        async def permissive_func(x: int) -> int:
            return x * 2

        # Ghost argument should be stripped silently
        result = await permissive_func(x=10, extra="ignored")  # type: ignore
        assert result == 20


class TestAsyncPolicy:
    """Tests for policy enforcement in async functions."""

    @pytest.mark.asyncio
    async def test_async_policy_allowed(self) -> None:
        """Test that allowed tools work with async."""
        policy = SecurityPolicy(allowed_tools=["async_tool"])

        @Airlock(policy=policy)
        async def async_tool(x: int) -> int:
            return x * 2

        result = await async_tool(x=5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_async_policy_denied(self) -> None:
        """Test that denied tools are blocked with async."""
        policy = SecurityPolicy(denied_tools=["blocked_async"])

        @Airlock(policy=policy)
        async def blocked_async(x: int) -> int:
            return x * 2

        result = await blocked_async(x=5)
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"


class TestAsyncOutputSanitization:
    """Tests for output sanitization in async functions."""

    @pytest.mark.asyncio
    async def test_async_pii_masking(self) -> None:
        """Test PII masking works with async functions."""
        config = AirlockConfig(mask_pii=True, mask_secrets=True)

        @Airlock(config=config)
        async def get_user_data() -> str:
            await asyncio.sleep(0.01)
            return "Contact: john@example.com, SSN: 123-45-6789"

        result = await get_user_data()
        assert "john@example.com" not in result
        assert "123-45-6789" not in result

    @pytest.mark.asyncio
    async def test_async_output_truncation(self) -> None:
        """Test output truncation works with async functions."""
        config = AirlockConfig(max_output_chars=50)

        @Airlock(config=config)
        async def get_long_data() -> str:
            return "x" * 200

        result = await get_long_data()
        assert len(result) <= 100  # Should be truncated


class TestAsyncErrorHandling:
    """Tests for error handling in async functions."""

    @pytest.mark.asyncio
    async def test_async_exception_handling(self) -> None:
        """Test that exceptions in async functions are handled."""

        @Airlock()
        async def failing_func() -> str:
            raise ValueError("Something went wrong")

        result = await failing_func()
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"
        assert "error" in str(result).lower()

    @pytest.mark.asyncio
    async def test_async_timeout_handling(self) -> None:
        """Test that long-running async functions work correctly."""

        @Airlock()
        async def slow_func(delay: float) -> str:
            await asyncio.sleep(delay)
            return "done"

        # Should complete normally
        result = await slow_func(delay=0.01)
        assert result == "done"


class TestMixedSyncAsync:
    """Tests for mixed sync/async usage."""

    def test_sync_and_async_same_config(self) -> None:
        """Test that same config works for both sync and async."""
        config = AirlockConfig(strict_mode=True, mask_pii=True)

        @Airlock(config=config)
        def sync_func(x: int) -> int:
            return x * 2

        @Airlock(config=config)
        async def async_func(x: int) -> int:
            return x * 3

        # Sync works
        assert sync_func(x=5) == 10

        # Async works (run in event loop)
        result = asyncio.run(async_func(x=5))
        assert result == 15

    @pytest.mark.asyncio
    async def test_async_calling_sync_internally(self) -> None:
        """Test async function that calls sync code internally."""

        @Airlock()
        async def async_wrapper(x: int) -> int:
            # Simulate some sync processing
            sync_result = x * 2
            await asyncio.sleep(0.01)
            return sync_result + 1

        result = await async_wrapper(x=10)
        assert result == 21


class TestAirlockFunctionDecorator:
    """Tests for the lowercase airlock() function decorator."""

    @pytest.mark.asyncio
    async def test_airlock_func_async(self) -> None:
        """Test airlock() function works with async."""

        @airlock
        async def async_func(x: int) -> int:
            return x * 2

        assert asyncio.iscoroutinefunction(async_func)
        result = await async_func(x=5)
        assert result == 10

    def test_airlock_func_sync(self) -> None:
        """Test airlock() function works with sync."""

        @airlock
        def sync_func(x: int) -> int:
            return x * 2

        result = sync_func(x=5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_airlock_func_with_options(self) -> None:
        """Test airlock() with options for async."""
        config = AirlockConfig(strict_mode=True)

        @airlock(config=config)
        async def strict_async(x: int) -> int:
            return x * 2

        result = await strict_async(x=5)
        assert result == 10
