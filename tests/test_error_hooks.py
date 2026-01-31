"""Tests for error recovery hooks (on_validation_error, on_blocked, on_rate_limit)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy


class TestOnValidationErrorHook:
    """Tests for the on_validation_error callback."""

    def test_callback_invoked_on_validation_error(self) -> None:
        """Callback is invoked when validation fails."""
        callback = MagicMock()
        config = AirlockConfig(on_validation_error=callback)

        @Airlock(config=config)
        def typed_tool(x: int) -> int:
            return x * 2

        # Pass wrong type to trigger validation error
        typed_tool(x="not_an_int")  # type: ignore[arg-type]

        # Verify callback was called
        assert callback.called
        call_args = callback.call_args
        assert call_args[0][0] == "typed_tool"  # tool name
        assert isinstance(call_args[0][1], ValidationError)  # error object

    def test_callback_receives_validation_error_details(self) -> None:
        """Callback receives the full ValidationError with error details."""
        captured_error: ValidationError | None = None

        def capture_callback(tool_name: str, error: ValidationError) -> None:
            nonlocal captured_error
            captured_error = error

        config = AirlockConfig(on_validation_error=capture_callback)

        @Airlock(config=config)
        def multi_param_tool(x: int, y: str, z: float) -> str:
            return f"{x}-{y}-{z}"

        # Pass multiple wrong types
        multi_param_tool(x="bad", y=123, z="also_bad")  # type: ignore[arg-type]

        assert captured_error is not None
        # Pydantic error should contain info about invalid fields
        error_fields = {err["loc"][0] for err in captured_error.errors()}
        assert "x" in error_fields

    def test_callback_error_does_not_break_airlock(self) -> None:
        """A failing callback should not break Airlock functionality."""

        def failing_callback(tool_name: str, error: ValidationError) -> None:
            raise RuntimeError("Callback crashed!")

        config = AirlockConfig(on_validation_error=failing_callback)

        @Airlock(config=config)
        def simple_tool(x: int) -> int:
            return x

        # Should still return blocked response despite callback failure
        result = simple_tool(x="bad")  # type: ignore[arg-type]
        assert isinstance(result, dict)
        assert result["status"] == "blocked"

    def test_no_callback_when_validation_succeeds(self) -> None:
        """Callback is not invoked when validation succeeds."""
        callback = MagicMock()
        config = AirlockConfig(on_validation_error=callback)

        @Airlock(config=config)
        def valid_tool(x: int) -> int:
            return x * 2

        result = valid_tool(x=42)
        assert result == 84
        assert not callback.called


class TestOnBlockedHook:
    """Tests for the on_blocked callback."""

    def test_callback_invoked_on_ghost_args_rejection(self) -> None:
        """Callback is invoked when ghost arguments are rejected in strict mode."""
        callback = MagicMock()
        config = AirlockConfig(strict_mode=True, on_blocked=callback)

        @Airlock(config=config)
        def strict_tool(x: int) -> int:
            return x

        # Pass ghost argument in strict mode
        strict_tool(x=42, ghost_arg="should_be_rejected")  # type: ignore[call-arg]

        assert callback.called
        call_args = callback.call_args
        assert call_args[0][0] == "strict_tool"  # tool name
        assert "ghost_arg" in call_args[0][1].lower()  # reason contains ghost info
        assert "ghost_args" in call_args[0][2]  # context dict

    def test_callback_invoked_on_policy_violation(self) -> None:
        """Callback is invoked when security policy blocks a tool."""
        callback = MagicMock()
        config = AirlockConfig(on_blocked=callback)
        policy = SecurityPolicy(denied_tools=["blocked_tool"])

        @Airlock(config=config, policy=policy)
        def blocked_tool(x: int) -> int:
            return x

        blocked_tool(x=42)

        assert callback.called
        call_args = callback.call_args
        assert call_args[0][0] == "blocked_tool"  # tool name
        assert "denied" in call_args[0][1].lower() or "blocked" in call_args[0][1].lower()

    def test_callback_receives_context_dict(self) -> None:
        """Callback receives a context dict with violation details."""
        captured_context: dict[str, Any] = {}

        def capture_callback(tool_name: str, reason: str, context: dict[str, Any]) -> None:
            captured_context.update(context)

        config = AirlockConfig(strict_mode=True, on_blocked=capture_callback)

        @Airlock(config=config)
        def context_tool(x: int) -> int:
            return x

        context_tool(x=42, extra="value")  # type: ignore[call-arg]

        assert "ghost_args" in captured_context
        assert "extra" in captured_context["ghost_args"]

    def test_callback_error_does_not_break_airlock(self) -> None:
        """A failing callback should not break Airlock functionality."""

        def failing_callback(tool_name: str, reason: str, context: dict[str, Any]) -> None:
            raise RuntimeError("Callback crashed!")

        config = AirlockConfig(strict_mode=True, on_blocked=failing_callback)

        @Airlock(config=config)
        def robust_tool(x: int) -> int:
            return x

        result = robust_tool(x=42, ghost="arg")  # type: ignore[call-arg]
        assert isinstance(result, dict)
        assert result["status"] == "blocked"


class TestOnRateLimitHook:
    """Tests for the on_rate_limit callback."""

    def test_callback_invoked_on_rate_limit(self) -> None:
        """Callback is invoked when rate limit is exceeded."""
        callback = MagicMock()
        config = AirlockConfig(on_rate_limit=callback)
        # Set very low rate limit to trigger it
        policy = SecurityPolicy(
            allowed_tools=["limited_tool"],
            rate_limits={"limited_tool": "1/minute"},
        )

        @Airlock(config=config, policy=policy)
        def limited_tool(x: int) -> int:
            return x

        # First call succeeds
        result1 = limited_tool(x=1)
        assert result1 == 1
        assert not callback.called

        # Second call hits rate limit
        result2 = limited_tool(x=2)
        assert isinstance(result2, dict)
        assert result2["status"] == "blocked"

        assert callback.called
        call_args = callback.call_args
        assert call_args[0][0] == "limited_tool"  # tool name
        assert isinstance(call_args[0][1], int)  # retry_after_seconds

    def test_callback_receives_retry_after_seconds(self) -> None:
        """Callback receives the retry_after_seconds value."""
        captured_seconds: int | None = None

        def capture_callback(tool_name: str, retry_after: int) -> None:
            nonlocal captured_seconds
            captured_seconds = retry_after

        config = AirlockConfig(on_rate_limit=capture_callback)
        policy = SecurityPolicy(
            allowed_tools=["limited_tool"],
            rate_limits={"limited_tool": "1/minute"},
        )

        @Airlock(config=config, policy=policy)
        def limited_tool(x: int) -> int:
            return x

        limited_tool(x=1)  # consume the limit
        limited_tool(x=2)  # trigger rate limit

        assert captured_seconds is not None
        assert captured_seconds > 0  # Should be positive

    def test_callback_error_does_not_break_airlock(self) -> None:
        """A failing callback should not break Airlock functionality."""

        def failing_callback(tool_name: str, retry_after: int) -> None:
            raise RuntimeError("Callback crashed!")

        config = AirlockConfig(on_rate_limit=failing_callback)
        policy = SecurityPolicy(
            allowed_tools=["robust_tool"],
            rate_limits={"robust_tool": "1/minute"},
        )

        @Airlock(config=config, policy=policy)
        def robust_tool(x: int) -> int:
            return x

        robust_tool(x=1)  # consume the limit
        result = robust_tool(x=2)  # trigger rate limit

        assert isinstance(result, dict)
        assert result["status"] == "blocked"


class TestMultipleCallbacks:
    """Tests for combining multiple callbacks."""

    def test_all_callbacks_can_be_set(self) -> None:
        """All callbacks can be set simultaneously."""
        validation_callback = MagicMock()
        blocked_callback = MagicMock()
        rate_limit_callback = MagicMock()

        config = AirlockConfig(
            on_validation_error=validation_callback,
            on_blocked=blocked_callback,
            on_rate_limit=rate_limit_callback,
        )

        @Airlock(config=config)
        def multi_tool(x: int) -> int:
            return x

        # Trigger validation error
        multi_tool(x="bad")  # type: ignore[arg-type]

        assert validation_callback.called
        assert not blocked_callback.called
        assert not rate_limit_callback.called

    def test_correct_callback_for_each_error_type(self) -> None:
        """Each error type triggers only its specific callback."""
        validation_calls: list[str] = []
        blocked_calls: list[str] = []
        rate_limit_calls: list[str] = []

        def track_validation(tool_name: str, error: ValidationError) -> None:
            validation_calls.append(tool_name)

        def track_blocked(tool_name: str, reason: str, context: dict[str, Any]) -> None:
            blocked_calls.append(tool_name)

        def track_rate_limit(tool_name: str, retry_after: int) -> None:
            rate_limit_calls.append(tool_name)

        config = AirlockConfig(
            strict_mode=True,
            on_validation_error=track_validation,
            on_blocked=track_blocked,
            on_rate_limit=track_rate_limit,
        )

        # Tool that will be blocked by ghost args
        @Airlock(config=config)
        def ghost_tool(x: int) -> int:
            return x

        ghost_tool(x=42, ghost="arg")  # type: ignore[call-arg]
        assert "ghost_tool" in blocked_calls
        assert "ghost_tool" not in validation_calls
        assert "ghost_tool" not in rate_limit_calls


class TestAsyncCallbacks:
    """Tests for callbacks with async functions."""

    @pytest.mark.asyncio
    async def test_callback_invoked_for_async_validation_error(self) -> None:
        """Callback is invoked for async function validation errors."""
        callback = MagicMock()
        config = AirlockConfig(on_validation_error=callback)

        @Airlock(config=config)
        async def async_tool(x: int) -> int:
            return x * 2

        await async_tool(x="not_an_int")  # type: ignore[arg-type]

        assert callback.called
        assert callback.call_args[0][0] == "async_tool"

    @pytest.mark.asyncio
    async def test_callback_invoked_for_async_blocked(self) -> None:
        """Callback is invoked for async function policy blocks."""
        callback = MagicMock()
        config = AirlockConfig(strict_mode=True, on_blocked=callback)

        @Airlock(config=config)
        async def async_blocked(x: int) -> int:
            return x

        await async_blocked(x=42, extra="ghost")  # type: ignore[call-arg]

        assert callback.called
        assert callback.call_args[0][0] == "async_blocked"
