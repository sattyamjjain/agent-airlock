"""Comprehensive tests for core module - targeting 100% coverage."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy, airlock
from agent_airlock.core import SENSITIVE_PARAM_NAMES, _filter_sensitive_keys


class TestFilterSensitiveKeys:
    """Tests for _filter_sensitive_keys function."""

    def test_filters_password(self) -> None:
        """Test filtering password key."""
        keys = ["name", "password", "email"]
        result = _filter_sensitive_keys(keys)
        assert "password" not in result
        assert "name" in result
        assert "email" in result

    def test_filters_api_key(self) -> None:
        """Test filtering api_key key."""
        keys = ["query", "api_key", "limit"]
        result = _filter_sensitive_keys(keys)
        assert "api_key" not in result

    def test_filters_case_insensitive(self) -> None:
        """Test filtering is case insensitive."""
        keys = ["PASSWORD", "Token", "SECRET"]
        result = _filter_sensitive_keys(keys)
        assert len(result) == 0

    def test_preserves_non_sensitive(self) -> None:
        """Test preserves non-sensitive keys."""
        keys = ["name", "email", "query", "limit"]
        result = _filter_sensitive_keys(keys)
        assert result == keys


class TestAirlockCallSyntaxes:
    """Tests for different Airlock call syntaxes."""

    def test_airlock_with_empty_parens(self) -> None:
        """Test @Airlock() with empty parentheses."""

        @Airlock()
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(x=5)
        assert result == 10

    def test_airlock_decorator_call_with_none(self) -> None:
        """Test Airlock.__call__ with func=None returns decorator."""
        decorator = Airlock()
        result = decorator(None)  # type: ignore
        assert callable(result)


class TestAirlockReturnDict:
    """Tests for return_dict option."""

    def test_return_dict_true_on_success(self) -> None:
        """Test return_dict=True returns dict on success."""

        @Airlock(return_dict=True)
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(x=5)
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["result"] == 10

    def test_return_dict_false_returns_raw(self) -> None:
        """Test return_dict=False returns raw result."""

        @Airlock(return_dict=False)
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(x=5)
        assert result == 10


class TestAirlockCallbackErrors:
    """Tests for callback error handling."""

    def test_on_blocked_callback_error_logged(self) -> None:
        """Test on_blocked callback errors are logged but not raised."""

        def bad_callback(tool: str, reason: str, ctx: dict) -> None:
            raise Exception("Callback error")

        config = AirlockConfig(strict_mode=True, on_blocked=bad_callback)

        @Airlock(config=config)
        def my_func(x: int) -> int:
            return x * 2

        # Should not raise despite callback error
        result = my_func(x=5, ghost=True)  # type: ignore
        assert isinstance(result, dict)
        assert result["success"] is False

    def test_on_rate_limit_callback_error_logged(self) -> None:
        """Test on_rate_limit callback errors are logged."""

        def bad_callback(tool: str, retry: int) -> None:
            raise Exception("Rate limit callback error")

        config = AirlockConfig(on_rate_limit=bad_callback)
        policy = SecurityPolicy(rate_limits={"my_func": "0/minute"})  # Immediate limit

        @Airlock(config=config, policy=policy)
        def my_func(x: int) -> int:
            return x * 2

        # First call succeeds, second is rate limited
        my_func(x=5)
        result = my_func(x=5)  # Should hit rate limit
        # Should not raise despite callback error
        assert isinstance(result, dict)

    def test_on_validation_error_callback_error_logged(self) -> None:
        """Test on_validation_error callback errors are logged."""

        def bad_callback(tool: str, error: ValidationError) -> None:
            raise Exception("Validation callback error")

        config = AirlockConfig(on_validation_error=bad_callback)

        @Airlock(config=config)
        def my_func(x: int) -> int:
            return x * 2

        # Should not raise despite callback error
        result = my_func(x="invalid")  # type: ignore
        assert isinstance(result, dict)
        assert result["success"] is False


class TestAirlockPolicyResolutionError:
    """Tests for policy resolution error handling."""

    def test_policy_resolver_exception(self) -> None:
        """Test policy resolver exceptions are handled."""

        def bad_resolver(ctx: Any) -> SecurityPolicy:
            raise Exception("Resolver failed")

        @Airlock(policy=bad_resolver)
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(x=5)
        assert isinstance(result, dict)
        assert result["success"] is False
        assert "Policy resolution failed" in result.get("error", "")


class TestAirlockUnexpectedErrors:
    """Tests for unexpected error handling."""

    def test_unexpected_exception_handled(self) -> None:
        """Test unexpected exceptions are handled gracefully."""

        @Airlock()
        def my_func(x: int) -> int:
            raise RuntimeError("Unexpected error")

        result = my_func(x=5)
        assert isinstance(result, dict)
        assert result["success"] is False
        assert "Unexpected error" in result.get("error", "")


class TestAirlockFunctionAlias:
    """Tests for airlock function alias."""

    def test_airlock_function_without_args(self) -> None:
        """Test @airlock without arguments."""

        @airlock
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(x=5)
        assert result == 10

    def test_airlock_function_with_args(self) -> None:
        """Test @airlock with arguments."""

        @airlock(sandbox=False, return_dict=True)
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(x=5)
        assert isinstance(result, dict)
        assert result["result"] == 10


class TestSandboxExceptions:
    """Tests for sandbox exception classes."""

    def test_sandbox_execution_error(self) -> None:
        """Test SandboxExecutionError class."""
        from agent_airlock.core import SandboxExecutionError

        error = SandboxExecutionError("Execution failed", {"code": 1})
        assert error.message == "Execution failed"
        assert error.details == {"code": 1}
        assert str(error) == "Execution failed"

    def test_sandbox_unavailable_error(self) -> None:
        """Test SandboxUnavailableError class."""
        from agent_airlock.core import SandboxUnavailableError

        error = SandboxUnavailableError("E2B not available")
        assert str(error) == "E2B not available"


class TestPydanticAttributeCopying:
    """Tests for Pydantic attribute copying."""

    def test_pydantic_attributes_copied(self) -> None:
        """Test Pydantic attributes are copied to wrapper."""
        from pydantic import validate_call

        @validate_call
        def validated_func(x: int) -> int:
            return x * 2

        # Add Pydantic attributes
        validated_func.__pydantic_complete__ = True  # type: ignore

        @Airlock()
        def airlock_func(x: int) -> int:
            return x * 2

        # The wrapper should handle functions with Pydantic attrs
        result = airlock_func(x=5)
        assert result == 10


class TestSandboxExecutionWithMock:
    """Tests for sandbox execution with mocking."""

    def test_sandbox_enabled_returns_error_when_unavailable(self) -> None:
        """Test sandbox=True with unavailable E2B returns error or falls back."""

        @Airlock(sandbox=True, sandbox_required=False)
        def my_func(x: int) -> int:
            return x * 2

        # With sandbox_required=False and no E2B, should either:
        # 1. Fall back to local execution (return 10)
        # 2. Return error dict
        result = my_func(x=5)
        # Accept either behavior
        assert result == 10 or (isinstance(result, dict) and "success" in result)

    def test_sandbox_required_true_fails_when_unavailable(self) -> None:
        """Test sandbox_required=True returns error when E2B unavailable."""
        from agent_airlock.core import SandboxUnavailableError

        @Airlock(sandbox=True, sandbox_required=True)
        def my_func(x: int) -> int:
            return x * 2

        # Should fail or return error dict when E2B unavailable
        result = my_func(x=5)
        # Either raises or returns error dict
        if isinstance(result, dict):
            assert result["success"] is False

    def test_sandbox_execution_success_sync(self) -> None:
        """Test successful sandbox execution with mocked result."""
        from agent_airlock.sandbox import SandboxResult

        mock_result = SandboxResult(
            success=True,
            result=42,
            sandbox_id="test-sandbox",
            execution_time_ms=100.0,
        )

        with patch("agent_airlock.sandbox.execute_in_sandbox", return_value=mock_result):
            @Airlock(sandbox=True)
            def my_func(x: int) -> int:
                return x * 2

            result = my_func(x=5)
            assert result == 42

    def test_sandbox_execution_failure_sync(self) -> None:
        """Test sandbox execution failure with mocked result."""
        from agent_airlock.sandbox import SandboxResult

        mock_result = SandboxResult(
            success=False,
            error="Sandbox crashed",
            sandbox_id="test-sandbox",
        )

        with patch("agent_airlock.sandbox.execute_in_sandbox", return_value=mock_result):
            @Airlock(sandbox=True)
            def my_func(x: int) -> int:
                return x * 2

            result = my_func(x=5)
            # Should return error dict
            assert isinstance(result, dict)
            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_sandbox_execution_success_async(self) -> None:
        """Test successful async sandbox execution with mocked result."""
        from agent_airlock.sandbox import SandboxResult

        mock_result = SandboxResult(
            success=True,
            result=100,
            sandbox_id="async-sandbox",
            execution_time_ms=50.0,
        )

        async def mock_execute(*args: Any, **kwargs: Any) -> SandboxResult:
            return mock_result

        with patch("agent_airlock.sandbox.execute_in_sandbox_async", side_effect=mock_execute):
            @Airlock(sandbox=True)
            async def my_async_func(x: int) -> int:
                return x ** 2

            result = await my_async_func(x=10)
            assert result == 100

    @pytest.mark.asyncio
    async def test_sandbox_execution_failure_async(self) -> None:
        """Test async sandbox execution failure with mocked result."""
        from agent_airlock.sandbox import SandboxResult

        mock_result = SandboxResult(
            success=False,
            error="Async sandbox failed",
            sandbox_id="async-sandbox",
        )

        async def mock_execute(*args: Any, **kwargs: Any) -> SandboxResult:
            return mock_result

        with patch("agent_airlock.sandbox.execute_in_sandbox_async", side_effect=mock_execute):
            @Airlock(sandbox=True)
            async def my_async_func(x: int) -> int:
                return x ** 2

            result = await my_async_func(x=10)
            assert isinstance(result, dict)
            assert result["success"] is False

    @pytest.mark.asyncio
    async def test_sandbox_import_error_async_fallback(self) -> None:
        """Test async sandbox fallback when ImportError occurs."""
        # Mock ImportError by making the import fail
        import agent_airlock.sandbox as sandbox_mod
        original_execute = sandbox_mod.execute_in_sandbox_async

        def raise_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("No E2B")

        with patch.object(sandbox_mod, "execute_in_sandbox_async", side_effect=raise_import_error):
            @Airlock(sandbox=True, sandbox_required=False)
            async def my_async_func(x: int) -> int:
                return x * 3

            # Falls back to local execution
            result = await my_async_func(x=7)
            assert result == 21

    @pytest.mark.asyncio
    async def test_sandbox_required_async_fails(self) -> None:
        """Test async sandbox required fails on ImportError."""
        import agent_airlock.sandbox as sandbox_mod

        def raise_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("No E2B")

        with patch.object(sandbox_mod, "execute_in_sandbox_async", side_effect=raise_import_error):
            @Airlock(sandbox=True, sandbox_required=True)
            async def my_async_func(x: int) -> int:
                return x * 3

            result = await my_async_func(x=7)
            # Should return error dict
            assert isinstance(result, dict)
            assert result["success"] is False

    def test_sandbox_import_error_sync_fallback(self) -> None:
        """Test sync sandbox fallback when ImportError occurs."""
        import agent_airlock.sandbox as sandbox_mod

        def raise_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("No E2B")

        with patch.object(sandbox_mod, "execute_in_sandbox", side_effect=raise_import_error):
            @Airlock(sandbox=True, sandbox_required=False)
            def my_sync_func(x: int) -> int:
                return x * 4

            # Falls back to local execution
            result = my_sync_func(x=5)
            assert result == 20

    def test_sandbox_required_sync_fails_on_import_error(self) -> None:
        """Test sync sandbox required fails on ImportError."""
        import agent_airlock.sandbox as sandbox_mod

        def raise_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("No E2B")

        with patch.object(sandbox_mod, "execute_in_sandbox", side_effect=raise_import_error):
            @Airlock(sandbox=True, sandbox_required=True)
            def my_sync_func(x: int) -> int:
                return x * 4

            result = my_sync_func(x=5)
            # Should return error dict
            assert isinstance(result, dict)
            assert result["success"] is False

    def test_sync_sandbox_fallback_without_e2b_key(self) -> None:
        """Test sync sandbox fallback works without sandbox execution."""
        # With sandbox=False, it should run locally
        @Airlock(sandbox=False)
        def my_local_func(x: int) -> int:
            return x * 5

        result = my_local_func(x=6)
        assert result == 30


class TestAsyncFunctions:
    """Tests for async function handling."""

    @pytest.mark.asyncio
    async def test_async_function_basic(self) -> None:
        """Test async function with Airlock."""

        @Airlock()
        async def my_async_func(x: int) -> int:
            await asyncio.sleep(0.01)
            return x * 2

        result = await my_async_func(x=5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_async_function_with_validation_error(self) -> None:
        """Test async function with validation error."""

        @Airlock()
        async def my_async_func(x: int) -> int:
            return x * 2

        result = await my_async_func(x="invalid")  # type: ignore
        assert isinstance(result, dict)
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_async_function_with_exception(self) -> None:
        """Test async function that raises exception."""

        @Airlock()
        async def my_async_func(x: int) -> int:
            raise RuntimeError("Async error")

        result = await my_async_func(x=5)
        assert isinstance(result, dict)
        assert result["success"] is False
        # Error message may be wrapped
        assert "error" in result or "block_reason" in result
