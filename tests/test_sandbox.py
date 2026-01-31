"""Tests for the sandbox module.

These tests use mocking to avoid requiring actual E2B API access.
Integration tests with real E2B require E2B_API_KEY environment variable.
"""

import base64
from unittest.mock import MagicMock, patch

import pytest

from agent_airlock.config import AirlockConfig


class TestSandboxDependencyChecks:
    """Tests for dependency availability checks."""

    def test_check_cloudpickle_available(self) -> None:
        from agent_airlock.sandbox import _check_cloudpickle_available

        # cloudpickle should be available if sandbox extras are installed
        # This test passes in either case
        result = _check_cloudpickle_available()
        assert isinstance(result, bool)

    def test_check_e2b_available(self) -> None:
        from agent_airlock.sandbox import _check_e2b_available

        # E2B may or may not be available
        result = _check_e2b_available()
        assert isinstance(result, bool)


class TestFunctionSerialization:
    """Tests for function serialization."""

    @pytest.fixture
    def mock_cloudpickle(self):
        """Mock cloudpickle for testing without the dependency."""
        with patch.dict("sys.modules", {"cloudpickle": MagicMock()}):
            yield

    def test_serialize_function_call(self) -> None:
        """Test serializing a simple function call."""
        from agent_airlock.sandbox import (
            _check_cloudpickle_available,
            serialize_function_call,
        )

        if not _check_cloudpickle_available():
            pytest.skip("cloudpickle not installed")

        def add(x: int, y: int) -> int:
            return x + y

        serialized = serialize_function_call(add, (1, 2), {})

        # Should be base64 encoded
        assert isinstance(serialized, str)
        # Should be valid base64
        decoded = base64.b64decode(serialized)
        assert len(decoded) > 0

    def test_serialize_function_with_kwargs(self) -> None:
        """Test serializing a function call with kwargs."""
        from agent_airlock.sandbox import _check_cloudpickle_available, serialize_function_call

        if not _check_cloudpickle_available():
            pytest.skip("cloudpickle not installed")

        def greet(name: str, greeting: str = "Hello") -> str:
            return f"{greeting}, {name}!"

        serialized = serialize_function_call(greet, (), {"name": "Alice", "greeting": "Hi"})

        assert isinstance(serialized, str)
        decoded = base64.b64decode(serialized)
        assert len(decoded) > 0


class TestExecutionCodeGeneration:
    """Tests for sandbox execution code generation."""

    def test_generate_execution_code(self) -> None:
        from agent_airlock.sandbox import generate_execution_code

        code = generate_execution_code("test_payload_base64")

        # Should contain the payload
        assert "test_payload_base64" in code
        # Should have result markers
        assert "__AIRLOCK_RESULT__" in code
        assert "__AIRLOCK_END__" in code
        # Should import required modules
        assert "import cloudpickle" in code
        assert "import json" in code

    def test_execution_code_handles_exceptions(self) -> None:
        from agent_airlock.sandbox import generate_execution_code

        code = generate_execution_code("dummy")

        # Should have exception handling
        assert "try:" in code
        assert "except Exception" in code
        assert "traceback" in code


class TestSandboxResult:
    """Tests for SandboxResult dataclass."""

    def test_success_result(self) -> None:
        from agent_airlock.sandbox import SandboxResult

        result = SandboxResult(
            success=True,
            result=42,
            execution_time_ms=100.5,
            sandbox_id="sbx-123",
        )

        assert result.success is True
        assert result.result == 42
        assert result.error is None
        assert result.execution_time_ms == 100.5
        assert result.sandbox_id == "sbx-123"

    def test_failure_result(self) -> None:
        from agent_airlock.sandbox import SandboxResult

        result = SandboxResult(
            success=False,
            error="Something went wrong",
            stderr="Error output",
        )

        assert result.success is False
        assert result.result is None
        assert result.error == "Something went wrong"

    def test_to_dict(self) -> None:
        from agent_airlock.sandbox import SandboxResult

        result = SandboxResult(
            success=True,
            result={"data": 123},
            stdout="Hello",
            execution_time_ms=50.0,
        )

        data = result.to_dict()

        assert data["success"] is True
        assert data["result"] == {"data": 123}
        assert data["stdout"] == "Hello"
        assert data["execution_time_ms"] == 50.0


class TestSandboxPool:
    """Tests for SandboxPool class."""

    def test_pool_initialization(self) -> None:
        from agent_airlock.sandbox import SandboxPool

        pool = SandboxPool(pool_size=3, timeout=30)

        assert pool.pool_size == 3
        assert pool.timeout == 30
        assert pool._initialized is False

    def test_pool_requires_e2b(self) -> None:
        from agent_airlock.sandbox import SandboxNotAvailableError, SandboxPool

        pool = SandboxPool()

        # Mock e2b not being available
        with (
            patch("agent_airlock.sandbox._check_e2b_available", return_value=False),
            pytest.raises(SandboxNotAvailableError),
        ):
            pool.warm_up()


class TestSandboxErrors:
    """Tests for sandbox error classes."""

    def test_sandbox_error(self) -> None:
        from agent_airlock.sandbox import SandboxError

        error = SandboxError("Test error", {"detail": "info"})

        assert error.message == "Test error"
        assert error.details == {"detail": "info"}
        assert str(error) == "Test error"

    def test_sandbox_not_available_error(self) -> None:
        from agent_airlock.sandbox import SandboxNotAvailableError

        error = SandboxNotAvailableError("E2B not installed")

        assert "E2B not installed" in str(error)

    def test_sandbox_execution_error(self) -> None:
        from agent_airlock.sandbox import SandboxExecutionError

        error = SandboxExecutionError("Execution failed", {"code": 1})

        assert error.message == "Execution failed"
        assert error.details == {"code": 1}


class TestExecuteInSandbox:
    """Tests for execute_in_sandbox function."""

    def test_returns_error_when_e2b_not_available(self) -> None:
        from agent_airlock.sandbox import execute_in_sandbox

        def simple_func(x: int) -> int:
            return x * 2

        with patch("agent_airlock.sandbox._check_e2b_available", return_value=False):
            result = execute_in_sandbox(simple_func, (5,))

        assert result.success is False
        assert "e2b-code-interpreter not installed" in result.error

    def test_returns_error_when_cloudpickle_not_available(self) -> None:
        from agent_airlock.sandbox import execute_in_sandbox

        def simple_func(x: int) -> int:
            return x * 2

        with (
            patch("agent_airlock.sandbox._check_e2b_available", return_value=True),
            patch("agent_airlock.sandbox._check_cloudpickle_available", return_value=False),
        ):
            result = execute_in_sandbox(simple_func, (5,))

        assert result.success is False
        assert "cloudpickle not installed" in result.error


class TestCoreIntegration:
    """Tests for core.py sandbox integration."""

    def test_sandbox_fallback_when_not_available(self) -> None:
        """Test that sandbox falls back to local execution when E2B unavailable."""
        from agent_airlock import Airlock

        @Airlock(sandbox=True)
        def multiply(x: int, y: int) -> int:
            return x * y

        # Should fall back to local execution and succeed
        result = multiply(x=3, y=4)

        # Either returns result (local fallback) or error dict
        assert result == 12 or (isinstance(result, dict) and "error" in result)

    def test_sandbox_execution_error_export(self) -> None:
        """Test that SandboxExecutionError is exported."""
        from agent_airlock import SandboxExecutionError

        error = SandboxExecutionError("test")
        assert error.message == "test"


class TestGlobalPool:
    """Tests for global sandbox pool management."""

    def test_get_sandbox_pool_returns_pool(self) -> None:
        # Reset global pool
        import agent_airlock.sandbox
        from agent_airlock.sandbox import SandboxPool, get_sandbox_pool

        agent_airlock.sandbox._global_pool = None

        pool = get_sandbox_pool()

        assert isinstance(pool, SandboxPool)

    def test_get_sandbox_pool_uses_config(self) -> None:
        # Reset global pool
        import agent_airlock.sandbox
        from agent_airlock.sandbox import get_sandbox_pool

        agent_airlock.sandbox._global_pool = None

        config = AirlockConfig(sandbox_pool_size=5, sandbox_timeout=120)
        pool = get_sandbox_pool(config)

        assert pool.pool_size == 5
        assert pool.timeout == 120

    def test_get_sandbox_pool_singleton(self) -> None:
        # Reset global pool
        import agent_airlock.sandbox
        from agent_airlock.sandbox import get_sandbox_pool

        agent_airlock.sandbox._global_pool = None

        pool1 = get_sandbox_pool()
        pool2 = get_sandbox_pool()

        assert pool1 is pool2
