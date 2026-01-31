"""Real E2B sandbox integration tests.

These tests require:
- E2B_API_KEY environment variable set
- e2b-code-interpreter installed
- cloudpickle installed

Run with: E2B_API_KEY=your_key pytest tests/test_sandbox_integration.py -v

NOTE: cloudpickle has cross-version limitations. Functions pickled in Python 3.13+
may not work in E2B sandboxes running Python 3.10-3.12 due to bytecode changes.
Tests that require function serialization may be skipped on newer Python versions.
"""

from __future__ import annotations

import os
import sys
import pytest

from agent_airlock import Airlock, AirlockConfig
from agent_airlock.sandbox import (
    SandboxPool,
    SandboxResult,
    execute_in_sandbox,
    execute_in_sandbox_async,
    get_sandbox_pool,
    serialize_function_call,
    generate_execution_code,
    _check_e2b_available,
    _check_cloudpickle_available,
)


# Skip all tests if E2B is not available
pytestmark = pytest.mark.skipif(
    not _check_e2b_available() or not os.environ.get("E2B_API_KEY"),
    reason="E2B SDK not installed or E2B_API_KEY not set",
)

# Python 3.13+ has bytecode changes that are incompatible with earlier versions
# E2B sandboxes typically run Python 3.10-3.12
PYTHON_313_PLUS = sys.version_info >= (3, 13)


class TestRealSandboxSerialization:
    """Tests for real serialization with cloudpickle."""

    def test_serialize_simple_function(self) -> None:
        """Test serializing a simple function."""
        def add(x: int, y: int) -> int:
            return x + y

        serialized = serialize_function_call(add, (1, 2), {})
        assert isinstance(serialized, str)
        assert len(serialized) > 0

    def test_serialize_with_kwargs(self) -> None:
        """Test serializing function with kwargs."""
        def greet(name: str, greeting: str = "Hello") -> str:
            return f"{greeting}, {name}!"

        serialized = serialize_function_call(greet, (), {"name": "World"})
        assert isinstance(serialized, str)

    def test_generate_execution_code(self) -> None:
        """Test generating execution code."""
        payload = "test_payload_base64"
        code = generate_execution_code(payload)
        assert "test_payload_base64" in code
        assert "__AIRLOCK_RESULT__" in code


class TestRealSandboxExecution:
    """Tests for real sandbox execution.

    NOTE: These tests require compatible Python versions between local
    and E2B sandbox. Python 3.13+ bytecode is not compatible with
    earlier versions due to changes in the bytecode format.
    """

    @pytest.mark.skipif(
        PYTHON_313_PLUS,
        reason="Python 3.13+ bytecode incompatible with E2B sandbox Python version"
    )
    def test_execute_simple_function(self) -> None:
        """Test executing a simple function in sandbox."""
        def multiply(x: int, y: int) -> int:
            return x * y

        config = AirlockConfig(sandbox_timeout=60)
        result = execute_in_sandbox(multiply, (3, 4), config=config)

        assert isinstance(result, SandboxResult)
        assert result.success is True
        assert result.result == 12
        assert result.sandbox_id is not None

    @pytest.mark.skipif(
        PYTHON_313_PLUS,
        reason="Python 3.13+ bytecode incompatible with E2B sandbox Python version"
    )
    def test_execute_function_with_error(self) -> None:
        """Test executing a function that raises error."""
        def fail() -> None:
            raise ValueError("Intentional error")

        result = execute_in_sandbox(fail, ())
        assert result.success is False
        assert "ValueError" in result.error or "Intentional error" in result.error

    @pytest.mark.skipif(
        PYTHON_313_PLUS,
        reason="Python 3.13+ bytecode incompatible with E2B sandbox Python version"
    )
    def test_execute_with_string_result(self) -> None:
        """Test executing function returning string."""
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        result = execute_in_sandbox(greet, ("World",))
        assert result.success is True
        assert result.result == "Hello, World!"

    @pytest.mark.skipif(
        PYTHON_313_PLUS,
        reason="Python 3.13+ bytecode incompatible with E2B sandbox Python version"
    )
    @pytest.mark.asyncio
    async def test_execute_async(self) -> None:
        """Test async sandbox execution."""
        def compute(x: int) -> int:
            return x ** 2

        result = await execute_in_sandbox_async(compute, (5,))
        assert result.success is True
        assert result.result == 25


class TestRealSandboxPool:
    """Tests for real sandbox pool."""

    def test_pool_acquire_release(self) -> None:
        """Test acquiring and releasing sandbox."""
        pool = SandboxPool(pool_size=1, timeout=60)

        try:
            sandbox = pool.acquire()
            assert sandbox is not None
            assert sandbox.sandbox_id is not None

            # Release back to pool
            pool.release(sandbox)
        finally:
            pool.shutdown()

    def test_pool_context_manager(self) -> None:
        """Test pool context manager."""
        pool = SandboxPool(pool_size=1, timeout=60)

        try:
            with pool.sandbox() as sandbox:
                assert sandbox is not None
                # Run simple code
                sandbox.run_code("print('hello')")
        finally:
            pool.shutdown()


class TestAirlockWithRealSandbox:
    """Tests for Airlock decorator with real sandbox.

    NOTE: These tests require compatible Python versions between local
    and E2B sandbox. Python 3.13+ bytecode is not compatible with
    earlier versions.
    """

    @pytest.mark.skipif(
        PYTHON_313_PLUS,
        reason="Python 3.13+ bytecode incompatible with E2B sandbox Python version"
    )
    def test_airlock_sandbox_success(self) -> None:
        """Test Airlock with sandbox=True succeeds."""

        @Airlock(sandbox=True, sandbox_required=True, return_dict=True)
        def safe_compute(x: int, y: int) -> int:
            return x + y

        result = safe_compute(x=10, y=20)
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["result"] == 30

    @pytest.mark.skipif(
        PYTHON_313_PLUS,
        reason="Python 3.13+ bytecode incompatible with E2B sandbox Python version"
    )
    def test_airlock_sandbox_with_validation(self) -> None:
        """Test Airlock sandbox with type validation."""

        @Airlock(sandbox=True, return_dict=True)
        def typed_func(value: int) -> int:
            return value * 2

        # Valid call
        result = typed_func(value=5)
        assert result["success"] is True
        assert result["result"] == 10

    @pytest.mark.skipif(
        PYTHON_313_PLUS,
        reason="Python 3.13+ bytecode incompatible with E2B sandbox Python version"
    )
    @pytest.mark.asyncio
    async def test_airlock_async_sandbox(self) -> None:
        """Test Airlock async function with sandbox."""

        @Airlock(sandbox=True, return_dict=True)
        async def async_compute(x: int) -> int:
            return x ** 2

        result = await async_compute(x=4)
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["result"] == 16
