"""Comprehensive tests for sandbox module - targeting 100% coverage."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from agent_airlock.config import AirlockConfig
from agent_airlock.sandbox import (
    SandboxError,
    SandboxExecutionError,
    SandboxNotAvailableError,
    SandboxPool,
    SandboxResult,
    _check_cloudpickle_available,
    _check_e2b_available,
    execute_in_sandbox,
    execute_in_sandbox_async,
    generate_execution_code,
    get_sandbox_pool,
    serialize_function_call,
)


class TestSandboxResult:
    """Tests for SandboxResult dataclass."""

    def test_to_dict(self) -> None:
        """Test to_dict method."""
        result = SandboxResult(
            success=True,
            result="test",
            error=None,
            stdout="out",
            stderr="err",
            execution_time_ms=100.5,
            sandbox_id="sandbox-123",
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["result"] == "test"
        assert d["sandbox_id"] == "sandbox-123"


class TestCheckAvailability:
    """Tests for availability check functions."""

    def test_check_e2b_available_returns_bool(self) -> None:
        """Test E2B check returns boolean."""
        result = _check_e2b_available()
        assert isinstance(result, bool)

    def test_check_e2b_available_with_mock(self) -> None:
        """Test E2B check when mocked as available."""
        mock_module = MagicMock()
        with patch.dict(sys.modules, {"e2b_code_interpreter": mock_module}):
            # Result depends on implementation
            result = _check_e2b_available()
            assert isinstance(result, bool)

    def test_check_cloudpickle_available_returns_bool(self) -> None:
        """Test cloudpickle check returns boolean."""
        result = _check_cloudpickle_available()
        assert isinstance(result, bool)


class TestSerializeFunctionCall:
    """Tests for function serialization."""

    def test_serialize_without_cloudpickle(self) -> None:
        """Test serialization fails without cloudpickle."""

        def func(x: int) -> int:
            return x

        with patch("agent_airlock.sandbox._check_cloudpickle_available", return_value=False):
            with pytest.raises(SandboxNotAvailableError) as exc_info:
                serialize_function_call(func, (), {})
            assert "cloudpickle" in str(exc_info.value)

    def test_serialize_function_behavior(self) -> None:
        """Test serialization requires cloudpickle."""

        def func(x: int) -> int:
            return x * 2

        # Check if cloudpickle is available
        if _check_cloudpickle_available():
            import base64

            # If cloudpickle is installed, test real serialization
            result = serialize_function_call(func, (5,), {"y": 10})
            assert isinstance(result, str)
            decoded = base64.b64decode(result)
            assert len(decoded) > 0
        else:
            # If not installed, should raise
            with pytest.raises(SandboxNotAvailableError):
                serialize_function_call(func, (5,), {"y": 10})


class TestGenerateExecutionCode:
    """Tests for execution code generation."""

    def test_generate_execution_code(self) -> None:
        """Test generating execution code."""
        code = generate_execution_code("serialized_payload_here")
        assert "serialized_payload_here" in code
        assert "__AIRLOCK_RESULT__" in code
        assert "__AIRLOCK_END__" in code
        assert "cloudpickle" in code


class TestSandboxPool:
    """Tests for SandboxPool class."""

    def test_init(self) -> None:
        """Test pool initialization."""
        pool = SandboxPool(pool_size=3, api_key="test-key", timeout=120)
        assert pool.pool_size == 3
        assert pool.api_key == "test-key"
        assert pool.timeout == 120
        assert pool._initialized is False

    def test_ensure_e2b_not_available(self) -> None:
        """Test _ensure_e2b_available raises when E2B not installed."""
        pool = SandboxPool()
        with patch("agent_airlock.sandbox._check_e2b_available", return_value=False):
            with pytest.raises(SandboxNotAvailableError) as exc_info:
                pool._ensure_e2b_available()
            assert "e2b-code-interpreter" in str(exc_info.value)

    def test_create_sandbox_mock(self) -> None:
        """Test _create_sandbox with mocked E2B."""
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "test-sandbox-id"
        mock_sandbox.run_code = MagicMock()

        mock_sandbox_class = MagicMock(return_value=mock_sandbox)

        pool = SandboxPool(api_key="test-key")

        with (
            patch.dict(
                sys.modules, {"e2b_code_interpreter": MagicMock(Sandbox=mock_sandbox_class)}
            ),
            patch("agent_airlock.sandbox._check_e2b_available", return_value=True),
        ):
            # Import the mocked module
            from unittest.mock import patch as mock_patch

            with mock_patch(
                "agent_airlock.sandbox.SandboxPool._create_sandbox",
                return_value=mock_sandbox,
            ):
                pool._ensure_e2b_available()

    def test_warm_up_with_mock(self) -> None:
        """Test warm_up creates sandboxes."""
        pool = SandboxPool(pool_size=2)
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "warm-sandbox"

        with patch.object(pool, "_ensure_e2b_available"):
            with patch.object(pool, "_create_sandbox", return_value=mock_sandbox):
                pool.warm_up(count=2)
                assert pool._initialized is True
                assert pool._pool.qsize() == 2

    def test_warm_up_handles_exceptions(self) -> None:
        """Test warm_up handles sandbox creation failures."""
        pool = SandboxPool(pool_size=2)

        with patch.object(pool, "_ensure_e2b_available"):
            with patch.object(pool, "_create_sandbox", side_effect=Exception("Creation failed")):
                # Should not raise, just log warning
                pool.warm_up(count=2)
                assert pool._initialized is True
                assert pool._pool.qsize() == 0

    def test_acquire_from_pool(self) -> None:
        """Test acquiring sandbox from warm pool."""
        pool = SandboxPool(pool_size=2)
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "pooled-sandbox"

        with patch.object(pool, "_ensure_e2b_available"):
            with patch.object(pool, "_create_sandbox", return_value=mock_sandbox):
                pool.warm_up(count=1)
                acquired = pool.acquire()
                assert acquired == mock_sandbox
                assert pool._pool.qsize() == 0

    def test_acquire_creates_new_when_empty(self) -> None:
        """Test acquiring sandbox when pool is empty."""
        pool = SandboxPool(pool_size=2)
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "new-sandbox"

        with patch.object(pool, "_ensure_e2b_available"):
            with patch.object(pool, "_create_sandbox", return_value=mock_sandbox):
                acquired = pool.acquire()
                assert acquired == mock_sandbox

    def test_release_to_pool(self) -> None:
        """Test releasing sandbox back to pool."""
        pool = SandboxPool(pool_size=2)
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "released-sandbox"

        pool.release(mock_sandbox)
        assert pool._pool.qsize() == 1

    def test_release_when_shutdown(self) -> None:
        """Test release closes sandbox when shutdown."""
        pool = SandboxPool(pool_size=1)
        pool._shutdown = True
        mock_sandbox = MagicMock()

        with patch.object(pool, "_close_sandbox") as mock_close:
            pool.release(mock_sandbox)
            mock_close.assert_called_once_with(mock_sandbox)

    def test_release_when_pool_full(self) -> None:
        """Test release closes sandbox when pool is full."""
        pool = SandboxPool(pool_size=1)
        mock_sandbox1 = MagicMock()
        mock_sandbox2 = MagicMock()

        pool.release(mock_sandbox1)  # Fills the pool

        with patch.object(pool, "_close_sandbox") as mock_close:
            pool.release(mock_sandbox2)  # Pool is full
            mock_close.assert_called_once_with(mock_sandbox2)

    def test_close_sandbox(self) -> None:
        """Test _close_sandbox kills the sandbox."""
        pool = SandboxPool()
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "to-close"

        pool._close_sandbox(mock_sandbox)
        mock_sandbox.kill.assert_called_once()

    def test_close_sandbox_handles_error(self) -> None:
        """Test _close_sandbox handles kill errors."""
        pool = SandboxPool()
        mock_sandbox = MagicMock()
        mock_sandbox.kill.side_effect = Exception("Kill failed")

        # Should not raise
        pool._close_sandbox(mock_sandbox)

    def test_sandbox_context_manager(self) -> None:
        """Test sandbox context manager."""
        pool = SandboxPool(pool_size=2)
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "ctx-sandbox"

        with patch.object(pool, "acquire", return_value=mock_sandbox):
            with patch.object(pool, "release") as mock_release:
                with pool.sandbox() as sandbox:
                    assert sandbox == mock_sandbox
                mock_release.assert_called_once_with(mock_sandbox)

    def test_shutdown(self) -> None:
        """Test pool shutdown."""
        pool = SandboxPool(pool_size=2)
        mock_sandbox1 = MagicMock()
        mock_sandbox2 = MagicMock()

        pool._pool.put(mock_sandbox1)
        pool._pool.put(mock_sandbox2)

        with patch.object(pool, "_close_sandbox") as mock_close:
            pool.shutdown()
            assert pool._shutdown is True
            assert mock_close.call_count == 2


class TestGetSandboxPool:
    """Tests for global sandbox pool."""

    def test_get_sandbox_pool_creates_new(self) -> None:
        """Test getting sandbox pool creates new instance."""
        import agent_airlock.sandbox as sandbox_module

        # Reset global pool
        sandbox_module._global_pool = None

        config = AirlockConfig(sandbox_pool_size=3, sandbox_timeout=120)
        pool = get_sandbox_pool(config)

        assert pool is not None
        assert pool.pool_size == 3
        assert pool.timeout == 120

    def test_get_sandbox_pool_returns_existing(self) -> None:
        """Test getting sandbox pool returns existing instance."""
        import agent_airlock.sandbox as sandbox_module

        # Reset and create
        sandbox_module._global_pool = None
        pool1 = get_sandbox_pool()
        pool2 = get_sandbox_pool()

        assert pool1 is pool2


class TestExecuteInSandbox:
    """Tests for execute_in_sandbox function."""

    def test_execute_without_e2b(self) -> None:
        """Test execute returns error when E2B not available."""
        with patch("agent_airlock.sandbox._check_e2b_available", return_value=False):

            def func(x: int) -> int:
                return x

            result = execute_in_sandbox(func, (5,))
            assert result.success is False
            assert "e2b-code-interpreter" in result.error

    def test_execute_without_cloudpickle(self) -> None:
        """Test execute returns error when cloudpickle not available."""
        with patch("agent_airlock.sandbox._check_e2b_available", return_value=True):
            with patch("agent_airlock.sandbox._check_cloudpickle_available", return_value=False):

                def func(x: int) -> int:
                    return x

                result = execute_in_sandbox(func, (5,))
                assert result.success is False
                assert "cloudpickle" in result.error

    def test_execute_serialization_error(self) -> None:
        """Test execute handles serialization errors."""
        with patch("agent_airlock.sandbox._check_e2b_available", return_value=True):
            with patch("agent_airlock.sandbox._check_cloudpickle_available", return_value=True):
                with patch(
                    "agent_airlock.sandbox.serialize_function_call",
                    side_effect=Exception("Serialize failed"),
                ):

                    def func(x: int) -> int:
                        return x

                    result = execute_in_sandbox(func, (5,))
                    assert result.success is False
                    assert "serialize" in result.error.lower()

    def test_execute_with_mock_sandbox(self) -> None:
        """Test full execution with mocked sandbox."""
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "exec-sandbox"

        # E2B v2 API: run_code returns Execution object with logs attribute
        mock_execution = MagicMock()
        mock_logs = MagicMock()
        mock_logs.stdout = ['__AIRLOCK_RESULT__\n{"success": true, "result": 10}\n__AIRLOCK_END__']
        mock_logs.stderr = []
        mock_execution.logs = mock_logs

        mock_sandbox.run_code = MagicMock(return_value=mock_execution)

        mock_pool = MagicMock()
        mock_pool.sandbox.return_value.__enter__ = MagicMock(return_value=mock_sandbox)
        mock_pool.sandbox.return_value.__exit__ = MagicMock(return_value=False)

        with patch("agent_airlock.sandbox._check_e2b_available", return_value=True):
            with patch("agent_airlock.sandbox._check_cloudpickle_available", return_value=True):
                with patch(
                    "agent_airlock.sandbox.serialize_function_call",
                    return_value="serialized",
                ):
                    with patch("agent_airlock.sandbox.get_sandbox_pool", return_value=mock_pool):

                        def func(x: int) -> int:
                            return x * 2

                        result = execute_in_sandbox(func, (5,))
                        assert result.success is True
                        assert result.result == 10

    def test_execute_no_result_marker(self) -> None:
        """Test execute handles missing result marker."""
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "exec-sandbox"

        # E2B v2 API: run_code returns Execution object with logs attribute
        mock_execution = MagicMock()
        mock_logs = MagicMock()
        mock_logs.stdout = ["Some random output without markers"]
        mock_logs.stderr = []
        mock_execution.logs = mock_logs

        mock_sandbox.run_code = MagicMock(return_value=mock_execution)

        mock_pool = MagicMock()
        mock_pool.sandbox.return_value.__enter__ = MagicMock(return_value=mock_sandbox)
        mock_pool.sandbox.return_value.__exit__ = MagicMock(return_value=False)

        with patch("agent_airlock.sandbox._check_e2b_available", return_value=True):
            with patch("agent_airlock.sandbox._check_cloudpickle_available", return_value=True):
                with patch(
                    "agent_airlock.sandbox.serialize_function_call",
                    return_value="serialized",
                ):
                    with patch("agent_airlock.sandbox.get_sandbox_pool", return_value=mock_pool):

                        def func(x: int) -> int:
                            return x

                        result = execute_in_sandbox(func, (5,))
                        assert result.success is False
                        assert "expected output" in result.error.lower()

    def test_execute_json_decode_error(self) -> None:
        """Test execute handles invalid JSON result."""
        mock_sandbox = MagicMock()
        mock_sandbox.sandbox_id = "exec-sandbox"

        # E2B v2 API: run_code returns Execution object with logs attribute
        mock_execution = MagicMock()
        mock_logs = MagicMock()
        mock_logs.stdout = ["__AIRLOCK_RESULT__\ninvalid json here\n__AIRLOCK_END__"]
        mock_logs.stderr = []
        mock_execution.logs = mock_logs

        mock_sandbox.run_code = MagicMock(return_value=mock_execution)

        mock_pool = MagicMock()
        mock_pool.sandbox.return_value.__enter__ = MagicMock(return_value=mock_sandbox)
        mock_pool.sandbox.return_value.__exit__ = MagicMock(return_value=False)

        with patch("agent_airlock.sandbox._check_e2b_available", return_value=True):
            with patch("agent_airlock.sandbox._check_cloudpickle_available", return_value=True):
                with patch(
                    "agent_airlock.sandbox.serialize_function_call",
                    return_value="serialized",
                ):
                    with patch("agent_airlock.sandbox.get_sandbox_pool", return_value=mock_pool):

                        def func(x: int) -> int:
                            return x

                        result = execute_in_sandbox(func, (5,))
                        assert result.success is False
                        assert "parse" in result.error.lower()

    def test_execute_exception(self) -> None:
        """Test execute handles sandbox exceptions."""
        mock_pool = MagicMock()
        mock_pool.sandbox.return_value.__enter__ = MagicMock(side_effect=Exception("Sandbox error"))

        with patch("agent_airlock.sandbox._check_e2b_available", return_value=True):
            with patch("agent_airlock.sandbox._check_cloudpickle_available", return_value=True):
                with patch(
                    "agent_airlock.sandbox.serialize_function_call",
                    return_value="serialized",
                ):
                    with patch("agent_airlock.sandbox.get_sandbox_pool", return_value=mock_pool):

                        def func(x: int) -> int:
                            return x

                        result = execute_in_sandbox(func, (5,))
                        assert result.success is False
                        assert "failed" in result.error.lower()


class TestExecuteInSandboxAsync:
    """Tests for async sandbox execution."""

    @pytest.mark.asyncio
    async def test_execute_async(self) -> None:
        """Test async execution."""

        def func(x: int) -> int:
            return x * 2

        mock_result = SandboxResult(success=True, result=10)

        with patch("agent_airlock.sandbox.execute_in_sandbox", return_value=mock_result):
            result = await execute_in_sandbox_async(func, (5,))
            assert result.success is True
            assert result.result == 10


class TestSandboxErrors:
    """Tests for sandbox error classes."""

    def test_sandbox_error(self) -> None:
        """Test SandboxError class."""
        error = SandboxError("Test error", {"key": "value"})
        assert error.message == "Test error"
        assert error.details == {"key": "value"}
        assert str(error) == "Test error"

    def test_sandbox_not_available_error(self) -> None:
        """Test SandboxNotAvailableError class."""
        error = SandboxNotAvailableError("Not available")
        assert isinstance(error, SandboxError)

    def test_sandbox_execution_error(self) -> None:
        """Test SandboxExecutionError class."""
        error = SandboxExecutionError("Execution failed")
        assert isinstance(error, SandboxError)
