"""Tests for sandbox_backend module (V0.4.0)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agent_airlock.sandbox_backend import (
    DockerBackend,
    E2BBackend,
    LocalBackend,
    SandboxBackend,
    SandboxResult,
    get_default_backend,
)


class TestSandboxResult:
    """Test the SandboxResult dataclass."""

    def test_success_result(self) -> None:
        """Test creating a success result."""
        result = SandboxResult(success=True, result="output", error=None)
        assert result.success is True
        assert result.result == "output"
        assert result.error is None

    def test_error_result(self) -> None:
        """Test creating an error result."""
        result = SandboxResult(success=False, result=None, error="Error message")
        assert result.success is False
        assert result.result is None
        assert result.error == "Error message"

    def test_result_with_execution_time(self) -> None:
        """Test result with execution time."""
        result = SandboxResult(success=True, result="output", error=None, execution_time_ms=150.5)
        assert result.execution_time_ms == 150.5

    def test_result_to_dict(self) -> None:
        """Test result to_dict method."""
        result = SandboxResult(
            success=True,
            result="output",
            error=None,
            sandbox_id="abc123",
            backend="e2b",
        )
        data = result.to_dict()
        assert data["success"] is True
        assert data["result"] == "output"
        assert data["sandbox_id"] == "abc123"
        assert data["backend"] == "e2b"


class TestLocalBackend:
    """Test the LocalBackend implementation."""

    def test_requires_allow_unsafe(self) -> None:
        """Test that LocalBackend requires allow_unsafe=True."""
        with pytest.raises(ValueError, match="NO security isolation"):
            LocalBackend()

    def test_name(self) -> None:
        """Test backend name."""
        backend = LocalBackend(allow_unsafe=True)
        assert backend.name == "local_unsafe"

    def test_is_available(self) -> None:
        """Test that local backend is always available."""
        backend = LocalBackend(allow_unsafe=True)
        assert backend.is_available() is True

    def test_execute_simple_function(self) -> None:
        """Test executing a simple function."""
        backend = LocalBackend(allow_unsafe=True)

        def add(a: int, b: int) -> int:
            return a + b

        result = backend.execute(add, (2, 3), {})
        assert result.success is True
        assert result.result == 5

    def test_execute_with_kwargs(self) -> None:
        """Test executing function with kwargs."""
        backend = LocalBackend(allow_unsafe=True)

        def greet(name: str, greeting: str = "Hello") -> str:
            return f"{greeting}, {name}!"

        result = backend.execute(greet, ("World",), {"greeting": "Hi"})
        assert result.success is True
        assert result.result == "Hi, World!"

    def test_execute_handles_exception(self) -> None:
        """Test that exceptions are caught."""
        backend = LocalBackend(allow_unsafe=True)

        def failing_func() -> None:
            raise ValueError("Test error")

        result = backend.execute(failing_func, (), {})
        assert result.success is False
        assert "Test error" in result.error

    def test_execute_records_execution_time(self) -> None:
        """Test that execution time is recorded."""
        backend = LocalBackend(allow_unsafe=True)

        def quick_func() -> int:
            return 42

        result = backend.execute(quick_func, (), {})
        assert result.execution_time_ms is not None
        assert result.execution_time_ms >= 0

    def test_execute_with_none_return(self) -> None:
        """Test local backend with function returning None."""
        backend = LocalBackend(allow_unsafe=True)

        def returns_none() -> None:
            pass

        result = backend.execute(returns_none, (), {})
        assert result.success is True
        assert result.result is None

    def test_execute_with_complex_return_type(self) -> None:
        """Test local backend with complex return type."""
        backend = LocalBackend(allow_unsafe=True)

        def returns_complex() -> dict[str, list[int]]:
            return {"numbers": [1, 2, 3]}

        result = backend.execute(returns_complex, (), {})
        assert result.success is True
        assert result.result == {"numbers": [1, 2, 3]}

    def test_execute_with_closure(self) -> None:
        """Test local backend with closure."""
        backend = LocalBackend(allow_unsafe=True)
        multiplier = 10

        def multiply(x: int) -> int:
            return x * multiplier

        result = backend.execute(multiply, (5,), {})
        assert result.success is True
        assert result.result == 50


class TestE2BBackend:
    """Test the E2BBackend implementation."""

    def test_name(self) -> None:
        """Test backend name."""
        backend = E2BBackend()
        assert backend.name == "e2b"

    def test_is_available_checks_import(self) -> None:
        """Test availability check."""
        backend = E2BBackend(api_key="test-api-key")
        # Result depends on whether e2b is installed
        _ = backend.is_available()


class TestDockerBackend:
    """Test the DockerBackend implementation."""

    def test_name(self) -> None:
        """Test backend name."""
        backend = DockerBackend()
        assert backend.name == "docker"

    def test_is_available_checks_docker(self) -> None:
        """Test availability checks for docker."""
        backend = DockerBackend()
        # Result depends on system, just verify it doesn't crash
        _ = backend.is_available()

    def test_image_configuration(self) -> None:
        """Test Docker image can be configured."""
        backend = DockerBackend(image="python:3.11-slim")
        assert backend.image == "python:3.11-slim"


class TestGetDefaultBackend:
    """Test the get_default_backend factory function."""

    def test_returns_sandbox_backend(self) -> None:
        """Test that function returns a SandboxBackend."""
        backend = get_default_backend()
        assert isinstance(backend, SandboxBackend)

    def test_prefers_e2b_when_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test E2B is preferred when available."""
        monkeypatch.setenv("E2B_API_KEY", "test-api-key")
        # Mock E2B availability
        with patch.object(E2BBackend, "is_available", return_value=True):
            backend = get_default_backend()
            assert backend.name == "e2b"

    def test_falls_back_to_docker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fallback to Docker when E2B unavailable."""
        monkeypatch.delenv("E2B_API_KEY", raising=False)
        with (
            patch.object(E2BBackend, "is_available", return_value=False),
            patch.object(DockerBackend, "is_available", return_value=True),
        ):
            backend = get_default_backend()
            assert backend.name == "docker"

    def test_falls_back_to_local(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fallback to local when others unavailable."""
        monkeypatch.delenv("E2B_API_KEY", raising=False)
        with (
            patch.object(E2BBackend, "is_available", return_value=False),
            patch.object(DockerBackend, "is_available", return_value=False),
        ):
            backend = get_default_backend()
            assert backend.name == "local_unsafe"


class TestSandboxBackendInterface:
    """Test the SandboxBackend abstract interface."""

    def test_local_backend_implements_interface(self) -> None:
        """Test LocalBackend implements full interface."""
        backend = LocalBackend(allow_unsafe=True)
        assert hasattr(backend, "execute")
        assert hasattr(backend, "is_available")
        assert hasattr(backend, "name")
        assert callable(backend.execute)
        assert callable(backend.is_available)

    def test_e2b_backend_implements_interface(self) -> None:
        """Test E2BBackend implements full interface."""
        backend = E2BBackend()
        assert hasattr(backend, "execute")
        assert hasattr(backend, "is_available")
        assert hasattr(backend, "name")

    def test_docker_backend_implements_interface(self) -> None:
        """Test DockerBackend implements full interface."""
        backend = DockerBackend()
        assert hasattr(backend, "execute")
        assert hasattr(backend, "is_available")
        assert hasattr(backend, "name")


class TestBackendConfiguration:
    """Test backend configuration options."""

    def test_e2b_with_pool_size(self) -> None:
        """Test E2B backend with pool size."""
        backend = E2BBackend(pool_size=5)
        assert backend.pool_size == 5

    def test_docker_with_memory_limit(self) -> None:
        """Test Docker backend with memory limit."""
        backend = DockerBackend(memory_limit="1g")
        assert backend.memory_limit == "1g"

    def test_docker_with_network_mode(self) -> None:
        """Test Docker backend with network mode."""
        backend = DockerBackend(network_mode="bridge")
        assert backend.network_mode == "bridge"
