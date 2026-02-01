"""Pluggable sandbox backend interface for Agent-Airlock (V0.4.0).

Makes sandbox execution pluggable so enterprises can use their preferred
isolation technology instead of being locked to E2B.

Backends:
    - E2BBackend: E2B Firecracker MicroVM (default, cloud-based)
    - DockerBackend: Docker containers (enterprise/on-prem)
    - LocalBackend: No isolation (UNSAFE - development only)

The key insight: agent-airlock's value is the POLICY ENFORCEMENT
(schema validation, RBAC, rate limiting, PII masking) - not the sandbox.
Making the sandbox pluggable proves this architectural distinction.

Usage:
    # Use E2B (default)
    config = AirlockConfig()

    # Use Docker for on-prem
    from agent_airlock.sandbox_backend import DockerBackend
    config = AirlockConfig(sandbox_backend=DockerBackend())

    # Use local execution (UNSAFE)
    from agent_airlock.sandbox_backend import LocalBackend
    config = AirlockConfig(sandbox_backend=LocalBackend(allow_unsafe=True))
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

import structlog

if TYPE_CHECKING:
    from .config import AirlockConfig

logger = structlog.get_logger("agent-airlock.sandbox_backend")

R = TypeVar("R")


@dataclass
class SandboxResult:
    """Result from sandbox execution.

    Attributes:
        success: Whether execution succeeded.
        result: Return value from the function (if successful).
        error: Error message (if failed).
        stdout: Standard output from execution.
        stderr: Standard error from execution.
        execution_time_ms: Time taken in milliseconds.
        sandbox_id: Identifier for the sandbox instance.
        backend: Name of the backend that executed the code.
    """

    success: bool
    result: Any = None
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: float = 0.0
    sandbox_id: str | None = None
    backend: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "result": self.result,
            "error": self.error,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "execution_time_ms": self.execution_time_ms,
            "sandbox_id": self.sandbox_id,
            "backend": self.backend,
        }


class SandboxBackend(ABC):
    """Abstract base class for sandbox backends.

    All sandbox backends must implement this interface. The interface is
    intentionally minimal to make it easy to add new backends.

    Subclasses must implement:
        - execute(): Run a function in the sandbox
        - is_available(): Check if the backend can be used
        - name: Property returning the backend name
    """

    @abstractmethod
    def execute(
        self,
        func: Callable[..., R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        timeout: int = 60,
    ) -> SandboxResult:
        """Execute a function in the sandbox.

        Args:
            func: The function to execute.
            args: Positional arguments for the function.
            kwargs: Keyword arguments for the function.
            timeout: Maximum execution time in seconds.

        Returns:
            SandboxResult with the execution outcome.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is available for use.

        Returns:
            True if the backend can be used (dependencies installed, etc.).
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the backend name for logging and identification."""
        ...

    def warmup(self) -> None:
        """Optional: Pre-warm the sandbox for faster first execution.

        The default implementation does nothing. Backends that support
        warm pools (like E2B) should override this.
        """
        ...  # noqa: B027 - intentionally empty, subclasses override

    def shutdown(self) -> None:
        """Optional: Clean up sandbox resources.

        The default implementation does nothing. Backends that maintain
        pools or persistent connections should override this.
        """
        ...  # noqa: B027 - intentionally empty, subclasses override


class E2BBackend(SandboxBackend):
    """E2B Firecracker MicroVM backend (default).

    Uses E2B's cloud-based sandboxes for secure, isolated execution.
    Recommended for production use.

    Attributes:
        api_key: E2B API key (falls back to E2B_API_KEY env var).
        pool_size: Number of warm sandboxes to maintain.
        timeout: Default execution timeout in seconds.
    """

    def __init__(
        self,
        api_key: str | None = None,
        pool_size: int = 2,
        timeout: int = 60,
    ) -> None:
        """Initialize E2B backend.

        Args:
            api_key: E2B API key. Falls back to E2B_API_KEY env var.
            pool_size: Number of warm sandboxes to maintain.
            timeout: Default execution timeout in seconds.
        """
        self.api_key = api_key
        self.pool_size = pool_size
        self.timeout = timeout
        self._pool = None

    @property
    def name(self) -> str:
        return "e2b"

    def is_available(self) -> bool:
        """Check if E2B SDK is installed."""
        try:
            import e2b_code_interpreter  # noqa: F401

            return True
        except ImportError:
            return False

    def execute(
        self,
        func: Callable[..., R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        timeout: int | None = None,
    ) -> SandboxResult:
        """Execute function in E2B sandbox.

        Delegates to the existing execute_in_sandbox implementation.
        """
        from .config import AirlockConfig
        from .sandbox import execute_in_sandbox

        config = AirlockConfig(
            e2b_api_key=self.api_key,
            sandbox_timeout=timeout or self.timeout,
            sandbox_pool_size=self.pool_size,
        )

        result = execute_in_sandbox(func, args, kwargs, config)

        return SandboxResult(
            success=result.success,
            result=result.result,
            error=result.error,
            stdout=result.stdout,
            stderr=result.stderr,
            execution_time_ms=result.execution_time_ms,
            sandbox_id=result.sandbox_id,
            backend=self.name,
        )

    def warmup(self) -> None:
        """Pre-warm the E2B sandbox pool."""
        from .config import AirlockConfig
        from .sandbox import get_sandbox_pool

        config = AirlockConfig(
            e2b_api_key=self.api_key,
            sandbox_pool_size=self.pool_size,
            sandbox_timeout=self.timeout,
        )
        pool = get_sandbox_pool(config)
        pool.warm_up()

    def shutdown(self) -> None:
        """Shutdown the E2B sandbox pool."""
        from .sandbox import get_sandbox_pool

        pool = get_sandbox_pool()
        pool.shutdown()


class DockerBackend(SandboxBackend):
    """Docker container backend for enterprise/on-prem use.

    Runs code in isolated Docker containers. Useful for environments
    where external cloud services (like E2B) are not permitted.

    Attributes:
        image: Docker image to use for execution.
        network_mode: Docker network mode ("none" for isolation).
        memory_limit: Memory limit for containers (e.g., "512m").
        cpu_limit: CPU limit for containers (e.g., 1.0).
    """

    def __init__(
        self,
        image: str = "python:3.11-slim",
        network_mode: str = "none",
        memory_limit: str = "512m",
        cpu_limit: float = 1.0,
    ) -> None:
        """Initialize Docker backend.

        Args:
            image: Docker image to use.
            network_mode: Docker network mode. "none" = no network access.
            memory_limit: Memory limit for containers.
            cpu_limit: CPU limit for containers.
        """
        self.image = image
        self.network_mode = network_mode
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit

    @property
    def name(self) -> str:
        return "docker"

    def is_available(self) -> bool:
        """Check if Docker is available."""
        try:
            import docker

            client = docker.from_env()
            client.ping()
            return True
        except Exception as e:
            logger.debug(
                "docker_unavailable",
                error=str(e),
            )
            return False

    def execute(
        self,
        func: Callable[..., R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        _timeout: int = 60,  # TODO: implement container timeout
    ) -> SandboxResult:
        """Execute function in Docker container."""
        start_time = time.time()

        if not self.is_available():
            return SandboxResult(
                success=False,
                error=(
                    "Docker is not available. Install docker package "
                    "and ensure Docker daemon is running."
                ),
                backend=self.name,
            )

        try:
            import base64
            import json

            import cloudpickle
            import docker

            client = docker.from_env()

            # Serialize the function call
            payload = {
                "func": func,
                "args": args,
                "kwargs": kwargs,
            }
            serialized = base64.b64encode(cloudpickle.dumps(payload, protocol=4)).decode()

            # Create Python script to run in container
            script = f'''
import base64
import cloudpickle
import json
import traceback

payload_b64 = "{serialized}"
payload = cloudpickle.loads(base64.b64decode(payload_b64))

func = payload["func"]
args = payload["args"]
kwargs = payload["kwargs"]

try:
    result = func(*args, **kwargs)
    output = {{"success": True, "result": result, "error": None}}
except Exception as e:
    output = {{
        "success": False,
        "result": None,
        "error": f"{{type(e).__name__}}: {{str(e)}}",
        "traceback": traceback.format_exc()
    }}

print("__AIRLOCK_RESULT__")
print(json.dumps(output, default=str))
print("__AIRLOCK_END__")
'''

            # Run container
            container = client.containers.run(
                self.image,
                command=["python", "-c", script],
                network_mode=self.network_mode,
                mem_limit=self.memory_limit,
                nano_cpus=int(self.cpu_limit * 1e9),
                remove=True,
                detach=False,
                stdout=True,
                stderr=True,
            )

            output = container.decode() if isinstance(container, bytes) else str(container)

            # Parse result
            if "__AIRLOCK_RESULT__" in output:
                start_marker = output.find("__AIRLOCK_RESULT__") + len("__AIRLOCK_RESULT__")
                end_marker = output.find("__AIRLOCK_END__")
                result_json = output[start_marker:end_marker].strip()

                result_data = json.loads(result_json)
                elapsed = (time.time() - start_time) * 1000

                return SandboxResult(
                    success=result_data["success"],
                    result=result_data.get("result"),
                    error=result_data.get("error"),
                    stdout=output,
                    execution_time_ms=round(elapsed, 2),
                    backend=self.name,
                )
            else:
                return SandboxResult(
                    success=False,
                    error="Container did not produce expected output",
                    stdout=output,
                    backend=self.name,
                )

        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            logger.exception("docker_execution_failed", error=str(e))
            return SandboxResult(
                success=False,
                error=f"Docker execution failed: {e}",
                execution_time_ms=round(elapsed, 2),
                backend=self.name,
            )


class LocalBackend(SandboxBackend):
    """Local execution backend (UNSAFE - development only).

    Executes code directly on the host with NO isolation.
    Only use this for local development and testing.

    This backend exists to:
    1. Allow testing without external dependencies
    2. Demonstrate that Airlock's value is the policy layer, not the sandbox
    3. Provide a fallback when no sandbox is available

    WARNING: This provides NO security isolation. The code runs with
    full access to the host system.
    """

    def __init__(self, allow_unsafe: bool = False) -> None:
        """Initialize local backend.

        Args:
            allow_unsafe: Must be True to acknowledge the security risk.

        Raises:
            ValueError: If allow_unsafe is not True.
        """
        if not allow_unsafe:
            raise ValueError(
                "LocalBackend provides NO security isolation. "
                "Set allow_unsafe=True to acknowledge this risk. "
                "Only use for development and testing."
            )
        self._acknowledged = True

    @property
    def name(self) -> str:
        return "local_unsafe"

    def is_available(self) -> bool:
        """Local execution is always available."""
        return True

    def execute(
        self,
        func: Callable[..., R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        _timeout: int = 60,  # Not used - local execution has no timeout
    ) -> SandboxResult:
        """Execute function locally with NO isolation.

        WARNING: This is UNSAFE. The function runs with full host access.
        """
        start_time = time.time()

        logger.warning(
            "local_unsafe_execution",
            function=getattr(func, "__name__", "unknown"),
            warning="Executing with NO sandbox isolation",
        )

        try:
            result = func(*args, **kwargs)
            elapsed = (time.time() - start_time) * 1000

            return SandboxResult(
                success=True,
                result=result,
                execution_time_ms=round(elapsed, 2),
                backend=self.name,
            )
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000
            return SandboxResult(
                success=False,
                error=f"{type(e).__name__}: {str(e)}",
                execution_time_ms=round(elapsed, 2),
                backend=self.name,
            )


# Default backend factory
def get_default_backend(config: AirlockConfig | None = None) -> SandboxBackend:
    """Get the default sandbox backend based on availability.

    Priority:
    1. E2B (if available and API key present)
    2. Docker (if available)
    3. None (sandbox not available)

    Args:
        config: Optional config to check for API keys.

    Returns:
        Best available SandboxBackend, or None if none available.
    """
    import os

    # Check E2B
    api_key = None
    if config:
        api_key = config.e2b_api_key
    if not api_key:
        api_key = os.environ.get("E2B_API_KEY")

    if api_key:
        e2b = E2BBackend(api_key=api_key)
        if e2b.is_available():
            return e2b

    # Check Docker
    docker = DockerBackend()
    if docker.is_available():
        return docker

    # No sandbox available
    logger.warning(
        "no_sandbox_available",
        hint="Install e2b-code-interpreter or docker for sandbox support",
    )
    return LocalBackend(allow_unsafe=True)


# Type alias for backend configuration
BackendType = E2BBackend | DockerBackend | LocalBackend
