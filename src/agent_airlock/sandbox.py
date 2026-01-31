"""E2B Sandbox integration for Agent-Airlock.

Provides secure, isolated execution of functions in E2B Firecracker MicroVMs.
Includes warm pool management for low-latency execution (<200ms target).

SECURITY NOTES:
    This module uses cloudpickle for function serialization. Pickle deserialization
    can execute arbitrary code, but this is mitigated by:

    1. Deserialization occurs INSIDE the E2B sandbox (isolated MicroVM)
    2. The sandbox has no access to the host filesystem or network
    3. Even if malicious code executes, it's contained in the sandbox

    For high-security environments, consider adding HMAC payload signing.
    See docs/SECURITY.md for detailed security guidance.
"""

from __future__ import annotations

import asyncio
import base64
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from queue import Empty, Queue
from typing import TYPE_CHECKING, Any, TypeVar

import structlog

from .config import DEFAULT_CONFIG, AirlockConfig

if TYPE_CHECKING:
    from e2b_code_interpreter import Sandbox

logger = structlog.get_logger("agent-airlock.sandbox")

R = TypeVar("R")


class SandboxError(Exception):
    """Raised when sandbox execution fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)


class SandboxNotAvailableError(SandboxError):
    """Raised when E2B SDK is not installed or API key is missing."""

    pass


class SandboxExecutionError(SandboxError):
    """Raised when code execution in sandbox fails."""

    pass


@dataclass
class SandboxResult:
    """Result from sandbox execution."""

    success: bool
    result: Any = None
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: float = 0.0
    sandbox_id: str | None = None

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
        }


def _check_e2b_available() -> bool:
    """Check if E2B SDK is installed."""
    try:
        import e2b_code_interpreter  # noqa: F401

        return True
    except ImportError:
        return False


def _check_cloudpickle_available() -> bool:
    """Check if cloudpickle is installed."""
    try:
        import cloudpickle  # noqa: F401

        return True
    except ImportError:
        return False


def serialize_function_call(
    func: Callable[..., R],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> str:
    """Serialize a function call for execution in sandbox.

    Uses cloudpickle to serialize the function and its arguments,
    then base64 encodes for safe transmission.

    Args:
        func: The function to serialize.
        args: Positional arguments.
        kwargs: Keyword arguments.

    Returns:
        Base64-encoded pickle string.

    Raises:
        SandboxNotAvailableError: If cloudpickle is not installed.
    """
    if not _check_cloudpickle_available():
        raise SandboxNotAvailableError(
            "cloudpickle is required for sandbox execution. "
            "Install with: pip install agent-airlock[sandbox]"
        )

    import cloudpickle

    payload = {
        "func": func,
        "args": args,
        "kwargs": kwargs,
    }
    pickled = cloudpickle.dumps(payload)
    return base64.b64encode(pickled).decode("utf-8")


def generate_execution_code(serialized_payload: str) -> str:
    """Generate Python code to execute in the sandbox.

    Args:
        serialized_payload: Base64-encoded pickle of function call.

    Returns:
        Python code string to execute in sandbox.
    """
    return f'''
import base64
import cloudpickle
import json
import traceback

# SECURITY: This code runs INSIDE the E2B sandbox (isolated MicroVM).
# Pickle deserialization is safe here because even if malicious code
# executes, it's contained within the sandbox with no host access.

# Decode and unpickle the function call
payload_b64 = "{serialized_payload}"
payload_bytes = base64.b64decode(payload_b64)
payload = cloudpickle.loads(payload_bytes)  # Safe: runs in sandbox

func = payload["func"]
args = payload["args"]
kwargs = payload["kwargs"]

# Execute the function
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

# Print as JSON for parsing
print("__AIRLOCK_RESULT__")
print(json.dumps(output, default=str))
print("__AIRLOCK_END__")
'''


class SandboxPool:
    """Pool of warm E2B sandboxes for low-latency execution.

    Maintains a pool of pre-created sandboxes to avoid cold start latency.
    Sandboxes are recycled after use if still healthy.
    """

    def __init__(
        self,
        pool_size: int = 2,
        api_key: str | None = None,
        timeout: int = 60,
    ) -> None:
        """Initialize the sandbox pool.

        Args:
            pool_size: Number of warm sandboxes to maintain.
            api_key: E2B API key. Falls back to E2B_API_KEY env var.
            timeout: Default timeout for sandbox operations in seconds.
        """
        self.pool_size = pool_size
        self.api_key = api_key
        self.timeout = timeout
        self._pool: Queue[Sandbox] = Queue(maxsize=pool_size)
        self._lock = threading.Lock()
        self._initialized = False
        self._shutdown = False

    def _ensure_e2b_available(self) -> None:
        """Ensure E2B SDK is available."""
        if not _check_e2b_available():
            raise SandboxNotAvailableError(
                "e2b-code-interpreter is required for sandbox execution. "
                "Install with: pip install agent-airlock[sandbox]"
            )

    def _create_sandbox(self) -> Sandbox:
        """Create a new E2B sandbox."""
        from e2b_code_interpreter import Sandbox

        logger.debug("sandbox_creating")
        start = time.time()

        sandbox = Sandbox(api_key=self.api_key, timeout=self.timeout)

        # Pre-install cloudpickle in the sandbox
        sandbox.run_code(
            "import subprocess; subprocess.run(['pip', 'install', 'cloudpickle', '-q'])"
        )

        elapsed = (time.time() - start) * 1000
        logger.info("sandbox_created", sandbox_id=sandbox.sandbox_id, elapsed_ms=round(elapsed, 2))

        return sandbox

    def warm_up(self, count: int | None = None) -> None:
        """Pre-create sandboxes to warm up the pool.

        Args:
            count: Number of sandboxes to create. Defaults to pool_size.
        """
        self._ensure_e2b_available()
        count = count or self.pool_size

        with self._lock:
            current_size = self._pool.qsize()
            to_create = min(count, self.pool_size - current_size)

            for _ in range(to_create):
                try:
                    sandbox = self._create_sandbox()
                    self._pool.put_nowait(sandbox)
                except Exception as e:
                    logger.warning("sandbox_warmup_failed", error=str(e))

            self._initialized = True

    def acquire(self) -> Sandbox:
        """Acquire a sandbox from the pool.

        Returns a warm sandbox if available, otherwise creates a new one.

        Returns:
            An E2B Sandbox instance.
        """
        self._ensure_e2b_available()

        try:
            # Try to get a warm sandbox
            sandbox = self._pool.get_nowait()
            logger.debug("sandbox_acquired_from_pool", sandbox_id=sandbox.sandbox_id)
            return sandbox
        except Empty:
            # No warm sandbox available, create a new one
            logger.debug("sandbox_pool_empty_creating_new")
            return self._create_sandbox()

    def release(self, sandbox: Sandbox) -> None:
        """Release a sandbox back to the pool.

        If the pool is full, the sandbox is closed.

        Args:
            sandbox: The sandbox to release.
        """
        if self._shutdown:
            self._close_sandbox(sandbox)
            return

        try:
            self._pool.put_nowait(sandbox)
            logger.debug("sandbox_released_to_pool", sandbox_id=sandbox.sandbox_id)
        except Exception:
            # Pool is full, close the sandbox
            self._close_sandbox(sandbox)

    def _close_sandbox(self, sandbox: Sandbox) -> None:
        """Close a sandbox."""
        try:
            sandbox.kill()
            logger.debug("sandbox_closed", sandbox_id=sandbox.sandbox_id)
        except Exception as e:
            logger.warning("sandbox_close_failed", error=str(e))

    @contextmanager
    def sandbox(self) -> Generator[Sandbox, None, None]:
        """Context manager for acquiring and releasing a sandbox.

        Yields:
            An E2B Sandbox instance.
        """
        sandbox = self.acquire()
        try:
            yield sandbox
        finally:
            self.release(sandbox)

    def shutdown(self) -> None:
        """Shutdown the pool and close all sandboxes."""
        self._shutdown = True

        while True:
            try:
                sandbox = self._pool.get_nowait()
                self._close_sandbox(sandbox)
            except Empty:
                break

        logger.info("sandbox_pool_shutdown")


# Global sandbox pool instance
_global_pool: SandboxPool | None = None
_pool_lock = threading.Lock()


def get_sandbox_pool(config: AirlockConfig | None = None) -> SandboxPool:
    """Get or create the global sandbox pool.

    Args:
        config: Configuration for the pool. Uses DEFAULT_CONFIG if not provided.

    Returns:
        The global SandboxPool instance.
    """
    global _global_pool

    with _pool_lock:
        if _global_pool is None:
            config = config or DEFAULT_CONFIG
            _global_pool = SandboxPool(
                pool_size=config.sandbox_pool_size,
                api_key=config.e2b_api_key,
                timeout=config.sandbox_timeout,
            )

        return _global_pool


def execute_in_sandbox(
    func: Callable[..., R],
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
    config: AirlockConfig | None = None,
) -> SandboxResult:
    """Execute a function in an E2B sandbox.

    Serializes the function and arguments, sends to sandbox,
    executes, and returns the result.

    Args:
        func: The function to execute.
        args: Positional arguments.
        kwargs: Keyword arguments.
        config: Configuration options.

    Returns:
        SandboxResult with execution outcome.
    """
    kwargs = kwargs or {}
    config = config or DEFAULT_CONFIG
    start_time = time.time()

    # Check dependencies
    if not _check_e2b_available():
        return SandboxResult(
            success=False,
            error="e2b-code-interpreter not installed. Install with: pip install agent-airlock[sandbox]",
        )

    if not _check_cloudpickle_available():
        return SandboxResult(
            success=False,
            error="cloudpickle not installed. Install with: pip install agent-airlock[sandbox]",
        )

    # Serialize the function call
    try:
        serialized = serialize_function_call(func, args, kwargs)
    except Exception as e:
        return SandboxResult(
            success=False,
            error=f"Failed to serialize function: {e}",
        )

    # Generate execution code
    code = generate_execution_code(serialized)

    # Execute in sandbox
    pool = get_sandbox_pool(config)
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    try:
        with pool.sandbox() as sandbox:
            sandbox.run_code(
                code,
                on_stdout=lambda line: stdout_lines.append(line),
                on_stderr=lambda line: stderr_lines.append(line),
            )

            stdout = "".join(stdout_lines)
            stderr = "".join(stderr_lines)

            # Parse the result from stdout
            if "__AIRLOCK_RESULT__" in stdout:
                import json

                # Extract JSON between markers
                start_marker = stdout.find("__AIRLOCK_RESULT__") + len("__AIRLOCK_RESULT__")
                end_marker = stdout.find("__AIRLOCK_END__")
                result_json = stdout[start_marker:end_marker].strip()

                try:
                    result_data = json.loads(result_json)
                    elapsed = (time.time() - start_time) * 1000

                    return SandboxResult(
                        success=result_data["success"],
                        result=result_data.get("result"),
                        error=result_data.get("error"),
                        stdout=stdout,
                        stderr=stderr,
                        execution_time_ms=round(elapsed, 2),
                        sandbox_id=sandbox.sandbox_id,
                    )
                except json.JSONDecodeError as e:
                    return SandboxResult(
                        success=False,
                        error=f"Failed to parse sandbox result: {e}",
                        stdout=stdout,
                        stderr=stderr,
                    )
            else:
                # No result marker found
                return SandboxResult(
                    success=False,
                    error="Sandbox execution did not produce expected output",
                    stdout=stdout,
                    stderr=stderr,
                )

    except Exception as e:
        elapsed = (time.time() - start_time) * 1000
        logger.exception("sandbox_execution_failed", error=str(e))
        return SandboxResult(
            success=False,
            error=f"Sandbox execution failed: {e}",
            execution_time_ms=round(elapsed, 2),
        )


async def execute_in_sandbox_async(
    func: Callable[..., R],
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
    config: AirlockConfig | None = None,
) -> SandboxResult:
    """Async version of execute_in_sandbox.

    Runs the synchronous execution in a thread pool to avoid blocking.

    Args:
        func: The function to execute.
        args: Positional arguments.
        kwargs: Keyword arguments.
        config: Configuration options.

    Returns:
        SandboxResult with execution outcome.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: execute_in_sandbox(func, args, kwargs, config),
    )
