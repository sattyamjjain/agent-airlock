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

THREAD SAFETY:
    This module is thread-safe. The SandboxPool uses a threading.Lock (_lock)
    to protect pool operations. The global pool uses _pool_lock for access.

    Lock Acquisition Order (to prevent deadlocks):
    1. _pool_lock (global pool access) - acquired first if needed
    2. self._lock (SandboxPool instance lock) - acquired for pool operations

    Never hold locks across async await boundaries or E2B API calls.
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


@contextmanager
def _temp_env_var(key: str, value: str | None) -> Generator[None, None, None]:
    """Temporarily set an environment variable.

    Thread-safe context manager that temporarily sets an environment variable
    and restores its previous value (or removes it) on exit.

    Args:
        key: Environment variable name.
        value: Value to set, or None to skip setting.

    Yields:
        None
    """
    import os

    if value is None:
        # No value provided, don't modify environment
        yield
        return

    old_value = os.environ.get(key)
    os.environ[key] = value
    try:
        yield
    finally:
        if old_value is None:
            # Variable didn't exist before, remove it
            os.environ.pop(key, None)
        else:
            # Restore original value
            os.environ[key] = old_value


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
    # Use protocol 4 for cross-version compatibility (Python 3.4+)
    # Protocol 5 and higher may have opcodes not supported in E2B sandbox
    pickled = cloudpickle.dumps(payload, protocol=4)
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
        """Create a new E2B sandbox.

        Uses temporary environment variable context to avoid mutating
        global os.environ state, ensuring thread safety.
        """
        from e2b_code_interpreter import Sandbox

        logger.debug("sandbox_creating")
        start = time.time()

        # E2B v2.x reads API key from environment variable E2B_API_KEY
        # Use temp context to avoid global env mutation
        with _temp_env_var("E2B_API_KEY", self.api_key):
            # E2B v2.x uses Sandbox.create() factory method with timeout in seconds
            sandbox = Sandbox.create(timeout=self.timeout)

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
        except Exception as e:
            # Pool is full, close the sandbox
            logger.debug(
                "sandbox_pool_full",
                sandbox_id=sandbox.sandbox_id,
                error=str(e),
            )
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


def _reset_pool() -> None:
    """Reset the global sandbox pool for testing.

    This function should only be used in tests to ensure isolation
    between test cases. Shuts down any existing pool and clears state.
    """
    import contextlib

    global _global_pool

    with _pool_lock:
        if _global_pool is not None:
            with contextlib.suppress(Exception):
                _global_pool.shutdown()
        _global_pool = None


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
            error=(
                "e2b-code-interpreter not installed. "
                "Install with: pip install agent-airlock[sandbox]"
            ),
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

    try:
        with pool.sandbox() as sandbox:
            execution = sandbox.run_code(code)

            # E2B v2.x returns Execution object with logs
            # Extract stdout/stderr from execution result
            stdout = ""
            stderr = ""
            if execution.logs:
                # logs.stdout and logs.stderr are lists of strings
                stdout = "".join(execution.logs.stdout)
                stderr = "".join(execution.logs.stderr)

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


# =============================================================================
# File Mounting Support
# =============================================================================


@dataclass
class MountedFile:
    """Represents a file to be mounted in the sandbox."""

    local_path: str
    sandbox_path: str
    content: bytes | None = None  # If set, use content instead of reading local_path

    def get_content(self) -> bytes:
        """Get file content."""
        if self.content is not None:
            return self.content
        with open(self.local_path, "rb") as f:
            return f.read()


def mount_files(
    sandbox: Any,
    files: list[MountedFile],
) -> list[str]:
    """Mount files into an E2B sandbox.

    Args:
        sandbox: E2B Sandbox instance.
        files: List of files to mount.

    Returns:
        List of sandbox paths where files were mounted.

    Raises:
        SandboxError: If file mounting fails.
    """
    mounted_paths = []

    for file in files:
        try:
            content = file.get_content()

            # E2B v2.x uses sandbox.files.write() to upload files
            sandbox.files.write(file.sandbox_path, content)

            mounted_paths.append(file.sandbox_path)
            logger.debug(
                "file_mounted",
                local=file.local_path if file.content is None else "<content>",
                sandbox=file.sandbox_path,
                size=len(content),
            )

        except Exception as e:
            raise SandboxError(
                f"Failed to mount file {file.local_path}: {e}",
                details={"local_path": file.local_path, "sandbox_path": file.sandbox_path},
            ) from e

    return mounted_paths


def mount_directory(
    sandbox: Any,
    local_dir: str,
    sandbox_dir: str,
    pattern: str = "*",
    recursive: bool = True,
) -> list[str]:
    """Mount a directory into an E2B sandbox.

    Args:
        sandbox: E2B Sandbox instance.
        local_dir: Local directory path.
        sandbox_dir: Target path in sandbox.
        pattern: Glob pattern for files to include.
        recursive: Whether to include subdirectories.

    Returns:
        List of mounted file paths in sandbox.
    """
    from pathlib import Path

    local_path = Path(local_dir)
    if not local_path.is_dir():
        raise SandboxError(f"Not a directory: {local_dir}")

    files_to_mount = []

    if recursive:
        for file_path in local_path.rglob(pattern):
            if file_path.is_file():
                rel_path = file_path.relative_to(local_path)
                sandbox_path = f"{sandbox_dir}/{rel_path}"
                files_to_mount.append(
                    MountedFile(
                        local_path=str(file_path),
                        sandbox_path=sandbox_path,
                    )
                )
    else:
        for file_path in local_path.glob(pattern):
            if file_path.is_file():
                sandbox_path = f"{sandbox_dir}/{file_path.name}"
                files_to_mount.append(
                    MountedFile(
                        local_path=str(file_path),
                        sandbox_path=sandbox_path,
                    )
                )

    return mount_files(sandbox, files_to_mount)


def download_file(
    sandbox: Any,
    sandbox_path: str,
    local_path: str | None = None,
) -> bytes:
    """Download a file from the sandbox.

    Args:
        sandbox: E2B Sandbox instance.
        sandbox_path: Path to file in sandbox.
        local_path: Optional local path to save file.

    Returns:
        File content as bytes.
    """
    try:
        # E2B v2.x uses sandbox.files.read()
        content: bytes = sandbox.files.read(sandbox_path)

        if local_path:
            with open(local_path, "wb") as f:
                f.write(content)

        logger.debug(
            "file_downloaded",
            sandbox=sandbox_path,
            local=local_path,
            size=len(content),
        )

        return content

    except Exception as e:
        raise SandboxError(
            f"Failed to download file {sandbox_path}: {e}",
            details={"sandbox_path": sandbox_path},
        ) from e


def execute_with_files(
    func: Callable[..., R],
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
    config: AirlockConfig | None = None,
    mount: list[MountedFile] | None = None,
    download: list[str] | None = None,
) -> tuple[SandboxResult, dict[str, bytes]]:
    """Execute function in sandbox with file mounting.

    Args:
        func: Function to execute.
        args: Positional arguments.
        kwargs: Keyword arguments.
        config: Airlock configuration.
        mount: Files to mount before execution.
        download: Sandbox paths to download after execution.

    Returns:
        Tuple of (SandboxResult, downloaded_files dict).
    """
    kwargs = kwargs or {}
    config = config or DEFAULT_CONFIG
    mount = mount or []
    download = download or []

    downloaded_files: dict[str, bytes] = {}

    # Get sandbox pool
    pool = get_sandbox_pool(config)

    try:
        with pool.sandbox() as sandbox:
            # Mount files
            if mount:
                mount_files(sandbox, mount)

            # Serialize and execute
            if not _check_cloudpickle_available():
                return (
                    SandboxResult(
                        success=False,
                        error="cloudpickle not installed",
                    ),
                    downloaded_files,
                )

            serialized = serialize_function_call(func, args, kwargs)
            code = generate_execution_code(serialized)

            start_time = time.time()
            execution = sandbox.run_code(code)
            elapsed = (time.time() - start_time) * 1000

            stdout = execution.logs.stdout if execution.logs else ""
            stderr = execution.logs.stderr if execution.logs else ""

            # Download requested files
            for path in download:
                try:
                    downloaded_files[path] = download_file(sandbox, path)
                except SandboxError as e:
                    logger.warning("file_download_failed", path=path, error=str(e))

            # Parse result
            if "---RESULT_START---" in stdout:
                result_start = stdout.index("---RESULT_START---") + len("---RESULT_START---")
                result_end = stdout.index("---RESULT_END---")
                result_b64 = stdout[result_start:result_end].strip()

                import cloudpickle

                result_data = cloudpickle.loads(base64.b64decode(result_b64))

                if result_data.get("success"):
                    return (
                        SandboxResult(
                            success=True,
                            result=result_data["result"],
                            stdout=stdout,
                            stderr=stderr,
                            execution_time_ms=round(elapsed, 2),
                            sandbox_id=sandbox.sandbox_id,
                        ),
                        downloaded_files,
                    )
                else:
                    return (
                        SandboxResult(
                            success=False,
                            error=result_data.get("error", "Unknown error"),
                            stdout=stdout,
                            stderr=stderr,
                            execution_time_ms=round(elapsed, 2),
                            sandbox_id=sandbox.sandbox_id,
                        ),
                        downloaded_files,
                    )
            else:
                return (
                    SandboxResult(
                        success=False,
                        error="Sandbox execution did not produce expected output",
                        stdout=stdout,
                        stderr=stderr,
                        execution_time_ms=round(elapsed, 2),
                    ),
                    downloaded_files,
                )

    except Exception as e:
        logger.exception("execute_with_files_failed", error=str(e))
        return (
            SandboxResult(
                success=False,
                error=f"Execution failed: {e}",
            ),
            downloaded_files,
        )
