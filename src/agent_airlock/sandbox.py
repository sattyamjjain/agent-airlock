"""E2B Sandbox integration for Agent-Airlock.

Provides isolated execution of functions in E2B Firecracker MicroVMs, with a pool of
pre-created sandboxes that hides the cold start. Each sandbox runs one call.

SECURITY NOTES:
    This module uses cloudpickle for function serialization. Pickle deserialization
    can execute arbitrary code, but this is mitigated by:

    1. Deserialization occurs INSIDE the E2B sandbox (isolated MicroVM)
    2. The sandbox runs on E2B's machines: it cannot read the host's filesystem or
       memory. It does have outbound internet access unless the E2B template removes it.
    3. Even if malicious code executes, it's contained in the sandbox
    4. Results come back as JSON, never as a pickle. Code running in the sandbox
       controls its own output, so unpickling that output would let it run code on the
       host.
    5. A sandbox is closed after its call, so nothing one call leaves behind reaches the
       next.

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
import json
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from queue import Empty, Queue
from typing import TYPE_CHECKING, Any, TypeVar

from ._log import structlog
from ._sandbox_errors import SandboxError as SandboxError
from ._sandbox_errors import SandboxExecutionError as SandboxExecutionError
from ._sandbox_errors import SandboxNotAvailableError as SandboxNotAvailableError
from .config import DEFAULT_CONFIG, AirlockConfig

if TYPE_CHECKING:
    from e2b_code_interpreter import Sandbox

logger = structlog.get_logger("agent-airlock.sandbox")

R = TypeVar("R")

# The payload prints its outcome as one JSON line between these two lines.
_RESULT_MARKER = "__AIRLOCK_RESULT__"
_END_MARKER = "__AIRLOCK_END__"


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


@dataclass
class SandboxResult:
    """Result from sandbox execution.

    ``tool_failed`` tells the two kinds of failure apart: True when the function ran in
    the sandbox and raised (or returned something that could not be sent back), False
    when the sandbox itself could not run it or returned nothing.
    """

    success: bool
    result: Any = None
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: float = 0.0
    sandbox_id: str | None = None
    tool_failed: bool = False

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
            "tool_failed": self.tool_failed,
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

    The code unpickles the call, runs it, awaits the result when the function is async,
    and prints the outcome as one JSON line between marker lines. E2B, Docker and Modal
    all run this same code, and the host reads it back with ``_parse_execution_output``.

    Args:
        serialized_payload: Base64-encoded pickle of function call.

    Returns:
        Python code string to execute in sandbox.
    """
    return f'''
import asyncio
import base64
import concurrent.futures
import inspect
import json
import traceback

import cloudpickle

# SECURITY: This code runs INSIDE the sandbox. Unpickling is safe here: the payload
# came from the host, and whatever it does stays in the sandbox. Nothing is pickled
# on the way back; the outcome is printed as JSON.
payload = cloudpickle.loads(base64.b64decode("{serialized_payload}"))
func = payload["func"]
args = payload["args"]
kwargs = payload["kwargs"]


def _airlock_resolve(value):
    """Return an async function's result instead of its coroutine."""
    if not inspect.isawaitable(value):
        return value

    async def _wait():
        return await value

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_wait())
    # E2B runs this in a Jupyter kernel, whose event loop is already running in this
    # thread, and asyncio.run() refuses to start another there. Use a thread of its own.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
        return worker.submit(asyncio.run, _wait()).result()


try:
    output = {{"success": True, "result": _airlock_resolve(func(*args, **kwargs)), "error": None}}
except BaseException as e:  # a tool calling sys.exit() still reports back
    output = {{
        "success": False,
        "result": None,
        "error": f"{{type(e).__name__}}: {{e}}",
        "traceback": traceback.format_exc(),
    }}

try:
    encoded = json.dumps(output, default=str)
except Exception as e:  # e.g. a dict with tuple keys, or a result that contains itself
    encoded = json.dumps({{
        "success": False,
        "result": None,
        "error": f"The result could not be encoded as JSON: {{type(e).__name__}}: {{e}}",
    }})

print("{_RESULT_MARKER}")
print(encoded)
print("{_END_MARKER}")
'''


def _parse_execution_output(stdout: str) -> dict[str, Any] | None:
    """Find the outcome the payload printed, or None when it printed none.

    The payload prints three lines last: the result marker, one line of JSON and the end
    marker. The tool's own output shares stdout and comes first, so the last such block
    is the payload's, even when the tool printed something that looks like one.

    Args:
        stdout: Everything the payload printed.

    Returns:
        The outcome, with a boolean ``success``, or None when there is no result block.

    Raises:
        ValueError: A result block is there but does not hold an outcome.
    """
    lines = stdout.splitlines()
    for i in range(len(lines) - 3, -1, -1):
        if lines[i] == _RESULT_MARKER and lines[i + 2] == _END_MARKER:
            outcome = json.loads(lines[i + 1])
            if not isinstance(outcome, dict) or not isinstance(outcome.get("success"), bool):
                raise ValueError("the result block does not hold a sandbox outcome")
            return outcome
    return None


def _missing_dependency() -> str | None:
    """Why a sandbox call cannot start here, or None when it can."""
    if not _check_e2b_available():
        return (
            "e2b-code-interpreter not installed. Install with: pip install agent-airlock[sandbox]"
        )
    if not _check_cloudpickle_available():
        return "cloudpickle not installed. Install with: pip install agent-airlock[sandbox]"
    return None


def _cell_error(execution: Any) -> str:
    """E2B's report of an exception the payload itself raised, such as a missing module."""
    error = getattr(execution, "error", None)
    name = getattr(error, "name", None)
    if not isinstance(name, str):
        return ""
    return f" ({name}: {getattr(error, 'value', '')})"


def _result_from_execution(
    execution: Any,
    sandbox_id: str | None,
    start_time: float,
) -> SandboxResult:
    """Turn an E2B execution into a SandboxResult.

    E2B's ``logs.stdout`` and ``logs.stderr`` are lists of output chunks, not strings.
    """
    logs = getattr(execution, "logs", None)
    stdout = "".join(logs.stdout) if logs else ""
    stderr = "".join(logs.stderr) if logs else ""
    elapsed = round((time.time() - start_time) * 1000, 2)

    try:
        outcome = _parse_execution_output(stdout)
    except ValueError as e:
        return SandboxResult(
            success=False,
            error=f"Failed to parse sandbox result: {e}",
            stdout=stdout,
            stderr=stderr,
            execution_time_ms=elapsed,
            sandbox_id=sandbox_id,
        )
    if outcome is None:
        return SandboxResult(
            success=False,
            error="Sandbox execution did not produce expected output" + _cell_error(execution),
            stdout=stdout,
            stderr=stderr,
            execution_time_ms=elapsed,
            sandbox_id=sandbox_id,
        )
    return SandboxResult(
        success=outcome["success"],
        result=outcome.get("result"),
        error=outcome.get("error"),
        stdout=stdout,
        stderr=stderr,
        execution_time_ms=elapsed,
        sandbox_id=sandbox_id,
        tool_failed=not outcome["success"],
    )


class SandboxPool:
    """Pool of pre-created E2B sandboxes, each used for one call.

    A sandbox that has run a call is closed, not returned to the pool. Code from that call
    can leave state behind (files, module globals, a background thread), and the next
    call, possibly another user's, would run next to it. Until 0.10.17 used sandboxes were
    recycled, a sandbox that had just failed included. The pool hides the cold start for
    as many calls as it holds; ``warm_up()`` refills it.
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
            timeout: Sandbox lifetime in seconds: E2B kills a sandbox this long after it
                is created, or after it is handed out of the pool.
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
        """Acquire a sandbox for one call.

        Takes a warm sandbox from the pool when there is one, otherwise creates one. A
        pooled sandbox has been ageing since it was created, so its lifetime is reset to
        ``timeout`` from now; one that has already expired is closed and skipped.

        Returns:
            An E2B Sandbox instance.
        """
        self._ensure_e2b_available()

        while True:
            try:
                sandbox = self._pool.get_nowait()
            except Empty:
                logger.debug("sandbox_pool_empty_creating_new")
                return self._create_sandbox()
            try:
                sandbox.set_timeout(self.timeout)
            except Exception as e:
                logger.info(
                    "sandbox_pool_discarded_expired",
                    sandbox_id=getattr(sandbox, "sandbox_id", None),
                    error=str(e),
                )
                self._close_sandbox(sandbox)
                continue
            logger.debug("sandbox_acquired_from_pool", sandbox_id=sandbox.sandbox_id)
            return sandbox

    def release(self, sandbox: Sandbox) -> None:
        """Close a sandbox that has been used.

        It is not returned to the pool: see the class docstring.

        Args:
            sandbox: The sandbox to close.
        """
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
        """Acquire a sandbox for one call and close it afterwards, whether or not it failed.

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


# One pool per (E2B API key, sandbox timeout, pool size). Until 0.10.17 a single
# process-wide pool took its settings from whichever config reached it first, so a second
# config's API key and timeout were silently ignored.
_pools: dict[tuple[str | None, int, int], SandboxPool] = {}
_pool_lock = threading.Lock()


def get_sandbox_pool(config: AirlockConfig | None = None) -> SandboxPool:
    """Get or create the sandbox pool for a config.

    Configs with the same E2B API key, sandbox timeout and pool size share a pool; a
    config that differs in any of them gets its own.

    Args:
        config: Configuration for the pool. Uses DEFAULT_CONFIG if not provided.

    Returns:
        The SandboxPool for those settings.
    """
    config = config or DEFAULT_CONFIG
    key = (config.e2b_api_key, config.sandbox_timeout, config.sandbox_pool_size)

    with _pool_lock:
        pool = _pools.get(key)
        if pool is None:
            pool = SandboxPool(
                pool_size=config.sandbox_pool_size,
                api_key=config.e2b_api_key,
                timeout=config.sandbox_timeout,
            )
            _pools[key] = pool
        return pool


def _reset_pool() -> None:
    """Shut down and forget every sandbox pool, for test isolation."""
    import contextlib

    with _pool_lock:
        pools = list(_pools.values())
        _pools.clear()

    for pool in pools:
        with contextlib.suppress(Exception):
            pool.shutdown()


def execute_in_sandbox(
    func: Callable[..., R],
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
    config: AirlockConfig | None = None,
) -> SandboxResult:
    """Execute a function in an E2B sandbox.

    Serializes the function and arguments, runs them in a sandbox from the pool, and
    returns the result. An async function's coroutine is awaited inside the sandbox.
    The sandbox is closed after the call.

    Args:
        func: The function to execute.
        args: Positional arguments.
        kwargs: Keyword arguments.
        config: Configuration options.

    Returns:
        SandboxResult with execution outcome. Failures are returned, not raised.
    """
    kwargs = kwargs or {}
    config = config or DEFAULT_CONFIG
    start_time = time.time()

    missing = _missing_dependency()
    if missing is not None:
        return SandboxResult(success=False, error=missing)

    try:
        code = generate_execution_code(serialize_function_call(func, args, kwargs))
    except Exception as e:
        return SandboxResult(
            success=False,
            error=f"Failed to serialize function: {e}",
        )

    try:
        with get_sandbox_pool(config).sandbox() as sandbox:
            execution = sandbox.run_code(code)
            return _result_from_execution(execution, sandbox.sandbox_id, start_time)

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

    Runs the synchronous execution in a worker thread so the event loop is not blocked.
    ``func`` may be sync or async; an async one is awaited inside the sandbox.

    Args:
        func: The function to execute.
        args: Positional arguments.
        kwargs: Keyword arguments.
        config: Configuration options.

    Returns:
        SandboxResult with execution outcome.
    """
    return await asyncio.to_thread(execute_in_sandbox, func, args, kwargs, config)


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

    Until 0.10.17 this never returned a result: it looked for markers the payload does
    not print and read E2B's list of output chunks as a string. Its result path also
    unpickled what the sandbox printed. It now reads the result exactly as
    ``execute_in_sandbox`` does, as JSON.

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
    start_time = time.time()
    downloaded_files: dict[str, bytes] = {}

    missing = _missing_dependency()
    if missing is not None:
        return SandboxResult(success=False, error=missing), downloaded_files

    try:
        code = generate_execution_code(serialize_function_call(func, args, kwargs))
    except Exception as e:
        return (
            SandboxResult(success=False, error=f"Failed to serialize function: {e}"),
            downloaded_files,
        )

    try:
        with get_sandbox_pool(config).sandbox() as sandbox:
            if mount:
                mount_files(sandbox, mount)

            execution = sandbox.run_code(code)
            result = _result_from_execution(execution, sandbox.sandbox_id, start_time)

            for path in download or []:
                try:
                    downloaded_files[path] = download_file(sandbox, path)
                except SandboxError as e:
                    logger.warning("file_download_failed", path=path, error=str(e))

            return result, downloaded_files

    except Exception as e:
        logger.exception("execute_with_files_failed", error=str(e))
        return (
            SandboxResult(
                success=False,
                error=f"Execution failed: {e}",
            ),
            downloaded_files,
        )
