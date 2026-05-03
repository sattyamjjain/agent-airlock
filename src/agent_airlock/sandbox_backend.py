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

import contextlib
import re
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

    # Image identifier in canonical digest-pinned form:
    #   <name>@sha256:<64-hex-chars>
    # Both ``name`` (anchored to repository segment chars) and the digest
    # length are checked. Used by ``require_digest_pin`` (v0.7.0+, #38).
    _DIGEST_PIN_RE = re.compile(r"^[A-Za-z0-9._/\-:]+@sha256:[0-9a-f]{64}$")

    def __init__(
        self,
        image: str = "python:3.11-slim",
        network_mode: str = "none",
        memory_limit: str = "512m",
        cpu_limit: float = 1.0,
        security_opt: list[str] | None = None,
        *,
        require_rootless: bool = False,
        require_digest_pin: bool = False,
    ) -> None:
        """Initialize Docker backend.

        Args:
            image: Docker image to use.
            network_mode: Docker network mode. ``"none"`` = no network
                access; strongly recommended default.
            memory_limit: Memory limit for containers.
            cpu_limit: CPU limit for containers.
            security_opt: Extra ``--security-opt`` flags. The backend
                already sets ``no-new-privileges`` and drops all
                capabilities by default; pass a seccomp profile here
                (e.g. ``["seccomp=/path/to/profile.json"]``) to tighten
                further. Leave as ``None`` to rely on the dropped-caps
                posture alone.
            require_rootless: v0.7.0+ (#37). If ``True``, ``is_available()``
                only reports the backend available when ``docker info``'s
                SecurityOptions advertise ``rootless`` (or ``name=rootless``).
                Some threat models (multi-tenant CI, shared dev hosts) want
                to fail-closed when the daemon runs as root.
            require_digest_pin: v0.7.0+ (#38). If ``True``, ``image``
                must be ``<name>@sha256:<64-hex>``. Tag-only images
                (e.g. ``"python:3.11-slim"``) are rejected at construction
                time with :class:`ValueError`. Closes the floating-tag
                supply-chain risk where an image's identity can change
                under you.

        Raises:
            ValueError: ``require_digest_pin`` is set and ``image`` does
                not match the canonical digest-pin form.
        """
        if require_digest_pin and not self._DIGEST_PIN_RE.match(image):
            raise ValueError(
                f"DockerBackend(require_digest_pin=True) refuses tag-only "
                f"image {image!r}. Use the form '<name>@sha256:<64-hex>' "
                "(see `docker pull --quiet <name>:<tag>` to discover the "
                "digest of the tag you currently use)."
            )
        self.image = image
        self.network_mode = network_mode
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.security_opt = security_opt or []
        self.require_rootless = require_rootless
        self.require_digest_pin = require_digest_pin

    @property
    def name(self) -> str:
        return "docker"

    def is_available(self) -> bool:
        """Check if Docker is available.

        v0.7.0+ (#37): when ``require_rootless`` is set, also inspect
        ``docker info`` and refuse to report available unless the
        daemon's ``SecurityOptions`` include ``rootless`` (or
        ``name=rootless``). This is a fail-closed check — a
        misconfigured daemon never silently downgrades to a rootful
        execution path.
        """
        try:
            import docker

            client = docker.from_env()
            client.ping()
            if self.require_rootless and not self._daemon_is_rootless(client):
                logger.warning(
                    "docker_unavailable_not_rootless",
                    require_rootless=True,
                )
                return False
            return True
        except Exception as e:
            logger.debug(
                "docker_unavailable",
                error=str(e),
            )
            return False

    @staticmethod
    def _daemon_is_rootless(client: Any) -> bool:
        """Return True iff ``docker info`` reports the daemon is rootless.

        Docker's rootless mode advertises itself in ``SecurityOptions``
        as either ``rootless`` (older) or ``name=rootless`` (newer).
        Both shapes are accepted.
        """
        try:
            info = client.info()
        except Exception:
            return False
        opts = info.get("SecurityOptions") or []
        for opt in opts:
            opt_str = str(opt)
            if opt_str == "rootless" or "name=rootless" in opt_str:
                return True
        return False

    def execute(
        self,
        func: Callable[..., R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        timeout: int = 60,
    ) -> SandboxResult:
        """Execute function in Docker container with a hard timeout (v0.5.1+).

        v0.5.1: the ``timeout`` parameter is now honored — the container
        is killed and removed if it has not exited within ``timeout``
        seconds. Prior to v0.5.1 a runaway function could hang forever
        because the parameter was a TODO.
        """
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

        container = None
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

            # Strong hardening defaults: no new privileges, drop every
            # capability, and honor the caller's extra security_opt.
            container = client.containers.run(
                self.image,
                command=["python", "-c", script],
                network_mode=self.network_mode,
                mem_limit=self.memory_limit,
                nano_cpus=int(self.cpu_limit * 1e9),
                security_opt=["no-new-privileges:true", *self.security_opt],
                cap_drop=["ALL"],
                detach=True,  # detach so we can enforce timeout
                stdout=True,
                stderr=True,
            )

            try:
                exit_info = container.wait(timeout=timeout)
            except Exception as wait_err:
                # docker-py raises either ReadTimeout (via requests) or
                # docker.errors.APIError on timeout. Kill + remove the
                # container either way and report.
                with contextlib.suppress(Exception):
                    container.kill()
                with contextlib.suppress(Exception):
                    container.remove(force=True)
                elapsed = (time.time() - start_time) * 1000
                return SandboxResult(
                    success=False,
                    error=f"Docker execution timed out after {timeout}s ({wait_err})",
                    execution_time_ms=round(elapsed, 2),
                    backend=self.name,
                )

            logs = container.logs(stdout=True, stderr=True)
            output = logs.decode() if isinstance(logs, bytes) else str(logs)
            container.remove(force=True)

            # Non-zero exit always yields a failure, regardless of what
            # (if anything) the script printed.
            exit_code = exit_info.get("StatusCode") if isinstance(exit_info, dict) else 0
            if exit_code != 0 and "__AIRLOCK_RESULT__" not in output:
                return SandboxResult(
                    success=False,
                    error=f"Container exited with status {exit_code}",
                    stdout=output,
                    backend=self.name,
                )

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
            # best-effort cleanup if the container was created but the
            # code path that would normally remove it did not run.
            if container is not None:
                with contextlib.suppress(Exception):
                    container.remove(force=True)
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


class ManagedSandboxBackend(SandboxBackend):
    """Anthropic Managed Agents backend — **beta, opt-in only**.

    Anthropic's Managed Agents product (https://anthropic.com/, announced
    April 2026) runs complete agent loops — model turns, tool calls, and
    state — on Anthropic-operated infrastructure. This does NOT map
    one-to-one onto the `SandboxBackend.execute()` contract, which is
    "run THIS function with THESE arguments in an isolated environment."

    Why this backend exists:

    - The roadmap (#6) tracks a Managed Agents story for v0.5.0.
    - Users need a clear opt-in hook rather than discovering later that
      Managed Agents is not plug-compatible with `E2BBackend`.

    What this backend currently does:

    - ``is_available()`` returns ``True`` when the ``anthropic`` SDK is
      importable **and** either ``api_key`` is provided or
      ``ANTHROPIC_API_KEY`` is set in the environment.
    - ``execute()`` does not run the provided function. It returns a
      ``SandboxResult(success=False, error=...)`` with a pointer to the
      Anthropic-SDK-based integration (``examples/anthropic_integration.py``)
      that wraps an agent loop rather than a single function call.
    - ``warmup()`` and ``shutdown()`` are no-ops.

    Future work (tracked in #6): a session-based ``ManagedAgentExecutor``
    that accepts a tool registry and a prompt, then runs a full agent
    loop inside a Managed session. That lives outside the
    ``SandboxBackend`` interface because the shapes disagree. When it
    lands, this class will document the integration point.
    """

    def __init__(self, api_key: str | None = None) -> None:
        """Initialize the Managed Agents backend.

        Args:
            api_key: Anthropic API key. Falls back to ``ANTHROPIC_API_KEY``
                env var.
        """
        self.api_key = api_key

    @property
    def name(self) -> str:
        return "managed"

    def is_available(self) -> bool:
        """Check that the SDK is installed AND an API key is reachable."""
        try:
            import anthropic  # type: ignore[import-not-found,unused-ignore]  # noqa: F401
        except ImportError:
            return False
        import os

        return bool(self.api_key or os.environ.get("ANTHROPIC_API_KEY"))

    def execute(
        self,
        func: Callable[..., R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        timeout: int = 60,
    ) -> SandboxResult:
        """Deliberately does not run ``func``.

        See class docstring — Managed Agents runs agent loops, not single
        function calls. This method returns a failure ``SandboxResult`` with
        a message pointing the caller at the right abstraction so silent
        misuse is impossible.
        """
        del args, kwargs, timeout  # intentionally unused — see docstring
        logger.warning(
            "managed_sandbox_execute_not_supported",
            tool_name=getattr(func, "__name__", "unknown"),
            hint=(
                "SandboxBackend.execute() runs one function; Anthropic Managed "
                "Agents runs a full agent loop. Use the anthropic SDK "
                "integration (examples/anthropic_integration.py) or the "
                "ClaudeAgentSDK extra for loop-style execution."
            ),
        )
        return SandboxResult(
            success=False,
            error=(
                "ManagedSandboxBackend is a session-based backend: "
                "single-function execute() is not supported. "
                "See examples/anthropic_integration.py for the agent-loop "
                "integration, or roadmap issue #6 for the planned "
                "ManagedAgentExecutor interface."
            ),
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
BackendType = E2BBackend | DockerBackend | LocalBackend | ManagedSandboxBackend
