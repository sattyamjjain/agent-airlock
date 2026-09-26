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

The ``@Airlock(sandbox=True)`` decorator always runs on E2B; ``AirlockConfig`` has no
backend setting. Call a backend directly to run a function on it:

Usage:
    from agent_airlock.sandbox_backend import DockerBackend

    backend = DockerBackend(image="agent-airlock-sandbox:local")
    result = backend.execute(my_function, args=(2, 3), kwargs={}, timeout=30)
    if result.success:
        print(result.result)

    # Local execution (UNSAFE): no isolation at all
    from agent_airlock.sandbox_backend import LocalBackend
    result = LocalBackend(allow_unsafe=True).execute(my_function, (2, 3), {})

E2B, Docker and Modal run the same payload and read its outcome back as JSON, so a
result arrives as JSON types: tuples as lists, anything else JSON cannot encode as its
``str()``.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import contextvars
import inspect
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from ._log import structlog

if TYPE_CHECKING:
    from .config import AirlockConfig
    from .network import NetworkPolicy

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
        tool_failed: True when the function ran and raised (or returned something that
            could not be sent back); False when the backend itself could not run it.
    """

    success: bool
    result: Any = None
    error: str | None = None
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: float = 0.0
    sandbox_id: str | None = None
    backend: str = "unknown"
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
            "backend": self.backend,
            "tool_failed": self.tool_failed,
        }


def _run_to_completion(value: Any) -> Any:
    """Return an async function's result instead of its coroutine.

    With no event loop running here, the coroutine runs on a new one. Inside a running
    loop ``asyncio.run()`` refuses, so it runs on a new loop in a worker thread, with a
    copy of this thread's context.
    """
    if not inspect.isawaitable(value):
        return value

    async def _wait() -> Any:
        return await value

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_wait())
    context = contextvars.copy_context()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
        return worker.submit(context.run, asyncio.run, _wait()).result()


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
        from .sandbox import execute_in_sandbox

        result = execute_in_sandbox(func, args, kwargs, self._config(timeout))

        return SandboxResult(
            success=result.success,
            result=result.result,
            error=result.error,
            stdout=result.stdout,
            stderr=result.stderr,
            execution_time_ms=result.execution_time_ms,
            sandbox_id=result.sandbox_id,
            backend=self.name,
            tool_failed=result.tool_failed,
        )

    def _config(self, timeout: int | None = None) -> AirlockConfig:
        """The config whose sandbox pool this backend uses."""
        from .config import AirlockConfig

        return AirlockConfig(
            e2b_api_key=self.api_key,
            sandbox_timeout=timeout or self.timeout,
            sandbox_pool_size=self.pool_size,
        )

    def warmup(self) -> None:
        """Pre-warm the E2B sandbox pool."""
        from .sandbox import get_sandbox_pool

        get_sandbox_pool(self._config()).warm_up()

    def shutdown(self) -> None:
        """Shutdown this backend's E2B sandbox pool.

        Until 0.10.17 this shut down the pool for the default config, not this backend's.
        """
        from .sandbox import get_sandbox_pool

        get_sandbox_pool(self._config()).shutdown()


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
                "(`docker pull <name>:<tag>` prints the digest of the tag you "
                "currently use on its 'Digest:' line)."
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

        The container runs the same payload as E2B, so an async function's coroutine is
        awaited there; until 0.10.17 it came back as its ``str()``.
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
            import docker

            from .sandbox import (
                _parse_execution_output,
                generate_execution_code,
                serialize_function_call,
            )

            client = docker.from_env()
            script = generate_execution_code(serialize_function_call(func, args, kwargs))

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

            outcome = _parse_execution_output(output)
            if outcome is None:
                # A non-zero exit with no outcome printed: the payload never finished.
                exit_code = exit_info.get("StatusCode") if isinstance(exit_info, dict) else 0
                return SandboxResult(
                    success=False,
                    error=(
                        f"Container exited with status {exit_code}"
                        if exit_code != 0
                        else "Container did not produce expected output"
                    ),
                    stdout=output,
                    backend=self.name,
                )

            elapsed = (time.time() - start_time) * 1000
            return SandboxResult(
                success=outcome["success"],
                result=outcome.get("result"),
                error=outcome.get("error"),
                stdout=output,
                execution_time_ms=round(elapsed, 2),
                backend=self.name,
                tool_failed=not outcome["success"],
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
        timeout: int = 60,
    ) -> SandboxResult:
        """Execute function locally with NO isolation.

        WARNING: This is UNSAFE. The function runs with full host access. An async
        function's coroutine is awaited. ``timeout`` is accepted so the call matches every
        other backend (until 0.10.17 it was named ``_timeout``, and ``timeout=`` raised a
        TypeError), but local execution has no timeout.
        """
        del timeout  # local execution has no timeout
        start_time = time.time()

        logger.warning(
            "local_unsafe_execution",
            function=getattr(func, "__name__", "unknown"),
            warning="Executing with NO sandbox isolation",
        )

        try:
            result = _run_to_completion(func(*args, **kwargs))
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
                tool_failed=True,
            )


class ManagedSandboxBackend(SandboxBackend):
    """Anthropic Managed Agents backend — **beta, opt-in only**.

    Anthropic's Managed Agents product (https://anthropic.com/, announced
    April 2026) runs complete agent loops — model turns, tool calls, and
    state — on Anthropic-operated infrastructure. This does NOT map
    one-to-one onto the `SandboxBackend.execute()` contract, which is
    "run THIS function with THESE arguments in an isolated environment."

    Why this backend exists:

    - A Managed Agents story was tracked in #6 (v0.5.0 roadmap), which
      closed 2026-05-03 without this landing. It is untracked today.
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

    Future work (**not currently tracked** — #6 is closed): a
    session-based ``ManagedAgentExecutor``
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


class ModalBackend(SandboxBackend):
    """Modal-backed sandbox (issue #30, v0.8.11+).

    Wraps `modal.Sandbox.create()` so callers can run airlocked tools inside
    Modal's hosted sandboxes — useful when the operator already runs the
    rest of their agent workload on Modal and wants a single billing /
    observability surface instead of mixing E2B and Modal.

    ## Isolation model — read this before you reach for ``cap_drop``

    Modal sandboxes run under gVisor (kernel-syscall filtering); container
    escape is mitigated at the syscall layer, *not* at the Linux-capability
    layer. The Modal Python SDK therefore does **not** expose ``cap_drop``,
    ``cap_add``, ``seccomp``, ``no-new-privileges``, or any other
    Docker-style capability primitive — there is nothing to map. Network
    egress is the only isolation knob the SDK surfaces, and this backend
    sets ``block_network=True`` by default so a freshly-constructed
    ``ModalBackend`` is air-gapped at the network layer.

    If your threat model requires Linux-capability dropping at the
    container level, use :class:`DockerBackend` — which *does* expose it —
    not this backend.

    ## NetworkPolicy → Modal mapping

    The :class:`agent_airlock.network.NetworkPolicy` shape is
    hostname-oriented, while Modal's allowlist is CIDR-oriented. The mapping
    this backend implements is intentionally narrow:

    - ``network_policy is None`` → ``block_network=True`` (fail-closed
      default; matches the rest of agent-airlock's deny-by-default ethos).
    - ``network_policy.allow_egress is False`` → ``block_network=True``.
    - ``network_policy.allow_egress is True`` → ``block_network=False``.
      Hostname allowlists in ``NetworkPolicy.allowed_hosts`` are **not**
      forwarded to Modal (Modal expects CIDRs); the backend emits a
      structlog warning when a hostname allowlist is supplied, and the
      operator is responsible for re-stating the constraint via
      ``policy.allowed_hosts`` enforcement inside ``Airlock`` itself.

    ## Availability

    ``is_available()`` returns ``True`` iff ``import modal`` succeeds — i.e.
    iff the operator installed the ``[modal]`` extra. The SDK import is
    lazy (inside ``is_available`` / ``execute``) so the base install of
    ``agent-airlock`` does not pay for it.

    Attributes:
        app_name: Modal app identifier. Resolved at execute-time via
            ``modal.App.lookup(app_name, create_if_missing=True)``.
        image_ref: Image reference for the sandbox container. Forwarded to
            ``modal.Image.from_registry(image_ref)``.
        cpu: Fractional CPU-core request. Modal accepts ``float`` or
            ``(request, limit)`` tuples; this backend only models the
            single-value request form to keep the surface narrow.
        memory_mb: Memory request in **MB**. Modal's parameter is named
            ``memory`` and is in **MiB**; the value is forwarded as-is
            (the < 5% MB/MiB delta is below the noise floor of any
            useful memory request).
        timeout_s: Sandbox lifetime in seconds. Forwarded to Modal's
            ``timeout`` parameter.
        network_policy: Optional :class:`NetworkPolicy`. See "NetworkPolicy
            → Modal mapping" above.

    Example:
        from agent_airlock.sandbox_backend import ModalBackend

        backend = ModalBackend(
            app_name="my-airlock-sandbox",
            image_ref="python:3.11-slim",
            cpu=0.5,
            memory_mb=512,
            timeout_s=30,
        )
        result = backend.execute(my_function, args=(2, 3), kwargs={})

    ``AirlockConfig`` has no backend setting and the ``@Airlock`` decorator runs on E2B,
    so a Modal sandbox is used by calling ``execute`` directly.
    """

    def __init__(
        self,
        app_name: str,
        image_ref: str,
        cpu: float = 0.5,
        memory_mb: int = 512,
        timeout_s: int = 30,
        network_policy: NetworkPolicy | None = None,
    ) -> None:
        """Initialize Modal backend.

        Args:
            app_name: Modal app name. Created on first use if missing.
            image_ref: Container image reference forwarded to
                ``modal.Image.from_registry``.
            cpu: Fractional CPU-core request. Default 0.5.
            memory_mb: Memory request in MB (forwarded as MiB to Modal).
                Default 512.
            timeout_s: Sandbox lifetime in seconds. Default 30.
            network_policy: Optional :class:`NetworkPolicy`. Default
                ``None`` means ``block_network=True`` (fail-closed).

        Raises:
            ValueError: ``cpu``, ``memory_mb``, or ``timeout_s`` is not
                strictly positive.
        """
        if cpu <= 0:
            raise ValueError(f"cpu must be > 0; got {cpu!r}")
        if memory_mb <= 0:
            raise ValueError(f"memory_mb must be > 0; got {memory_mb!r}")
        if timeout_s <= 0:
            raise ValueError(f"timeout_s must be > 0; got {timeout_s!r}")

        self.app_name = app_name
        self.image_ref = image_ref
        self.cpu = cpu
        self.memory_mb = memory_mb
        self.timeout_s = timeout_s
        self.network_policy = network_policy

    @property
    def name(self) -> str:
        return "modal"

    def is_available(self) -> bool:
        """Check whether the ``modal`` SDK is importable.

        Returns ``True`` iff the operator installed the ``[modal]`` extra.
        """
        try:
            import modal  # noqa: F401

            return True
        except ImportError:
            return False

    def _resolve_block_network(self) -> bool:
        """Map :class:`NetworkPolicy` → Modal's ``block_network`` boolean.

        See the class docstring's "NetworkPolicy → Modal mapping" section
        for the rationale. Default (no policy supplied) is the fail-closed
        ``block_network=True``.
        """
        policy = self.network_policy
        if policy is None:
            return True
        if not policy.allow_egress:
            return True
        if policy.allowed_hosts:
            logger.warning(
                "modal_backend.hostname_allowlist_not_enforced",
                hint=(
                    "Modal's outbound allowlist is CIDR-based; the "
                    "NetworkPolicy.allowed_hosts entries are not "
                    "forwarded to Modal. Enforce the hostname allowlist "
                    "at the Airlock policy layer instead."
                ),
                allowed_hosts=list(policy.allowed_hosts),
            )
        return False

    def execute(
        self,
        func: Callable[..., R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        timeout: int | None = None,
    ) -> SandboxResult:
        """Run ``func(*args, **kwargs)`` inside a Modal sandbox.

        The function is cloudpickled, base64-encoded, and shipped to a
        freshly-created Modal sandbox running ``image_ref``. The sandbox runs
        the same payload as E2B and Docker, which prints the outcome as JSON.

        Until 0.10.17 the sandbox printed a cloudpickled result that this
        method unpickled on the host. Code running in the sandbox controls
        that output, so a tool could print a pickle of its own, or replace
        ``cloudpickle.dumps`` before the harness ran, and run code on the host.
        Nothing from the sandbox is unpickled now; a result arrives as JSON
        types.

        Args:
            func: The function to execute. Must be cloudpickle-able.
            args: Positional arguments for ``func``.
            kwargs: Keyword arguments for ``func``.
            timeout: Per-call execution-time override. Falls back to
                ``self.timeout_s`` when ``None``.
        """
        start = time.monotonic()
        sandbox_id: str | None = None

        try:
            import modal  # local: keep optional
        except ImportError:
            return SandboxResult(
                success=False,
                error=(
                    "modal SDK is not installed; "
                    "run `pip install agent-airlock[modal]` to enable "
                    "the Modal sandbox backend"
                ),
                backend=self.name,
            )

        try:
            import cloudpickle  # noqa: F401 - the payload is pickled with it
        except ImportError:
            return SandboxResult(
                success=False,
                error=(
                    "cloudpickle is required for the Modal backend; "
                    "run `pip install agent-airlock[sandbox]` "
                    "(or pip install cloudpickle directly)"
                ),
                backend=self.name,
            )

        from .sandbox import (
            _parse_execution_output,
            generate_execution_code,
            serialize_function_call,
        )

        harness = generate_execution_code(serialize_function_call(func, args, kwargs))

        effective_timeout = timeout if timeout is not None else self.timeout_s
        block_network = self._resolve_block_network()

        sandbox = None
        try:
            app = modal.App.lookup(self.app_name, create_if_missing=True)
            image = modal.Image.from_registry(self.image_ref).pip_install("cloudpickle>=3.0")
            sandbox = modal.Sandbox.create(
                "python",
                "-c",
                harness,
                app=app,
                image=image,
                cpu=self.cpu,
                memory=self.memory_mb,
                timeout=effective_timeout,
                block_network=block_network,
            )
            sandbox_id = getattr(sandbox, "object_id", None)
            sandbox.wait()
            stdout = sandbox.stdout.read()
            stderr = sandbox.stderr.read()
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                success=False,
                error=f"modal sandbox failed: {exc}",
                execution_time_ms=(time.monotonic() - start) * 1000.0,
                sandbox_id=sandbox_id,
                backend=self.name,
            )
        finally:
            if sandbox is not None:
                with contextlib.suppress(Exception):
                    sandbox.terminate()

        elapsed_ms = (time.monotonic() - start) * 1000.0
        try:
            outcome = _parse_execution_output(stdout)
            no_outcome = "modal sandbox produced no result envelope"
        except ValueError as exc:
            outcome = None
            no_outcome = f"modal sandbox result could not be read: {exc}"

        if outcome is None:
            return SandboxResult(
                success=False,
                error=no_outcome,
                stdout=stdout,
                stderr=stderr,
                execution_time_ms=elapsed_ms,
                sandbox_id=sandbox_id,
                backend=self.name,
            )
        return SandboxResult(
            success=outcome["success"],
            result=outcome.get("result"),
            error=outcome.get("error"),
            stdout=stdout,
            # A tool's traceback travels in the outcome; keep it where it used to land.
            stderr=outcome.get("traceback") or stderr,
            execution_time_ms=elapsed_ms,
            sandbox_id=sandbox_id,
            backend=self.name,
            tool_failed=not outcome["success"],
        )


# Default backend factory
def get_default_backend(config: AirlockConfig | None = None) -> SandboxBackend:
    """Get the default sandbox backend based on availability.

    Priority:
    1. E2B (if available and API key present)
    2. Docker (if a daemon answers), with the default image
    3. ``LocalBackend(allow_unsafe=True)``, which runs the function in this process
       with NO isolation, after a ``no_sandbox_available`` warning

    It never returns None, so a caller that needs isolation must check the backend's
    ``name`` (``"local_unsafe"`` for the last case) before running anything dangerous.
    ModalBackend and ManagedSandboxBackend are never picked.

    Args:
        config: Optional config to check for API keys.

    Returns:
        The best available SandboxBackend.
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
BackendType = E2BBackend | DockerBackend | LocalBackend | ManagedSandboxBackend | ModalBackend
