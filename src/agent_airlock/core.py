"""Core Airlock decorator for securing MCP tool calls.

The @Airlock decorator provides:
1. Ghost argument detection and stripping
2. Pydantic strict schema validation
3. Self-healing error responses
4. Optional E2B sandbox execution
5. Policy enforcement
6. Audit logging (JSON Lines format)
7. Full async function support
8. Filesystem path validation (V0.3.0)
9. Network egress control (V0.3.0)
10. Honeypot deception (V0.3.0)

Security Notes
--------------

exec() Usage:
    This module contains exec() calls ONLY in docstring examples demonstrating
    how to safely execute user code with sandbox=True. These examples show the
    intended pattern:

        @Airlock(sandbox=True, sandbox_required=True)
        def run_code(code: str) -> str:
            exec(code)  # Runs in E2B MicroVM, never locally
            return "ok"

    When sandbox_required=True, Airlock raises SandboxUnavailableError if E2B
    is not available, preventing accidental local execution of dangerous code.
    Never use exec() without sandbox protection in production.

Thread Safety:
    This module is thread-safe. The Airlock class can be used as a decorator
    from multiple threads concurrently. State is managed through:
    - contextvars for request-scoped context (AirlockContext)
    - Thread-local storage for network policy (in network.py)
    - Locks in sandbox pool and audit logger

    Lock Acquisition Order (to prevent deadlocks):
    1. _pool_lock (sandbox.py) - sandbox pool access
    2. audit._file_lock (audit.py) - audit file writes
    3. _patch_lock (network.py) - socket interceptor installation

    Note: Locks should never be held across await boundaries or external calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import time
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar, overload

import structlog
from pydantic import ValidationError

from .audit import AuditLogger
from .capabilities import (
    Capability,
    CapabilityDeniedError,
    capabilities_to_list,
    get_required_capabilities,
)
from .config import DEFAULT_CONFIG, AirlockConfig
from .context import AirlockContext, ContextExtractor, reset_context, set_current_context
from .filesystem import PathValidationError, validate_path
from .honeypot import (
    create_honeypot_response,
    create_honeypot_response_async,
    should_soft_block,
    should_use_honeypot,
)
from .network import NetworkBlockedError, network_airgap
from .policy import PolicyViolation, SecurityPolicy, ViolationType
from .sanitizer import sanitize_output
from .self_heal import (
    AirlockResponse,
    BlockReason,
    handle_ghost_argument_error,
    handle_network_blocked,
    handle_path_violation,
    handle_policy_violation,
    handle_rate_limit,
    handle_validation_error,
)
from .unknown_args import UnknownArgsMode, handle_unknown_args
from .validator import GhostArgumentError, create_strict_validator, strip_ghost_arguments

logger = structlog.get_logger("agent-airlock")

P = ParamSpec("P")
R = TypeVar("R")

# Type alias for policy resolver functions
PolicyResolver = Callable[[AirlockContext[Any]], SecurityPolicy | None]

# Parameter names that should not appear in debug logs
SENSITIVE_PARAM_NAMES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "key",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "credential",
        "credentials",
        "private_key",
        "privatekey",
        "access_token",
        "refresh_token",
        "session",
        "cookie",
        "ssn",
        "credit_card",
        "card_number",
    }
)


def _filter_sensitive_keys(keys: list[str]) -> list[str]:
    """Filter out sensitive parameter names from a list of keys.

    SECURITY: Prevents leaking sensitive parameter names to logs.
    """
    return [k for k in keys if k.lower() not in SENSITIVE_PARAM_NAMES]


# Parameter names that typically contain file paths
PATH_PARAM_NAMES = frozenset(
    {
        "path",
        "file",
        "filename",
        "filepath",
        "file_path",
        "directory",
        "dir",
        "folder",
        "source",
        "destination",
        "dest",
        "src",
        "target",
        "input_file",
        "output_file",
        "config_file",
        "log_file",
    }
)


def _looks_like_path(key: str, value: Any) -> bool:
    """Check if a parameter looks like a file path.

    Uses heuristics based on:
    - Parameter name patterns
    - Value patterns (starts with /, contains path separators)
    """
    if not isinstance(value, str):
        return False

    # Check parameter name
    if key.lower() in PATH_PARAM_NAMES:
        return True

    # Check value patterns
    value_lower = value.lower()

    # Absolute paths
    if value.startswith("/") or value.startswith("\\"):
        return True

    # Windows paths
    if len(value) > 2 and value[1] == ":" and value[2] in ("/", "\\"):
        return True

    # Relative paths with separators
    if "/" in value or "\\" in value:
        # Exclude URLs
        return "://" not in value

    # Common file extensions
    return any(
        value_lower.endswith(ext) for ext in (".txt", ".json", ".yaml", ".yml", ".env", ".py")
    )


class Airlock:
    """Decorator that secures function calls with validation, sandboxing, and policies.

    Example:
        @Airlock()
        def read_file(filename: str) -> str:
            with open(filename) as f:
                return f.read()

        @Airlock(sandbox=True)
        def run_code(code: str) -> str:
            exec(code)
            return "executed"

        @Airlock(config=AirlockConfig(strict_mode=True))
        def delete_record(id: int) -> bool:
            ...
    """

    def __init__(
        self,
        *,
        sandbox: bool = False,
        sandbox_required: bool = False,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | PolicyResolver | None = None,
        return_dict: bool = False,
    ) -> None:
        """Initialize the Airlock decorator.

        Args:
            sandbox: If True, execute the function in an E2B sandbox.
            sandbox_required: If True and sandbox=True, raise an error instead of
                            falling back to local execution when E2B is unavailable.
                            SECURITY: Always set this to True for dangerous operations
                            like exec() to prevent accidental local execution.
            config: Configuration options. Uses DEFAULT_CONFIG if not provided.
            policy: Security policy to enforce (RBAC, rate limits, time restrictions).
                   Can be a SecurityPolicy instance or a callable that takes an
                   AirlockContext and returns a SecurityPolicy (for dynamic resolution).
            return_dict: If True, always return AirlockResponse as dict.
                        If False (default), return the raw result on success,
                        and AirlockResponse dict on error.
        """
        self.sandbox = sandbox
        self.sandbox_required = sandbox_required
        self.config = config or DEFAULT_CONFIG
        self.policy = policy
        self.return_dict = return_dict

    @overload
    def __call__(self, func: Callable[P, R]) -> Callable[P, R | dict[str, Any]]: ...

    @overload
    def __call__(
        self, func: None = None
    ) -> Callable[[Callable[P, R]], Callable[P, R | dict[str, Any]]]: ...

    def __call__(
        self,
        func: Callable[P, R] | None = None,
    ) -> (
        Callable[P, R | dict[str, Any]]
        | Callable[[Callable[P, R]], Callable[P, R | dict[str, Any]]]
    ):
        """Apply the Airlock decorator to a function.

        Supports both @Airlock() and @Airlock syntaxes.
        """
        if func is None:
            # Called with arguments: @Airlock(sandbox=True)
            return self._decorator

        # Called without arguments: @Airlock
        return self._decorator(func)

    def _decorator(self, func: Callable[P, R]) -> Callable[P, R | dict[str, Any]]:
        """The actual decorator implementation.

        Detects if the function is async and creates the appropriate wrapper.
        Both sync and async wrappers share the same validation logic.
        """
        # Create strict validator wrapper
        validated_func = create_strict_validator(func)
        is_async = asyncio.iscoroutinefunction(func)

        # Initialize audit logger
        audit_logger = AuditLogger(
            self.config.audit_log_path if self.config.enable_audit_log else None,
            self.config.enable_audit_log,
        )

        def _pre_execution(
            func_name: str,
            args: tuple[Any, ...],
            kwargs: dict[str, Any],
        ) -> tuple[dict[str, Any], float, AirlockContext[Any], AirlockResponse | None]:
            """Shared pre-execution logic for sync and async wrappers.

            Orchestrates 4 validation steps:
            1. Ghost argument validation (strip/reject hallucinated params)
            2. Security policy resolution and checking
            3. Filesystem path validation
            4. Capability gating

            Returns:
                Tuple of (cleaned_kwargs, start_time, context, error_response or None)
            """
            start_time = time.time()

            # Extract context from function arguments
            context = ContextExtractor.extract_from_args(args, kwargs)

            logger.debug(
                "airlock_intercept",
                function=func_name,
                args_count=len(args),
                kwargs_keys=_filter_sensitive_keys(list(kwargs.keys())),
                is_async=is_async,
                agent_id=context.agent_id,
                session_id=context.session_id,
            )

            # Step 1: Validate and handle ghost arguments
            cleaned_kwargs, _, ghost_error = self._validate_ghost_arguments(func, func_name, kwargs)
            if ghost_error is not None:
                return kwargs, start_time, context, ghost_error

            # Step 2: Resolve and check security policy
            resolved_policy, policy_error = self._resolve_and_check_policy(func_name, context)
            if policy_error is not None:
                return kwargs, start_time, context, policy_error

            # Step 3: Validate filesystem paths
            fs_error = self._validate_filesystem_paths(func_name, cleaned_kwargs)
            if fs_error is not None:
                return kwargs, start_time, context, fs_error

            # Step 4: Check capability requirements
            cap_error = self._check_capabilities(func, func_name, resolved_policy)
            if cap_error is not None:
                return kwargs, start_time, context, cap_error

            return cleaned_kwargs, start_time, context, None

        def _post_execution(
            func_name: str,
            result: Any,
            start_time: float,
            kwargs: dict[str, Any],
            context: AirlockContext[Any] | None = None,
        ) -> tuple[Any, list[str], int, bool]:
            """Shared post-execution logic for sync and async wrappers.

            Returns:
                Tuple of (processed_result, warnings, sanitized_count, was_truncated)
            """
            warnings: list[str] = []
            sanitized_count = 0
            was_truncated = False

            if self.config.sanitize_output and result is not None:
                max_chars = (
                    self.config.max_output_chars if self.config.max_output_chars > 0 else None
                )

                sanitization = sanitize_output(
                    result,
                    mask_pii=self.config.mask_pii,
                    mask_secrets=self.config.mask_secrets,
                    max_chars=max_chars,
                )

                sanitized_count = sanitization.detection_count
                was_truncated = sanitization.was_truncated

                if sanitization.detection_count > 0:
                    warnings.append(
                        f"Masked {sanitization.detection_count} sensitive value(s) in output"
                    )
                    logger.info(
                        "output_sanitized",
                        function=func_name,
                        detections=sanitization.detection_count,
                    )

                if sanitization.was_truncated:
                    warnings.append(
                        f"Output truncated from {sanitization.original_length:,} "
                        f"to {sanitization.sanitized_length:,} characters"
                    )

                if isinstance(result, str):
                    result = sanitization.content

            elapsed = time.time() - start_time
            logger.info(
                "airlock_success",
                function=func_name,
                elapsed_ms=round(elapsed * 1000, 2),
                is_async=is_async,
            )

            # Audit log successful call
            audit_logger.log(
                tool_name=func_name,
                blocked=False,
                duration_ms=(time.time() - start_time) * 1000,
                sanitized_count=sanitized_count,
                truncated=was_truncated,
                args=kwargs,
                result=result,
                agent_id=context.agent_id if context else None,
                session_id=context.session_id if context else None,
            )

            return result, warnings, sanitized_count, was_truncated

        def _handle_error(
            func_name: str,
            error: Exception,
            start_time: float,
            kwargs: dict[str, Any],
        ) -> dict[str, Any]:
            """Handle execution errors and return appropriate response."""
            if isinstance(error, ValidationError):
                response = handle_validation_error(error, func_name)
                self._safe_invoke_callback(
                    self.config.on_validation_error,
                    "on_validation_error",
                    func_name,
                    error,
                )
            else:
                logger.exception("unexpected_error", function=func_name, error=str(error))
                response = AirlockResponse.blocked_response(
                    reason=BlockReason.VALIDATION_ERROR,
                    error=f"AIRLOCK_BLOCK: Unexpected error in '{func_name}'",
                    fix_hints=["An internal error occurred. Please try again."],
                )

            self._log_blocked(func_name, response, start_time)

            # Audit log blocked call
            audit_logger.log(
                tool_name=func_name,
                blocked=True,
                block_reason=response.block_reason.value if response.block_reason else "unknown",
                duration_ms=(time.time() - start_time) * 1000,
                args=kwargs,
                error=response.error,
            )

            return response.to_dict()

        # Initialize wrapper variable - will be assigned to sync or async wrapper
        wrapper: Callable[..., Any]

        if is_async:
            # Async wrapper for async functions
            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R | dict[str, Any]:
                func_name = func.__name__
                cleaned_kwargs, start_time, context, error_response = _pre_execution(
                    func_name, args, dict(kwargs)
                )

                if error_response is not None:
                    # Check for honeypot response before returning error
                    if should_use_honeypot(self.config.honeypot_config):
                        # Use async version to avoid blocking event loop
                        honeypot_result = await create_honeypot_response_async(
                            func_name,
                            cleaned_kwargs,
                            self.config.honeypot_config,
                            block_reason=error_response.block_reason.value
                            if error_response.block_reason
                            else "unknown",
                        )
                        if honeypot_result is not None:
                            return honeypot_result  # type: ignore[no-any-return]

                    self._log_blocked(func_name, error_response, start_time)
                    audit_logger.log(
                        tool_name=func_name,
                        blocked=True,
                        block_reason=error_response.block_reason.value
                        if error_response.block_reason
                        else "unknown",
                        duration_ms=(time.time() - start_time) * 1000,
                        args=dict(kwargs),
                        error=error_response.error,
                        agent_id=context.agent_id,
                        session_id=context.session_id,
                    )
                    return error_response.to_dict()

                # Set context as current for the duration of execution
                token = set_current_context(context)
                try:
                    # V0.3.0: Apply network airgap if configured
                    # Note: For async, we still use the sync context manager
                    # as socket operations are fundamentally sync
                    if (
                        self.config.network_policy is not None
                        and not self.config.network_policy.allow_egress
                    ):
                        with network_airgap(self.config.network_policy):
                            if self.sandbox:
                                result = await self._execute_in_sandbox_async(
                                    func, *args, **cleaned_kwargs
                                )
                            else:
                                result = await validated_func(*args, **cleaned_kwargs)  # type: ignore[misc]
                    else:
                        if self.sandbox:
                            result = await self._execute_in_sandbox_async(
                                func, *args, **cleaned_kwargs
                            )
                        else:
                            # Await the async validated function
                            # Type ignore: validated_func preserves async nature of func
                            result = await validated_func(*args, **cleaned_kwargs)  # type: ignore[misc]

                except NetworkBlockedError as e:
                    # Handle network blocking with potential honeypot
                    if should_use_honeypot(self.config.honeypot_config):
                        # Use async version to avoid blocking event loop
                        honeypot_result = await create_honeypot_response_async(
                            func_name,
                            cleaned_kwargs,
                            self.config.honeypot_config,
                            block_reason="network_blocked",
                        )
                        if honeypot_result is not None:
                            return honeypot_result  # type: ignore[no-any-return]

                    response = handle_network_blocked(
                        func_name,
                        operation=e.operation,
                        target=e.target,
                        details=e.details,
                    )
                    self._log_blocked(func_name, response, start_time)
                    audit_logger.log(
                        tool_name=func_name,
                        blocked=True,
                        block_reason="network_blocked",
                        duration_ms=(time.time() - start_time) * 1000,
                        args=cleaned_kwargs,
                        error=response.error,
                    )
                    return response.to_dict()
                except Exception as e:
                    return _handle_error(func_name, e, start_time, cleaned_kwargs)
                finally:
                    reset_context(token)

                result, warnings, _, _ = _post_execution(
                    func_name, result, start_time, cleaned_kwargs, context
                )

                if self.return_dict:
                    return AirlockResponse.success_response(
                        result, warnings=warnings or None
                    ).to_dict()

                return result

            wrapper = async_wrapper
        else:
            # Sync wrapper for sync functions
            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R | dict[str, Any]:
                func_name = func.__name__
                cleaned_kwargs, start_time, context, error_response = _pre_execution(
                    func_name, args, dict(kwargs)
                )

                if error_response is not None:
                    # Check for honeypot response before returning error
                    if should_use_honeypot(self.config.honeypot_config):
                        honeypot_result = create_honeypot_response(
                            func_name,
                            cleaned_kwargs,
                            self.config.honeypot_config,
                            block_reason=error_response.block_reason.value
                            if error_response.block_reason
                            else "unknown",
                        )
                        if honeypot_result is not None:
                            return honeypot_result  # type: ignore[no-any-return]

                    self._log_blocked(func_name, error_response, start_time)
                    audit_logger.log(
                        tool_name=func_name,
                        blocked=True,
                        block_reason=error_response.block_reason.value
                        if error_response.block_reason
                        else "unknown",
                        duration_ms=(time.time() - start_time) * 1000,
                        args=dict(kwargs),
                        error=error_response.error,
                        agent_id=context.agent_id,
                        session_id=context.session_id,
                    )
                    return error_response.to_dict()

                # Set context as current for the duration of execution
                token = set_current_context(context)
                try:
                    # V0.3.0: Apply network airgap if configured
                    if (
                        self.config.network_policy is not None
                        and not self.config.network_policy.allow_egress
                    ):
                        with network_airgap(self.config.network_policy):
                            if self.sandbox:
                                result = self._execute_in_sandbox(func, *args, **cleaned_kwargs)
                            else:
                                result = validated_func(*args, **cleaned_kwargs)
                    else:
                        if self.sandbox:
                            result = self._execute_in_sandbox(func, *args, **cleaned_kwargs)
                        else:
                            result = validated_func(*args, **cleaned_kwargs)

                except NetworkBlockedError as e:
                    # Handle network blocking with potential honeypot
                    if should_use_honeypot(self.config.honeypot_config):
                        honeypot_result = create_honeypot_response(
                            func_name,
                            cleaned_kwargs,
                            self.config.honeypot_config,
                            block_reason="network_blocked",
                        )
                        if honeypot_result is not None:
                            return honeypot_result  # type: ignore[no-any-return]

                    response = handle_network_blocked(
                        func_name,
                        operation=e.operation,
                        target=e.target,
                        details=e.details,
                    )
                    self._log_blocked(func_name, response, start_time)
                    audit_logger.log(
                        tool_name=func_name,
                        blocked=True,
                        block_reason="network_blocked",
                        duration_ms=(time.time() - start_time) * 1000,
                        args=cleaned_kwargs,
                        error=response.error,
                    )
                    return response.to_dict()
                except Exception as e:
                    return _handle_error(func_name, e, start_time, cleaned_kwargs)
                finally:
                    reset_context(token)

                result, warnings, _, _ = _post_execution(
                    func_name, result, start_time, cleaned_kwargs, context
                )

                if self.return_dict:
                    return AirlockResponse.success_response(
                        result, warnings=warnings or None
                    ).to_dict()

                return result

            wrapper = sync_wrapper

        # CRITICAL: Preserve function signature for framework introspection
        # LangChain, CrewAI, AutoGen, PydanticAI use inspect.signature() to
        # generate JSON schemas for LLM tool calls. Without this, the LLM
        # sees "empty arguments" and tool calls fail.
        with contextlib.suppress(ValueError, TypeError):
            wrapper.__signature__ = inspect.signature(func)  # type: ignore[union-attr]

        # Copy annotations for type-aware frameworks
        wrapper.__annotations__ = getattr(func, "__annotations__", {})

        # Pydantic V2 pass-through: Copy validator attributes if they exist
        for attr in (
            "__pydantic_complete__",
            "__pydantic_config__",
            "__pydantic_decorators__",
            "__pydantic_fields__",
            "__pydantic_validator__",
            "__get_pydantic_core_schema__",
        ):
            if hasattr(func, attr):
                setattr(wrapper, attr, getattr(func, attr))

        return wrapper  # type: ignore[return-value]

    def _execute_in_sandbox(
        self,
        func: Callable[P, R],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        """Execute function in E2B sandbox (sync version).

        Serializes the function and arguments, executes in an isolated
        E2B Firecracker MicroVM, and returns the result.

        Falls back to local execution if E2B is not available.
        """
        try:
            from .sandbox import execute_in_sandbox

            result = execute_in_sandbox(
                func,
                args=args,
                kwargs=dict(kwargs),
                config=self.config,
            )

            if result.success:
                logger.info(
                    "sandbox_execution_success",
                    function=func.__name__,
                    sandbox_id=result.sandbox_id,
                    execution_time_ms=result.execution_time_ms,
                )
                return result.result  # type: ignore[no-any-return]
            else:
                raise SandboxExecutionError(
                    f"Sandbox execution failed: {result.error}",
                    details=result.to_dict(),
                )

        except ImportError:
            if self.sandbox_required:
                raise SandboxUnavailableError(
                    f"Sandbox required for '{func.__name__}' but E2B is not available. "
                    "Install with: pip install agent-airlock[sandbox] and set E2B_API_KEY. "
                    "SECURITY WARNING: This function was marked sandbox_required=True to "
                    "prevent accidental local execution of dangerous code."
                ) from None
            logger.warning(
                "sandbox_fallback_local",
                function=func.__name__,
                message="E2B not available. Install with: pip install agent-airlock[sandbox]",
            )
            validated_func = create_strict_validator(func)
            return validated_func(*args, **kwargs)

    async def _execute_in_sandbox_async(
        self,
        func: Callable[P, R],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        """Execute function in E2B sandbox (async version).

        Uses asyncio to run the sandbox execution without blocking.
        """
        try:
            from .sandbox import execute_in_sandbox_async

            result = await execute_in_sandbox_async(
                func,
                args=args,
                kwargs=dict(kwargs),
                config=self.config,
            )

            if result.success:
                logger.info(
                    "sandbox_execution_success",
                    function=func.__name__,
                    sandbox_id=result.sandbox_id,
                    execution_time_ms=result.execution_time_ms,
                    is_async=True,
                )
                return result.result  # type: ignore[no-any-return]
            else:
                raise SandboxExecutionError(
                    f"Sandbox execution failed: {result.error}",
                    details=result.to_dict(),
                )

        except ImportError:
            if self.sandbox_required:
                raise SandboxUnavailableError(
                    f"Sandbox required for '{func.__name__}' but E2B is not available. "
                    "Install with: pip install agent-airlock[sandbox] and set E2B_API_KEY. "
                    "SECURITY WARNING: This function was marked sandbox_required=True to "
                    "prevent accidental local execution of dangerous code."
                ) from None
            logger.warning(
                "sandbox_fallback_local",
                function=func.__name__,
                message="E2B not available. Install with: pip install agent-airlock[sandbox]",
            )
            validated_func = create_strict_validator(func)
            # For async functions falling back to local, we need to await
            if asyncio.iscoroutinefunction(func):
                return await validated_func(*args, **kwargs)  # type: ignore[misc, no-any-return]
            return validated_func(*args, **kwargs)  # pragma: no cover - defensive code

    def _validate_ghost_arguments(
        self,
        func: Callable[..., Any],
        func_name: str,
        kwargs: dict[str, Any],
    ) -> tuple[dict[str, Any], set[str] | None, AirlockResponse | None]:
        """Validate and strip ghost (hallucinated) arguments.

        Args:
            func: The function being called.
            func_name: Name of the function.
            kwargs: Keyword arguments to validate.

        Returns:
            Tuple of (cleaned_kwargs, stripped_args, error_response).
            If error_response is not None, validation failed.
        """
        should_block = self.config.unknown_args == UnknownArgsMode.BLOCK
        try:
            cleaned_kwargs, stripped = strip_ghost_arguments(
                func,
                dict(kwargs),
                strict=should_block,
            )

            if stripped:
                filtered_stripped = _filter_sensitive_keys(sorted(stripped))
                logger.info(
                    "ghost_arguments_handled",
                    function=func_name,
                    stripped=filtered_stripped,
                    stripped_count=len(stripped),
                    mode=self.config.unknown_args.value,
                )

                handle_unknown_args(
                    mode=self.config.unknown_args,
                    func_name=func_name,
                    stripped_args=stripped,
                    audit_logger=None,
                )

            return cleaned_kwargs, stripped, None

        except GhostArgumentError as e:
            response = handle_ghost_argument_error(e)
            self._safe_invoke_callback(
                self.config.on_blocked,
                "on_blocked",
                func_name,
                f"Ghost arguments rejected: {e.ghost_args}",
                {"ghost_args": list(e.ghost_args)},
            )
            return kwargs, None, response

    def _resolve_and_check_policy(
        self,
        func_name: str,
        context: AirlockContext[Any],
    ) -> tuple[SecurityPolicy | None, AirlockResponse | None]:
        """Resolve and check security policy.

        Args:
            func_name: Name of the function being called.
            context: The current airlock context.

        Returns:
            Tuple of (resolved_policy, error_response).
            If error_response is not None, policy check failed.
        """
        if self.policy is None:
            return None, None

        resolved_policy: SecurityPolicy | None = None

        # Support dynamic policy resolution via callable
        if callable(self.policy) and not isinstance(self.policy, SecurityPolicy):
            try:
                resolved_policy = self.policy(context)
            except Exception as e:
                logger.error(
                    "policy_resolver_error",
                    function=func_name,
                    error=str(e),
                )
                response = handle_policy_violation(
                    func_name,
                    policy_name="PolicyResolver",
                    reason=f"Policy resolution failed: {e}",
                )
                return None, response
        else:
            resolved_policy = self.policy

        if resolved_policy is not None:
            try:
                resolved_policy.check(func_name)
            except PolicyViolation as e:
                if e.violation_type == ViolationType.RATE_LIMITED.value:
                    reset_seconds = int(e.details.get("reset_seconds", 60))
                    response = handle_rate_limit(
                        func_name,
                        limit=e.details.get("limit", "unknown"),
                        reset_seconds=reset_seconds,
                    )
                    self._safe_invoke_callback(
                        self.config.on_rate_limit,
                        "on_rate_limit",
                        func_name,
                        reset_seconds,
                    )
                else:
                    response = handle_policy_violation(
                        func_name,
                        policy_name="SecurityPolicy",
                        reason=e.message,
                    )
                    self._safe_invoke_callback(
                        self.config.on_blocked,
                        "on_blocked",
                        func_name,
                        e.message,
                        {"violation_type": e.violation_type, **e.details},
                    )
                return resolved_policy, response

        return resolved_policy, None

    def _validate_filesystem_paths(
        self,
        func_name: str,
        cleaned_kwargs: dict[str, Any],
    ) -> AirlockResponse | None:
        """Validate filesystem paths in arguments.

        Args:
            func_name: Name of the function being called.
            cleaned_kwargs: Cleaned keyword arguments to check.

        Returns:
            Error response if validation failed, None otherwise.
        """
        if self.config.filesystem_policy is None:
            return None

        for key, value in cleaned_kwargs.items():
            if _looks_like_path(key, value):
                try:
                    validate_path(value, self.config.filesystem_policy)
                except PathValidationError as e:
                    logger.warning(
                        "path_validation_failed",
                        function=func_name,
                        path=e.path,
                        violation_type=e.violation_type,
                    )
                    # Check for honeypot or soft block strategies
                    if should_use_honeypot(self.config.honeypot_config):
                        # Honeypot response handled later in main flow
                        pass
                    elif not should_soft_block(self.config.honeypot_config):
                        response = handle_path_violation(
                            func_name,
                            path=e.path,
                            violation_type=e.violation_type,
                            details=e.details,
                        )
                        self._safe_invoke_callback(
                            self.config.on_blocked,
                            "on_blocked",
                            func_name,
                            f"Path violation: {e.message}",
                            {"path": e.path, "violation_type": e.violation_type},
                        )
                        return response

        return None

    def _check_capabilities(
        self,
        func: Callable[..., Any],
        func_name: str,
        resolved_policy: SecurityPolicy | None,
    ) -> AirlockResponse | None:
        """Check capability requirements for the function.

        Args:
            func: The function being called.
            func_name: Name of the function.
            resolved_policy: The resolved security policy (may have capability_policy).

        Returns:
            Error response if capability check failed, None otherwise.
        """
        # Determine which capability policy to use
        capability_policy = self.config.capability_policy
        if resolved_policy is not None and resolved_policy.capability_policy is not None:
            capability_policy = resolved_policy.capability_policy

        if capability_policy is None:
            return None

        required_caps = get_required_capabilities(func)
        if required_caps == Capability.NONE:
            return None

        try:
            capability_policy.check(required_caps, func_name)
            logger.debug(
                "capability_check_passed",
                function=func_name,
                required=capabilities_to_list(required_caps),
            )
        except CapabilityDeniedError as e:
            logger.warning(
                "capability_denied",
                function=func_name,
                required=str(e.required),
                missing=str(e.missing) if e.missing else None,
                denied=str(e.denied) if e.denied else None,
            )
            response = AirlockResponse.blocked_response(
                reason=BlockReason.CAPABILITY_DENIED,
                error=f"{func_name}: {e.message}",
            )
            self._safe_invoke_callback(
                self.config.on_blocked,
                "on_blocked",
                func_name,
                e.message,
                {"required": str(e.required), "denied": str(e.denied)},
            )
            return response

        return None

    def _safe_invoke_callback(
        self,
        callback: Callable[..., Any] | None,
        callback_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Safely invoke a callback, logging any errors.

        Args:
            callback: The callback function to invoke (may be None).
            callback_name: Name of the callback for logging.
            *args: Positional arguments to pass to the callback.
            **kwargs: Keyword arguments to pass to the callback.
        """
        if callback is None:
            return
        try:
            callback(*args, **kwargs)
        except Exception as e:
            logger.warning("callback_error", callback=callback_name, error=str(e))

    def _log_blocked(
        self,
        func_name: str,
        response: AirlockResponse,
        start_time: float,
    ) -> None:
        """Log a blocked tool call."""
        elapsed = time.time() - start_time
        logger.warning(
            "airlock_blocked",
            function=func_name,
            reason=response.block_reason.value if response.block_reason else "unknown",
            error=response.error,
            elapsed_ms=round(elapsed * 1000, 2),
        )


class SandboxExecutionError(Exception):
    """Raised when sandbox execution fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)


class SandboxUnavailableError(Exception):
    """Raised when sandbox is required but E2B is not available.

    This error is raised when sandbox_required=True and E2B dependencies
    are not installed or configured. This prevents dangerous operations
    like exec() from accidentally running on the local machine.
    """

    pass


# Convenience alias for common use case
def airlock(
    func: Callable[P, R] | None = None,
    *,
    sandbox: bool = False,
    sandbox_required: bool = False,
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | PolicyResolver | None = None,
    return_dict: bool = False,
) -> Callable[P, R | dict[str, Any]] | Callable[[Callable[P, R]], Callable[P, R | dict[str, Any]]]:
    """Functional interface for the Airlock decorator.

    Example:
        @airlock
        def my_tool(x: int) -> int:
            return x * 2

        @airlock(sandbox=True, sandbox_required=True)
        def dangerous_tool(code: str) -> str:
            # SECURITY: sandbox_required=True ensures this never runs locally
            exec(code)
            return "ok"
    """
    decorator = Airlock(
        sandbox=sandbox,
        sandbox_required=sandbox_required,
        config=config,
        policy=policy,
        return_dict=return_dict,
    )

    if func is None:
        return decorator
    return decorator(func)
