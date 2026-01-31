"""Core Airlock decorator for securing MCP tool calls.

The @Airlock decorator provides:
1. Ghost argument detection and stripping
2. Pydantic strict schema validation
3. Self-healing error responses
4. Optional E2B sandbox execution
5. Policy enforcement
6. Audit logging (JSON Lines format)
7. Full async function support
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
from .config import DEFAULT_CONFIG, AirlockConfig
from .context import AirlockContext, ContextExtractor, reset_context, set_current_context
from .policy import PolicyViolation, SecurityPolicy, ViolationType
from .sanitizer import sanitize_output
from .self_heal import (
    AirlockResponse,
    BlockReason,
    handle_ghost_argument_error,
    handle_policy_violation,
    handle_rate_limit,
    handle_validation_error,
)
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

            # Step 1: Strip or reject ghost arguments
            try:
                cleaned_kwargs, stripped = strip_ghost_arguments(
                    func,
                    dict(kwargs),
                    strict=self.config.strict_mode,
                )

                if stripped:
                    filtered_stripped = _filter_sensitive_keys(sorted(stripped))
                    logger.info(
                        "ghost_arguments_handled",
                        function=func_name,
                        stripped=filtered_stripped,
                        stripped_count=len(stripped),
                        mode="rejected" if self.config.strict_mode else "stripped",
                    )

            except GhostArgumentError as e:
                response = handle_ghost_argument_error(e)
                # Invoke on_blocked callback if configured
                if self.config.on_blocked is not None:
                    try:
                        self.config.on_blocked(
                            func_name,
                            f"Ghost arguments rejected: {e.ghost_args}",
                            {"ghost_args": list(e.ghost_args)},
                        )
                    except Exception as callback_error:
                        logger.warning(
                            "callback_error",
                            callback="on_blocked",
                            error=str(callback_error),
                        )
                return kwargs, start_time, context, response

            # Step 2: Resolve and check security policy
            resolved_policy: SecurityPolicy | None = None
            if self.policy is not None:
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
                        return kwargs, start_time, context, response
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
                        # Invoke on_rate_limit callback if configured
                        if self.config.on_rate_limit is not None:
                            try:
                                self.config.on_rate_limit(func_name, reset_seconds)
                            except Exception as callback_error:
                                logger.warning(
                                    "callback_error",
                                    callback="on_rate_limit",
                                    error=str(callback_error),
                                )
                    else:
                        response = handle_policy_violation(
                            func_name,
                            policy_name="SecurityPolicy",
                            reason=e.message,
                        )
                        # Invoke on_blocked callback if configured
                        if self.config.on_blocked is not None:
                            try:
                                self.config.on_blocked(
                                    func_name,
                                    e.message,
                                    {"violation_type": e.violation_type, **e.details},
                                )
                            except Exception as callback_error:
                                logger.warning(
                                    "callback_error",
                                    callback="on_blocked",
                                    error=str(callback_error),
                                )
                    return kwargs, start_time, context, response

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
                # Invoke on_validation_error callback if configured
                if self.config.on_validation_error is not None:
                    try:
                        self.config.on_validation_error(func_name, error)
                    except Exception as callback_error:
                        logger.warning(
                            "callback_error",
                            callback="on_validation_error",
                            error=str(callback_error),
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
                    if self.sandbox:
                        result = await self._execute_in_sandbox_async(
                            func, *args, **cleaned_kwargs
                        )
                    else:
                        # Await the async validated function
                        # Type ignore: validated_func preserves async nature of func
                        result = await validated_func(*args, **cleaned_kwargs)  # type: ignore[misc]

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
                    if self.sandbox:
                        result = self._execute_in_sandbox(func, *args, **cleaned_kwargs)
                    else:
                        result = validated_func(*args, **cleaned_kwargs)

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
