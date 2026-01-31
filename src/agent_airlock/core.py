"""Core Airlock decorator for securing MCP tool calls.

The @Airlock decorator provides:
1. Ghost argument detection and stripping
2. Pydantic strict schema validation
3. Self-healing error responses
4. Optional E2B sandbox execution
5. Policy enforcement
6. Audit logging
"""

from __future__ import annotations

import functools
import time
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar, overload

import structlog
from pydantic import ValidationError

from .config import DEFAULT_CONFIG, AirlockConfig
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

# Parameter names that should not appear in debug logs
SENSITIVE_PARAM_NAMES = frozenset({
    "password", "passwd", "pwd", "secret", "token", "key", "api_key",
    "apikey", "auth", "authorization", "credential", "credentials",
    "private_key", "privatekey", "access_token", "refresh_token",
    "session", "cookie", "ssn", "credit_card", "card_number",
})


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
        policy: SecurityPolicy | None = None,
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
        """The actual decorator implementation."""
        # Create strict validator wrapper
        validated_func = create_strict_validator(func)

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R | dict[str, Any]:
            start_time = time.time()
            func_name = func.__name__

            logger.debug(
                "airlock_intercept",
                function=func_name,
                args_count=len(args),
                kwargs_keys=_filter_sensitive_keys(list(kwargs.keys())),
            )

            # Step 1: Strip or reject ghost arguments
            try:
                cleaned_kwargs, stripped = strip_ghost_arguments(
                    func,
                    dict(kwargs),
                    strict=self.config.strict_mode,
                )
                kwargs = cleaned_kwargs  # type: ignore[assignment]

                if stripped:
                    # Filter sensitive names from log output
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
                self._log_blocked(func_name, response, start_time)
                return response.to_dict()

            # Step 2: Check security policy
            if self.policy is not None:
                try:
                    self.policy.check(func_name)
                except PolicyViolation as e:
                    if e.violation_type == ViolationType.RATE_LIMITED.value:
                        response = handle_rate_limit(
                            func_name,
                            limit=e.details.get("limit", "unknown"),
                            reset_seconds=int(e.details.get("reset_seconds", 60)),
                        )
                    else:
                        response = handle_policy_violation(
                            func_name,
                            policy_name="SecurityPolicy",
                            reason=e.message,
                        )
                    self._log_blocked(func_name, response, start_time)
                    return response.to_dict()

            # Step 3: Validate with Pydantic strict mode
            try:
                if self.sandbox:
                    # Phase 2: E2B sandbox execution
                    result = self._execute_in_sandbox(func, *args, **kwargs)
                else:
                    result = validated_func(*args, **kwargs)

            except ValidationError as e:
                response = handle_validation_error(e, func_name)
                self._log_blocked(func_name, response, start_time)
                return response.to_dict()

            except Exception as e:
                # Unexpected errors - don't expose internals to LLM
                logger.exception("unexpected_error", function=func_name, error=str(e))
                response = AirlockResponse.blocked_response(
                    reason=BlockReason.VALIDATION_ERROR,
                    error=f"AIRLOCK_BLOCK: Unexpected error in '{func_name}'",
                    fix_hints=["An internal error occurred. Please try again."],
                )
                return response.to_dict()

            # Step 4: Post-process result (sanitization, truncation)
            warnings: list[str] = []

            if self.config.sanitize_output and result is not None:
                # Determine max chars (0 = unlimited)
                max_chars = (
                    self.config.max_output_chars if self.config.max_output_chars > 0 else None
                )

                sanitization = sanitize_output(
                    result,
                    mask_pii=self.config.mask_pii,
                    mask_secrets=self.config.mask_secrets,
                    max_chars=max_chars,
                )

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

                # If result was a string, use sanitized content
                # For complex types, the sanitization was for logging/detection
                if isinstance(result, str):
                    result = sanitization.content  # type: ignore[assignment]

            elapsed = time.time() - start_time
            logger.info(
                "airlock_success",
                function=func_name,
                elapsed_ms=round(elapsed * 1000, 2),
            )

            if self.return_dict:
                return AirlockResponse.success_response(result, warnings=warnings or None).to_dict()

            return result

        return wrapper

    def _execute_in_sandbox(
        self,
        func: Callable[P, R],
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        """Execute function in E2B sandbox.

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
                # Result is deserialized from sandbox - type is preserved by cloudpickle
                return result.result  # type: ignore[no-any-return]
            else:
                # Sandbox execution failed - raise as exception
                raise SandboxExecutionError(
                    f"Sandbox execution failed: {result.error}",
                    details=result.to_dict(),
                )

        except ImportError:
            # E2B not installed
            if self.sandbox_required:
                # SECURITY: Do not fall back to local execution for dangerous operations
                raise SandboxUnavailableError(
                    f"Sandbox required for '{func.__name__}' but E2B is not available. "
                    "Install with: pip install agent-airlock[sandbox] and set E2B_API_KEY. "
                    "SECURITY WARNING: This function was marked sandbox_required=True to "
                    "prevent accidental local execution of dangerous code."
                )
            # Fall back to local execution with warning
            logger.warning(
                "sandbox_fallback_local",
                function=func.__name__,
                message="E2B not available. Install with: pip install agent-airlock[sandbox]",
            )
            validated_func = create_strict_validator(func)
            return validated_func(*args, **kwargs)

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
    policy: SecurityPolicy | None = None,
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
