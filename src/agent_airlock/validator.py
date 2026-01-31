"""Validation logic for Agent-Airlock.

Handles:
1. Ghost argument detection and stripping
2. Pydantic strict schema validation
3. Type coercion rejection
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, TypeVar

import structlog
from pydantic import ConfigDict, ValidationError, validate_call

logger = structlog.get_logger("agent-airlock.validator")

F = TypeVar("F", bound=Callable[..., Any])


class GhostArgumentError(Exception):
    """Raised when unknown arguments are detected in strict mode."""

    def __init__(self, func_name: str, ghost_args: set[str]) -> None:
        self.func_name = func_name
        self.ghost_args = ghost_args
        super().__init__(
            f"Unknown arguments for '{func_name}': {', '.join(sorted(ghost_args))}. "
            "These arguments do not exist in the function signature."
        )


def get_valid_parameters(func: Callable[..., Any]) -> tuple[set[str], bool]:
    """Extract valid parameter names from a function signature.

    Args:
        func: The function to inspect.

    Returns:
        Tuple of (set of parameter names, whether **kwargs is accepted).
    """
    sig = inspect.signature(func)
    params = set()
    accepts_kwargs = False

    for name, param in sig.parameters.items():
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            accepts_kwargs = True
        elif param.kind != inspect.Parameter.VAR_POSITIONAL:
            params.add(name)

    return params, accepts_kwargs


def detect_ghost_arguments(
    func: Callable[..., Any],
    kwargs: dict[str, Any],
) -> set[str]:
    """Detect arguments that don't exist in the function signature.

    Args:
        func: The function being called.
        kwargs: The keyword arguments passed to the function.

    Returns:
        Set of argument names that don't exist in the function signature.
    """
    valid_params, accepts_kwargs = get_valid_parameters(func)

    # If function accepts **kwargs, no arguments are "ghost"
    if accepts_kwargs:
        return set()

    return set(kwargs.keys()) - valid_params


def strip_ghost_arguments(
    func: Callable[..., Any],
    kwargs: dict[str, Any],
    strict: bool = False,
) -> tuple[dict[str, Any], set[str]]:
    """Remove ghost arguments from kwargs.

    Args:
        func: The function being called.
        kwargs: The keyword arguments passed to the function.
        strict: If True, raise GhostArgumentError instead of stripping.

    Returns:
        Tuple of (cleaned kwargs, set of removed argument names).

    Raises:
        GhostArgumentError: If strict=True and ghost arguments are detected.
    """
    ghost_args = detect_ghost_arguments(func, kwargs)

    if not ghost_args:
        return kwargs, set()

    if strict:
        raise GhostArgumentError(func.__name__, ghost_args)

    # Log warning about stripped arguments
    logger.warning(
        "ghost_arguments_stripped",
        function=func.__name__,
        stripped_args=sorted(ghost_args),
    )

    # Return cleaned kwargs
    cleaned = {k: v for k, v in kwargs.items() if k not in ghost_args}
    return cleaned, ghost_args


def create_strict_validator(func: F) -> F:
    """Wrap a function with Pydantic strict validation.

    Uses validate_call with strict=True to ensure:
    - No type coercion (e.g., "100" -> int fails)
    - Exact type matching required
    - Clear validation error messages

    Args:
        func: The function to wrap with validation.

    Returns:
        Wrapped function with strict Pydantic validation.
    """
    return validate_call(config=ConfigDict(strict=True))(func)


def format_validation_error(error: ValidationError) -> dict[str, Any]:
    """Format a Pydantic ValidationError into LLM-friendly structure.

    Args:
        error: The Pydantic validation error.

    Returns:
        Dictionary with error details and fix hints for the LLM.
    """
    errors = error.errors()
    formatted_errors = []

    for err in errors:
        location = ".".join(str(loc) for loc in err["loc"])
        error_type = err["type"]
        message = err["msg"]
        input_value = err.get("input")

        # Generate fix hint based on error type
        fix_hint = _generate_fix_hint(error_type, location, input_value)

        formatted_errors.append(
            {
                "field": location,
                "type": error_type,
                "message": message,
                "input": repr(input_value) if input_value is not None else None,
                "fix_hint": fix_hint,
            }
        )

    return {
        "error_count": len(errors),
        "errors": formatted_errors,
    }


def _generate_fix_hint(error_type: str, field: str, input_value: Any) -> str:
    """Generate a helpful fix hint for the LLM based on error type."""
    hints = {
        "string_type": f"'{field}' must be a string, not {type(input_value).__name__}",
        "int_type": f"'{field}' must be an integer, not {type(input_value).__name__}",
        "float_type": f"'{field}' must be a number, not {type(input_value).__name__}",
        "bool_type": f"'{field}' must be a boolean (true/false), not {type(input_value).__name__}",
        "list_type": f"'{field}' must be a list/array, not {type(input_value).__name__}",
        "dict_type": f"'{field}' must be an object/dict, not {type(input_value).__name__}",
        "missing": f"'{field}' is required but was not provided",
        "string_pattern_mismatch": f"'{field}' does not match the required pattern",
        "greater_than": f"'{field}' must be greater than the minimum value",
        "less_than": f"'{field}' must be less than the maximum value",
        "value_error": f"'{field}' has an invalid value",
    }

    return hints.get(error_type, f"'{field}' failed validation: check the type and format")
