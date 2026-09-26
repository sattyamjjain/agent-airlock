"""Validation logic for Agent-Airlock.

Handles:
1. Ghost argument detection and stripping
2. Pydantic strict schema validation
3. Type coercion rejection
"""

from __future__ import annotations

import dataclasses
import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar, get_args, get_type_hints

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError, validate_call
from typing_extensions import TypedDict, is_typeddict

from ._log import structlog

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


#: The one strict config both entry points below build on. Shared rather than
#: repeated so :func:`create_strict_validator` and :func:`create_argument_validator`
#: cannot drift into enforcing different rules on the two dispatch paths, which is
#: the exact class of bug the sandbox gap was.
_STRICT_CONFIG = ConfigDict(strict=True)


def _has_own_config(hint: Any) -> bool:
    """Whether ``hint`` holds a type validated by its own config: a model, dataclass or TypedDict."""
    if isinstance(hint, type) and (
        issubclass(hint, BaseModel) or dataclasses.is_dataclass(hint) or is_typeddict(hint)
    ):
        return True
    return any(_has_own_config(arg) for arg in get_args(hint))


def _nested_strict_check(func: Callable[..., Any]) -> Callable[..., None] | None:
    """A check that validates the arguments whose type has its own config, strictly.

    ``validate_call`` applies :data:`_STRICT_CONFIG` to the function's parameters, but a
    Pydantic model, dataclass or TypedDict is validated with its own config, which is lax by
    default: until 0.10.16 ``{"age": "30"}`` for a model with ``age: int`` was coerced and
    the call ran. Strictness given at *call* level does reach nested types, so these
    arguments are validated once more with ``strict=True``. Their error locations keep the
    parameter name (``user.age``), since they are checked as keys of one TypedDict.

    Returns ``None`` when no parameter needs it, so ordinary tools pay nothing.
    """
    try:
        hints = get_type_hints(func, include_extras=True)
        signature = inspect.signature(func)
    except Exception:  # unresolvable annotations: validate_call reports them at build time
        return None
    variadic = (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
    fields = {
        name: hints[name]
        for name, param in signature.parameters.items()
        if param.kind not in variadic and name in hints and _has_own_config(hints[name])
    }
    if not fields:
        return None
    typed_dict: Any = TypedDict  # a runtime-built TypedDict, which mypy cannot type
    adapter: TypeAdapter[Any] = TypeAdapter(
        typed_dict(f"{getattr(func, '__name__', 'tool')}_arguments", fields, total=False)
    )

    def check(*args: Any, **kwargs: Any) -> None:
        try:
            bound = signature.bind_partial(*args, **kwargs)
        except TypeError:
            return  # a binding error is validate_call's to report
        provided = {name: value for name, value in bound.arguments.items() if name in fields}
        if provided:
            adapter.validate_python(provided, strict=True)

    return check


def create_strict_validator(func: F) -> F:
    """Wrap a function with Pydantic strict validation.

    Uses validate_call with strict=True to ensure:
    - No type coercion (e.g., "100" -> int fails)
    - Exact type matching required
    - Clear validation error messages

    Strictness reaches inside a Pydantic model, dataclass or TypedDict argument too (see
    :func:`_nested_strict_check`).

    Args:
        func: The function to wrap with validation.

    Returns:
        Wrapped function with strict Pydantic validation.
    """
    validated: Any = validate_call(config=_STRICT_CONFIG)(func)
    check = _nested_strict_check(func)
    if check is None:
        return validated  # type: ignore[no-any-return]

    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def checked_async(*args: Any, **kwargs: Any) -> Any:
            check(*args, **kwargs)
            return await validated(*args, **kwargs)

        return checked_async  # type: ignore[return-value]

    @functools.wraps(func)
    def checked(*args: Any, **kwargs: Any) -> Any:
        check(*args, **kwargs)
        return validated(*args, **kwargs)

    return checked  # type: ignore[return-value]


#: What :func:`create_argument_validator` hands back: takes the call's positional and
#: keyword arguments, returns the *validated* ones, and raises ``ValidationError`` on
#: refusal exactly as the wrapped callable would.
ArgumentValidator = Callable[
    [tuple[Any, ...], dict[str, Any]], tuple[tuple[Any, ...], dict[str, Any]]
]


def create_argument_validator(func: Callable[..., Any]) -> ArgumentValidator:
    """Build a validator that returns validated argument *values*, without executing ``func``.

    :func:`create_strict_validator` wraps a function so that validation happens on the way
    into a call. That is unusable on a dispatch path that does not call the wrapper: the
    ``sandbox=True`` path serialises the *undecorated* function into the micro-VM, so every
    ``Annotated`` validator (``SafePath``, ``SafeURL``, ``HandleField``) silently did not
    run. The wrapper cannot simply be shipped instead, because it is a closure and the
    ``HandleField`` ledger is in-process by design (see :mod:`agent_airlock.handles`).

    So validation is split from execution. This runs the same coercion and constraint
    checks against the arguments and hands back the validated values for the caller to
    dispatch with.

    It is the *same machinery*, not a reimplementation: a capture function is given
    ``func``'s signature and annotations, wrapped with the same ``validate_call`` and the
    same :data:`_STRICT_CONFIG`, and returns the arguments Pydantic passed it. A rule that
    holds on one path therefore holds on the other by construction.

    Annotations are resolved with ``get_type_hints(..., include_extras=True)`` rather than
    read raw. Under ``from __future__ import annotations`` (which this codebase mandates,
    and which tool authors commonly use) ``__annotations__`` holds *strings*, and the
    capture function does not share ``func``'s module globals, so the raw strings raise
    ``NameError`` at build time. ``include_extras`` is what preserves ``Annotated``; drop it
    and every safe type degrades to its base type and silently stops enforcing anything.

    Args:
        func: The undecorated function whose signature declares the contract.

    Returns:
        An :data:`ArgumentValidator`. Calling it returns ``(args, kwargs)`` with validated
        values, or raises ``pydantic.ValidationError``. If the validator could not be built
        at all, calling it raises ``TypeError`` rather than passing the arguments through:
        a contract that cannot be checked is refused, not waived.

    Note:
        A parameter with no annotation declares no contract, so nothing is enforced for it.
        That is true of :func:`create_strict_validator` too, and is the documented
        ``**kwargs`` limit in :mod:`agent_airlock.handles`, not a new gap.
    """

    def _capture(*args: Any, **kwargs: Any) -> tuple[tuple[Any, ...], dict[str, Any]]:
        return args, kwargs

    try:
        hints: dict[str, Any] = get_type_hints(func, include_extras=True)
    except Exception:  # pragma: no cover - unresolvable forward ref
        # Fall back to whatever is literally on the function. This only differs from the
        # resolved form for modules that postpone evaluation, and such a module would
        # already be failing in create_strict_validator for the same reason.
        hints = dict(getattr(func, "__annotations__", {}))
    hints.pop("return", None)

    build_error: str | None = None
    validating_capture: Callable[..., tuple[tuple[Any, ...], dict[str, Any]]] | None = None
    try:
        signature = inspect.signature(func)
        signature = signature.replace(
            parameters=[
                param.replace(annotation=hints.get(name, param.annotation))
                for name, param in signature.parameters.items()
            ],
            return_annotation=inspect.Signature.empty,
        )
        _capture.__signature__ = signature  # type: ignore[attr-defined]
        _capture.__annotations__ = hints
        _capture.__name__ = getattr(func, "__name__", "tool")
        _capture.__qualname__ = getattr(func, "__qualname__", _capture.__name__)
        validating_capture = validate_call(config=_STRICT_CONFIG)(_capture)
    except Exception as exc:  # pragma: no cover - degenerate signature
        build_error = f"{type(exc).__name__}: {exc}"

    nested_check = _nested_strict_check(func)

    def _validate(
        args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        if validating_capture is None:
            raise TypeError(
                f"cannot validate arguments for "
                f"'{getattr(func, '__name__', 'tool')}' before sandbox dispatch "
                f"({build_error}). Refusing rather than dispatching unvalidated."
            )
        if nested_check is not None:
            nested_check(*args, **kwargs)
        return validating_capture(*args, **kwargs)

    return _validate


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
