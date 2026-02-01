"""Framework injection module for Agent-Airlock.

Provides "vaccination" - automatic security wrapping for existing AI framework
decorators without requiring code changes. Monkeypatches framework decorators
to automatically apply Airlock security.

Usage:
    # One-line cure for existing frameworks
    from agent_airlock import vaccinate, STRICT_POLICY
    vaccinate("langchain", policy=STRICT_POLICY)

    # Now all @tool decorated functions are automatically secured!
    @tool
    def my_tool(): ...  # Automatically wrapped with Airlock

SECURITY: This module must preserve function signatures for framework
introspection. LangChain, OpenAI SDK, etc. use inspect.signature() to
generate JSON schemas for LLM tool calls.
"""

from __future__ import annotations

import contextlib
import functools
import importlib
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import structlog

from .config import AirlockConfig
from .core import Airlock
from .policy import SecurityPolicy

logger = structlog.get_logger("agent-airlock.vaccine")


# Framework decorator paths for monkeypatching
# Maps framework name -> list of decorator module paths
FRAMEWORK_DECORATORS: dict[str, list[str]] = {
    "langchain": [
        "langchain_core.tools.tool",
        "langchain.tools.tool",
    ],
    "openai": [
        "agents.function_tool",
        "openai.agents.function_tool",
    ],
    "pydanticai": [
        "pydantic_ai.tools.tool",
    ],
    "crewai": [
        "crewai.tools.tool",
    ],
    "autogen": [
        "autogen.function_utils.register_function",
    ],
    "llamaindex": [
        "llama_index.core.tools.function_tool",
    ],
}


@dataclass
class VaccinationResult:
    """Result of vaccinating a framework.

    Attributes:
        framework: Name of the vaccinated framework.
        tools_secured: Number of existing tools that were wrapped.
        decorators_patched: List of decorator paths that were patched.
        warnings: Any warnings during vaccination.
        success: Whether vaccination succeeded.
    """

    framework: str
    tools_secured: int = 0
    decorators_patched: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    success: bool = True


# Global registry of original decorators (for unvaccination)
_original_decorators: dict[str, tuple[Any, Callable[..., Any]]] = {}

# Global registry of vaccinated tools
_vaccinated_tools: set[str] = set()


def _get_decorator(module_path: str) -> tuple[Any, str, Callable[..., Any]] | None:
    """Import and return a decorator from a module path.

    Args:
        module_path: Dot-separated path like "langchain_core.tools.tool"

    Returns:
        Tuple of (module, attr_name, decorator) or None if not found.
    """
    parts = module_path.rsplit(".", 1)
    if len(parts) != 2:
        return None

    module_name, attr_name = parts

    try:
        module = importlib.import_module(module_name)
        decorator = getattr(module, attr_name, None)
        if decorator is not None and callable(decorator):
            return (module, attr_name, decorator)
    except ImportError:
        pass

    return None


def _create_vaccinated_decorator(
    original_decorator: Callable[..., Any],
    config: AirlockConfig | None,
    policy: SecurityPolicy | None,
    sandbox: bool,
) -> Callable[..., Any]:
    """Create a vaccinated version of a framework decorator.

    The vaccinated decorator:
    1. Applies Airlock security wrapper
    2. Then applies the original framework decorator
    3. Preserves function signature for framework introspection
    """

    @functools.wraps(original_decorator)
    def vaccinated_decorator(
        func: Callable[..., Any] | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Vaccinated decorator that applies Airlock before the framework decorator."""

        def apply_vaccination(f: Callable[..., Any]) -> Any:
            # Track that this tool was vaccinated
            tool_id = f"{f.__module__}.{f.__name__}"
            _vaccinated_tools.add(tool_id)

            # Apply Airlock security wrapper
            airlock = Airlock(
                sandbox=sandbox,
                config=config,
                policy=policy,
            )
            secured_func = airlock(f)

            # CRITICAL: Preserve original signature for framework introspection
            # Frameworks like LangChain use inspect.signature() to generate JSON schemas
            with contextlib.suppress(ValueError, TypeError):
                secured_func.__signature__ = inspect.signature(f)  # type: ignore[attr-defined]

            # Preserve other important attributes
            secured_func.__annotations__ = getattr(f, "__annotations__", {})
            secured_func.__doc__ = f.__doc__

            # Apply the original framework decorator
            # Handle both @decorator and @decorator(...) patterns
            result = original_decorator(secured_func, *args, **kwargs)

            logger.debug(
                "tool_vaccinated",
                tool=tool_id,
                framework_decorator=original_decorator.__name__,
            )

            return result

        if func is None:
            # Called as @decorator(...) - return wrapper that will receive func
            return apply_vaccination
        else:
            # Called as @decorator - func is the function to wrap
            return apply_vaccination(func)

    return vaccinated_decorator


def vaccinate(
    framework: str | None = None,
    *,
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    sandbox: bool = False,
    target: Any | None = None,
) -> VaccinationResult:
    """Vaccinate a framework by monkeypatching its decorators.

    After vaccination, all tools decorated with the framework's @tool decorator
    will automatically be wrapped with Airlock security.

    Args:
        framework: Framework name to vaccinate (e.g., "langchain", "openai").
                  If None and target is None, vaccinates all available frameworks.
        config: Airlock configuration to use for wrapped tools.
        policy: Security policy to enforce on wrapped tools.
        sandbox: If True, execute tools in E2B sandbox.
        target: Optional specific module/object to vaccinate instead of
               auto-detecting from framework name.

    Returns:
        VaccinationResult with details about what was patched.

    Example:
        # Vaccinate LangChain
        result = vaccinate("langchain", policy=STRICT_POLICY)
        print(f"Patched {len(result.decorators_patched)} decorators")

        # Now all @tool decorated functions are secured
        @tool
        def my_tool(): ...
    """
    result = VaccinationResult(framework=framework or "all")

    if target is not None:
        # Vaccinate a specific target (advanced usage)
        return _vaccinate_target(target, config, policy, sandbox)

    if framework is None:
        # Vaccinate all available frameworks
        for fw_name in FRAMEWORK_DECORATORS:
            fw_result = vaccinate(
                fw_name,
                config=config,
                policy=policy,
                sandbox=sandbox,
            )
            result.decorators_patched.extend(fw_result.decorators_patched)
            result.warnings.extend(fw_result.warnings)
        return result

    framework_lower = framework.lower()
    if framework_lower not in FRAMEWORK_DECORATORS:
        result.success = False
        result.warnings.append(
            f"Unknown framework: {framework}. Supported: {', '.join(FRAMEWORK_DECORATORS.keys())}"
        )
        return result

    decorator_paths = FRAMEWORK_DECORATORS[framework_lower]

    for path in decorator_paths:
        decorator_info = _get_decorator(path)
        if decorator_info is None:
            continue

        module, attr_name, original_decorator = decorator_info

        # Skip if already vaccinated
        if path in _original_decorators:
            result.warnings.append(f"Already vaccinated: {path}")
            continue

        # Save original decorator for potential unvaccination
        _original_decorators[path] = (module, original_decorator)

        # Create and install vaccinated decorator
        vaccinated = _create_vaccinated_decorator(
            original_decorator,
            config,
            policy,
            sandbox,
        )

        setattr(module, attr_name, vaccinated)
        result.decorators_patched.append(path)

        logger.info(
            "decorator_vaccinated",
            path=path,
            framework=framework,
        )

    if not result.decorators_patched:
        result.warnings.append(f"No decorators found for {framework}. Is the framework installed?")

    return result


def _vaccinate_target(
    target: Any,
    config: AirlockConfig | None,
    policy: SecurityPolicy | None,
    sandbox: bool,
) -> VaccinationResult:
    """Vaccinate a specific target object (advanced usage).

    Can vaccinate:
    - A module (patches all callable attributes named 'tool')
    - A class (patches the __call__ method if it's a decorator class)
    - A function/decorator directly
    """
    result = VaccinationResult(framework="custom")

    target_name = getattr(target, "__name__", str(target))

    if callable(target):
        # It's a function/decorator - wrap it directly
        _create_vaccinated_decorator(
            target,
            config,
            policy,
            sandbox,
        )
        result.decorators_patched.append(target_name)
        result.tools_secured = 1

        logger.info("custom_target_vaccinated", target=target_name)

    return result


def unvaccinate(framework: str | None = None) -> int:
    """Remove vaccination from a framework, restoring original decorators.

    Args:
        framework: Framework name to unvaccinate. If None, unvaccinates all.

    Returns:
        Number of decorators restored.
    """
    count = 0

    if framework is None:
        paths_to_restore = list(_original_decorators.keys())
    else:
        framework_lower = framework.lower()
        paths_to_restore = [
            path for path in _original_decorators if framework_lower in path.lower()
        ]

    for path in paths_to_restore:
        if path not in _original_decorators:
            continue

        module, original_decorator = _original_decorators[path]
        attr_name = path.rsplit(".", 1)[1]

        setattr(module, attr_name, original_decorator)
        del _original_decorators[path]
        count += 1

        logger.info("decorator_unvaccinated", path=path)

    return count


def get_supported_frameworks() -> list[str]:
    """Get list of supported frameworks for vaccination.

    Returns:
        List of framework names that can be passed to vaccinate().
    """
    return list(FRAMEWORK_DECORATORS.keys())


def get_vaccinated_tools() -> set[str]:
    """Get set of tool identifiers that have been vaccinated.

    Returns:
        Set of "module.function" identifiers for vaccinated tools.
    """
    return _vaccinated_tools.copy()


def is_vaccinated(framework: str) -> bool:
    """Check if a framework has been vaccinated.

    Args:
        framework: Framework name to check.

    Returns:
        True if at least one decorator from the framework is vaccinated.
    """
    framework_lower = framework.lower()
    if framework_lower not in FRAMEWORK_DECORATORS:
        return False

    return any(path in _original_decorators for path in FRAMEWORK_DECORATORS[framework_lower])
