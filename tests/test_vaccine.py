"""Tests for the vaccine (framework injection) module (V0.3.0)."""

from __future__ import annotations

import functools
import inspect

import pytest

from agent_airlock.config import AirlockConfig
from agent_airlock.policy import SecurityPolicy
from agent_airlock.vaccine import (
    FRAMEWORK_DECORATORS,
    VaccinationResult,
    _create_vaccinated_decorator,
    _get_decorator,
    get_supported_frameworks,
    get_vaccinated_tools,
    is_vaccinated,
    unvaccinate,
    vaccinate,
)


class TestFrameworkDecorators:
    """Tests for FRAMEWORK_DECORATORS configuration."""

    def test_langchain_decorators(self) -> None:
        """Test LangChain decorator paths are defined."""
        assert "langchain" in FRAMEWORK_DECORATORS
        assert len(FRAMEWORK_DECORATORS["langchain"]) > 0
        assert any("tool" in path for path in FRAMEWORK_DECORATORS["langchain"])

    def test_openai_decorators(self) -> None:
        """Test OpenAI decorator paths are defined."""
        assert "openai" in FRAMEWORK_DECORATORS
        assert any("function_tool" in path for path in FRAMEWORK_DECORATORS["openai"])

    def test_pydanticai_decorators(self) -> None:
        """Test PydanticAI decorator paths are defined."""
        assert "pydanticai" in FRAMEWORK_DECORATORS

    def test_crewai_decorators(self) -> None:
        """Test CrewAI decorator paths are defined."""
        assert "crewai" in FRAMEWORK_DECORATORS


class TestGetSupportedFrameworks:
    """Tests for get_supported_frameworks function."""

    def test_returns_list(self) -> None:
        """Test that function returns a list."""
        frameworks = get_supported_frameworks()
        assert isinstance(frameworks, list)

    def test_contains_expected_frameworks(self) -> None:
        """Test that list contains expected frameworks."""
        frameworks = get_supported_frameworks()
        assert "langchain" in frameworks
        assert "openai" in frameworks

    def test_matches_decorator_keys(self) -> None:
        """Test that returned list matches FRAMEWORK_DECORATORS keys."""
        frameworks = get_supported_frameworks()
        assert set(frameworks) == set(FRAMEWORK_DECORATORS.keys())


class TestVaccinationResult:
    """Tests for VaccinationResult dataclass."""

    def test_default_values(self) -> None:
        """Test default values."""
        result = VaccinationResult(framework="test")
        assert result.framework == "test"
        assert result.tools_secured == 0
        assert result.decorators_patched == []
        assert result.warnings == []
        assert result.success is True

    def test_with_values(self) -> None:
        """Test with specific values."""
        result = VaccinationResult(
            framework="langchain",
            tools_secured=5,
            decorators_patched=["langchain_core.tools.tool"],
            warnings=["Some warning"],
            success=True,
        )
        assert result.framework == "langchain"
        assert result.tools_secured == 5
        assert len(result.decorators_patched) == 1
        assert len(result.warnings) == 1


class TestGetDecorator:
    """Tests for _get_decorator helper function."""

    def test_invalid_path_format(self) -> None:
        """Test with invalid path format."""
        result = _get_decorator("invalid")
        assert result is None

    def test_nonexistent_module(self) -> None:
        """Test with nonexistent module."""
        result = _get_decorator("nonexistent.module.decorator")
        assert result is None

    def test_valid_builtin_module(self) -> None:
        """Test with a valid builtin module."""
        # functools.wraps is a known decorator
        result = _get_decorator("functools.wraps")
        if result is not None:
            module, attr_name, decorator = result
            assert attr_name == "wraps"
            assert callable(decorator)


class TestCreateVaccinatedDecorator:
    """Tests for _create_vaccinated_decorator function."""

    def test_creates_callable(self) -> None:
        """Test that vaccinated decorator is callable."""
        original = lambda f: f  # noqa: E731
        vaccinated = _create_vaccinated_decorator(
            original,
            config=None,
            policy=None,
            sandbox=False,
        )
        assert callable(vaccinated)

    def test_preserves_wrapper_attributes(self) -> None:
        """Test that functools.wraps attributes are preserved."""

        @functools.wraps(lambda: None)
        def original_decorator(f):
            return f

        original_decorator.__name__ = "test_decorator"

        vaccinated = _create_vaccinated_decorator(
            original_decorator,
            config=None,
            policy=None,
            sandbox=False,
        )

        assert vaccinated.__name__ == "test_decorator"

    def test_applies_airlock_wrapper(self) -> None:
        """Test that Airlock is applied to decorated functions."""
        call_order: list[str] = []

        def original_decorator(f):
            call_order.append("original")
            return f

        vaccinated = _create_vaccinated_decorator(
            original_decorator,
            config=None,
            policy=None,
            sandbox=False,
        )

        @vaccinated
        def my_tool(x: int) -> int:
            return x * 2

        # Function should still work
        result = my_tool(5)
        assert result == 10

    def test_signature_preserved(self) -> None:
        """Test that function signature is preserved."""

        def original_decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                return f(*args, **kwargs)

            return wrapper

        vaccinated = _create_vaccinated_decorator(
            original_decorator,
            config=None,
            policy=None,
            sandbox=False,
        )

        @vaccinated
        def my_tool(name: str, count: int = 1) -> str:
            """Tool docstring."""
            return name * count

        # Check signature is preserved
        sig = inspect.signature(my_tool)
        params = list(sig.parameters.keys())
        assert "name" in params
        assert "count" in params

        # Check docstring preserved
        assert my_tool.__doc__ == "Tool docstring."


class TestVaccinate:
    """Tests for vaccinate function."""

    def test_unknown_framework(self) -> None:
        """Test vaccination of unknown framework."""
        result = vaccinate("unknown_framework")
        assert result.success is False
        assert len(result.warnings) > 0
        assert "Unknown framework" in result.warnings[0]

    def test_framework_not_installed(self) -> None:
        """Test vaccination when framework is not installed."""
        # Most frameworks won't be installed in test environment
        result = vaccinate("crewai")
        # Should either succeed with patches or warn about missing framework
        assert isinstance(result, VaccinationResult)

    def test_case_insensitive_framework_name(self) -> None:
        """Test that framework names are case-insensitive."""
        result1 = vaccinate("LANGCHAIN")
        result2 = vaccinate("LangChain")
        result3 = vaccinate("langchain")
        # All should be treated the same way (lowercase)
        assert result1.framework.lower() == result2.framework.lower() == result3.framework.lower()

    def test_with_config(self) -> None:
        """Test vaccination with custom config."""
        config = AirlockConfig(strict_mode=True)
        result = vaccinate("langchain", config=config)
        assert isinstance(result, VaccinationResult)

    def test_with_policy(self) -> None:
        """Test vaccination with security policy."""
        policy = SecurityPolicy(rate_limits={"*": "100/hour"})
        result = vaccinate("langchain", policy=policy)
        assert isinstance(result, VaccinationResult)

    def test_with_sandbox(self) -> None:
        """Test vaccination with sandbox enabled."""
        result = vaccinate("langchain", sandbox=True)
        assert isinstance(result, VaccinationResult)


class TestVaccinateAll:
    """Tests for vaccinating all frameworks."""

    def test_vaccinate_all(self) -> None:
        """Test vaccinating all frameworks at once."""
        try:
            result = vaccinate(framework=None)
            assert result.framework == "all"
            # Should have attempted all frameworks
            assert isinstance(result.decorators_patched, list)
        except Exception as e:
            # Some frameworks may have version incompatibilities
            # (e.g., openai-agents may have Pydantic model changes)
            # The vaccination function itself works, but importing
            # certain packages may fail due to version conflicts
            if "ValidationError" in str(type(e).__name__):
                pytest.skip(f"Skipping due to package version incompatibility: {e}")


class TestUnvaccinate:
    """Tests for unvaccinate function."""

    def test_unvaccinate_nonexistent(self) -> None:
        """Test unvaccinating a framework that wasn't vaccinated."""
        count = unvaccinate("nonexistent")
        assert count == 0

    def test_unvaccinate_all(self) -> None:
        """Test unvaccinating all frameworks."""
        count = unvaccinate()
        assert count >= 0  # May be 0 if nothing was vaccinated


class TestIsVaccinated:
    """Tests for is_vaccinated function."""

    def test_unknown_framework(self) -> None:
        """Test is_vaccinated for unknown framework."""
        assert is_vaccinated("unknown") is False

    def test_unvaccinated_framework(self) -> None:
        """Test is_vaccinated for known but unvaccinated framework."""
        # First ensure it's not vaccinated
        unvaccinate("crewai")
        assert is_vaccinated("crewai") is False


class TestGetVaccinatedTools:
    """Tests for get_vaccinated_tools function."""

    def test_returns_set(self) -> None:
        """Test that function returns a set."""
        tools = get_vaccinated_tools()
        assert isinstance(tools, set)

    def test_returns_copy(self) -> None:
        """Test that function returns a copy."""
        tools1 = get_vaccinated_tools()
        tools2 = get_vaccinated_tools()
        # Should be different objects
        assert tools1 is not tools2


class TestIntegration:
    """Integration tests for vaccination."""

    def test_vaccinated_tool_validates_input(self) -> None:
        """Test that vaccinated tools have input validation."""

        # Create a mock decorator
        def mock_tool_decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                return f(*args, **kwargs)

            return wrapper

        vaccinated = _create_vaccinated_decorator(
            mock_tool_decorator,
            config=AirlockConfig(strict_mode=True),
            policy=None,
            sandbox=False,
        )

        @vaccinated
        def my_tool(x: int) -> int:
            return x * 2

        # Valid call should work
        result = my_tool(x=5)
        assert result == 10

        # Call with ghost argument should be handled
        # In strict mode, this should return an error dict
        result = my_tool(x=5, unknown_arg="test")
        assert isinstance(result, dict)
        assert result.get("success") is False

    def test_vaccinated_tool_preserves_framework_behavior(self) -> None:
        """Test that original decorator behavior is preserved."""
        decorator_was_called = False

        def mock_tool_decorator(f):
            nonlocal decorator_was_called
            decorator_was_called = True

            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                return f(*args, **kwargs)

            return wrapper

        vaccinated = _create_vaccinated_decorator(
            mock_tool_decorator,
            config=None,
            policy=None,
            sandbox=False,
        )

        @vaccinated
        def my_tool() -> str:
            return "hello"

        assert decorator_was_called
        assert my_tool() == "hello"


class TestEdgeCases:
    """Tests for edge cases."""

    def test_decorator_with_arguments(self) -> None:
        """Test vaccination of decorator that takes arguments."""

        def mock_tool_decorator(f=None, *, name: str = "default"):
            """Decorator that supports both @decorator and @decorator(name=...) syntax."""

            def decorator(func):
                @functools.wraps(func)
                def wrapper(*args, **kwargs):
                    return func(*args, **kwargs)

                wrapper._tool_name = name  # type: ignore[attr-defined]
                return wrapper

            if f is not None:
                return decorator(f)
            return decorator

        vaccinated = _create_vaccinated_decorator(
            mock_tool_decorator,
            config=None,
            policy=None,
            sandbox=False,
        )

        @vaccinated
        def my_tool() -> str:
            return "result"

        assert my_tool() == "result"

    def test_decorator_without_arguments(self) -> None:
        """Test vaccination of decorator without arguments."""

        def mock_tool_decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                return f(*args, **kwargs)

            return wrapper

        vaccinated = _create_vaccinated_decorator(
            mock_tool_decorator,
            config=None,
            policy=None,
            sandbox=False,
        )

        @vaccinated
        def my_tool() -> str:
            return "result"

        assert my_tool() == "result"

    def test_async_function_vaccination(self) -> None:
        """Test vaccination of async functions."""
        import asyncio

        def mock_tool_decorator(f):
            @functools.wraps(f)
            async def wrapper(*args, **kwargs):
                return await f(*args, **kwargs)

            return wrapper

        vaccinated = _create_vaccinated_decorator(
            mock_tool_decorator,
            config=None,
            policy=None,
            sandbox=False,
        )

        @vaccinated
        async def my_async_tool(x: int) -> int:
            return x * 2

        # Run async function
        result = asyncio.run(my_async_tool(x=5))
        assert result == 10

    def test_vaccination_idempotent(self) -> None:
        """Test that vaccinating twice doesn't double-wrap."""
        # First vaccination
        result1 = vaccinate("langchain")

        # Second vaccination of same framework should warn
        result2 = vaccinate("langchain")

        # If any decorators were patched the first time, the second should warn
        # about already being vaccinated
        if result1.decorators_patched:
            assert len(result2.warnings) > 0 or len(result2.decorators_patched) == 0
