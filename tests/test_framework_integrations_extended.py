"""Extended framework integration tests for Anthropic, AutoGen, CrewAI, LlamaIndex, smolagents.

These tests verify that Airlock works correctly with the remaining major AI frameworks.
Tests focus on:
1. Function signature preservation
2. Type validation
3. Ghost argument handling
4. PII masking
5. Framework decorator compatibility
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, get_type_hints

import pytest

from agent_airlock import READ_ONLY_POLICY, Airlock, AirlockConfig

# Common config for tests
test_config = AirlockConfig(
    strict_mode=True,
    mask_pii=True,
    sanitize_output=True,
)

non_strict_config = AirlockConfig(
    strict_mode=False,
    mask_pii=True,
)


# =============================================================================
# Anthropic SDK Tests
# =============================================================================


class TestAnthropicIntegration:
    """Test Airlock compatibility with Anthropic Claude SDK patterns."""

    @pytest.fixture(autouse=True)
    def check_anthropic(self) -> None:
        """Skip if anthropic is not installed."""
        pytest.importorskip("anthropic")

    def test_basic_airlock_function(self) -> None:
        """Test basic function with Airlock works."""

        @Airlock(config=test_config)
        def get_weather(location: str, units: str = "celsius") -> str:
            """Get the current weather for a location."""
            return f"Weather in {location}: 22°{units[0].upper()}"

        result = get_weather(location="Tokyo")
        assert "Tokyo" in result
        assert "22" in result

    def test_tool_schema_generation(self) -> None:
        """Test that tool schemas can be generated from Airlock functions."""

        @Airlock(config=test_config)
        def search_products(query: str, category: str = "all", limit: int = 10) -> str:
            """Search for products in the catalog."""
            return f"Found {limit} products"

        # Simulate Anthropic's tool schema generation
        sig = inspect.signature(search_products)

        assert "query" in sig.parameters
        assert "category" in sig.parameters
        assert "limit" in sig.parameters
        assert sig.parameters["category"].default == "all"
        assert sig.parameters["limit"].default == 10

    def test_type_validation_rejects_wrong_types(self) -> None:
        """Test that type validation blocks wrong types."""

        @Airlock(config=test_config)
        def typed_function(name: str, count: int) -> str:
            return f"{name}: {count}"

        # Wrong type should return blocked response
        result = typed_function(name=123, count="ten")  # type: ignore
        assert isinstance(result, dict)
        assert result.get("success") is False

    def test_ghost_args_rejected_strict_mode(self) -> None:
        """Test ghost arguments are rejected in strict mode."""

        @Airlock(config=test_config)
        def simple_tool(x: int) -> int:
            return x * 2

        # Ghost argument should be rejected
        result = simple_tool(x=5, force=True, verbose=True)  # type: ignore
        assert isinstance(result, dict)
        assert result.get("success") is False

    def test_pii_masked_in_output(self) -> None:
        """Test PII is masked in output."""

        @Airlock(config=test_config)
        def get_customer(customer_id: str) -> str:
            return "Customer: john.doe@example.com, Phone: 555-123-4567"

        result = get_customer(customer_id="123")
        # Email and phone should be masked
        assert "john.doe@example.com" not in result or "[EMAIL" in result

    def test_docstring_preserved(self) -> None:
        """Test docstring is preserved for tool description."""

        @Airlock(config=test_config)
        def documented_tool(x: int) -> int:
            """This is a detailed description of the tool."""
            return x

        assert documented_tool.__doc__ is not None
        assert "detailed description" in documented_tool.__doc__


# =============================================================================
# AutoGen Tests
# =============================================================================


class TestAutoGenIntegration:
    """Test Airlock compatibility with Microsoft AutoGen."""

    @pytest.fixture(autouse=True)
    def check_autogen(self) -> None:
        """Skip if autogen is not installed."""
        pytest.importorskip("autogen_agentchat")

    def test_function_tool_pattern(self) -> None:
        """Test the FunctionTool pattern from AutoGen 0.4+."""
        from autogen_core.tools import FunctionTool

        @Airlock(config=test_config)
        def get_stock_price(ticker: str) -> str:
            """Get the current stock price.

            Args:
                ticker: Stock ticker symbol like AAPL
            """
            return f"Stock {ticker}: $150.25"

        # Create FunctionTool
        tool = FunctionTool(get_stock_price, description="Get stock price")

        assert tool.name == "get_stock_price"
        assert "stock" in tool.description.lower()

    def test_annotated_parameters_preserved(self) -> None:
        """Test that parameters with defaults work correctly."""

        @Airlock(config=test_config)
        def search_tool(query: str, limit: int = 10) -> str:
            """Tool with default parameters.

            Args:
                query: Search query string
                limit: Max results to return
            """
            return f"Found {limit} results for '{query}'"

        result = search_tool(query="test", limit=5)
        assert "5 results" in result

    def test_async_tool_with_autogen(self) -> None:
        """Test async tools work with AutoGen patterns."""

        @Airlock(config=test_config)
        async def async_api_call(endpoint: str, method: str = "GET") -> str:
            """Make an async API call.

            Args:
                endpoint: API endpoint URL
                method: HTTP method
            """
            await asyncio.sleep(0.01)
            return f"Response from {method} {endpoint}"

        # Verify it's still async
        assert asyncio.iscoroutinefunction(async_api_call)

        # Test execution
        result = asyncio.run(async_api_call(endpoint="/users"))
        assert "Response from" in result

    def test_function_tool_validation(self) -> None:
        """Test FunctionTool validates inputs correctly."""
        from autogen_core.tools import FunctionTool

        @Airlock(config=test_config)
        def calculator(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        FunctionTool(calculator, description="Calculator")

        # Valid call
        result = calculator(a=5, b=3)
        assert result == 8


# =============================================================================
# CrewAI Tests
# =============================================================================


class TestCrewAIIntegration:
    """Test Airlock compatibility with CrewAI."""

    @pytest.fixture(autouse=True)
    def check_crewai(self) -> None:
        """Skip if crewai is not installed."""
        pytest.importorskip("crewai")

    def test_airlock_function_for_crewai(self) -> None:
        """Test Airlock-decorated functions work before CrewAI wrapping."""
        # Note: CrewAI's @tool decorator returns a Tool object, not a callable.
        # The pattern is to use Airlock first, then pass to CrewAI tools list.

        @Airlock(config=test_config)
        def search_database(query: str, table: str = "customers") -> str:
            """Search a database table.

            Args:
                query: Search query string
                table: Database table to search
            """
            return f"Found 5 results in '{table}' for '{query}'"

        # Direct call works
        result = search_database(query="test", table="users")
        assert "5 results" in result
        assert "users" in result

    def test_crewai_tool_can_wrap_airlock_function(self) -> None:
        """Test that CrewAI tool can wrap an Airlock-decorated function."""
        from crewai.tools import tool

        @Airlock(config=test_config)
        def query_analytics(metric: str) -> str:
            """Query analytics data.

            Args:
                metric: The metric name to query
            """
            return f"Analytics for {metric}"

        # CrewAI @tool wraps the function into a Tool object
        wrapped = tool("Analytics Query")(query_analytics)

        # The wrapped object should have tool attributes
        assert hasattr(wrapped, "name") or hasattr(wrapped, "run")

    def test_policy_enforcement_before_crewai(self) -> None:
        """Test policy enforcement works with Airlock before CrewAI."""

        @Airlock(config=test_config, policy=READ_ONLY_POLICY)
        def read_data(key: str) -> str:
            """Read data from store.

            Args:
                key: The data key to read
            """
            return f"Data for {key}"

        result = read_data(key="test-key")
        assert "Data for" in result

    def test_crewai_type_validation(self) -> None:
        """Test type validation with Airlock for CrewAI tools."""

        @Airlock(config=test_config)
        def calculate(x: int, y: int) -> int:
            """Calculate sum.

            Args:
                x: First number
                y: Second number
            """
            return x + y

        # Valid call
        result = calculate(x=10, y=20)
        assert result == 30

        # Invalid call (wrong types)
        result = calculate(x="not an int", y="also not")  # type: ignore
        assert isinstance(result, dict)
        assert result.get("success") is False


# =============================================================================
# LlamaIndex Tests
# =============================================================================


class TestLlamaIndexIntegration:
    """Test Airlock compatibility with LlamaIndex."""

    @pytest.fixture(autouse=True)
    def check_llamaindex(self) -> None:
        """Skip if llama_index is not installed."""
        pytest.importorskip("llama_index")

    def test_function_tool_from_defaults(self) -> None:
        """Test FunctionTool.from_defaults() pattern."""
        from llama_index.core.tools import FunctionTool

        @Airlock(config=test_config)
        def add_numbers(a: int, b: int) -> int:
            """Add two numbers together."""
            return a + b

        tool = FunctionTool.from_defaults(fn=add_numbers)

        assert tool.metadata.name == "add_numbers"
        assert "Add two numbers" in tool.metadata.description

    def test_function_tool_call(self) -> None:
        """Test calling a FunctionTool."""
        from llama_index.core.tools import FunctionTool

        @Airlock(config=test_config)
        def multiply(a: int, b: int) -> int:
            """Multiply two numbers."""
            return a * b

        tool = FunctionTool.from_defaults(fn=multiply)
        result = tool.call(a=6, b=7)
        # LlamaIndex returns a ToolOutput object, check raw_output
        assert result.raw_output == 42

    def test_custom_tool_name_description(self) -> None:
        """Test custom name and description."""
        from llama_index.core.tools import FunctionTool

        @Airlock(config=test_config)
        def search_docs(query: str) -> str:
            """Search documents."""
            return f"Results for '{query}'"

        tool = FunctionTool.from_defaults(
            fn=search_docs,
            name="document_search",
            description="Custom search description",
        )

        assert tool.metadata.name == "document_search"
        assert "Custom search" in tool.metadata.description

    def test_async_function_tool(self) -> None:
        """Test async functions with LlamaIndex."""
        from llama_index.core.tools import FunctionTool

        @Airlock(config=test_config)
        async def async_fetch(url: str) -> str:
            """Fetch data async."""
            await asyncio.sleep(0.01)
            return f"Fetched from {url}"

        FunctionTool.from_defaults(fn=async_fetch)

        # Should still be identifiable as async
        assert asyncio.iscoroutinefunction(async_fetch)

    def test_type_hints_for_schema(self) -> None:
        """Test type hints are preserved for schema generation."""
        from llama_index.core.tools import FunctionTool

        @Airlock(config=test_config)
        def typed_search(
            query: str,
            top_k: int = 5,
            include_metadata: bool = False,
        ) -> list[str]:
            """Search with typed parameters."""
            return [f"result_{i}" for i in range(top_k)]

        FunctionTool.from_defaults(fn=typed_search)

        # Check signature is preserved
        sig = inspect.signature(typed_search)
        assert "query" in sig.parameters
        assert sig.parameters["top_k"].default == 5
        assert sig.parameters["include_metadata"].default is False


# =============================================================================
# smolagents Tests
# =============================================================================


class TestSmolagentsIntegration:
    """Test Airlock compatibility with Hugging Face smolagents."""

    @pytest.fixture(autouse=True)
    def check_smolagents(self) -> None:
        """Skip if smolagents is not installed."""
        pytest.importorskip("smolagents")

    def test_tool_decorator_pattern(self) -> None:
        """Test @tool + @Airlock pattern with smolagents."""
        from smolagents import tool

        @tool
        @Airlock(config=test_config)
        def calculator(expression: str) -> str:
            """Evaluate a mathematical expression.

            Args:
                expression: A mathematical expression like '2 + 2' or '10 * 5'
            """
            return str(eval(expression, {"__builtins__": {}}, {}))  # noqa: S307

        result = calculator(expression="2 + 2")
        assert result == "4"

    def test_tool_attributes_preserved(self) -> None:
        """Test that smolagents tool attributes are set."""
        from smolagents import tool

        @tool
        @Airlock(config=test_config)
        def get_time() -> str:
            """Get current time."""
            return "12:00:00"

        # smolagents tools should be callable
        assert callable(get_time)
        result = get_time()
        assert result == "12:00:00"

    def test_read_only_policy_with_smolagents(self) -> None:
        """Test read-only policy works with smolagents."""
        from smolagents import tool

        @tool
        @Airlock(config=test_config, policy=READ_ONLY_POLICY)
        def search_db(query: str) -> str:
            """Search database (read-only).

            Args:
                query: The search query string
            """
            return f"Results for '{query}'"

        result = search_db(query="test")
        assert "Results for" in result

    def test_ghost_args_with_smolagents(self) -> None:
        """Test ghost arguments handling with smolagents."""
        from smolagents import tool

        @tool
        @Airlock(config=test_config)
        def simple_tool(x: int) -> int:
            """Simple tool for testing.

            Args:
                x: The input number
            """
            return x * 2

        # Strict mode should reject ghost args
        result = simple_tool(x=5, extra_arg=True)  # type: ignore
        assert isinstance(result, dict)
        assert result.get("success") is False

    def test_custom_tool_class(self) -> None:
        """Test custom Tool class with Airlock."""
        from smolagents import Tool

        class SecureTool(Tool):
            name = "secure_reader"
            description = "Read data securely."
            inputs = {"key": {"type": "string", "description": "Data key"}}
            output_type = "string"

            def __init__(self):
                super().__init__()
                self._secured = self._create_secured()

            def _create_secured(self):
                @Airlock(config=test_config)
                def read_data(key: str) -> str:
                    return f"Data for '{key}'"

                return read_data

            def forward(self, key: str) -> str:
                return self._secured(key=key)

        tool = SecureTool()
        result = tool.forward(key="test-key")
        assert "Data for" in result


# =============================================================================
# Cross-Framework Tests
# =============================================================================


class TestCrossFrameworkPatterns:
    """Test patterns that apply across all frameworks."""

    def test_signature_preservation_all_frameworks(self) -> None:
        """Test signature preservation works for all frameworks."""

        @Airlock(config=test_config)
        def universal_tool(
            query: str,
            limit: int = 10,
            include_metadata: bool = False,
            filters: dict[str, Any] | None = None,
        ) -> list[str]:
            """A universal tool that works with any framework."""
            return [f"result_{i}" for i in range(limit)]

        sig = inspect.signature(universal_tool)
        params = list(sig.parameters.keys())

        assert params == ["query", "limit", "include_metadata", "filters"]
        assert sig.parameters["limit"].default == 10
        assert sig.parameters["include_metadata"].default is False
        assert sig.parameters["filters"].default is None

    def test_type_hints_extraction(self) -> None:
        """Test type hints can be extracted for schema generation."""

        @Airlock(config=test_config)
        def typed_tool(
            name: str,
            count: int,
            ratio: float,
            active: bool,
        ) -> dict[str, Any]:
            """Tool with various types."""
            return {"name": name, "count": count}

        hints = get_type_hints(typed_tool)
        assert hints.get("name") is str
        assert hints.get("count") is int
        assert hints.get("ratio") is float
        assert hints.get("active") is bool

    def test_async_support_universal(self) -> None:
        """Test async support works universally."""

        @Airlock(config=test_config)
        async def async_universal(x: int) -> int:
            """Async tool."""
            await asyncio.sleep(0.01)
            return x * 2

        assert asyncio.iscoroutinefunction(async_universal)
        result = asyncio.run(async_universal(x=21))
        assert result == 42

    def test_non_strict_mode_strips_ghost_args(self) -> None:
        """Test non-strict mode strips but doesn't reject."""

        @Airlock(config=non_strict_config)
        def permissive_tool(x: int) -> int:
            """Tool that strips ghost args."""
            return x * 2

        # Should succeed despite ghost args
        result = permissive_tool(x=5, extra=True, another="value")  # type: ignore
        assert result == 10

    def test_validation_error_provides_hints(self) -> None:
        """Test validation errors provide fix hints."""

        @Airlock(config=test_config)
        def strict_tool(name: str, count: int) -> str:
            """Tool with strict validation."""
            return f"{name}: {count}"

        result = strict_tool(name=123, count="not a number")  # type: ignore
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert "fix_hints" in result or "error" in result
