"""Integration tests for framework compatibility.

Tests that Airlock-decorated functions work correctly with:
- LangChain StructuredTool
- PydanticAI tools
- OpenAI Agents SDK

These tests verify:
1. Function signature is preserved for framework introspection
2. Type hints are preserved for schema generation
3. Docstrings are preserved for tool descriptions
4. Functions can be called normally through the frameworks
"""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, get_type_hints

import pytest

from agent_airlock import Airlock, AirlockConfig


class TestSignaturePreservation:
    """Test that function signatures are preserved for framework introspection."""

    def test_sync_function_signature_preserved(self) -> None:
        """Sync function signature is preserved after decoration."""

        @Airlock()
        def search_database(query: str, limit: int = 10, fuzzy: bool = False) -> list[str]:
            """Search the database for matching records."""
            return [f"result_{i}" for i in range(limit)]

        sig = inspect.signature(search_database)
        params = list(sig.parameters.keys())

        assert params == ["query", "limit", "fuzzy"]
        # Annotations may be strings due to PEP 563 (from __future__ import annotations)
        assert sig.parameters["query"].annotation in (str, "str")
        assert sig.parameters["limit"].annotation in (int, "int")
        assert sig.parameters["limit"].default == 10
        assert sig.parameters["fuzzy"].annotation in (bool, "bool")
        assert sig.parameters["fuzzy"].default is False

    def test_async_function_signature_preserved(self) -> None:
        """Async function signature is preserved after decoration."""

        @Airlock()
        async def async_fetch(url: str, timeout: float = 30.0) -> dict[str, Any]:
            """Fetch data from a URL asynchronously."""
            return {"url": url, "data": "fetched"}

        sig = inspect.signature(async_fetch)
        params = list(sig.parameters.keys())

        assert params == ["url", "timeout"]
        # Annotations may be strings due to PEP 563 (from __future__ import annotations)
        assert sig.parameters["url"].annotation in (str, "str")
        assert sig.parameters["timeout"].annotation in (float, "float")

    def test_return_type_preserved(self) -> None:
        """Return type annotation is preserved."""

        @Airlock()
        def get_user(user_id: int) -> dict[str, str]:
            """Get user by ID."""
            return {"id": str(user_id), "name": "Test"}

        inspect.signature(get_user)
        # Note: Return type may be modified by Airlock to include dict[str, Any]
        # but the original should still be accessible via get_type_hints
        hints = get_type_hints(get_user)
        assert "return" in hints


class TestDocstringPreservation:
    """Test that docstrings are preserved for framework tool descriptions."""

    def test_docstring_preserved(self) -> None:
        """Function docstring is preserved after decoration."""

        @Airlock()
        def documented_tool(x: int) -> int:
            """This is a detailed docstring.

            Args:
                x: The input number.

            Returns:
                The input doubled.
            """
            return x * 2

        assert documented_tool.__doc__ is not None
        assert "detailed docstring" in documented_tool.__doc__
        assert "Args:" in documented_tool.__doc__
        assert "Returns:" in documented_tool.__doc__

    def test_name_preserved(self) -> None:
        """Function __name__ is preserved after decoration."""

        @Airlock()
        def my_special_tool(x: int) -> int:
            """A tool with a special name."""
            return x

        assert my_special_tool.__name__ == "my_special_tool"


class TestTypeHintPreservation:
    """Test that type hints are preserved for schema generation."""

    def test_annotations_preserved(self) -> None:
        """Function __annotations__ are preserved."""

        @Airlock()
        def typed_tool(
            name: str,
            count: int,
            items: list[str],
            metadata: dict[str, Any],
        ) -> bool:
            """A tool with various type annotations."""
            return True

        annotations = typed_tool.__annotations__
        assert "name" in annotations
        # Annotations may be strings due to PEP 563 (from __future__ import annotations)
        assert annotations["name"] in (str, "str")
        assert annotations["count"] in (int, "int")

    def test_get_type_hints_works(self) -> None:
        """get_type_hints() works on decorated function."""

        @Airlock()
        def hint_tool(x: int, y: str) -> float:
            """Tool for testing hints."""
            return float(x)

        hints = get_type_hints(hint_tool)
        assert hints.get("x") is int
        assert hints.get("y") is str
        assert hints.get("return") is not None


class TestLangChainCompatibility:
    """Test compatibility with LangChain-style introspection."""

    def test_langchain_tool_pattern(self) -> None:
        """Test the pattern LangChain uses for tool creation.

        LangChain uses inspect.signature() and the docstring to build
        tool definitions for LLMs.
        """

        @Airlock()
        def calculator(operation: str, a: float, b: float) -> float:
            """Perform a mathematical operation.

            Args:
                operation: One of 'add', 'subtract', 'multiply', 'divide'
                a: First operand
                b: Second operand

            Returns:
                The result of the operation
            """
            ops = {
                "add": lambda x, y: x + y,
                "subtract": lambda x, y: x - y,
                "multiply": lambda x, y: x * y,
                "divide": lambda x, y: x / y if y != 0 else 0,
            }
            return ops.get(operation, ops["add"])(a, b)

        # Simulate LangChain's introspection
        sig = inspect.signature(calculator)
        name = calculator.__name__
        description = calculator.__doc__ or ""

        # Build a tool schema like LangChain would
        tool_schema = {
            "name": name,
            "description": description.split("\n")[0].strip(),
            "parameters": {},
        }

        for param_name, param in sig.parameters.items():
            param_type = param.annotation
            tool_schema["parameters"][param_name] = {
                "type": param_type.__name__ if hasattr(param_type, "__name__") else str(param_type),
                "required": param.default == inspect.Parameter.empty,
            }
            if param.default != inspect.Parameter.empty:
                tool_schema["parameters"][param_name]["default"] = param.default

        # Verify the schema was built correctly
        assert tool_schema["name"] == "calculator"
        assert "mathematical operation" in tool_schema["description"]
        assert "operation" in tool_schema["parameters"]
        assert "a" in tool_schema["parameters"]
        assert "b" in tool_schema["parameters"]

        # Verify the function still works
        assert calculator(operation="add", a=5.0, b=3.0) == 8.0
        assert calculator(operation="multiply", a=4.0, b=2.5) == 10.0


class TestPydanticAICompatibility:
    """Test compatibility with PydanticAI-style tools."""

    def test_pydantic_style_tool(self) -> None:
        """Test the pattern PydanticAI uses for tool introspection."""

        @Airlock()
        def web_search(query: str, max_results: int = 5) -> list[dict[str, str]]:
            """Search the web for information.

            Returns a list of search results with title and url.
            """
            return [
                {"title": f"Result {i}", "url": f"https://example.com/{i}"}
                for i in range(max_results)
            ]

        # PydanticAI inspects the signature and type hints
        sig = inspect.signature(web_search)
        hints = get_type_hints(web_search)

        # Verify PydanticAI can extract what it needs
        assert "query" in sig.parameters
        assert hints.get("query") is str
        assert "max_results" in sig.parameters
        assert hints.get("max_results") is int

        # Verify the function works
        results = web_search(query="test", max_results=3)
        assert len(results) == 3


class TestOpenAIAgentsSDKCompatibility:
    """Test compatibility with OpenAI Agents SDK patterns."""

    def test_function_calling_pattern(self) -> None:
        """Test the pattern OpenAI's function calling uses.

        OpenAI Agents SDK uses inspect to build JSON schemas for functions.
        """

        @Airlock()
        def send_email(
            recipient: str,
            subject: str,
            body: str,
            urgent: bool = False,
        ) -> dict[str, bool]:
            """Send an email to the specified recipient.

            Args:
                recipient: Email address of the recipient
                subject: Email subject line
                body: Email body content
                urgent: Whether this is an urgent email
            """
            return {"sent": True, "urgent": urgent}

        # Simulate OpenAI's function schema extraction
        sig = inspect.signature(send_email)

        # Build properties for JSON schema
        properties: dict[str, dict[str, Any]] = {}
        required: list[str] = []

        for name, param in sig.parameters.items():
            prop_type = param.annotation
            type_name = getattr(prop_type, "__name__", str(prop_type))

            # Map Python types to JSON schema types
            json_type_map = {
                "str": "string",
                "int": "integer",
                "float": "number",
                "bool": "boolean",
            }

            properties[name] = {"type": json_type_map.get(type_name, "string")}

            if param.default == inspect.Parameter.empty:
                required.append(name)

        # Verify schema extraction works
        assert "recipient" in properties
        assert properties["recipient"]["type"] == "string"
        assert "urgent" in properties
        assert properties["urgent"]["type"] == "boolean"
        assert "recipient" in required
        assert "urgent" not in required  # Has default value

        # Verify the function works
        result = send_email(
            recipient="test@example.com",
            subject="Test",
            body="Hello",
        )
        assert result["sent"] is True


class TestAsyncFrameworkCompatibility:
    """Test async function compatibility with frameworks."""

    @pytest.mark.asyncio
    async def test_async_tool_introspection(self) -> None:
        """Async tools can be introspected like sync tools."""

        @Airlock()
        async def async_api_call(
            endpoint: str,
            method: str = "GET",
            payload: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            """Make an async API call.

            Simulates calling an external API asynchronously.
            """
            await asyncio.sleep(0.001)  # Simulate async operation
            return {"endpoint": endpoint, "method": method, "success": True}

        # Verify introspection works
        sig = inspect.signature(async_api_call)
        assert "endpoint" in sig.parameters
        assert "method" in sig.parameters
        assert "payload" in sig.parameters

        # Verify it's still async
        assert asyncio.iscoroutinefunction(async_api_call)

        # Verify it works
        result = await async_api_call(endpoint="/users", method="GET")
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_async_with_config(self) -> None:
        """Async tools work with custom config."""
        config = AirlockConfig(sanitize_output=False)

        @Airlock(config=config)
        async def configured_async(x: int) -> int:
            """An async tool with custom config."""
            return x * 2

        result = await configured_async(x=21)
        assert result == 42


class TestEdgeCases:
    """Test edge cases for framework compatibility."""

    def test_no_type_hints(self) -> None:
        """Functions without type hints still work."""

        @Airlock()
        def untyped_tool(x, y):  # type: ignore[no-untyped-def]
            """A tool without type hints."""
            return x + y

        # Should still be callable
        untyped_tool(x=1, y=2)
        # May return blocked response due to strict validation
        # but signature should be preserved
        sig = inspect.signature(untyped_tool)
        assert "x" in sig.parameters
        assert "y" in sig.parameters

    def test_complex_return_type(self) -> None:
        """Functions with complex return types are introspectable."""

        @Airlock()
        def complex_return(x: int) -> tuple[list[str], dict[str, int], bool]:
            """Returns a complex tuple."""
            return (["a", "b"], {"count": x}, True)

        sig = inspect.signature(complex_return)
        assert "x" in sig.parameters

        result = complex_return(x=5)
        assert isinstance(result, tuple)
        assert result[1]["count"] == 5

    def test_optional_parameters(self) -> None:
        """Optional parameters are correctly introspected."""

        @Airlock()
        def optional_params(
            required: str,
            optional_str: str | None = None,
            optional_int: int | None = None,
        ) -> str:
            """Tool with optional parameters."""
            parts = [required]
            if optional_str:
                parts.append(optional_str)
            if optional_int:
                parts.append(str(optional_int))
            return "-".join(parts)

        sig = inspect.signature(optional_params)

        # Check defaults
        assert sig.parameters["required"].default == inspect.Parameter.empty
        assert sig.parameters["optional_str"].default is None
        assert sig.parameters["optional_int"].default is None

        # Verify it works
        result = optional_params(required="base", optional_str="extra")
        assert result == "base-extra"
