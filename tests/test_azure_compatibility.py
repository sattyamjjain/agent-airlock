"""Tests for Azure OpenAI compatibility.

These tests verify that Airlock-decorated functions work correctly with
Azure OpenAI SDK patterns, ensuring:
1. Function schemas are compatible with Azure OpenAI function calling
2. Tool definitions can be extracted for Azure tool_choice
3. Response formats work with Azure structured outputs
4. No interference with Azure-specific parameters
"""

from __future__ import annotations

import inspect
import json
from typing import Any, Literal, get_type_hints

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy


class TestAzureOpenAIFunctionSchema:
    """Tests for Azure OpenAI function schema compatibility."""

    def test_function_schema_extraction(self) -> None:
        """Function schema can be extracted for Azure OpenAI."""

        @Airlock()
        def get_weather(
            location: str,
            unit: Literal["celsius", "fahrenheit"] = "celsius",
        ) -> dict[str, Any]:
            """Get the current weather for a location.

            Args:
                location: City and country, e.g. "London, UK"
                unit: Temperature unit preference
            """
            return {"location": location, "temperature": 22, "unit": unit}

        # Extract function signature (like Azure SDK would)
        sig = inspect.signature(get_weather)
        hints = get_type_hints(get_weather)

        # Build Azure-compatible function definition
        function_def = {
            "name": get_weather.__name__,
            "description": (get_weather.__doc__ or "").split("\n")[0].strip(),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        }

        for name, param in sig.parameters.items():
            hint = hints.get(name)
            prop: dict[str, Any] = {}

            # Map Python types to JSON Schema types
            if hint is str or str(hint) == "str":
                prop["type"] = "string"
            elif hint is int or str(hint) == "int":
                prop["type"] = "integer"
            elif hint is float or str(hint) == "float":
                prop["type"] = "number"
            elif hint is bool or str(hint) == "bool":
                prop["type"] = "boolean"
            elif hasattr(hint, "__origin__") and hint.__origin__ is Literal:
                prop["type"] = "string"
                prop["enum"] = list(hint.__args__)
            else:
                prop["type"] = "string"  # Default fallback

            function_def["parameters"]["properties"][name] = prop

            if param.default == inspect.Parameter.empty:
                function_def["parameters"]["required"].append(name)

        # Verify schema structure
        assert function_def["name"] == "get_weather"
        assert "location" in function_def["parameters"]["properties"]
        assert "unit" in function_def["parameters"]["properties"]
        assert function_def["parameters"]["properties"]["unit"]["enum"] == [
            "celsius",
            "fahrenheit",
        ]
        assert "location" in function_def["parameters"]["required"]
        assert "unit" not in function_def["parameters"]["required"]

    def test_complex_function_schema(self) -> None:
        """Complex function with nested types can be schema-extracted."""

        @Airlock()
        def search_products(
            query: str,
            category: str | None = None,
            min_price: float = 0.0,
            max_price: float = 1000.0,
            in_stock: bool = True,
            limit: int = 10,
        ) -> list[dict[str, Any]]:
            """Search for products in the catalog.

            Args:
                query: Search query string
                category: Optional category filter
                min_price: Minimum price (inclusive)
                max_price: Maximum price (inclusive)
                in_stock: Only show in-stock items
                limit: Maximum results to return
            """
            return [{"name": "Product", "price": 99.99}]

        sig = inspect.signature(search_products)
        params = list(sig.parameters.keys())

        # Verify all parameters are preserved
        assert params == ["query", "category", "min_price", "max_price", "in_stock", "limit"]

        # Verify defaults are preserved
        assert sig.parameters["limit"].default == 10
        assert sig.parameters["in_stock"].default is True

    def test_function_execution_with_azure_style_args(self) -> None:
        """Function can be called with Azure-style JSON arguments."""

        @Airlock()
        def create_reminder(
            title: str,
            due_date: str,
            priority: Literal["low", "medium", "high"] = "medium",
        ) -> dict[str, str]:
            """Create a new reminder."""
            return {"id": "123", "title": title, "due": due_date, "priority": priority}

        # Simulate Azure passing parsed JSON as kwargs
        azure_args = {"title": "Meeting", "due_date": "2024-12-01", "priority": "high"}

        result = create_reminder(**azure_args)
        assert result["title"] == "Meeting"
        assert result["priority"] == "high"


class TestAzureToolChoice:
    """Tests for Azure tool_choice compatibility."""

    def test_tool_name_preserved(self) -> None:
        """Tool name is preserved for tool_choice parameter."""

        @Airlock()
        def send_email(
            recipient: str,
            subject: str,
            body: str,
        ) -> dict[str, bool]:
            """Send an email to the specified recipient."""
            return {"sent": True}

        # Azure uses function.__name__ for tool_choice
        assert send_email.__name__ == "send_email"

        # Simulate Azure tool_choice
        tool_choice = {"type": "function", "function": {"name": send_email.__name__}}
        assert tool_choice["function"]["name"] == "send_email"

    def test_multiple_tools_preserved(self) -> None:
        """Multiple tools maintain distinct identities."""

        @Airlock()
        def tool_a(x: int) -> int:
            """Tool A."""
            return x

        @Airlock()
        def tool_b(y: str) -> str:
            """Tool B."""
            return y

        @Airlock()
        def tool_c(z: float) -> float:
            """Tool C."""
            return z

        # Simulate Azure tools array
        tools = [
            {"type": "function", "function": {"name": tool_a.__name__}},
            {"type": "function", "function": {"name": tool_b.__name__}},
            {"type": "function", "function": {"name": tool_c.__name__}},
        ]

        tool_names = [t["function"]["name"] for t in tools]
        assert tool_names == ["tool_a", "tool_b", "tool_c"]


class TestAzureStructuredOutputs:
    """Tests for Azure structured output compatibility."""

    def test_dict_return_type(self) -> None:
        """Dict return types work with Azure structured outputs."""

        @Airlock()
        def analyze_sentiment(text: str) -> dict[str, Any]:
            """Analyze sentiment of text."""
            return {
                "sentiment": "positive",
                "confidence": 0.95,
                "aspects": [
                    {"topic": "quality", "sentiment": "positive"},
                ],
            }

        result = analyze_sentiment(text="Great product!")
        assert isinstance(result, dict)
        assert "sentiment" in result
        assert result["confidence"] == 0.95

    def test_json_serializable_output(self) -> None:
        """Output can be serialized to JSON for Azure response."""

        @Airlock()
        def get_user_info(user_id: int) -> dict[str, Any]:
            """Get user information."""
            return {
                "id": user_id,
                "name": "Test User",
                "email": "test@example.com",
                "roles": ["user", "admin"],
                "metadata": {"last_login": "2024-01-01T00:00:00Z"},
            }

        result = get_user_info(user_id=123)

        # Verify it's JSON serializable
        json_str = json.dumps(result)
        parsed = json.loads(json_str)

        assert parsed["id"] == 123
        assert parsed["roles"] == ["user", "admin"]


class TestAzureSpecificPatterns:
    """Tests for Azure-specific usage patterns."""

    def test_azure_style_error_handling(self) -> None:
        """Airlock error responses are structured like Azure errors."""

        @Airlock(config=AirlockConfig(strict_mode=True))
        def strict_function(x: int) -> int:
            """A strict function."""
            return x

        # Call with invalid argument type
        result = strict_function(x="not_an_int")  # type: ignore[arg-type]

        # Should return structured error
        assert isinstance(result, dict)
        assert result.get("status") == "blocked"
        assert "error" in result

    def test_azure_with_policy_enforcement(self) -> None:
        """Policy enforcement works with Azure tool patterns."""
        policy = SecurityPolicy(
            allowed_tools=["allowed_tool"],
            denied_tools=["denied_tool"],
        )

        @Airlock(policy=policy)
        def allowed_tool(x: int) -> int:
            """An allowed tool."""
            return x * 2

        @Airlock(policy=policy)
        def denied_tool(x: int) -> int:
            """A denied tool."""
            return x * 2

        # Allowed tool works
        assert allowed_tool(x=5) == 10

        # Denied tool is blocked
        result = denied_tool(x=5)
        assert isinstance(result, dict)
        assert result.get("status") == "blocked"

    def test_azure_async_function_compatibility(self) -> None:
        """Async functions work with Azure async SDK patterns."""

        @Airlock()
        async def async_azure_tool(query: str) -> dict[str, str]:
            """An async tool for Azure."""
            return {"result": f"Processed: {query}"}

        # Verify it's still async
        import asyncio

        assert asyncio.iscoroutinefunction(async_azure_tool)

        # Verify signature is preserved
        sig = inspect.signature(async_azure_tool)
        assert "query" in sig.parameters


class TestAzureOpenAIClientSimulation:
    """Simulate Azure OpenAI client usage patterns."""

    def test_chat_completions_tools_format(self) -> None:
        """Tools can be formatted for chat.completions.create()."""

        @Airlock()
        def search_database(
            query: str,
            table: str = "users",
            limit: int = 10,
        ) -> list[dict[str, Any]]:
            """Search a database table.

            Args:
                query: SQL-like query
                table: Table name
                limit: Max results
            """
            return [{"id": 1, "name": "Result"}]

        # Format tool for Azure chat.completions.create(tools=[...])
        sig = inspect.signature(search_database)
        hints = get_type_hints(search_database)

        tool_definition = {
            "type": "function",
            "function": {
                "name": search_database.__name__,
                "description": "Search a database table.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        name: {
                            "type": self._python_type_to_json(hints.get(name)),
                            "description": f"Parameter {name}",
                        }
                        for name in sig.parameters
                    },
                    "required": [
                        name
                        for name, param in sig.parameters.items()
                        if param.default == inspect.Parameter.empty
                    ],
                },
            },
        }

        assert tool_definition["type"] == "function"
        assert tool_definition["function"]["name"] == "search_database"
        assert "query" in tool_definition["function"]["parameters"]["required"]
        assert "limit" not in tool_definition["function"]["parameters"]["required"]

    def test_function_call_response_handling(self) -> None:
        """Simulate handling Azure function_call response."""

        @Airlock()
        def calculate(expression: str) -> float:
            """Evaluate a math expression."""
            # Safe eval for basic math
            allowed = set("0123456789+-*/.() ")
            if all(c in allowed for c in expression):
                return float(eval(expression))  # noqa: S307
            return 0.0

        # Simulate Azure response with function_call
        azure_response = {
            "function_call": {
                "name": "calculate",
                "arguments": '{"expression": "2 + 2 * 3"}',
            }
        }

        # Parse and execute
        func_name = azure_response["function_call"]["name"]
        args = json.loads(azure_response["function_call"]["arguments"])

        assert func_name == calculate.__name__
        result = calculate(**args)
        assert result == 8.0

    @staticmethod
    def _python_type_to_json(hint: Any) -> str:
        """Convert Python type hint to JSON schema type."""
        if hint is None:
            return "string"
        if hint is str or str(hint) == "str":
            return "string"
        if hint is int or str(hint) == "int":
            return "integer"
        if hint is float or str(hint) == "float":
            return "number"
        if hint is bool or str(hint) == "bool":
            return "boolean"
        return "string"


class TestAzureRateLimiting:
    """Tests for rate limiting with Azure patterns."""

    def test_rate_limit_with_azure_retry_pattern(self) -> None:
        """Rate limiting returns retry-after compatible response."""
        policy = SecurityPolicy(
            allowed_tools=["rate_limited_tool"],
            rate_limits={"rate_limited_tool": "1/minute"},
        )

        @Airlock(policy=policy)
        def rate_limited_tool(x: int) -> int:
            """A rate-limited tool."""
            return x

        # First call succeeds
        assert rate_limited_tool(x=1) == 1

        # Second call is rate limited
        result = rate_limited_tool(x=2)
        assert isinstance(result, dict)
        assert result.get("status") == "blocked"
        assert (
            "rate" in result.get("reason", "").lower() or "limit" in result.get("error", "").lower()
        )


class TestAzureGovCloud:
    """Tests for Azure Government Cloud compatibility."""

    def test_no_external_dependencies(self) -> None:
        """Airlock doesn't require external Azure endpoints."""

        @Airlock()
        def gov_safe_tool(data: str) -> str:
            """A tool safe for government cloud."""
            return f"Processed: {data}"

        # Tool works without any external calls
        result = gov_safe_tool(data="classified")
        assert result == "Processed: classified"

    def test_no_telemetry_injection(self) -> None:
        """Airlock doesn't inject telemetry into responses."""

        @Airlock()
        def clean_tool(x: int) -> dict[str, int]:
            """Returns clean response."""
            return {"result": x * 2}

        result = clean_tool(x=5)

        # Verify no extra fields injected
        assert set(result.keys()) == {"result"}
        assert result["result"] == 10
