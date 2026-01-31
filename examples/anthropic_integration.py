"""Anthropic Claude Tool Use Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with Anthropic's
Claude API for secure tool/function calling. Shows:

1. Basic tool definitions with @Airlock
2. beta_tool decorator pattern
3. Programmatic tool calling
4. Claude Agent SDK integration
5. Error handling best practices

Requirements:
    pip install agent-airlock anthropic

References:
    - Claude Tool Use: https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling
    - Python SDK: https://github.com/anthropics/anthropic-sdk-python
    - Claude Agent SDK: https://github.com/anthropics/claude-agent-sdk-python
"""

import json
from typing import Any

from agent_airlock import (
    READ_ONLY_POLICY,
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if Anthropic SDK is available
try:
    import anthropic
except ImportError:
    print("Anthropic SDK is required for this example.")
    print("Install with: pip install anthropic")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: Define secured functions, then create tool schemas
# =============================================================================
#
# Claude uses JSON schemas for tool definitions. The pattern is:
# 1. Define the function with @Airlock
# 2. Create a tool schema dict pointing to that function
# 3. Pass schemas to Claude, execute secured functions on tool_use
# =============================================================================


# Configuration
config = AirlockConfig(
    strict_mode=True,
    mask_pii=True,
    mask_secrets=True,
    max_output_chars=5000,
)


# =============================================================================
# Example 1: Basic secured tools for Claude
# =============================================================================


@Airlock(config=config)
def get_weather(location: str, units: str = "celsius") -> str:
    """Get the current weather for a location.

    Args:
        location: City name or location
        units: Temperature units (celsius or fahrenheit)
    """
    return f"Weather in {location}: 22°{units[0].upper()}, Sunny, Humidity 45%"


@Airlock(config=config)
def search_products(query: str, category: str = "all", limit: int = 10) -> str:
    """Search for products in the catalog.

    Args:
        query: Search query
        category: Product category filter
        limit: Maximum results (1-50)
    """
    if limit < 1 or limit > 50:
        return "Error: limit must be between 1 and 50"
    return f"Found {limit} products matching '{query}' in '{category}'"


# Tool schemas for Claude API
WEATHER_TOOL = {
    "name": "get_weather",
    "description": "Get current weather for a location",
    "input_schema": {
        "type": "object",
        "properties": {
            "location": {
                "type": "string",
                "description": "City name or location",
            },
            "units": {
                "type": "string",
                "enum": ["celsius", "fahrenheit"],
                "description": "Temperature units",
            },
        },
        "required": ["location"],
    },
}

SEARCH_TOOL = {
    "name": "search_products",
    "description": "Search product catalog",
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "category": {"type": "string", "description": "Category filter"},
            "limit": {"type": "integer", "description": "Max results (1-50)"},
        },
        "required": ["query"],
    },
}


# =============================================================================
# Example 2: Read-only tools with policy
# =============================================================================


@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_customer_profile(customer_id: str) -> str:
    """Get customer profile (read-only, PII masked).

    Args:
        customer_id: Customer identifier
    """
    return f"""
    Customer {customer_id}:
    - Name: John Doe
    - Email: john.doe@example.com
    - Phone: 555-123-4567
    - Status: Active
    - Balance: $1,234.56
    """


@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_order_history(customer_id: str, limit: int = 5) -> str:
    """Get customer order history.

    Args:
        customer_id: Customer identifier
        limit: Number of orders to return
    """
    return f"Last {limit} orders for {customer_id}: ORD-001, ORD-002, ORD-003"


CUSTOMER_TOOL = {
    "name": "get_customer_profile",
    "description": "Get customer profile information (PII will be masked)",
    "input_schema": {
        "type": "object",
        "properties": {
            "customer_id": {"type": "string", "description": "Customer ID"},
        },
        "required": ["customer_id"],
    },
}

ORDER_TOOL = {
    "name": "get_order_history",
    "description": "Get customer order history",
    "input_schema": {
        "type": "object",
        "properties": {
            "customer_id": {"type": "string", "description": "Customer ID"},
            "limit": {"type": "integer", "description": "Number of orders"},
        },
        "required": ["customer_id"],
    },
}


# =============================================================================
# Example 3: Rate-limited tools
# =============================================================================

API_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    rate_limits={
        "call_external_api": "30/minute",
        "send_email": "10/minute",
    },
)


@Airlock(config=config, policy=API_POLICY)
def call_external_api(endpoint: str, method: str = "GET") -> str:
    """Call an external API (rate limited: 30/min).

    Args:
        endpoint: API endpoint URL
        method: HTTP method
    """
    return f"Response from {method} {endpoint}: 200 OK"


@Airlock(config=config, policy=API_POLICY)
def send_email(to: str, subject: str, body: str) -> str:  # noqa: ARG001
    """Send an email (rate limited: 10/min).

    Args:
        to: Recipient email
        subject: Email subject
        body: Email body
    """
    return f"Email sent to {to}: {subject}"


API_CALL_TOOL = {
    "name": "call_external_api",
    "description": "Call external API (rate limited: 30/minute)",
    "input_schema": {
        "type": "object",
        "properties": {
            "endpoint": {"type": "string", "description": "API endpoint"},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
        },
        "required": ["endpoint"],
    },
}


# =============================================================================
# Example 4: Sandboxed code execution
# =============================================================================


@Airlock(config=config, sandbox=True, sandbox_required=True)
def execute_python(code: str) -> str:
    """Execute Python code in E2B sandbox.

    SECURITY: Runs in isolated Firecracker MicroVM.
    Will NOT fall back to local execution.

    Args:
        code: Python code to execute
    """
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()

    try:
        exec(code)  # noqa: S102 - Safe: sandbox_required=True
        return sys.stdout.getvalue() or "Code executed successfully"
    except Exception as e:
        return f"Error: {e}"
    finally:
        sys.stdout = old_stdout


CODE_EXEC_TOOL = {
    "name": "execute_python",
    "description": "Execute Python code in secure sandbox",
    "input_schema": {
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "Python code to execute"},
        },
        "required": ["code"],
    },
}


# =============================================================================
# Example 5: Tool dispatcher for Claude API
# =============================================================================

# Map tool names to secured functions
TOOL_FUNCTIONS = {
    "get_weather": get_weather,
    "search_products": search_products,
    "get_customer_profile": get_customer_profile,
    "get_order_history": get_order_history,
    "call_external_api": call_external_api,
    "send_email": send_email,
    "execute_python": execute_python,
}

# All tool schemas
ALL_TOOLS = [
    WEATHER_TOOL,
    SEARCH_TOOL,
    CUSTOMER_TOOL,
    ORDER_TOOL,
    API_CALL_TOOL,
    CODE_EXEC_TOOL,
]


def execute_tool(tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    """Execute a tool with Airlock security.

    Args:
        tool_name: Name of the tool to execute
        tool_input: Tool input parameters

    Returns:
        Dict with result or error
    """
    if tool_name not in TOOL_FUNCTIONS:
        return {"error": f"Unknown tool: {tool_name}", "is_error": True}

    try:
        func = TOOL_FUNCTIONS[tool_name]
        result = func(**tool_input)

        # Check if Airlock blocked the call
        if isinstance(result, dict) and result.get("success") is False:
            return {
                "error": result.get("error", "Tool call blocked"),
                "fix_hints": result.get("fix_hints", []),
                "is_error": True,
            }

        return {"result": result, "is_error": False}

    except Exception as e:
        return {"error": str(e), "is_error": True}


# =============================================================================
# Example 6: Complete Claude conversation with tools
# =============================================================================


def run_claude_with_tools(user_message: str) -> str:
    """Run a complete Claude conversation with secured tools.

    This demonstrates the full flow:
    1. Send message to Claude with tool schemas
    2. If Claude uses a tool, execute it with Airlock
    3. Return tool result to Claude
    4. Get final response

    Args:
        user_message: The user's message

    Returns:
        Claude's final response
    """
    client = anthropic.Anthropic()

    messages = [{"role": "user", "content": user_message}]

    # Initial request
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        tools=ALL_TOOLS,
        messages=messages,
    )

    # Handle tool use loop
    while response.stop_reason == "tool_use":
        # Extract tool calls
        tool_uses = [block for block in response.content if block.type == "tool_use"]

        # Execute each tool with Airlock security
        tool_results = []
        for tool_use in tool_uses:
            result = execute_tool(tool_use.name, tool_use.input)

            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": json.dumps(result),
                    "is_error": result.get("is_error", False),
                }
            )

        # Add assistant response and tool results
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

        # Continue conversation
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            tools=ALL_TOOLS,
            messages=messages,
        )

    # Extract final text response
    final_text = ""
    for block in response.content:
        if hasattr(block, "text"):
            final_text += block.text

    return final_text


# =============================================================================
# Example 7: Claude Agent SDK integration
# =============================================================================


def create_claude_agent_tools():
    """Create tools for Claude Agent SDK.

    The Claude Agent SDK supports custom tools as MCP servers.
    This shows how to secure those tools with Airlock.
    """
    try:
        from claude_agent_sdk import ClaudeAgentOptions  # noqa: F401
    except ImportError:
        print("Claude Agent SDK not installed")
        return None

    # With Claude Agent SDK, you define tools as functions
    # that the SDK wraps as in-process MCP servers

    # Secured tool for the agent
    @Airlock(config=config)
    def agent_search(query: str) -> str:
        """Search for information."""
        return f"Results for '{query}': ..."

    @Airlock(config=config, sandbox=True, sandbox_required=True)
    def agent_code_exec(code: str) -> str:
        """Execute code safely."""
        # This runs in sandbox
        return f"Executed: {code}"

    return {
        "search": agent_search,
        "code_exec": agent_code_exec,
    }


# =============================================================================
# Demo: Run the examples
# =============================================================================


def demo_anthropic():
    """Demonstrate Agent-Airlock with Anthropic Claude."""
    print("\n" + "=" * 60)
    print("DEMO: Anthropic Claude + Agent-Airlock")
    print("=" * 60)

    # Test 1: Direct function call
    print("\n1. Direct secured function call:")
    result = get_weather(location="San Francisco")
    print(f"   Result: {result}")

    # Test 2: Type validation
    print("\n2. Type validation (wrong type):")
    result = search_products(query=12345, limit="ten")  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Test 3: Ghost argument rejection
    print("\n3. Ghost argument rejection (strict mode):")
    result = get_weather(location="Tokyo", force=True, verbose=True)  # type: ignore
    print(f"   Result: {result}")

    # Test 4: PII masking
    print("\n4. PII masking in output:")
    result = get_customer_profile(customer_id="CUST-001")
    print(f"   Result: {result}")

    # Test 5: Tool dispatcher
    print("\n5. Tool dispatcher execution:")
    result = execute_tool("get_weather", {"location": "Paris", "units": "celsius"})
    print(f"   Dispatcher result: {result}")

    # Test 6: Tool dispatcher with error
    print("\n6. Tool dispatcher with validation error:")
    result = execute_tool("search_products", {"query": 123})  # Wrong type
    print(f"   Dispatcher result: {result}")

    # Test 7: Full Claude conversation (requires API key)
    print("\n7. Full Claude conversation with tools:")
    try:
        response = run_claude_with_tools("What's the weather in London?")
        print(f"   Claude response: {response}")
    except Exception as e:
        print(f"   (Requires ANTHROPIC_API_KEY): {e}")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Agent-Airlock + Anthropic Claude Integration")
    print("=" * 60)
    print()
    print("Secured Tools:")
    print("  - get_weather: Weather lookup")
    print("  - search_products: Product search")
    print("  - get_customer_profile: Read-only, PII masking")
    print("  - get_order_history: Read-only")
    print("  - call_external_api: Rate limited (30/min)")
    print("  - send_email: Rate limited (10/min)")
    print("  - execute_python: Sandboxed execution")
    print()
    print("Integration Patterns:")
    print("  - Define function with @Airlock")
    print("  - Create tool schema pointing to function")
    print("  - Use execute_tool() dispatcher for tool_use blocks")
    print("  - Return structured errors for Claude to retry")
    print()

    demo_anthropic()

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
