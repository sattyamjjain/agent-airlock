"""LangChain Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with LangChain for
secure AI agent tool calls. Shows:

1. Basic @tool + @Airlock pattern
2. LangChain agents with secured tools
3. Pydantic schema validation with args_schema
4. ReAct agents with security policies
5. Self-healing error handling for LLM retries

Requirements:
    pip install agent-airlock langchain langchain-openai

References:
    - LangChain Tools: https://docs.langchain.com/oss/python/langchain/tools
    - LangChain Agents: https://docs.langchain.com/oss/python/langgraph/quickstart
"""

from pydantic import BaseModel, Field

from agent_airlock import (
    READ_ONLY_POLICY,
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if LangChain is available
try:
    from langchain.tools import tool
    from langchain_core.tools import BaseTool  # noqa: F401
except ImportError:
    print("LangChain is required for this example.")
    print("Install with: pip install langchain langchain-openai")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: @Airlock MUST be closest to the function definition
# =============================================================================
#
# ✅ CORRECT:
#   @tool
#   @Airlock()
#   def my_function(): ...
#
# ❌ WRONG:
#   @Airlock()
#   @tool
#   def my_function(): ...
#
# Why? Agent-Airlock preserves __signature__ and __annotations__ so frameworks
# can introspect the function. If @Airlock is on the outside, LangChain sees
# "empty arguments" and tool calls fail.
# =============================================================================


# =============================================================================
# Example 1: Basic @tool + @Airlock pattern
# =============================================================================


# Default config - strips ghost arguments, validates types
@tool
@Airlock()
def search_database(query: str, limit: int = 10) -> str:
    """Search the customer database for matching records.

    Args:
        query: Search terms to look for
        limit: Maximum number of results to return (1-100)
    """
    # Ghost arguments like "force=True" are automatically stripped
    # Type mismatches like query=123 return self-healing error
    return f"Found {limit} results for '{query}'"


# =============================================================================
# Example 2: Strict mode - rejects hallucinated arguments
# =============================================================================

strict_config = AirlockConfig(strict_mode=True)


@tool
@Airlock(config=strict_config)
def delete_user(user_id: str) -> str:
    """Delete a user from the system.

    Args:
        user_id: The unique identifier of the user to delete
    """
    # In strict mode, if LLM sends ghost args like "confirm=True", the call
    # is blocked with a helpful error message for the LLM to retry correctly.
    return f"User {user_id} deleted successfully"


# =============================================================================
# Example 3: With Pydantic args_schema for complex validation
# =============================================================================


class OrderQueryArgs(BaseModel):
    """Arguments for querying orders with validation."""

    customer_id: str = Field(..., description="Customer's unique ID")
    status: str = Field(
        default="all",
        pattern=r"^(pending|shipped|delivered|cancelled|all)$",
        description="Filter by order status",
    )
    limit: int = Field(default=10, gt=0, le=100, description="Max results (1-100)")


@tool(args_schema=OrderQueryArgs)
@Airlock()
def query_orders(customer_id: str, status: str = "all", limit: int = 10) -> str:
    """Query orders for a specific customer.

    Args:
        customer_id: Customer's unique ID
        status: Filter by order status (pending/shipped/delivered/cancelled/all)
        limit: Maximum number of results to return (1-100)
    """
    return f"Found orders for customer {customer_id} with status '{status}' (limit: {limit})"


# =============================================================================
# Example 4: Read-only policy enforcement
# =============================================================================


@tool
@Airlock(policy=READ_ONLY_POLICY)
def get_account_balance(account_id: str) -> str:
    """Get the current balance of an account.

    This tool is read-only and cannot modify data.

    Args:
        account_id: The account identifier
    """
    return f"Account {account_id} balance: $1,234.56"


# =============================================================================
# Example 5: Custom policy with rate limiting
# =============================================================================

API_POLICY = SecurityPolicy(
    allowed_tools=["api_*", "fetch_*", "get_*"],
    denied_tools=["delete_*", "drop_*"],
    rate_limits={
        "api_*": "60/minute",  # Rate limit API calls
        "fetch_*": "30/minute",
    },
)


@tool
@Airlock(policy=API_POLICY)
def api_call(endpoint: str, method: str = "GET") -> str:
    """Make an API call to an external service.

    Rate limited to 60 calls per minute.

    Args:
        endpoint: The API endpoint to call
        method: HTTP method (GET, POST, PUT, DELETE)
    """
    return f"API response from {method} {endpoint}"


# =============================================================================
# Example 6: PII masking in outputs
# =============================================================================

pii_config = AirlockConfig(mask_pii=True, mask_secrets=True)


@tool
@Airlock(config=pii_config)
def get_user_profile(user_id: str) -> str:  # noqa: ARG001
    """Get user profile information.

    PII in the output will be automatically masked.

    Args:
        user_id: The user's unique identifier
    """
    # The SSN, email, and phone will be masked in the output
    return """
    User Profile:
    - Name: John Doe
    - Email: john.doe@example.com
    - Phone: 555-123-4567
    - SSN: 123-45-6789
    """


# =============================================================================
# Example 7: Sandbox execution for code execution
# =============================================================================


@tool
@Airlock(sandbox=True, sandbox_required=True)
def execute_python_code(code: str) -> str:
    """Execute Python code in a secure sandbox.

    SECURITY: This runs in an isolated E2B Firecracker MicroVM.
    If E2B is unavailable, the call is blocked (sandbox_required=True).

    Args:
        code: The Python code to execute
    """
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()

    try:
        exec(code)  # noqa: S102 - Safe: runs only in E2B sandbox
        return sys.stdout.getvalue()
    except Exception as e:
        return f"Error: {e}"
    finally:
        sys.stdout = old_stdout


# =============================================================================
# Example 8: Using with LangChain AgentExecutor
# =============================================================================


def create_secure_langchain_agent():
    """Create a LangChain agent with secured tools.

    This example shows how to build a complete agent with:
    - Multiple secured tools
    - OpenAI function calling
    - Automatic error handling
    """
    try:
        from langchain.agents import AgentExecutor, create_openai_tools_agent
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_openai import ChatOpenAI
    except ImportError:
        print("LangChain OpenAI not available. Skipping agent example.")
        return None

    # Define secured tools
    @tool
    @Airlock(config=strict_config)
    def calculator(expression: str) -> str:
        """Evaluate a mathematical expression.

        Args:
            expression: A mathematical expression like '2 + 2' or '10 * 5'
        """
        try:
            # Safe eval for math only
            result = eval(expression, {"__builtins__": {}}, {})  # noqa: S307
            return str(result)
        except Exception as e:
            return f"Error: {e}"

    @tool
    @Airlock(policy=READ_ONLY_POLICY)
    def get_weather(city: str) -> str:
        """Get current weather for a city.

        Args:
            city: The city name
        """
        return f"Weather in {city}: 72°F, Sunny"

    # Create the agent
    llm = ChatOpenAI(model="gpt-4", temperature=0)
    tools = [calculator, get_weather]

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", "You are a helpful assistant with access to tools."),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ]
    )

    agent = create_openai_tools_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True)


# =============================================================================
# Demo: Show how self-healing works
# =============================================================================


def demo_self_healing():
    """Demonstrate how Agent-Airlock provides self-healing errors for LLM retry."""
    print("\n" + "=" * 60)
    print("DEMO: Self-Healing Error Responses")
    print("=" * 60)

    # Simulate LLM sending wrong type
    print("\n1. LLM sends string '10' instead of int 10:")
    result = search_database(query="test", limit="10")  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Simulate LLM sending ghost arguments
    print("\n2. LLM sends ghost argument 'force=True' (strict mode):")
    result = delete_user(user_id="123", force=True)  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Valid call
    print("\n3. Correct call passes validation:")
    result = search_database(query="customer query", limit=25)
    print(f"   Result: {result}")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Agent-Airlock + LangChain Integration Examples")
    print("=" * 60)
    print()
    print("Tools created:")
    print("  - search_database: Basic secured search")
    print("  - delete_user: Strict mode (rejects ghosts)")
    print("  - query_orders: Pydantic schema validation")
    print("  - get_account_balance: Read-only policy")
    print("  - api_call: Rate limited policy")
    print("  - get_user_profile: PII masking")
    print("  - execute_python_code: Sandboxed execution")
    print()

    # Run the self-healing demo
    demo_self_healing()

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
