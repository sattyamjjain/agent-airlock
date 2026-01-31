"""PydanticAI Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with PydanticAI for
type-safe, validated AI agents. Shows:

1. @agent.tool + @Airlock pattern
2. Dependencies with security policies
3. Structured outputs with validation
4. Human-in-the-loop integration
5. LangChain toolsets integration

Requirements:
    pip install agent-airlock pydantic-ai

References:
    - PydanticAI: https://ai.pydantic.dev/
    - Function Tools: https://ai.pydantic.dev/tools/
    - Toolsets: https://ai.pydantic.dev/toolsets/
"""

from dataclasses import dataclass

from pydantic import BaseModel, Field

from agent_airlock import (
    READ_ONLY_POLICY,
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if PydanticAI is available
try:
    from pydantic_ai import Agent, RunContext
except ImportError:
    print("PydanticAI is required for this example.")
    print("Install with: pip install pydantic-ai")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: @Airlock MUST be closest to the function definition
# =============================================================================
#
# For PydanticAI, tools are registered differently:
#
# Option 1: Pre-secure the function, then register
#   @Airlock()
#   def my_func(): ...
#   agent = Agent(tools=[my_func])
#
# Option 2: Use @agent.tool_plain with @Airlock inside
#   @agent.tool_plain
#   @Airlock()
#   def my_func(): ...
#
# Option 3: For @agent.tool (with context), apply @Airlock to the logic
# =============================================================================


# Configuration
config = AirlockConfig(
    strict_mode=True,
    mask_pii=True,
    mask_secrets=True,
    max_output_chars=5000,
)


# =============================================================================
# Example 1: Basic secured tools with Agent
# =============================================================================


# Pre-secure the function before passing to Agent
@Airlock(config=config)
def get_stock_price(symbol: str) -> str:
    """Get the current stock price.

    Args:
        symbol: Stock ticker symbol (e.g., AAPL, GOOGL)
    """
    return f"Stock {symbol}: $150.25 (+2.3%)"


@Airlock(config=config)
def get_company_info(symbol: str) -> str:
    """Get company information.

    Args:
        symbol: Stock ticker symbol
    """
    return f"Company {symbol}: Technology sector, Market cap $2.5T"


# Create agent with secured tools
stock_agent = Agent(
    "openai:gpt-4o",
    system_prompt="You are a financial assistant. Use the tools to answer stock questions.",
    tools=[get_stock_price, get_company_info],
)


# =============================================================================
# Example 2: Using @agent.tool_plain with Airlock
# =============================================================================

weather_agent = Agent(
    "openai:gpt-4o-mini",
    system_prompt="You are a weather assistant.",
)


@weather_agent.tool_plain
@Airlock(config=config)
def get_weather(city: str, units: str = "celsius") -> str:
    """Get current weather for a city.

    Args:
        city: City name
        units: Temperature units (celsius or fahrenheit)
    """
    return f"Weather in {city}: 22°{units[0].upper()}, Sunny, Humidity 45%"


@weather_agent.tool_plain
@Airlock(config=config)
def get_forecast(city: str, days: int = 3) -> str:
    """Get weather forecast for a city.

    Args:
        city: City name
        days: Number of days to forecast (1-7)
    """
    if days < 1 or days > 7:
        return "Error: days must be between 1 and 7"
    return f"Forecast for {city}: Sunny for the next {days} days"


# =============================================================================
# Example 3: Dependencies with security context
# =============================================================================


@dataclass
class SecurityContext:
    """Security context with user info and permissions."""

    user_id: str
    role: str
    permissions: list[str]


# Agent that uses dependencies
secure_agent = Agent(
    "openai:gpt-4o",
    deps_type=SecurityContext,
    system_prompt="You are a secure data assistant.",
)


# For tools that need context, secure the inner logic
@secure_agent.tool
async def access_database(
    ctx: RunContext[SecurityContext],
    table: str,
    query: str,
) -> str:
    """Access database with permission checks.

    Args:
        table: Database table name
        query: SQL-like query
    """
    # Check permissions from context
    if "read" not in ctx.deps.permissions:
        return f"Error: User {ctx.deps.user_id} lacks read permission"

    # Create an inner secured function
    @Airlock(config=config, policy=READ_ONLY_POLICY)
    def execute_query(table_name: str, sql: str) -> str:  # noqa: ARG001
        return f"Query result from {table_name}: 5 rows returned"

    return execute_query(table_name=table, sql=query)


@secure_agent.tool
async def update_record(
    ctx: RunContext[SecurityContext],
    table: str,
    record_id: str,
    data: str,
) -> str:
    """Update a database record.

    Args:
        table: Database table name
        record_id: Record identifier
        data: JSON data to update
    """
    if "write" not in ctx.deps.permissions:
        return f"Error: User {ctx.deps.user_id} lacks write permission"

    if ctx.deps.role not in ["admin", "operator"]:
        return f"Error: Role {ctx.deps.role} cannot modify records"

    # Secured update function
    @Airlock(config=config)
    def do_update(tbl: str, rid: str, payload: str) -> str:
        return f"Updated {tbl}.{rid} with {payload}"

    return do_update(tbl=table, rid=record_id, payload=data)


# =============================================================================
# Example 4: Structured outputs with Pydantic models
# =============================================================================


class OrderStatus(BaseModel):
    """Order status response."""

    order_id: str
    status: str = Field(pattern=r"^(pending|processing|shipped|delivered)$")
    estimated_delivery: str | None = None
    tracking_number: str | None = None


class OrderQuery(BaseModel):
    """Order query parameters."""

    order_id: str = Field(..., min_length=5, max_length=20)
    include_tracking: bool = False


# Agent with structured output
order_agent = Agent(
    "openai:gpt-4o",
    output_type=OrderStatus,
    system_prompt="You look up order statuses.",
)


@order_agent.tool_plain
@Airlock(config=config)
def lookup_order(order_id: str, include_tracking: bool = False) -> str:
    """Look up an order by ID.

    Args:
        order_id: The order identifier
        include_tracking: Whether to include tracking info
    """
    result = f"Order {order_id}: Status=shipped"
    if include_tracking:
        result += ", Tracking=1Z999AA10123456784"
    return result


# =============================================================================
# Example 5: Rate-limited and policy-enforced tools
# =============================================================================

API_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    rate_limits={
        "fetch_external_data": "30/minute",
        "send_message": "10/minute",
    },
)

api_agent = Agent(
    "openai:gpt-4o-mini",
    system_prompt="You can fetch data and send messages.",
)


@api_agent.tool_plain
@Airlock(config=config, policy=API_POLICY)
def fetch_external_data(url: str, format: str = "json") -> str:
    """Fetch data from an external URL.

    Rate limited to 30 calls per minute.

    Args:
        url: URL to fetch
        format: Response format (json, xml, text)
    """
    return f"Fetched {format} data from {url}"


@api_agent.tool_plain
@Airlock(config=config, policy=API_POLICY)
def send_message(recipient: str, message: str, priority: str = "normal") -> str:  # noqa: ARG001
    """Send a message to a recipient.

    Rate limited to 10 per minute.

    Args:
        recipient: Message recipient (email or user ID)
        message: Message content
        priority: Message priority (low, normal, high)
    """
    return f"Message sent to {recipient} with {priority} priority"


# =============================================================================
# Example 6: Sandboxed code execution
# =============================================================================

code_agent = Agent(
    "openai:gpt-4o",
    system_prompt="You can execute Python code to solve problems.",
)


@code_agent.tool_plain
@Airlock(config=config, sandbox=True, sandbox_required=True)
def run_python(code: str) -> str:
    """Execute Python code in a secure sandbox.

    SECURITY: Runs in isolated E2B Firecracker MicroVM.

    Args:
        code: Python code to execute
    """
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()

    try:
        exec(code)  # noqa: S102 - Safe: sandbox_required=True
        return sys.stdout.getvalue() or "Executed successfully"
    except Exception as e:
        return f"Error: {e}"
    finally:
        sys.stdout = old_stdout


# =============================================================================
# Example 7: Using PydanticAI Toolsets with Airlock
# =============================================================================


def create_secured_toolset():
    """Create a toolset with secured functions.

    Toolsets can be reused across multiple agents.
    """
    from pydantic_ai import Toolset

    # Define secured functions
    @Airlock(config=config)
    def calculate(expression: str) -> str:
        """Evaluate a math expression.

        Args:
            expression: Mathematical expression
        """
        try:
            result = eval(expression, {"__builtins__": {}}, {})  # noqa: S307
            return str(result)
        except Exception as e:
            return f"Error: {e}"

    @Airlock(config=config)
    def format_currency(amount: float, currency: str = "USD") -> str:
        """Format a number as currency.

        Args:
            amount: Numeric amount
            currency: Currency code (USD, EUR, GBP)
        """
        symbols = {"USD": "$", "EUR": "€", "GBP": "£"}
        symbol = symbols.get(currency, currency)
        return f"{symbol}{amount:,.2f}"

    # Create toolset
    return Toolset(tools=[calculate, format_currency])


# =============================================================================
# Demo: Run the examples
# =============================================================================


async def demo_pydanticai():
    """Demonstrate Agent-Airlock with PydanticAI."""
    print("\n" + "=" * 60)
    print("DEMO: PydanticAI + Agent-Airlock")
    print("=" * 60)

    # Test 1: Direct function call
    print("\n1. Direct secured function call:")
    result = get_stock_price(symbol="AAPL")
    print(f"   Result: {result}")

    # Test 2: Type validation
    print("\n2. Type validation (wrong type):")
    result = get_weather(city=123)  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Test 3: Ghost argument rejection
    print("\n3. Ghost argument rejection:")
    result = get_forecast(city="London", days=5, force=True)  # type: ignore
    print(f"   Result: {result}")

    # Test 4: Run with Agent
    print("\n4. Running agent with secured tools:")
    try:
        result = await weather_agent.run("What's the weather in Tokyo?")
        print(f"   Agent response: {result.data}")
    except Exception as e:
        print(f"   (Agent run requires API key): {e}")

    # Test 5: Dependency context
    print("\n5. Running with security context:")
    try:
        ctx = SecurityContext(
            user_id="user-123",
            role="analyst",
            permissions=["read"],
        )
        result = await secure_agent.run(
            "Query the users table for active users",
            deps=ctx,
        )
        print(f"   Agent response: {result.data}")
    except Exception as e:
        print(f"   (Agent run requires API key): {e}")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    import asyncio

    print("=" * 60)
    print("Agent-Airlock + PydanticAI Integration")
    print("=" * 60)
    print()
    print("Agents Created:")
    print("  - stock_agent: Financial data with secured tools")
    print("  - weather_agent: Weather with @agent.tool_plain")
    print("  - secure_agent: Database access with context")
    print("  - order_agent: Structured output with validation")
    print("  - api_agent: Rate-limited external calls")
    print("  - code_agent: Sandboxed code execution")
    print()
    print("Key Patterns:")
    print("  - Pre-secure functions before passing to Agent")
    print("  - Use @agent.tool_plain + @Airlock for simple tools")
    print("  - Wrap context-dependent logic with @Airlock")
    print()

    asyncio.run(demo_pydanticai())

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
