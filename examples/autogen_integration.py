"""Microsoft AutoGen Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with Microsoft's
AutoGen framework for secure multi-agent conversations. Shows:

1. FunctionTool with @Airlock pattern (AutoGen 0.4+)
2. register_for_llm pattern (AutoGen 0.2)
3. Multi-agent conversations with security
4. Code execution agents with sandboxing
5. Group chat with policy enforcement

Requirements:
    pip install agent-airlock autogen-agentchat autogen-ext[openai]

References:
    - AutoGen: https://microsoft.github.io/autogen/stable/
    - Tools: https://microsoft.github.io/autogen/stable/user-guide/core-user-guide/components/tools.html
    - GitHub: https://github.com/microsoft/autogen
"""

from typing import Annotated

from agent_airlock import (
    READ_ONLY_POLICY,
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if AutoGen is available
try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_core.tools import FunctionTool
    from autogen_ext.models.openai import OpenAIChatCompletionClient
except ImportError:
    print("AutoGen is required for this example.")
    print("Install with: pip install autogen-agentchat autogen-ext[openai]")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: @Airlock MUST be closest to the function definition
# =============================================================================
#
# AutoGen uses FunctionTool to wrap functions. Apply @Airlock first:
#
# @Airlock()
# def my_function(): ...
# tool = FunctionTool(my_function, description="...")
#
# For AssistantAgent, you can pass secured functions directly:
#
# @Airlock()
# def my_function(): ...
# agent = AssistantAgent(tools=[my_function])
# =============================================================================


# Configuration
config = AirlockConfig(
    strict_mode=True,
    mask_pii=True,
    mask_secrets=True,
)


# =============================================================================
# Example 1: Basic FunctionTool with Airlock (AutoGen 0.4+)
# =============================================================================


@Airlock(config=config)
def get_stock_price(
    ticker: Annotated[str, "Stock ticker symbol like AAPL or GOOGL"],
) -> str:
    """Get the current stock price for a ticker symbol."""
    return f"Stock {ticker}: $150.25 (+2.3%)"


@Airlock(config=config)
def get_market_summary() -> str:
    """Get a summary of today's market performance."""
    return "Market Summary: S&P 500 +0.5%, NASDAQ +0.8%, DOW +0.3%"


# Create FunctionTools
stock_price_tool = FunctionTool(get_stock_price, description="Get current stock price")
market_summary_tool = FunctionTool(get_market_summary, description="Get market summary")


# =============================================================================
# Example 2: Read-only tools with policy
# =============================================================================


@Airlock(config=config, policy=READ_ONLY_POLICY)
def query_database(
    table: Annotated[str, "Database table to query"],
    conditions: Annotated[str, "SQL WHERE conditions"],  # noqa: ARG001
) -> str:
    """Query a database table (read-only).

    This tool cannot modify data.
    """
    return f"Query result from {table}: 5 matching records"


@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_customer_data(
    customer_id: Annotated[str, "Customer ID"],
) -> str:
    """Get customer information (PII will be masked)."""
    return f"""
    Customer {customer_id}:
    - Name: John Doe
    - Email: john.doe@example.com
    - Phone: 555-123-4567
    """


# =============================================================================
# Example 3: Rate-limited tools for expensive operations
# =============================================================================

API_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    rate_limits={
        "call_external_api": "30/minute",
        "send_email": "10/minute",
    },
)


@Airlock(config=config, policy=API_POLICY)
async def call_external_api(
    endpoint: Annotated[str, "API endpoint URL"],
    method: Annotated[str, "HTTP method"] = "GET",
) -> str:
    """Call an external API. Rate limited to 30/minute."""
    return f"Response from {method} {endpoint}: 200 OK"


@Airlock(config=config, policy=API_POLICY)
async def send_email(
    to: Annotated[str, "Recipient email"],
    subject: Annotated[str, "Email subject"],
    body: Annotated[str, "Email body"],  # noqa: ARG001
) -> str:
    """Send an email. Rate limited to 10/minute."""
    return f"Email sent to {to}: {subject}"


# =============================================================================
# Example 4: Sandboxed code execution
# =============================================================================


@Airlock(config=config, sandbox=True, sandbox_required=True)
def execute_python_code(
    code: Annotated[str, "Python code to execute"],
) -> str:
    """Execute Python code in a secure E2B sandbox.

    SECURITY: This runs in an isolated Firecracker MicroVM.
    Will NOT fall back to local execution.
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


# =============================================================================
# Example 5: Creating secure AssistantAgent
# =============================================================================


def create_secure_assistant():
    """Create an AssistantAgent with secured tools.

    The agent can:
    - Look up stock prices (validated)
    - Query databases (read-only)
    - Execute code (sandboxed)
    """
    model_client = OpenAIChatCompletionClient(model="gpt-4o-mini")

    agent = AssistantAgent(
        name="secure_assistant",
        model_client=model_client,
        tools=[
            get_stock_price,
            get_market_summary,
            query_database,
            execute_python_code,
        ],
        system_message="""You are a helpful financial assistant.
        Use the tools to answer questions about stocks and data.
        You can execute Python code for calculations.""",
    )

    return agent


# =============================================================================
# Example 6: Multi-agent conversation with security
# =============================================================================


def create_secure_team():
    """Create a team of agents with different security levels.

    - Analyst: Read-only access to data
    - Developer: Can execute code in sandbox
    - Manager: Coordinates the team
    """
    model_client = OpenAIChatCompletionClient(model="gpt-4o-mini")

    # Analyst agent - read-only tools
    analyst = AssistantAgent(
        name="analyst",
        model_client=model_client,
        tools=[get_stock_price, get_market_summary, query_database],
        system_message="You are a data analyst. Use tools to gather information.",
    )

    # Developer agent - can execute code
    developer = AssistantAgent(
        name="developer",
        model_client=model_client,
        tools=[execute_python_code],
        system_message="You are a developer. Execute code to solve problems.",
    )

    # Manager agent - coordinates
    manager = AssistantAgent(
        name="manager",
        model_client=model_client,
        system_message="""You are a project manager.
        Coordinate with the analyst and developer to complete tasks.
        The analyst can look up data.
        The developer can write and run code.""",
    )

    return {"analyst": analyst, "developer": developer, "manager": manager}


# =============================================================================
# Example 7: Legacy AutoGen 0.2 pattern
# =============================================================================


def autogen_02_pattern():
    """Example of AutoGen 0.2 register_for_llm pattern.

    This is for older AutoGen versions.
    """
    try:
        from autogen import ConversableAgent, register_function
    except ImportError:
        print("AutoGen 0.2 not available")
        return

    # Create secured function
    @Airlock(config=config)
    def calculate_tax(
        income: Annotated[float, "Annual income"],
        deductions: Annotated[float, "Total deductions"] = 0,
    ) -> str:
        """Calculate estimated tax based on income and deductions."""
        taxable = income - deductions
        tax = taxable * 0.25  # Simplified tax calculation
        return f"Estimated tax on ${income:,.2f}: ${tax:,.2f}"

    # Configure LLM
    llm_config = {"model": "gpt-4o-mini", "temperature": 0}

    # Create agents
    assistant = ConversableAgent(
        "assistant",
        llm_config=llm_config,
        system_message="You help calculate taxes.",
    )

    executor = ConversableAgent(
        "executor",
        human_input_mode="NEVER",
        max_consecutive_auto_reply=1,
    )

    # Register the secured function
    register_function(
        calculate_tax,
        caller=assistant,
        executor=executor,
        description="Calculate estimated tax",
    )

    return assistant, executor


# =============================================================================
# Demo: Run the examples
# =============================================================================


async def demo_autogen():
    """Demonstrate Agent-Airlock with AutoGen."""
    print("\n" + "=" * 60)
    print("DEMO: AutoGen + Agent-Airlock")
    print("=" * 60)

    # Test 1: Direct function call
    print("\n1. Direct secured function call:")
    result = get_stock_price(ticker="AAPL")
    print(f"   Result: {result}")

    # Test 2: Type validation
    print("\n2. Type validation (wrong type):")
    result = get_stock_price(ticker=12345)  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Test 3: Ghost argument rejection
    print("\n3. Ghost argument rejection (strict mode):")
    result = get_stock_price(ticker="GOOGL", force=True)  # type: ignore
    print(f"   Result: {result}")

    # Test 4: PII masking
    print("\n4. PII masking in output:")
    result = get_customer_data(customer_id="CUST-123")
    print(f"   Result: {result}")

    # Test 5: FunctionTool usage
    print("\n5. FunctionTool with validation:")
    result = await stock_price_tool.run_json({"ticker": "MSFT"}, None)
    print(f"   FunctionTool result: {result}")

    # Test 6: Run with AssistantAgent
    print("\n6. Running AssistantAgent:")
    try:
        agent = create_secure_assistant()
        result = await agent.run(task="What is the current price of AAPL?")
        print(f"   Agent response: {result.messages[-1].content}")
    except Exception as e:
        print(f"   (Agent run requires API key): {e}")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    import asyncio

    print("=" * 60)
    print("Agent-Airlock + Microsoft AutoGen Integration")
    print("=" * 60)
    print()
    print("Secured Functions:")
    print("  - get_stock_price: Stock data with validation")
    print("  - get_market_summary: Market summary")
    print("  - query_database: Read-only policy")
    print("  - get_customer_data: PII masking")
    print("  - call_external_api: Rate limited (30/min)")
    print("  - send_email: Rate limited (10/min)")
    print("  - execute_python_code: Sandboxed execution")
    print()
    print("Agents:")
    print("  - secure_assistant: Single agent with secured tools")
    print("  - secure_team: Multi-agent with role-based security")
    print()

    asyncio.run(demo_autogen())

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
