"""OpenAI Agents SDK Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with OpenAI's
Agents SDK for secure multi-agent workflows. Shows:

1. @function_tool + @Airlock pattern
2. Multi-agent handoffs with security
3. Guardrails integration
4. MCP tool integration
5. Manager pattern with secured sub-agents

Requirements:
    pip install agent-airlock openai-agents

References:
    - OpenAI Agents SDK: https://openai.github.io/openai-agents-python/
    - GitHub: https://github.com/openai/openai-agents-python
    - PyPI: https://pypi.org/project/openai-agents/
"""

from agent_airlock import (
    READ_ONLY_POLICY,
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if OpenAI Agents SDK is available
try:
    from agents import Agent, Runner, function_tool
except ImportError:
    print("OpenAI Agents SDK is required for this example.")
    print("Install with: pip install openai-agents")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: @Airlock MUST be closest to the function definition
# =============================================================================
#
# ✅ CORRECT:
#   @function_tool
#   @Airlock()
#   def my_function(): ...
#
# ❌ WRONG:
#   @Airlock()
#   @function_tool
#   def my_function(): ...
#
# The @function_tool decorator generates schema from function signature.
# @Airlock preserves the signature so schema generation works correctly.
# =============================================================================


# Configuration
config = AirlockConfig(
    strict_mode=True,  # Reject hallucinated arguments
    mask_pii=True,  # Mask PII in outputs
    mask_secrets=True,  # Mask API keys, passwords
)


# =============================================================================
# Example 1: Basic @function_tool + @Airlock pattern
# =============================================================================


@function_tool
@Airlock(config=config)
def get_weather(city: str, units: str = "celsius") -> str:
    """Get the current weather for a city.

    Args:
        city: Name of the city
        units: Temperature units (celsius or fahrenheit)
    """
    return f"Weather in {city}: 22°{units[0].upper()}, Sunny"


@function_tool
@Airlock(config=config)
def search_products(query: str, category: str = "all", limit: int = 10) -> str:
    """Search for products in the catalog.

    Args:
        query: Search query string
        category: Product category filter
        limit: Maximum number of results (1-100)
    """
    return f"Found {limit} products matching '{query}' in category '{category}'"


# =============================================================================
# Example 2: Read-only tools for data retrieval
# =============================================================================


@function_tool
@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_customer_info(customer_id: str) -> str:
    """Get customer information (read-only).

    Args:
        customer_id: The customer's unique identifier
    """
    # PII will be masked in the output
    return f"""
    Customer {customer_id}:
    - Name: John Doe
    - Email: john.doe@example.com
    - Phone: 555-123-4567
    - Status: Active
    """


@function_tool
@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_order_status(order_id: str) -> str:
    """Get the status of an order.

    Args:
        order_id: The order identifier
    """
    return f"Order {order_id}: Shipped, arriving in 2 days"


# =============================================================================
# Example 3: Rate-limited tools for expensive operations
# =============================================================================

API_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    rate_limits={
        "call_external_api": "30/minute",
        "send_notification": "10/minute",
    },
)


@function_tool
@Airlock(config=config, policy=API_POLICY)
def call_external_api(endpoint: str, method: str = "GET") -> str:
    """Call an external API endpoint.

    Rate limited to 30 calls per minute.

    Args:
        endpoint: API endpoint URL
        method: HTTP method (GET, POST, PUT, DELETE)
    """
    return f"Response from {method} {endpoint}: 200 OK"


@function_tool
@Airlock(config=config, policy=API_POLICY)
def send_notification(user_id: str, message: str, channel: str = "email") -> str:  # noqa: ARG001
    """Send a notification to a user.

    Rate limited to 10 per minute.

    Args:
        user_id: Target user ID
        message: Notification message
        channel: Notification channel (email, sms, push)
    """
    return f"Notification sent to {user_id} via {channel}"


# =============================================================================
# Example 4: Sandboxed code execution
# =============================================================================


@function_tool
@Airlock(config=config, sandbox=True, sandbox_required=True)
def execute_code(code: str, language: str = "python") -> str:
    """Execute code in a secure sandbox.

    SECURITY: Runs in isolated E2B Firecracker MicroVM.
    Will NOT fall back to local execution.

    Args:
        code: Source code to execute
        language: Programming language (python only for now)
    """
    if language != "python":
        return f"Error: Only Python is supported, got {language}"

    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()

    try:
        exec(code)  # noqa: S102 - Safe: sandbox_required=True
        return sys.stdout.getvalue() or "Code executed successfully"
    except Exception as e:
        return f"Execution error: {e}"
    finally:
        sys.stdout = old_stdout


# =============================================================================
# Example 5: Creating secure agents with handoffs
# =============================================================================


def create_support_agents():
    """Create a support agent system with handoffs.

    Architecture:
    - Triage Agent: Routes to appropriate specialist
    - Billing Agent: Handles billing questions (read-only)
    - Technical Agent: Handles technical issues (can run code)
    """

    # Define agent-specific tools
    @function_tool
    @Airlock(config=config, policy=READ_ONLY_POLICY)
    def get_billing_info(account_id: str) -> str:
        """Get billing information for an account.

        Args:
            account_id: The account identifier
        """
        return f"Account {account_id}: Balance $150.00, Next payment: Feb 15"

    @function_tool
    @Airlock(config=config, policy=READ_ONLY_POLICY)
    def check_service_status(service: str) -> str:
        """Check the status of a service.

        Args:
            service: Service name to check
        """
        return f"Service '{service}': All systems operational"

    # Create specialized agents
    billing_agent = Agent(
        name="billing_agent",
        instructions="You are a billing specialist. Help with billing questions.",
        tools=[get_billing_info],
        model="gpt-4o-mini",
    )

    technical_agent = Agent(
        name="technical_agent",
        instructions="You are a technical support specialist.",
        tools=[check_service_status, execute_code],
        model="gpt-4o-mini",
    )

    # Triage agent with handoffs
    triage_agent = Agent(
        name="triage_agent",
        instructions="""You are a customer support triage agent.
        Route billing questions to billing_agent.
        Route technical issues to technical_agent.
        """,
        handoffs=[billing_agent, technical_agent],
        model="gpt-4o-mini",
    )

    return triage_agent


# =============================================================================
# Example 6: Manager pattern - agents as tools
# =============================================================================


def create_manager_agent():
    """Create a manager agent that uses other agents as tools.

    The manager orchestrates specialized agents to solve complex tasks.
    Each sub-agent has its own security policies.
    """

    # Create specialized agents
    research_agent = Agent(
        name="researcher",
        instructions="You research topics and provide detailed information.",
        tools=[search_products, get_customer_info],
        model="gpt-4o-mini",
    )

    writer_agent = Agent(
        name="writer",
        instructions="You write clear, professional content.",
        model="gpt-4o-mini",
    )

    # Manager agent with agents as tools
    manager = Agent(
        name="manager",
        instructions="""You are a project manager coordinating a team.
        Use the researcher for gathering information.
        Use the writer for creating content.
        """,
        tools=[
            research_agent.as_tool(
                tool_name="research",
                tool_description="Research a topic thoroughly",
            ),
            writer_agent.as_tool(
                tool_name="write",
                tool_description="Write professional content",
            ),
        ],
        model="gpt-4o",
    )

    return manager


# =============================================================================
# Example 7: Async tools for parallel execution
# =============================================================================


@function_tool
@Airlock(config=config)
async def async_fetch_data(url: str, timeout: int = 30) -> str:  # noqa: ARG001
    """Fetch data from a URL asynchronously.

    Args:
        url: URL to fetch data from
        timeout: Request timeout in seconds
    """
    import asyncio

    await asyncio.sleep(0.1)  # Simulate async IO
    return f"Fetched data from {url}"


@function_tool
@Airlock(config=config)
async def async_process_data(data: str, operation: str = "summarize") -> str:
    """Process data asynchronously.

    Args:
        data: Input data to process
        operation: Processing operation (summarize, analyze, transform)
    """
    import asyncio

    await asyncio.sleep(0.1)  # Simulate processing
    return f"Processed '{data}' with {operation}: Result ready"


# =============================================================================
# Demo: Run the examples
# =============================================================================


async def demo_openai_agents():
    """Demonstrate Agent-Airlock with OpenAI Agents SDK."""
    print("\n" + "=" * 60)
    print("DEMO: OpenAI Agents SDK + Agent-Airlock")
    print("=" * 60)

    # Test 1: Basic tool call
    print("\n1. Basic secured tool call:")
    result = get_weather(city="San Francisco")
    print(f"   Result: {result}")

    # Test 2: PII masking
    print("\n2. PII masking in output:")
    result = get_customer_info(customer_id="CUST-123")
    print(f"   Result: {result}")

    # Test 3: Type validation
    print("\n3. Type validation (wrong type):")
    result = search_products(query="laptop", limit="ten")  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Test 4: Ghost argument rejection
    print("\n4. Ghost argument rejection (strict mode):")
    result = get_weather(city="Tokyo", force=True, debug=True)  # type: ignore
    print(f"   Result: {result}")

    # Test 5: Run with Agent
    print("\n5. Running agent with secured tools:")
    try:
        agent = Agent(
            name="demo_agent",
            instructions="You are a helpful assistant.",
            tools=[get_weather, search_products],
            model="gpt-4o-mini",
        )
        result = await Runner.run(agent, "What's the weather in Paris?")
        print(f"   Agent response: {result.final_output}")
    except Exception as e:
        print(f"   (Agent run requires OpenAI API key): {e}")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    import asyncio

    print("=" * 60)
    print("Agent-Airlock + OpenAI Agents SDK Integration")
    print("=" * 60)
    print()
    print("Secured Tools:")
    print("  - get_weather: Basic weather lookup")
    print("  - search_products: Product search with validation")
    print("  - get_customer_info: Read-only, PII masking")
    print("  - get_order_status: Read-only")
    print("  - call_external_api: Rate limited (30/min)")
    print("  - send_notification: Rate limited (10/min)")
    print("  - execute_code: Sandboxed execution")
    print()
    print("Agent Patterns:")
    print("  - Handoff pattern: Triage → Specialist agents")
    print("  - Manager pattern: Agents as tools")
    print()

    asyncio.run(demo_openai_agents())

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
