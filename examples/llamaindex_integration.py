"""LlamaIndex Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with LlamaIndex for
secure RAG and agent workflows. Shows:

1. FunctionTool with @Airlock pattern
2. ReActAgent with secured tools
3. FunctionAgent and AgentWorkflow
4. QueryEngine tools with security
5. Multi-agent systems with policy enforcement

Requirements:
    pip install agent-airlock llama-index llama-index-llms-openai

References:
    - LlamaIndex Tools: https://developers.llamaindex.ai/python/framework/module_guides/deploying/agents/tools/
    - FunctionAgent: https://developers.llamaindex.ai/python/examples/agent/agent_workflow_basic/
    - ReActAgent: https://developers.llamaindex.ai/python/examples/agent/react_agent/
"""

from agent_airlock import (
    READ_ONLY_POLICY,
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if LlamaIndex is available
try:
    from llama_index.core.agent import ReActAgent
    from llama_index.core.tools import FunctionTool, QueryEngineTool  # noqa: F401
    from llama_index.llms.openai import OpenAI
except ImportError:
    print("LlamaIndex is required for this example.")
    print("Install with: pip install llama-index llama-index-llms-openai")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: @Airlock MUST be closest to the function definition
# =============================================================================
#
# LlamaIndex uses FunctionTool.from_defaults() to wrap functions.
# Apply @Airlock first, then wrap with FunctionTool:
#
# @Airlock()
# def my_function(): ...
# tool = FunctionTool.from_defaults(fn=my_function)
#
# The tool name defaults to function name, description to docstring.
# =============================================================================


# Configuration
config = AirlockConfig(
    strict_mode=True,
    mask_pii=True,
    mask_secrets=True,
    max_output_chars=5000,
)


# =============================================================================
# Example 1: Basic FunctionTool with Airlock
# =============================================================================


@Airlock(config=config)
def add_numbers(a: int, b: int) -> int:
    """Add two numbers together.

    Args:
        a: First number
        b: Second number
    """
    return a + b


@Airlock(config=config)
def multiply_numbers(a: int, b: int) -> int:
    """Multiply two numbers together.

    Args:
        a: First number
        b: Second number
    """
    return a * b


# Create LlamaIndex FunctionTools
add_tool = FunctionTool.from_defaults(fn=add_numbers)
multiply_tool = FunctionTool.from_defaults(fn=multiply_numbers)


# =============================================================================
# Example 2: Custom tool name and description
# =============================================================================


@Airlock(config=config)
def search_documents(query: str, top_k: int = 5) -> str:
    """Search the document store for relevant documents.

    Args:
        query: Search query string
        top_k: Number of results to return (1-20)
    """
    if top_k < 1 or top_k > 20:
        return "Error: top_k must be between 1 and 20"
    return f"Found {top_k} documents matching '{query}'"


# Create tool with custom name and description
search_tool = FunctionTool.from_defaults(
    fn=search_documents,
    name="document_search",
    description="Search the knowledge base for relevant documents. Use for any information lookup.",
)


# =============================================================================
# Example 3: Read-only tools with policy
# =============================================================================


@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_user_profile(user_id: str) -> str:
    """Get user profile information (read-only).

    PII will be automatically masked in the output.

    Args:
        user_id: The user's unique identifier
    """
    return f"""
    User {user_id}:
    - Name: John Doe
    - Email: john.doe@example.com
    - Phone: 555-123-4567
    - Role: Customer
    """


@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_order_history(user_id: str, limit: int = 10) -> str:  # noqa: ARG001
    """Get order history for a user.

    Args:
        user_id: User identifier
        limit: Maximum orders to return (1-50)
    """
    return f"Order history for {user_id}: 3 orders in last 30 days"


user_profile_tool = FunctionTool.from_defaults(fn=get_user_profile)
order_history_tool = FunctionTool.from_defaults(fn=get_order_history)


# =============================================================================
# Example 4: Rate-limited tools for expensive operations
# =============================================================================

API_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    rate_limits={
        "call_api": "30/minute",
        "generate_report": "5/minute",
    },
)


@Airlock(config=config, policy=API_POLICY)
def call_api(endpoint: str, method: str = "GET") -> str:
    """Call an external API endpoint.

    Rate limited to 30 calls per minute.

    Args:
        endpoint: API endpoint URL
        method: HTTP method (GET, POST)
    """
    return f"API response from {method} {endpoint}: Success"


@Airlock(config=config, policy=API_POLICY)
def generate_report(report_type: str, format: str = "pdf") -> str:
    """Generate a report.

    Rate limited to 5 per minute due to resource cost.

    Args:
        report_type: Type of report (sales, inventory, performance)
        format: Output format (pdf, csv, xlsx)
    """
    return f"Generated {report_type} report in {format} format"


api_tool = FunctionTool.from_defaults(fn=call_api)
report_tool = FunctionTool.from_defaults(fn=generate_report)


# =============================================================================
# Example 5: Sandboxed code execution
# =============================================================================


@Airlock(config=config, sandbox=True, sandbox_required=True)
def execute_python(code: str) -> str:
    """Execute Python code in a secure E2B sandbox.

    SECURITY: Runs in an isolated Firecracker MicroVM.
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


code_tool = FunctionTool.from_defaults(
    fn=execute_python,
    name="python_executor",
    description="Execute Python code for calculations and data processing. Use for any programming task.",
)


# =============================================================================
# Example 6: Creating a ReActAgent with secured tools
# =============================================================================


def create_react_agent():
    """Create a ReActAgent with secured tools.

    ReAct (Reasoning + Acting) agents can work with any LLM.
    They reason about which tools to use step by step.
    """
    llm = OpenAI(model="gpt-4o", temperature=0)

    tools = [
        add_tool,
        multiply_tool,
        search_tool,
        user_profile_tool,
    ]

    agent = ReActAgent.from_tools(
        tools=tools,
        llm=llm,
        verbose=True,
        max_iterations=10,
    )

    return agent


# =============================================================================
# Example 7: FunctionAgent with secured workflow
# =============================================================================


def create_function_agent():
    """Create a FunctionAgent for function calling.

    FunctionAgent uses the LLM's native function calling capability.
    More efficient than ReAct for models that support it.
    """
    try:
        from llama_index.core.agent.function_calling import FunctionAgent
    except ImportError:
        print("FunctionAgent requires newer LlamaIndex version")
        return None

    llm = OpenAI(model="gpt-4o", temperature=0)

    tools = [
        add_tool,
        multiply_tool,
        search_tool,
        code_tool,
    ]

    agent = FunctionAgent.from_tools(
        tools=tools,
        llm=llm,
        verbose=True,
    )

    return agent


# =============================================================================
# Example 8: Async tools for parallel execution
# =============================================================================


@Airlock(config=config)
async def async_fetch_data(url: str) -> str:
    """Fetch data from a URL asynchronously.

    Args:
        url: URL to fetch
    """
    import asyncio

    await asyncio.sleep(0.1)  # Simulate async IO
    return f"Fetched data from {url}"


@Airlock(config=config)
async def async_process(data: str, operation: str = "summarize") -> str:
    """Process data asynchronously.

    Args:
        data: Data to process
        operation: Processing operation
    """
    import asyncio

    await asyncio.sleep(0.1)  # Simulate processing
    return f"Processed with {operation}: {data[:50]}..."


async_fetch_tool = FunctionTool.from_defaults(fn=async_fetch_data)
async_process_tool = FunctionTool.from_defaults(fn=async_process)


# =============================================================================
# Example 9: Agent with QueryEngineTool
# =============================================================================


def create_rag_agent(index):
    """Create an agent that combines RAG with secured tools.

    Args:
        index: A LlamaIndex VectorStoreIndex or similar

    This combines document retrieval (via QueryEngineTool) with
    custom secured functions for a complete RAG + action system.
    """
    from llama_index.core.tools import QueryEngineTool, ToolMetadata

    # Create query engine tool from index
    query_engine = index.as_query_engine()
    query_tool = QueryEngineTool(
        query_engine=query_engine,
        metadata=ToolMetadata(
            name="document_qa",
            description="Answer questions based on the document store.",
        ),
    )

    # Combine with secured function tools
    llm = OpenAI(model="gpt-4o", temperature=0)

    agent = ReActAgent.from_tools(
        tools=[query_tool, search_tool, user_profile_tool],
        llm=llm,
        verbose=True,
    )

    return agent


# =============================================================================
# Demo: Run the examples
# =============================================================================


def demo_llamaindex():
    """Demonstrate Agent-Airlock with LlamaIndex."""
    print("\n" + "=" * 60)
    print("DEMO: LlamaIndex + Agent-Airlock")
    print("=" * 60)

    # Test 1: Direct function call
    print("\n1. Direct secured function call:")
    result = add_numbers(a=5, b=3)
    print(f"   Result: {result}")

    # Test 2: Type validation
    print("\n2. Type validation (wrong type):")
    result = multiply_numbers(a="five", b=3)  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Test 3: Ghost argument rejection
    print("\n3. Ghost argument rejection (strict mode):")
    result = search_documents(query="AI agents", force=True)  # type: ignore
    print(f"   Result: {result}")

    # Test 4: PII masking
    print("\n4. PII masking in output:")
    result = get_user_profile(user_id="USER-123")
    print(f"   Result: {result}")

    # Test 5: FunctionTool call
    print("\n5. FunctionTool.call():")
    result = add_tool.call(a=10, b=20)
    print(f"   FunctionTool result: {result}")

    # Test 6: ReActAgent
    print("\n6. Creating ReActAgent:")
    try:
        agent = create_react_agent()
        response = agent.chat("What is 15 + 27?")
        print(f"   Agent response: {response}")
    except Exception as e:
        print(f"   (Agent requires API key): {e}")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Agent-Airlock + LlamaIndex Integration")
    print("=" * 60)
    print()
    print("Secured Functions & Tools:")
    print("  - add_numbers / add_tool: Basic arithmetic")
    print("  - multiply_numbers / multiply_tool: Multiplication")
    print("  - search_documents / search_tool: Document search")
    print("  - get_user_profile: Read-only, PII masking")
    print("  - get_order_history: Read-only")
    print("  - call_api: Rate limited (30/min)")
    print("  - generate_report: Rate limited (5/min)")
    print("  - execute_python: Sandboxed execution")
    print()
    print("Agents:")
    print("  - ReActAgent: Reasoning + Acting with secured tools")
    print("  - FunctionAgent: Native function calling")
    print("  - RAG Agent: QueryEngineTool + secured functions")
    print()

    demo_llamaindex()

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
