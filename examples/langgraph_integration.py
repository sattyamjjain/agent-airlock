"""LangGraph Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with LangGraph for
secure, stateful agent workflows. Shows:

1. Node functions with @Airlock secured tools
2. ToolNode with secured tools
3. Conditional routing with security checks
4. ReAct agent pattern with policies
5. Multi-agent graphs with role-based access

Requirements:
    pip install agent-airlock langgraph langchain-openai

References:
    - LangGraph: https://docs.langchain.com/oss/python/langgraph/quickstart
    - ToolNode: https://langchain-tutorials.github.io/langgraph-tutorial-2026-beginners-guide/
    - PyPI: https://pypi.org/project/langgraph/
"""

from typing import Annotated, TypedDict

from agent_airlock import (
    READ_ONLY_POLICY,
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if LangGraph is available
try:
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: F401
    from langchain_core.tools import tool
    from langchain_openai import ChatOpenAI
    from langgraph.graph import END, START, MessagesState, StateGraph
    from langgraph.prebuilt import ToolNode
except ImportError:
    print("LangGraph is required for this example.")
    print("Install with: pip install langgraph langchain-openai")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: @Airlock MUST be closest to the function definition
# =============================================================================
#
# LangGraph uses LangChain's @tool decorator. Apply @Airlock first:
#
# @tool
# @Airlock()
# def my_function(): ...
#
# Then use the tools in ToolNode or direct invocation.
# =============================================================================


# Configuration
config = AirlockConfig(
    strict_mode=True,
    mask_pii=True,
    mask_secrets=True,
)


# =============================================================================
# Example 1: Basic secured tools for LangGraph
# =============================================================================


@tool
@Airlock(config=config)
def add(a: int, b: int) -> int:
    """Add two numbers together.

    Args:
        a: First number
        b: Second number
    """
    return a + b


@tool
@Airlock(config=config)
def multiply(a: int, b: int) -> int:
    """Multiply two numbers.

    Args:
        a: First number
        b: Second number
    """
    return a * b


@tool
@Airlock(config=config)
def search(query: str) -> str:
    """Search for information on a topic.

    Args:
        query: Search query string
    """
    return f"Search results for '{query}': Found 5 relevant documents"


# =============================================================================
# Example 2: Read-only tools with policy
# =============================================================================


@tool
@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_user_data(user_id: str) -> str:
    """Get user data (read-only, PII masked).

    Args:
        user_id: User identifier
    """
    return f"""
    User {user_id}:
    - Name: Jane Doe
    - Email: jane.doe@example.com
    - Account Status: Active
    """


@tool
@Airlock(config=config, policy=READ_ONLY_POLICY)
def query_database(table: str, conditions: str) -> str:
    """Query a database table (read-only).

    Args:
        table: Table name
        conditions: WHERE clause conditions
    """
    return f"Query result from {table}: 10 rows matching '{conditions}'"


# =============================================================================
# Example 3: Rate-limited tools
# =============================================================================

API_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    rate_limits={
        "call_api": "30/minute",
        "send_notification": "10/minute",
    },
)


@tool
@Airlock(config=config, policy=API_POLICY)
def call_api(endpoint: str, method: str = "GET") -> str:
    """Call an external API (rate limited: 30/min).

    Args:
        endpoint: API endpoint URL
        method: HTTP method
    """
    return f"API response from {method} {endpoint}: 200 OK"


@tool
@Airlock(config=config, policy=API_POLICY)
def send_notification(user_id: str, message: str) -> str:  # noqa: ARG001
    """Send a notification (rate limited: 10/min).

    Args:
        user_id: Target user
        message: Notification content
    """
    return f"Notification sent to {user_id}"


# =============================================================================
# Example 4: Sandboxed code execution
# =============================================================================


@tool
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
        return sys.stdout.getvalue() or "Executed successfully"
    except Exception as e:
        return f"Error: {e}"
    finally:
        sys.stdout = old_stdout


# =============================================================================
# Example 5: Simple LangGraph with secured tools
# =============================================================================


def create_simple_graph():
    """Create a simple LangGraph with secured tools.

    This is a basic ReAct-style agent that:
    1. Takes user input
    2. Calls LLM to decide tool usage
    3. Executes secured tools
    4. Returns response
    """
    # Collect all tools
    tools = [add, multiply, search, get_user_data]

    # Create tool node with secured tools
    tool_node = ToolNode(tools)  # noqa: F841

    # Create LLM with tools
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    llm_with_tools = llm.bind_tools(tools)

    # Define the agent node
    def call_model(state: MessagesState):
        messages = state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    # Define routing logic
    def should_continue(state: MessagesState) -> str:
        last_message = state["messages"][-1]
        if hasattr(last_message, "tool_calls") and last_message.tool_calls:
            return "tools"
        return END

    # Build the graph
    workflow = StateGraph(MessagesState)
    workflow.add_node("agent", call_model)
    workflow.add_node("tools", tool_node)

    workflow.add_edge(START, "agent")
    workflow.add_conditional_edges("agent", should_continue, ["tools", END])
    workflow.add_edge("tools", "agent")

    return workflow.compile()


# =============================================================================
# Example 6: Custom state with security context
# =============================================================================


class SecureState(TypedDict):
    """State that includes security context."""

    messages: Annotated[list, "Chat messages"]
    user_role: str
    permissions: list[str]
    tool_calls_count: int


def create_secure_graph():
    """Create a graph with security-aware state.

    The state tracks:
    - User role for RBAC
    - Permissions list
    - Tool call count for rate limiting
    """
    tools = [add, multiply, search, get_user_data, execute_python]
    tool_node = ToolNode(tools)  # noqa: F841

    llm = ChatOpenAI(model="gpt-4o", temperature=0)
    llm_with_tools = llm.bind_tools(tools)

    def call_model(state: SecureState):
        # Could add role-based filtering here
        messages = state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def check_permissions(state: SecureState) -> str:
        """Check if user has permission for requested tools."""
        last_message = state["messages"][-1]

        if not hasattr(last_message, "tool_calls") or not last_message.tool_calls:
            return END

        # Check each tool call
        for tool_call in last_message.tool_calls:
            tool_name = tool_call["name"]

            # Example: Only admins can execute code
            if tool_name == "execute_python" and state["user_role"] != "admin":
                # Add permission denied message
                return "permission_denied"

        return "tools"

    def handle_permission_denied(state: SecureState):  # noqa: ARG001
        """Handle permission denied case."""
        denied_msg = AIMessage(
            content="I'm sorry, but you don't have permission to execute that operation."
        )
        return {"messages": [denied_msg]}

    # Build graph
    workflow = StateGraph(SecureState)
    workflow.add_node("agent", call_model)
    workflow.add_node("tools", tool_node)
    workflow.add_node("permission_denied", handle_permission_denied)

    workflow.add_edge(START, "agent")
    workflow.add_conditional_edges("agent", check_permissions, ["tools", "permission_denied", END])
    workflow.add_edge("tools", "agent")
    workflow.add_edge("permission_denied", END)

    return workflow.compile()


# =============================================================================
# Example 7: Multi-agent graph with role-based security
# =============================================================================


def create_multi_agent_graph():
    """Create a multi-agent graph with different security levels.

    Agents:
    - Researcher: Read-only tools
    - Calculator: Math tools
    - Router: Decides which agent to use
    """
    # Researcher tools (read-only)
    researcher_tools = [search, get_user_data, query_database]
    researcher_tool_node = ToolNode(researcher_tools)

    # Calculator tools (math only)
    calculator_tools = [add, multiply]
    calculator_tool_node = ToolNode(calculator_tools)

    # Create specialized LLMs
    researcher_llm = ChatOpenAI(model="gpt-4o-mini", temperature=0).bind_tools(researcher_tools)
    calculator_llm = ChatOpenAI(model="gpt-4o-mini", temperature=0).bind_tools(calculator_tools)
    router_llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)  # noqa: F841

    def router_node(state: MessagesState):
        """Route to appropriate agent based on query."""
        messages = state["messages"]
        # Simple routing based on content
        last_human = [m for m in messages if isinstance(m, HumanMessage)][-1]
        content = last_human.content.lower()

        if any(word in content for word in ["calculate", "add", "multiply", "math"]):
            route_msg = AIMessage(content="Routing to calculator agent...")
            return {"messages": [route_msg], "next": "calculator"}
        else:
            route_msg = AIMessage(content="Routing to researcher agent...")
            return {"messages": [route_msg], "next": "researcher"}

    def researcher_node(state: MessagesState):
        response = researcher_llm.invoke(state["messages"])
        return {"messages": [response]}

    def calculator_node(state: MessagesState):
        response = calculator_llm.invoke(state["messages"])
        return {"messages": [response]}

    def route_to_agent(state: MessagesState) -> str:
        return state.get("next", "researcher")

    def should_continue_research(state: MessagesState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "researcher_tools"
        return END

    def should_continue_calc(state: MessagesState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "calculator_tools"
        return END

    # Build graph
    workflow = StateGraph(MessagesState)

    # Add nodes
    workflow.add_node("router", router_node)
    workflow.add_node("researcher", researcher_node)
    workflow.add_node("researcher_tools", researcher_tool_node)
    workflow.add_node("calculator", calculator_node)
    workflow.add_node("calculator_tools", calculator_tool_node)

    # Add edges
    workflow.add_edge(START, "router")
    workflow.add_conditional_edges("router", route_to_agent, ["researcher", "calculator"])
    workflow.add_conditional_edges(
        "researcher", should_continue_research, ["researcher_tools", END]
    )
    workflow.add_edge("researcher_tools", "researcher")
    workflow.add_conditional_edges("calculator", should_continue_calc, ["calculator_tools", END])
    workflow.add_edge("calculator_tools", "calculator")

    return workflow.compile()


# =============================================================================
# Demo: Run the examples
# =============================================================================


def demo_langgraph():
    """Demonstrate Agent-Airlock with LangGraph."""
    print("\n" + "=" * 60)
    print("DEMO: LangGraph + Agent-Airlock")
    print("=" * 60)

    # Test 1: Direct tool call
    print("\n1. Direct secured tool call:")
    result = add.invoke({"a": 5, "b": 3})
    print(f"   Result: {result}")

    # Test 2: Type validation
    print("\n2. Type validation (wrong type):")
    result = multiply.invoke({"a": "five", "b": 3})
    print(f"   Result: {result}")

    # Test 3: Ghost argument (through underlying function)
    print("\n3. Ghost argument rejection:")
    # Access the underlying function
    result = search.__wrapped__(query="AI", force=True)  # type: ignore
    print(f"   Result: {result}")

    # Test 4: PII masking
    print("\n4. PII masking in output:")
    result = get_user_data.invoke({"user_id": "USER-123"})
    print(f"   Result: {result}")

    # Test 5: ToolNode
    print("\n5. ToolNode execution:")
    tools = [add, multiply]
    tool_node = ToolNode(tools)  # noqa: F841
    print(f"   ToolNode created with {len(tools)} secured tools")

    # Test 6: Graph creation
    print("\n6. Creating LangGraph:")
    try:
        graph = create_simple_graph()
        print("   Simple graph created successfully")

        # Run the graph
        result = graph.invoke({"messages": [HumanMessage(content="What is 5 + 3?")]})
        print(f"   Graph result: {result['messages'][-1].content}")
    except Exception as e:
        print(f"   (Graph requires API key): {e}")

    # Test 7: Secure graph
    print("\n7. Creating security-aware graph:")
    try:
        secure_graph = create_secure_graph()  # noqa: F841
        print("   Secure graph with role-based access created")
    except Exception as e:
        print(f"   Error: {e}")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Agent-Airlock + LangGraph Integration")
    print("=" * 60)
    print()
    print("Secured Tools:")
    print("  - add, multiply: Math operations")
    print("  - search: Information search")
    print("  - get_user_data: Read-only, PII masking")
    print("  - query_database: Read-only")
    print("  - call_api: Rate limited (30/min)")
    print("  - send_notification: Rate limited (10/min)")
    print("  - execute_python: Sandboxed execution")
    print()
    print("Graph Patterns:")
    print("  - Simple ReAct: Agent → ToolNode → Agent loop")
    print("  - Secure State: Role-based permission checks")
    print("  - Multi-Agent: Router → Specialized agents")
    print()

    demo_langgraph()

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
