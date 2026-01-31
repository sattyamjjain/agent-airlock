"""Hugging Face smolagents Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with Hugging Face's
smolagents framework for secure code-writing agents. Shows:

1. @tool decorator with @Airlock pattern
2. CodeAgent with secured tools
3. E2B sandbox integration (native to smolagents)
4. Multi-agent collaboration
5. Custom tool classes with security

Requirements:
    pip install agent-airlock smolagents

References:
    - smolagents: https://huggingface.co/docs/smolagents/en/index
    - GitHub: https://github.com/huggingface/smolagents
    - Tools: https://huggingface.co/learn/agents-course/en/unit2/smolagents/tools
"""

from agent_airlock import (
    READ_ONLY_POLICY,
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if smolagents is available
try:
    from smolagents import CodeAgent, InferenceClientModel, Tool, tool
except ImportError:
    print("smolagents is required for this example.")
    print("Install with: pip install smolagents")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: @Airlock MUST be closest to the function definition
# =============================================================================
#
# smolagents uses the @tool decorator. Apply @Airlock first:
#
# @tool
# @Airlock()
# def my_function(): ...
#
# smolagents also supports Tool classes - wrap the forward() logic.
# =============================================================================


# Configuration
config = AirlockConfig(
    strict_mode=True,
    mask_pii=True,
    mask_secrets=True,
)


# =============================================================================
# Example 1: Basic @tool + @Airlock pattern
# =============================================================================


@tool
@Airlock(config=config)
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
@Airlock(config=config)
def get_current_time() -> str:
    """Get the current date and time."""
    from datetime import datetime

    return datetime.now().isoformat()


# =============================================================================
# Example 2: Read-only tools with policy
# =============================================================================


@tool
@Airlock(config=config, policy=READ_ONLY_POLICY)
def search_database(query: str, limit: int = 10) -> str:
    """Search the database for matching records.

    This is a read-only operation.

    Args:
        query: Search query string
        limit: Maximum results to return (1-100)
    """
    if limit < 1 or limit > 100:
        return "Error: limit must be between 1 and 100"
    return f"Found {limit} records matching '{query}'"


@tool
@Airlock(config=config, policy=READ_ONLY_POLICY)
def get_user_info(user_id: str) -> str:
    """Get user information.

    PII will be masked in the output.

    Args:
        user_id: User identifier
    """
    return f"""
    User {user_id}:
    - Name: Jane Doe
    - Email: jane.doe@example.com
    - Phone: 555-987-6543
    """


# =============================================================================
# Example 3: Rate-limited tools
# =============================================================================

API_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    rate_limits={
        "fetch_url": "30/minute",
        "send_notification": "10/minute",
    },
)


@tool
@Airlock(config=config, policy=API_POLICY)
def fetch_url(url: str) -> str:
    """Fetch content from a URL.

    Rate limited to 30 requests per minute.

    Args:
        url: URL to fetch
    """
    return f"Content from {url}: <html>...</html>"


@tool
@Airlock(config=config, policy=API_POLICY)
def send_notification(recipient: str, message: str) -> str:  # noqa: ARG001
    """Send a notification to a user.

    Rate limited to 10 per minute.

    Args:
        recipient: Recipient ID or email
        message: Notification message
    """
    return f"Notification sent to {recipient}"


# =============================================================================
# Example 4: Custom Tool class with Airlock
# =============================================================================


class SecureFileReaderTool(Tool):
    """A secure file reader tool with Airlock protection."""

    name = "file_reader"
    description = "Read contents of a file securely."
    inputs = {
        "filepath": {
            "type": "string",
            "description": "Path to the file to read",
        }
    }
    output_type = "string"

    def __init__(self):
        super().__init__()
        # Create secured inner function
        self._secured_read = self._create_secured_reader()

    def _create_secured_reader(self):
        @Airlock(config=config, policy=READ_ONLY_POLICY)
        def read_file_content(filepath: str) -> str:
            """Read file contents with security checks."""
            from pathlib import Path

            path = Path(filepath)
            if not path.exists():
                return f"Error: File not found: {filepath}"
            if not path.is_file():
                return f"Error: Not a file: {filepath}"

            # Size limit for safety
            if path.stat().st_size > 1_000_000:  # 1MB
                return "Error: File too large (max 1MB)"

            return path.read_text()

        return read_file_content

    def forward(self, filepath: str) -> str:
        return self._secured_read(filepath=filepath)


# =============================================================================
# Example 5: Sandboxed code execution (E2B integration)
# =============================================================================

# Note: smolagents has native E2B integration via CodeAgent
# But we add an extra layer of Airlock security


@tool
@Airlock(config=config, sandbox=True, sandbox_required=True)
def execute_python_safely(code: str) -> str:
    """Execute Python code in a secure E2B sandbox.

    SECURITY: This runs in an isolated Firecracker MicroVM.
    Airlock ensures the code ONLY runs in the sandbox.

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


# =============================================================================
# Example 6: Creating a CodeAgent with secured tools
# =============================================================================


def create_secure_code_agent():
    """Create a smolagents CodeAgent with secured tools.

    CodeAgent writes Python code to orchestrate tools.
    This is more efficient than ReAct-style reasoning.
    """
    # Use Hugging Face Inference API (free tier available)
    model = InferenceClientModel()

    # Collect secured tools
    tools = [
        calculator,
        get_current_time,
        search_database,
        get_user_info,
        fetch_url,
        SecureFileReaderTool(),
    ]

    agent = CodeAgent(
        tools=tools,
        model=model,
        max_steps=10,
    )

    return agent


# =============================================================================
# Example 7: CodeAgent with E2B sandbox
# =============================================================================


def create_sandboxed_agent():
    """Create a CodeAgent that runs in E2B sandbox.

    This combines smolagents' native E2B support with
    Airlock's additional security layers.
    """
    try:
        from smolagents import E2BSandbox
    except ImportError:
        print("E2B sandbox requires: pip install smolagents[e2b]")
        return None

    model = InferenceClientModel()

    # Create E2B sandbox for execution
    sandbox = E2BSandbox()

    agent = CodeAgent(
        tools=[calculator, search_database, execute_python_safely],
        model=model,
        sandbox=sandbox,  # Native E2B integration
        max_steps=10,
    )

    return agent


# =============================================================================
# Example 8: Multi-agent system with security
# =============================================================================


def create_multi_agent_system():
    """Create a multi-agent system with role-based security.

    - Research Agent: Read-only tools
    - Calculator Agent: Math tools
    - Manager Agent: Orchestrates the others
    """
    model = InferenceClientModel()

    # Research agent - read-only access
    research_agent = CodeAgent(
        tools=[search_database, get_user_info, fetch_url],
        model=model,
        max_steps=5,
    )

    # Calculator agent - math only
    calc_agent = CodeAgent(
        tools=[calculator, get_current_time],
        model=model,
        max_steps=5,
    )

    # Manager agent could orchestrate these
    # (In a real scenario, you'd use agent-as-tool patterns)

    return {
        "research": research_agent,
        "calculator": calc_agent,
    }


# =============================================================================
# Demo: Run the examples
# =============================================================================


def demo_smolagents():
    """Demonstrate Agent-Airlock with smolagents."""
    print("\n" + "=" * 60)
    print("DEMO: smolagents + Agent-Airlock")
    print("=" * 60)

    # Test 1: Direct function call
    print("\n1. Direct secured function call:")
    result = calculator(expression="2 + 2 * 3")
    print(f"   Result: {result}")

    # Test 2: Type validation
    print("\n2. Type validation (wrong type):")
    result = search_database(query=123, limit=10)  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Test 3: Ghost argument rejection
    print("\n3. Ghost argument rejection (strict mode):")
    result = get_current_time(timezone="UTC")  # type: ignore - ghost arg
    print(f"   Result: {result}")

    # Test 4: PII masking
    print("\n4. PII masking in output:")
    result = get_user_info(user_id="USER-456")
    print(f"   Result: {result}")

    # Test 5: Rate limiting info
    print("\n5. Rate-limited tools:")
    print("   - fetch_url: Limited to 30/minute")
    print("   - send_notification: Limited to 10/minute")

    # Test 6: Custom Tool class
    print("\n6. Custom Tool class with Airlock:")
    reader = SecureFileReaderTool()
    result = reader.forward(filepath="nonexistent.txt")
    print(f"   Result: {result}")

    # Test 7: CodeAgent creation
    print("\n7. Creating CodeAgent:")
    try:
        agent = create_secure_code_agent()
        print(f"   Agent created with {len(agent.tools)} secured tools")
        result = agent.run("Calculate 15 * 23")
        print(f"   Agent result: {result}")
    except Exception as e:
        print(f"   (Agent requires HF token or model): {e}")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Agent-Airlock + Hugging Face smolagents Integration")
    print("=" * 60)
    print()
    print("Secured Tools:")
    print("  - calculator: Math expressions")
    print("  - get_current_time: Current timestamp")
    print("  - search_database: Read-only search")
    print("  - get_user_info: Read-only, PII masking")
    print("  - fetch_url: Rate limited (30/min)")
    print("  - send_notification: Rate limited (10/min)")
    print("  - execute_python_safely: Sandboxed execution")
    print("  - SecureFileReaderTool: Custom Tool class")
    print()
    print("Key Benefits of smolagents + Airlock:")
    print("  - CodeAgent writes efficient orchestration code")
    print("  - Airlock validates all tool calls")
    print("  - Native E2B support + Airlock's sandbox_required")
    print("  - 30% fewer LLM calls than ReAct agents")
    print()

    demo_smolagents()

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)
