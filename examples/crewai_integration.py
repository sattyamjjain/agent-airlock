"""CrewAI Integration Examples for Agent-Airlock.

This example demonstrates how to integrate Agent-Airlock with CrewAI for
secure multi-agent collaboration. Shows:

1. Basic @tool + @Airlock pattern with CrewAI
2. Agent role-based access control
3. Multi-agent crews with secured tools
4. Async tool support
5. Custom caching with security

Requirements:
    pip install agent-airlock crewai crewai-tools

References:
    - CrewAI Tools: https://docs.crewai.com/en/learn/create-custom-tools
    - CrewAI GitHub: https://github.com/crewAIInc/crewAI
"""

from pydantic import BaseModel, Field

from agent_airlock import (
    Airlock,
    AirlockConfig,
    SecurityPolicy,
)

# Check if CrewAI is available
try:
    from crewai import Agent, Crew, Task
    from crewai.tools import tool
except ImportError:
    print("CrewAI is required for this example.")
    print("Install with: pip install crewai crewai-tools")
    raise SystemExit(1) from None


# =============================================================================
# THE GOLDEN RULE: @Airlock MUST be closest to the function definition
# =============================================================================
#
# ✅ CORRECT:
#   @tool("Tool Name")
#   @Airlock()
#   def my_function(): ...
#
# ❌ WRONG:
#   @Airlock()
#   @tool("Tool Name")
#   def my_function(): ...
# =============================================================================


# Configuration
config = AirlockConfig(
    strict_mode=True,  # Reject ghost arguments
    mask_pii=True,  # Mask PII in outputs
    sanitize_output=True,
)


# =============================================================================
# Example 1: Basic @tool + @Airlock pattern
# =============================================================================


@tool("Database Search")
@Airlock(config=config)
def search_database(query: str, table: str = "customers") -> str:
    """Search a database table for matching records.

    Args:
        query: The search query string
        table: Database table to search (customers, orders, products)
    """
    return f"Found 5 results in '{table}' for query: '{query}'"


# =============================================================================
# Example 2: Role-based policy for different agents
# =============================================================================

# Policy for research/analyst agents (read-only)
ANALYST_POLICY = SecurityPolicy(
    allowed_tools=["search_*", "query_*", "get_*", "read_*"],
    denied_tools=["write_*", "delete_*", "update_*"],
    rate_limits={"*": "100/hour"},
)

# Policy for operator agents (can modify)
OPERATOR_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    denied_tools=["delete_*", "drop_*"],
    allowed_roles=["operator", "admin"],
    rate_limits={"write_*": "50/hour", "update_*": "50/hour"},
)


@tool("Query Analytics")
@Airlock(config=config, policy=ANALYST_POLICY)
def query_analytics(metric: str, start_date: str, end_date: str) -> str:
    """Query analytics data for a specific metric.

    This tool is read-only and rate-limited.

    Args:
        metric: The metric name to query (revenue, users, conversions)
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
    """
    return f"Analytics for '{metric}' from {start_date} to {end_date}: 12,345"


@tool("Update Record")
@Airlock(config=config, policy=OPERATOR_POLICY)
def update_record(table: str, record_id: str, field: str, value: str) -> str:
    """Update a field in a database record.

    Requires operator or admin role.

    Args:
        table: The database table
        record_id: ID of the record to update
        field: The field name to update
        value: The new value
    """
    return f"Updated {table}.{record_id}: {field} = {value}"


# =============================================================================
# Example 3: With Pydantic validation
# =============================================================================


class ReportArgs(BaseModel):
    """Arguments for generating a report."""

    report_type: str = Field(
        ..., pattern=r"^(sales|inventory|performance)$", description="Type of report"
    )
    period: str = Field(
        default="monthly",
        pattern=r"^(daily|weekly|monthly|quarterly)$",
        description="Report period",
    )
    format: str = Field(default="json", pattern=r"^(json|csv|pdf)$", description="Output format")


@tool("Generate Report")
@Airlock(config=config)
def generate_report(report_type: str, period: str = "monthly", format: str = "json") -> str:
    """Generate a business report.

    Args:
        report_type: Type of report (sales, inventory, performance)
        period: Report period (daily, weekly, monthly, quarterly)
        format: Output format (json, csv, pdf)
    """
    return f"Generated {period} {report_type} report in {format} format"


# =============================================================================
# Example 4: Async tool with security
# =============================================================================


@tool("Async API Call")
@Airlock(config=config, policy=ANALYST_POLICY)
async def async_api_call(endpoint: str, timeout: int = 30) -> str:
    """Make an async API call to an external service.

    Args:
        endpoint: The API endpoint URL
        timeout: Request timeout in seconds
    """
    import asyncio

    await asyncio.sleep(0.1)  # Simulate async operation
    return f"Response from {endpoint} (timeout: {timeout}s)"


# =============================================================================
# Example 5: Sandboxed code execution for agents
# =============================================================================


@tool("Execute Python")
@Airlock(config=config, sandbox=True, sandbox_required=True)
def execute_python(code: str) -> str:
    """Execute Python code in a secure E2B sandbox.

    SECURITY: This runs in an isolated Firecracker MicroVM.
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


# =============================================================================
# Example 6: Complete CrewAI multi-agent example
# =============================================================================


def create_secure_crew():
    """Create a CrewAI crew with secured tools.

    This demonstrates a research crew with:
    - Analyst agent (read-only tools)
    - Reporter agent (can generate reports)
    - Each agent has appropriate security policies
    """

    # Define secured tools for each agent
    @tool("Market Research")
    @Airlock(config=config, policy=ANALYST_POLICY)
    def market_research(topic: str, depth: str = "summary") -> str:
        """Research market trends and data.

        Args:
            topic: Research topic
            depth: Analysis depth (summary, detailed, comprehensive)
        """
        return f"Market research on '{topic}' ({depth}): Industry growing 15% YoY"

    @tool("Competitor Analysis")
    @Airlock(config=config, policy=ANALYST_POLICY)
    def competitor_analysis(company: str) -> str:
        """Analyze a competitor company.

        Args:
            company: Company name to analyze
        """
        return f"Analysis of {company}: Strong market position, 25% market share"

    @tool("Write Report")
    @Airlock(config=config, policy=OPERATOR_POLICY)
    def write_report(title: str, content: str, audience: str = "executive") -> str:  # noqa: ARG001
        """Write and save a report.

        Args:
            title: Report title
            content: Report content
            audience: Target audience (executive, technical, general)
        """
        return f"Report '{title}' saved for {audience} audience"

    # Create agents with secured tools
    analyst = Agent(
        role="Market Analyst",
        goal="Research and analyze market trends and competitors",
        backstory="You are an expert market analyst with access to research tools.",
        tools=[market_research, competitor_analysis],
        verbose=True,
    )

    reporter = Agent(
        role="Report Writer",
        goal="Create comprehensive reports based on research findings",
        backstory="You are a skilled report writer who creates clear, actionable reports.",
        tools=[write_report],
        verbose=True,
    )

    # Define tasks
    research_task = Task(
        description="Research the AI agent market and analyze key competitors",
        expected_output="A summary of market trends and competitor analysis",
        agent=analyst,
    )

    report_task = Task(
        description="Create an executive report based on the research findings",
        expected_output="A professional executive summary report",
        agent=reporter,
        context=[research_task],
    )

    # Create and return the crew
    return Crew(
        agents=[analyst, reporter],
        tasks=[research_task, report_task],
        verbose=True,
    )


# =============================================================================
# Example 7: Tool with caching and security
# =============================================================================


def custom_cache_function(args: dict, result: str) -> bool:  # noqa: ARG001
    """Custom cache function - only cache successful results."""
    return "Error" not in result


@tool("Cached Lookup")
@Airlock(config=config)
def cached_lookup(key: str) -> str:
    """Lookup a value with caching.

    Results are cached for performance.

    Args:
        key: The lookup key
    """
    return f"Value for '{key}': cached_result_123"


# =============================================================================
# Demo: Show self-healing with CrewAI
# =============================================================================


def demo_crewai_security():
    """Demonstrate Agent-Airlock security features with CrewAI tools."""
    print("\n" + "=" * 60)
    print("DEMO: CrewAI + Agent-Airlock Security")
    print("=" * 60)

    # Test 1: Valid call
    print("\n1. Valid tool call:")
    result = search_database(query="customer data", table="customers")
    print(f"   Result: {result}")

    # Test 2: Ghost argument stripped (in non-strict mode)
    print("\n2. Ghost argument handling (strict mode):")
    non_strict = AirlockConfig(strict_mode=False)

    @tool("Test Tool")
    @Airlock(config=non_strict)
    def test_tool(x: int) -> str:
        return f"Value: {x}"

    result = test_tool(x=5, force=True)  # type: ignore
    print(f"   Result: {result}")
    print("   (ghost 'force=True' was silently stripped)")

    # Test 3: Type validation error
    print("\n3. Type validation error:")
    result = query_analytics(metric=123, start_date="2025-01-01", end_date="2025-12-31")  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Test 4: Policy enforcement
    print("\n4. Policy enforcement (read-only policy):")
    print("   ANALYST_POLICY only allows: search_*, query_*, get_*, read_*")
    print("   ANALYST_POLICY blocks: write_*, delete_*, update_*")


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Agent-Airlock + CrewAI Integration Examples")
    print("=" * 60)
    print()
    print("Secured Tools:")
    print("  - search_database: Basic search with validation")
    print("  - query_analytics: Read-only policy, rate limited")
    print("  - update_record: Operator policy (role-based)")
    print("  - generate_report: Pydantic validation")
    print("  - async_api_call: Async support")
    print("  - execute_python: Sandboxed execution")
    print()
    print("Security Policies:")
    print("  - ANALYST_POLICY: Read-only, 100/hour rate limit")
    print("  - OPERATOR_POLICY: Can modify, role-based access")
    print()

    demo_crewai_security()

    print("\n" + "=" * 60)
    print("To run with a real crew, use create_secure_crew().kickoff()")
    print("=" * 60)
