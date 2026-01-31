# Framework Compatibility Guide

Agent-Airlock is designed to work seamlessly with all major AI agent frameworks in 2026. This guide covers integration patterns, the critical "Golden Rule" for decorator ordering, and links to comprehensive examples.

> **See also:** Full working examples in [`examples/`](../examples/README.md)

---

## The Golden Rule

> **Always put `@Airlock` closest to the function definition.**

AI frameworks like LangChain, CrewAI, OpenAI Agents SDK, and AutoGen use `inspect.signature()` to generate JSON schemas for LLM tool calls. If decorators are ordered incorrectly, the LLM sees "empty arguments" and tool calls fail.

### Correct Order

```python
# ✅ CORRECT: @Airlock is closest to the function
@framework_decorator
@Airlock()
def my_tool(x: int, y: str) -> dict:
    return {"x": x, "y": y}
```

### Incorrect Order

```python
# ❌ WRONG: @Airlock wraps the framework decorator
@Airlock()
@framework_decorator
def my_tool(x: int, y: str) -> dict:
    return {"x": x, "y": y}
```

**Why?** Agent-Airlock preserves the original function's `__signature__`, `__annotations__`, and `__wrapped__` attributes. When it's closest to the function, this information flows up through the decorator chain correctly.

---

## LangChain Integration

LangChain's `@tool` decorator reads function signatures to build schemas for the LLM.

> **Full example:** [`examples/langchain_integration.py`](../examples/langchain_integration.py)

### Basic Usage

```python
from langchain.tools import tool
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(strict_mode=True)

@tool
@Airlock(config=config)
def search_database(query: str, limit: int = 10) -> list[dict]:
    """Search the database for matching records.

    Args:
        query: The search query string
        limit: Maximum number of results to return
    """
    return db.search(query, limit=limit)
```

### With AgentExecutor

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from agent_airlock import Airlock, STRICT_POLICY

@tool
@Airlock(policy=STRICT_POLICY)
def get_user_info(user_id: str) -> dict:
    """Get information about a user."""
    return {"id": user_id, "name": "John Doe"}

llm = ChatOpenAI(model="gpt-4")
tools = [get_user_info]
agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)
```

### References
- [LangChain Tools Documentation](https://docs.langchain.com/oss/python/langchain/tools)
- [LangChain Custom Tools Guide](https://latenode.com/blog/ai-frameworks-technical-infrastructure/langchain-setup-tools-agents-memory/langchain-tools-complete-guide-creating-using-custom-llm-tools-code-examples-2025)

---

## LangGraph Integration

LangGraph is the evolution of LangChain for stateful, graph-based agent workflows.

> **Full example:** [`examples/langgraph_integration.py`](../examples/langgraph_integration.py)

### With ToolNode

```python
from langchain_core.tools import tool
from langgraph.prebuilt import ToolNode
from langgraph.graph import StateGraph, MessagesState
from agent_airlock import Airlock

@tool
@Airlock()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b

@tool
@Airlock()
def multiply(a: int, b: int) -> int:
    """Multiply two numbers."""
    return a * b

# Create ToolNode with secured tools
tools = [add, multiply]
tool_node = ToolNode(tools)

# Build graph
workflow = StateGraph(MessagesState)
workflow.add_node("agent", call_model)
workflow.add_node("tools", tool_node)
# ... add edges
```

### References
- [LangGraph Documentation](https://docs.langchain.com/oss/python/langgraph/quickstart)
- [LangGraph Tutorial 2026](https://langchain-tutorials.github.io/langgraph-tutorial-2026-beginners-guide/)

---

## CrewAI Integration

CrewAI's `@tool` decorator enables role-based multi-agent collaboration.

> **Full example:** [`examples/crewai_integration.py`](../examples/crewai_integration.py)

### Basic Usage

```python
from crewai.tools import tool
from agent_airlock import Airlock, READ_ONLY_POLICY

@tool("Database Query Tool")
@Airlock(policy=READ_ONLY_POLICY)
def query_database(sql: str) -> list[dict]:
    """Execute a read-only SQL query."""
    return db.execute(sql)
```

### With Crew Agents

```python
from crewai import Agent, Crew, Task
from crewai.tools import tool
from agent_airlock import Airlock, SecurityPolicy

ANALYST_POLICY = SecurityPolicy(
    allowed_tools=["query_*", "read_*"],
    denied_tools=["write_*", "delete_*"],
    rate_limits={"*": "100/hour"},
)

@tool("Query Tool")
@Airlock(policy=ANALYST_POLICY)
def query_data(metric: str) -> dict:
    """Query analytics data."""
    return analytics.query(metric)

analyst = Agent(
    role="Data Analyst",
    goal="Analyze business metrics",
    tools=[query_data],
)
```

### References
- [CrewAI Tools Documentation](https://docs.crewai.com/en/learn/create-custom-tools)
- [CrewAI GitHub](https://github.com/crewAIInc/crewAI-tools)

---

## OpenAI Agents SDK Integration

OpenAI's Agents SDK is a lightweight framework for multi-agent workflows.

> **Full example:** [`examples/openai_agents_sdk_integration.py`](../examples/openai_agents_sdk_integration.py)

### Basic Usage

```python
from agents import Agent, Runner, function_tool
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(strict_mode=True, mask_pii=True)

@function_tool
@Airlock(config=config)
def get_weather(city: str, units: str = "celsius") -> str:
    """Get weather for a city."""
    return f"Weather in {city}: 22°{units[0].upper()}"

agent = Agent(
    name="weather_agent",
    tools=[get_weather],
    model="gpt-4o-mini",
)
```

### Handoff Pattern

```python
# Specialist agents with secured tools
billing_agent = Agent(
    name="billing",
    tools=[get_billing_info],  # @Airlock secured
)

technical_agent = Agent(
    name="technical",
    tools=[check_service, execute_code],  # @Airlock secured
)

# Triage agent with handoffs
triage = Agent(
    name="triage",
    handoffs=[billing_agent, technical_agent],
)
```

### References
- [OpenAI Agents SDK Documentation](https://openai.github.io/openai-agents-python/)
- [OpenAI Agents SDK GitHub](https://github.com/openai/openai-agents-python)

---

## PydanticAI Integration

PydanticAI provides type-safe agents with Pydantic validation.

> **Full example:** [`examples/pydanticai_integration.py`](../examples/pydanticai_integration.py)

### Basic Usage

```python
from pydantic_ai import Agent
from agent_airlock import Airlock

# Pre-secure the function
@Airlock()
def get_stock_price(symbol: str) -> str:
    """Get stock price."""
    return f"Stock {symbol}: $150.25"

# Pass to Agent
agent = Agent(
    "openai:gpt-4o",
    tools=[get_stock_price],
)
```

### With @agent.tool_plain

```python
from pydantic_ai import Agent
from agent_airlock import Airlock

agent = Agent("openai:gpt-4o")

@agent.tool_plain
@Airlock()
def search(query: str) -> str:
    """Search for information."""
    return f"Results for '{query}'"
```

### References
- [PydanticAI Documentation](https://ai.pydantic.dev/)
- [PydanticAI Function Tools](https://ai.pydantic.dev/tools/)

---

## Microsoft AutoGen Integration

AutoGen enables multi-agent conversations and code execution.

> **Full example:** [`examples/autogen_integration.py`](../examples/autogen_integration.py)

### AutoGen 0.4+ (FunctionTool)

```python
from autogen_agentchat.agents import AssistantAgent
from autogen_core.tools import FunctionTool
from agent_airlock import Airlock

@Airlock()
def get_weather(city: str) -> str:
    """Get weather."""
    return f"Weather in {city}: Sunny"

# Wrap as FunctionTool
weather_tool = FunctionTool(get_weather, description="Get weather")

# Use with AssistantAgent
agent = AssistantAgent(
    name="assistant",
    tools=[get_weather],  # Direct function works too
)
```

### AutoGen 0.2 (register_function)

```python
from autogen import ConversableAgent, register_function
from agent_airlock import Airlock

@Airlock()
def calculate(expression: str) -> str:
    """Calculate math."""
    return str(eval(expression))

assistant = ConversableAgent("assistant", llm_config=llm_config)
executor = ConversableAgent("executor", human_input_mode="NEVER")

register_function(
    calculate,
    caller=assistant,
    executor=executor,
    description="Calculate math expressions",
)
```

### References
- [AutoGen Documentation](https://microsoft.github.io/autogen/stable/)
- [AutoGen Tools](https://microsoft.github.io/autogen/stable/user-guide/core-user-guide/components/tools.html)

---

## LlamaIndex Integration

LlamaIndex provides tools for RAG and agent workflows.

> **Full example:** [`examples/llamaindex_integration.py`](../examples/llamaindex_integration.py)

### FunctionTool

```python
from llama_index.core.tools import FunctionTool
from llama_index.core.agent import ReActAgent
from agent_airlock import Airlock

@Airlock()
def search_docs(query: str) -> str:
    """Search documents."""
    return f"Found docs for '{query}'"

# Wrap as FunctionTool
search_tool = FunctionTool.from_defaults(fn=search_docs)

# Use with ReActAgent
agent = ReActAgent.from_tools([search_tool], llm=llm)
```

### References
- [LlamaIndex Tools](https://developers.llamaindex.ai/python/framework/module_guides/deploying/agents/tools/)
- [LlamaIndex Agents](https://developers.llamaindex.ai/python/framework/use_cases/agents/)

---

## Hugging Face smolagents Integration

smolagents provides code-writing agents that are 30% more efficient than ReAct.

> **Full example:** [`examples/smolagents_integration.py`](../examples/smolagents_integration.py)

### Basic Usage

```python
from smolagents import CodeAgent, InferenceClientModel, tool
from agent_airlock import Airlock

@tool
@Airlock()
def calculator(expression: str) -> str:
    """Calculate math expressions."""
    return str(eval(expression))

agent = CodeAgent(
    tools=[calculator],
    model=InferenceClientModel(),
)
result = agent.run("Calculate 15 * 23")
```

### References
- [smolagents Documentation](https://huggingface.co/docs/smolagents/en/index)
- [smolagents GitHub](https://github.com/huggingface/smolagents)

---

## Anthropic Claude Integration

Direct integration with Anthropic's Claude API for tool use.

> **Full example:** [`examples/anthropic_integration.py`](../examples/anthropic_integration.py)

### Pattern

```python
import anthropic
from agent_airlock import Airlock

# 1. Define secured function
@Airlock()
def get_weather(location: str) -> str:
    """Get weather."""
    return f"Weather in {location}: Sunny"

# 2. Create tool schema
WEATHER_TOOL = {
    "name": "get_weather",
    "description": "Get weather for a location",
    "input_schema": {
        "type": "object",
        "properties": {
            "location": {"type": "string"},
        },
        "required": ["location"],
    },
}

# 3. Execute on tool_use
def execute_tool(name: str, input: dict) -> str:
    if name == "get_weather":
        return get_weather(**input)
```

### References
- [Claude Tool Use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/programmatic-tool-calling)
- [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python)

---

## FastMCP Integration

FastMCP is the recommended way to build MCP servers.

> **Full example:** [`examples/fastmcp_integration.py`](../examples/fastmcp_integration.py)

### @secure_tool Convenience Decorator

```python
from agent_airlock.mcp import secure_tool, create_secure_mcp_server

mcp, secure = create_secure_mcp_server("My Server")

@secure
def read_file(path: str) -> str:
    """Read a file."""
    return Path(path).read_text()

@secure(sandbox=True, sandbox_required=True)
def execute_code(code: str) -> str:
    """Execute code in sandbox."""
    exec(code)
    return "done"
```

---

## Sandbox Execution with Frameworks

For dangerous operations, use `sandbox=True` with `sandbox_required=True`:

```python
from langchain.tools import tool
from agent_airlock import Airlock

@tool
@Airlock(sandbox=True, sandbox_required=True)
def execute_code(python_code: str) -> str:
    """Execute Python code in a secure sandbox.

    SECURITY: This runs in an isolated E2B Firecracker MicroVM.
    It will NEVER fall back to local execution.
    """
    import io, sys
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        exec(python_code)
        return sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
```

---

## Troubleshooting

### Problem: LLM sees empty arguments

**Cause:** Decorator order is wrong.

**Solution:** Put `@Airlock` closest to the function definition.

### Problem: Type validation fails unexpectedly

**Cause:** Airlock uses Pydantic strict mode—no type coercion.

**Solution:** Ensure your function has proper type hints and the LLM sends correct types.

### Problem: Ghost arguments being stripped

**Cause:** LLM is hallucinating parameters that don't exist.

**Solution:** This is expected behavior! Airlock strips them by default. Use `strict_mode=True` to reject instead.

### Problem: Rate limit errors

**Cause:** Policy rate limits exceeded.

**Solution:** Check your `SecurityPolicy` rate limits. Default is no limit.

---

## Framework Support Matrix

| Framework | Version | Status | Decorator Pattern |
|-----------|---------|--------|-------------------|
| LangChain | 0.3+ | ✅ Full | `@tool` → `@Airlock` |
| LangGraph | 1.x | ✅ Full | `@tool` → `@Airlock` |
| CrewAI | 0.50+ | ✅ Full | `@tool()` → `@Airlock` |
| OpenAI Agents SDK | 0.7+ | ✅ Full | `@function_tool` → `@Airlock` |
| PydanticAI | 0.3+ | ✅ Full | `@agent.tool_plain` → `@Airlock` |
| AutoGen | 0.4+ | ✅ Full | `@Airlock` → `FunctionTool()` |
| AutoGen | 0.2 | ✅ Full | `@Airlock` → `register_function()` |
| LlamaIndex | 0.11+ | ✅ Full | `@Airlock` → `FunctionTool.from_defaults()` |
| smolagents | 1.x | ✅ Full | `@tool` → `@Airlock` |
| Anthropic Claude | 0.40+ | ✅ Full | `@Airlock` → schema dict |
| FastMCP | 2.x | ✅ Full | `@mcp.tool` → `@Airlock` or `@secure_tool` |
| Claude Tools | - | ✅ Full | Standard decorator pattern |
| OpenAI Functions | - | ✅ Full | Schema generated correctly |

---

## Performance Notes

- **Validation overhead:** <50ms per call
- **E2B cold start:** ~125ms ([Firecracker MicroVM](https://e2b.dev/blog/firecracker-vs-qemu))
- **E2B warm pool:** <200ms (pre-warmed sandboxes)
- **Signature introspection:** Negligible (cached by frameworks)

---

## References

- [LangChain Documentation](https://docs.langchain.com/)
- [LangGraph Documentation](https://docs.langchain.com/oss/python/langgraph/)
- [CrewAI Documentation](https://docs.crewai.com/)
- [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/)
- [PydanticAI Documentation](https://ai.pydantic.dev/)
- [Microsoft AutoGen](https://microsoft.github.io/autogen/)
- [LlamaIndex Documentation](https://developers.llamaindex.ai/)
- [smolagents Documentation](https://huggingface.co/docs/smolagents/)
- [Anthropic Claude](https://platform.claude.com/docs/)
- [Agent Framework Comparison 2026](https://langfuse.com/blog/2025-03-19-ai-agent-comparison)
