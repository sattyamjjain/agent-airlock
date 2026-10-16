# Framework Compatibility Guide

Agent-Airlock is designed to work seamlessly with all major AI agent frameworks in 2026. This guide covers integration patterns, the critical "Golden Rule" for decorator ordering, and links to comprehensive examples.

> **See also:** Full working examples in [`examples/`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/README.md)

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

> **Full example:** [`examples/langchain_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/langchain_integration.py)

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

> **Full example:** [`examples/langgraph_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/langgraph_integration.py)

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

> **Full example:** [`examples/crewai_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/crewai_integration.py)

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

> **Full example:** [`examples/openai_agents_sdk_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/openai_agents_sdk_integration.py)

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

> **Full example:** [`examples/pydanticai_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/pydanticai_integration.py)

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

> **Full example:** [`examples/autogen_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/autogen_integration.py)

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

> **Full example:** [`examples/llamaindex_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/llamaindex_integration.py)

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

> **Full example:** [`examples/smolagents_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/smolagents_integration.py)

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

> **Full example:** [`examples/anthropic_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/anthropic_integration.py)

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

> **Full example:** [`examples/fastmcp_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/fastmcp_integration.py)

### @secure_tool Convenience Decorator

```python
from pathlib import Path

from agent_airlock import Airlock
from agent_airlock.mcp import create_secure_mcp_server

mcp, secure = create_secure_mcp_server("My Server")

@secure
def read_file(path: str) -> str:
    """Read a file."""
    return Path(path).read_text()

# The server's decorator takes sandbox= but not sandbox_required=, so stack
# @Airlock under @mcp.tool for a tool that must never run locally.
@mcp.tool
@Airlock(sandbox=True, sandbox_required=True)
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
| FastMCP | 2.x–4.x | ✅ Full | `@mcp.tool` → `@Airlock` or `@secure_tool` |
| Claude Tools | - | ✅ Full | Standard decorator pattern |
| OpenAI Functions | - | ✅ Full | Schema generated correctly |

---

## Live Smoke Matrix

The table above records the integration patterns. This one records a live run: one allowed
and one denied tool call through each framework, against a real model. Run
`python scripts/smoke_frameworks.py` first: at no cost it installs every framework into its
own throwaway virtualenv and drives the same exchange against a scripted stand-in for the
Messages API, so a broken install or a wiring fault shows up before any credit is spent.

<!-- SMOKE-MATRIX:BEGIN -->
Generated by [`scripts/smoke_frameworks.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/scripts/smoke_frameworks.py); do not edit by hand. Each framework runs in its own virtualenv with the agent-airlock wheel, and the model is asked to call `get_order_status`, which the policy allows, and then `delete_order`, which `SecurityPolicy(allowed_tools=["get_order_status"])` denies. Each tool body appends to a canary list, so a denied tool that never ran is observed, not inferred, and the refusal is read back from airlock's audit log (for smolagents, from the guard raising `AirlockError`).

**PASS**: the allowed tool ran, the denied tool did not, and the refusal was observed. **INCONCLUSIVE**: the model never attempted the denied call. **ERROR**: the exchange broke before that. **ENV**: the install or an import failed.

**Last run:** 2026-10-16 (UTC) on `claude-haiku-5-5`, max_tokens 4096, at most 4 model calls per framework; agent-airlock 0.10.24 (`1a3e9eba49`); ledger-priced spend $0.0049.

| Framework | Versions | Airlock path | Result | Allowed ran | Denied attempted | Denied refused | Refusal reached the model as | Model calls | Notes |
|---|---|---|---|---|---|---|---|---|---|
| Anthropic Messages | anthropic 1.15.0 | `integrations.anthropic` `ToolRegistry` + `process_message_tools` | PASS | yes | yes | yes | error | 3 | — |
| LangChain | anthropic 1.15.0, langchain 1.4.6, langchain-anthropic 1.7.6, langchain-core 1.6.12 | `integrations.langchain.create_secure_tool` in a `create_agent` loop | PASS | yes | yes | yes | result | 3 | the refusal reaches the model as a normal tool result, not is_error |
| LangGraph | langchain-anthropic 1.7.6, langchain-core 1.6.12, langgraph 1.2.15, langgraph-prebuilt 1.1.1 | `@tool` over `@Airlock`, `ToolNode` + `langgraph_toolnode_compat` | PASS | yes | yes | yes | result | 3 | the refusal reaches the model as a normal tool result, not is_error |
| PydanticAI | anthropic 1.15.0, pydantic-ai-slim 2.57.0 | `PydanticAIAdapter.wrap_agent` on an `AnthropicModel` agent | PASS | yes | yes | yes | result | 3 | the refusal reaches the model as a normal tool result, not is_error; agent-airlock could not attach output sanitisation: this agent has no `output_validate` attribute (PydanticAI 2.x removed it); pydantic-ai 2.57.0 is outside SUPPORTED_PYDANTIC_AI_VERSIONS ('1.88.0', '1.89.0', '1.89.1', '2.31.1', '2.43.0'); adapter behaviour is best-effort |
| OpenAI Agents SDK | litellm 1.83.0, openai-agents 0.24.0 | `@function_tool` over `@Airlock`, `LitellmModel` | PASS | yes | yes | yes | result | 3 | thinking blocks dropped on the next request; the refusal reaches the model as a normal tool result, not is_error; litellm 1.83.0's bundled model map lacks claude-haiku-5-5: it is known only from the map litellm fetches from GitHub at import (not offline, not with LITELLM_LOCAL_MODEL_COST_MAP=True) |
| CrewAI | anthropic 0.73.0, crewai 1.15.28, litellm 1.105.1 | `CrewAIAdapter.wrap_crew`, `LLM(..., is_litellm=True)` | PASS | yes | yes | yes | result | 3 | thinking blocks dropped on the next request; the refusal reaches the model as a normal tool result, not is_error; litellm 1.105.1's bundled model map lacks claude-haiku-5-5: it is known only from the map litellm fetches from GitHub at import (not offline, not with LITELLM_LOCAL_MODEL_COST_MAP=True); crewai's LLM(is_litellm=True) still imports its native Anthropic provider for an anthropic/claud... |
| smolagents | litellm 1.105.1, smolagents 1.26.0 | `smolagents_wrapper.wrap_agent` with a `PolicyBundle` guard raising `AirlockError` | PASS | yes | yes | yes | text | 4 | forces tool_choice (Haiku 5.5 accepts it; the forced call skips thinking); litellm 1.105.1's bundled model map lacks claude-haiku-5-5: it is known only from the map litellm fetches from GitHub at import (not offline, not with LITELLM_LOCAL_MODEL_COST_MAP=True); the guard's policy also allows smolagents' own final_answer tool |
| Google ADK | google-adk 2.12.0, litellm 1.105.1 | `google_adk.wrap_agent`, `LiteLlm` | PASS | yes | yes | yes | result | 3 | thinking blocks dropped on the next request; the refusal reaches the model as a normal tool result, not is_error; litellm 1.105.1's bundled model map lacks claude-haiku-5-5: it is known only from the map litellm fetches from GitHub at import (not offline, not with LITELLM_LOCAL_MODEL_COST_MAP=True); google-adk 2.12.0 is outside SUPPORTED_GOOGLE_ADK_VERSIONS ('2.9.0',); adapter behaviour is best... |
| LlamaIndex | anthropic 1.15.0, llama-index-core 0.14.25, llama-index-llms-anthropic 0.12.3 | `FunctionTool.from_defaults` over `@Airlock` (example-level) | PASS | yes | yes | yes | result | 3 | thinking blocks dropped on the next request; the refusal reaches the model as a normal tool result, not is_error |
| AutoGen | anthropic 0.125.0, autogen-agentchat 0.7.5, autogen-ext 0.7.5 | `AssistantAgent` tools over `@Airlock` (example-level) | ERROR | yes | no | no | not seen | 2 | sends temperature=1.0 (the one value Haiku 5.5 accepts); thinking blocks dropped on the next request; API error: HTTP 400 invalid_request_error: messages: text content blocks must be non-empty; run error: BadRequestError: Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', 'message': 'messages: text content blocks must be non-empty'}, 'request_id': 'req_011Cg6X71Mc5Zh... |
| Claude Agent SDK | claude-agent-sdk 0.2.168 | `wrap_tools` then `create_sdk_mcp_server` | PASS | yes | yes | yes | error | 3 | Claude Code CLI apiKeySource: ANTHROPIC_API_KEY; CLI-reported cost $0.00035 over 3 turn(s); claude-agent-sdk 0.2.168 is outside SUPPORTED_SDK_VERSIONS ('0.1.58', '0.1.73', '0.2.152', '0.2.160'); adapter behaviour is best-effort |

Not in the matrix:

- **Claude Managed Agents**: a hosted runtime with no local tool callable to wrap; its approval gate needs a live session test, not a framework smoke.
- **GPT-5.5 and Gemini 3 tool-shape adapters**: they normalise vendor payloads, wrap no tool and call no model.
- **Google Model Armor**: a classifier the caller invokes; it wraps no tool call.
- **FastMCP**: needs no model; its integration runs in CI's test job.
<!-- SMOKE-MATRIX:END -->

---

## Performance Notes

- **Validation overhead:** measured by `tests/benchmarks/test_bench_core.py` (`make bench`);
  no figure is published here.
- **E2B cold start:** E2B reports about 125ms for its
  [Firecracker micro-VMs](https://e2b.dev/blog/firecracker-vs-qemu); not measured by this
  project.
- **E2B warm pool:** `get_sandbox_pool(config).warm_up()` creates sandboxes before the first
  call; the saving is not measured here.
- **Signature introspection:** once per tool, when it is decorated, not per call.

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
