# Agent-Airlock Integration Examples

This directory contains comprehensive examples showing how to integrate Agent-Airlock with all major AI agent frameworks in 2026.

## Quick Start

```bash
# Install Agent-Airlock with your preferred framework
pip install agent-airlock[mcp]           # FastMCP integration
pip install agent-airlock langchain      # LangChain integration
pip install agent-airlock crewai         # CrewAI integration
pip install agent-airlock openai-agents  # OpenAI Agents SDK
pip install agent-airlock pydantic-ai    # PydanticAI
pip install agent-airlock autogen-agentchat  # Microsoft AutoGen
pip install agent-airlock llama-index    # LlamaIndex
pip install agent-airlock smolagents     # Hugging Face smolagents
pip install agent-airlock anthropic      # Anthropic Claude

# For sandbox execution
pip install agent-airlock[sandbox]       # E2B integration
```

## The Golden Rule

> **Always put `@Airlock` closest to the function definition.**

```python
# ✅ CORRECT
@framework_decorator
@Airlock()
def my_tool(x: int) -> str:
    return str(x)

# ❌ WRONG
@Airlock()
@framework_decorator
def my_tool(x: int) -> str:
    return str(x)
```

Agent-Airlock preserves `__signature__` and `__annotations__` so frameworks can introspect the function correctly.

## Example Files

### Core Examples

| File | Description |
|------|-------------|
| [`basic_usage.py`](basic_usage.py) | Core features: validation, ghost args, strict mode |
| [`policy_example.py`](policy_example.py) | Security policies, rate limits, RBAC |
| [`e2b_sandbox.py`](e2b_sandbox.py) | E2B Firecracker sandbox execution |
| [`async_tools.py`](async_tools.py) | Async function support with Airlock |
| [`streaming.py`](streaming.py) | Generator/streaming support with per-chunk sanitization |
| [`conversation_tracking.py`](conversation_tracking.py) | Multi-agent conversation validation |
| [`workspace_pii.py`](workspace_pii.py) | Workspace-specific PII masking |
| [`error_hooks.py`](error_hooks.py) | Error recovery hooks (on_validation_error, on_blocked, on_rate_limit) |

### MCP Integration

| File | Description |
|------|-------------|
| [`fastmcp_integration.py`](fastmcp_integration.py) | FastMCP server with all security features |

### Framework Integrations

| File | Framework | Key Features |
|------|-----------|--------------|
| [`langchain_integration.py`](langchain_integration.py) | LangChain | @tool decorator, AgentExecutor, Pydantic schemas |
| [`langgraph_integration.py`](langgraph_integration.py) | LangGraph | StateGraph, ToolNode, multi-agent routing |
| [`crewai_integration.py`](crewai_integration.py) | CrewAI | Multi-agent crews, role-based access |
| [`openai_agents_sdk_integration.py`](openai_agents_sdk_integration.py) | OpenAI Agents SDK | @function_tool, handoffs, manager pattern |
| [`pydanticai_integration.py`](pydanticai_integration.py) | PydanticAI | @agent.tool, dependencies, structured outputs |
| [`autogen_integration.py`](autogen_integration.py) | Microsoft AutoGen | FunctionTool, AssistantAgent, multi-agent |
| [`llamaindex_integration.py`](llamaindex_integration.py) | LlamaIndex | FunctionTool, ReActAgent, QueryEngineTool |
| [`smolagents_integration.py`](smolagents_integration.py) | smolagents | CodeAgent, @tool decorator, E2B native |
| [`anthropic_integration.py`](anthropic_integration.py) | Anthropic Claude | Tool schemas, programmatic tool calling |

## Common Patterns

### 1. Basic Validation

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(strict_mode=True)

@Airlock(config=config)
def my_tool(x: int, y: str) -> str:
    return f"{x}: {y}"
```

### 2. Read-Only Policy

```python
from agent_airlock import Airlock, READ_ONLY_POLICY

@Airlock(policy=READ_ONLY_POLICY)
def get_data(id: str) -> dict:
    return {"id": id, "data": "..."}
```

### 3. Rate Limiting

```python
from agent_airlock import Airlock, SecurityPolicy

API_POLICY = SecurityPolicy(
    rate_limits={"*": "30/minute"}
)

@Airlock(policy=API_POLICY)
def call_api(endpoint: str) -> str:
    return f"Response from {endpoint}"
```

### 4. PII Masking

```python
config = AirlockConfig(mask_pii=True, mask_secrets=True)

@Airlock(config=config)
def get_user(id: str) -> str:
    # Email, phone, SSN will be masked
    return "Name: John, Email: john@example.com"
```

### 5. Sandboxed Execution

```python
@Airlock(sandbox=True, sandbox_required=True)
def execute_code(code: str) -> str:
    # ONLY runs in E2B sandbox
    # sandbox_required=True prevents local fallback
    exec(code)
    return "done"
```

## Running Examples

Each example file can be run directly:

```bash
# Basic usage demo
python examples/basic_usage.py

# LangChain integration
python examples/langchain_integration.py

# FastMCP server (starts MCP server)
python examples/fastmcp_integration.py
```

## Security Features by Example

| Feature | Basic | Policy | Sandbox | FastMCP | All Others |
|---------|-------|--------|---------|---------|------------|
| Ghost arg stripping | ✅ | ✅ | ✅ | ✅ | ✅ |
| Strict type validation | ✅ | ✅ | ✅ | ✅ | ✅ |
| Self-healing errors | ✅ | ✅ | ✅ | ✅ | ✅ |
| Read-only policy | | ✅ | | ✅ | ✅ |
| Rate limiting | | ✅ | | ✅ | ✅ |
| Time restrictions | | ✅ | | ✅ | ✅ |
| Role-based access | | ✅ | | ✅ | ✅ |
| PII masking | ✅ | ✅ | ✅ | ✅ | ✅ |
| Secret masking | ✅ | ✅ | ✅ | ✅ | ✅ |
| E2B sandbox | | | ✅ | ✅ | ✅ |
| sandbox_required | | | ✅ | ✅ | ✅ |

## Framework Compatibility Matrix

| Framework | Version | Status | Notes |
|-----------|---------|--------|-------|
| FastMCP | 2.x | ✅ Full | Use `@secure_tool` for convenience |
| LangChain | 0.3+ | ✅ Full | Use `@tool` then `@Airlock` |
| LangGraph | 1.x | ✅ Full | Works with ToolNode |
| CrewAI | 0.50+ | ✅ Full | Use `@tool()` then `@Airlock` |
| OpenAI Agents SDK | 0.7+ | ✅ Full | Use `@function_tool` then `@Airlock` |
| PydanticAI | 0.3+ | ✅ Full | Use `@agent.tool_plain` then `@Airlock` |
| AutoGen | 0.4+ | ✅ Full | Works with FunctionTool |
| AutoGen | 0.2 | ✅ Full | Use register_function pattern |
| LlamaIndex | 0.11+ | ✅ Full | Works with FunctionTool.from_defaults |
| smolagents | 1.x | ✅ Full | Use `@tool` then `@Airlock` |
| Anthropic | 0.40+ | ✅ Full | Define function, create schema |

## Need Help?

- 📖 [Full Documentation](https://github.com/sattyamjain/agent-airlock#readme)
- 🔒 [Security Guide](../docs/SECURITY.md)
- 🤝 [Compatibility Guide](../docs/COMPATIBILITY.md)
- 🐛 [Report Issues](https://github.com/sattyamjain/agent-airlock/issues)
