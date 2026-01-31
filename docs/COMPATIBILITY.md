# Framework Compatibility Guide

Agent-Airlock is designed to work seamlessly with all major AI agent frameworks. This guide covers integration patterns and the critical "Golden Rule" for decorator ordering.

---

## The Golden Rule

> **Always put `@Airlock` closest to the function definition.**

AI frameworks like LangChain, CrewAI, and AutoGen use `inspect.signature()` to generate JSON schemas for LLM tool calls. If decorators are ordered incorrectly, the LLM sees "empty arguments" and tool calls fail.

### Correct Order

```python
# ✅ CORRECT: @Airlock is closest to the function
@langchain_tool
@Airlock()
def my_tool(x: int, y: str) -> dict:
    return {"x": x, "y": y}
```

### Incorrect Order

```python
# ❌ WRONG: @Airlock wraps the framework decorator
@Airlock()
@langchain_tool
def my_tool(x: int, y: str) -> dict:
    return {"x": x, "y": y}
```

**Why?** Agent-Airlock preserves the original function's `__signature__`, `__annotations__`, and `__wrapped__` attributes. When it's closest to the function, this information flows up through the decorator chain correctly.

---

## LangChain Integration

LangChain's `@tool` decorator reads function signatures to build schemas for the LLM.

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

### With LangChain Agents

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain.tools import tool
from agent_airlock import Airlock, STRICT_POLICY

@tool
@Airlock(policy=STRICT_POLICY)
def get_user_info(user_id: str) -> dict:
    """Get information about a user.

    Args:
        user_id: The unique user identifier
    """
    return {"id": user_id, "name": "John Doe"}

# Create agent with secured tools
llm = ChatOpenAI(model="gpt-4")
tools = [get_user_info]
agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(agent=agent, tools=tools)
```

### Reference
- [LangChain Tools Documentation](https://docs.langchain.com/oss/python/langchain/tools)
- [LangChain Custom Tools Guide](https://latenode.com/blog/ai-frameworks-technical-infrastructure/langchain-setup-tools-agents-memory/langchain-tools-complete-guide-creating-using-custom-llm-tools-code-examples-2025)

---

## CrewAI Integration

CrewAI's `@tool` decorator works similarly to LangChain.

### Basic Usage

```python
from crewai_tools import tool
from agent_airlock import Airlock, READ_ONLY_POLICY

@tool("Database Query Tool")
@Airlock(policy=READ_ONLY_POLICY)
def query_database(sql: str) -> list[dict]:
    """Execute a read-only SQL query against the database.

    Args:
        sql: The SQL query to execute (SELECT only)
    """
    return db.execute(sql)
```

### With CrewAI Agents

```python
from crewai import Agent, Task, Crew
from crewai_tools import tool
from agent_airlock import Airlock, SecurityPolicy

# Custom policy for this crew
ANALYST_POLICY = SecurityPolicy(
    allowed_tools=["query_*", "read_*", "get_*"],
    denied_tools=["write_*", "delete_*"],
    rate_limits={"*": "100/hour"},
)

@tool("Query Tool")
@Airlock(policy=ANALYST_POLICY)
def query_data(metric: str, start_date: str, end_date: str) -> dict:
    """Query analytics data for a specific metric.

    Args:
        metric: The metric name to query
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
    """
    return analytics.query(metric, start_date, end_date)

# Create agent with secured tool
analyst = Agent(
    role="Data Analyst",
    goal="Analyze business metrics",
    tools=[query_data],
)
```

### Reference
- [CrewAI Tools Documentation](https://docs.crewai.com/en/learn/create-custom-tools)
- [CrewAI Tools GitHub](https://github.com/crewAIInc/crewAI-tools)

---

## AutoGen Integration

AutoGen uses `register_for_llm` to generate tool schemas from function signatures.

### Basic Usage (AutoGen 0.2)

```python
from autogen import ConversableAgent
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(strict_mode=True, mask_pii=True)

# Define the secured function first
@Airlock(config=config)
def calculate_price(item_id: str, quantity: int, discount: float = 0.0) -> dict:
    """Calculate the total price for an order.

    Args:
        item_id: The product ID
        quantity: Number of items
        discount: Discount percentage (0.0 to 1.0)
    """
    price = get_item_price(item_id)
    total = price * quantity * (1 - discount)
    return {"item_id": item_id, "total": total}

# Create agent and register the tool
assistant = ConversableAgent("assistant", llm_config=llm_config)
user_proxy = ConversableAgent("user_proxy", human_input_mode="NEVER")

# Register with both agents
assistant.register_for_llm(description="Calculate order price")(calculate_price)
user_proxy.register_for_execution()(calculate_price)
```

### AutoGen 0.4+ (FunctionTool)

```python
from autogen_core.tools import FunctionTool
from agent_airlock import Airlock

@Airlock()
def get_weather(city: str) -> dict:
    """Get current weather for a city.

    Args:
        city: The city name
    """
    return {"city": city, "temp": 72, "condition": "sunny"}

# Wrap as FunctionTool - signature is preserved
weather_tool = FunctionTool(get_weather, description="Get weather info")
```

### Reference
- [AutoGen Tools Documentation](https://microsoft.github.io/autogen/stable//user-guide/core-user-guide/components/tools.html)
- [AutoGen Function Utils](https://microsoft.github.io/autogen/0.2/docs/reference/function_utils/)

---

## PydanticAI Integration

PydanticAI uses Pydantic models for tool schemas, which works naturally with Airlock.

### Basic Usage

```python
from pydantic_ai import Agent
from pydantic import BaseModel
from agent_airlock import Airlock

class UserQuery(BaseModel):
    user_id: str
    include_history: bool = False

@Airlock()
def get_user_details(query: UserQuery) -> dict:
    """Get detailed user information.

    Args:
        query: The user query parameters
    """
    user = db.get_user(query.user_id)
    if query.include_history:
        user["history"] = db.get_history(query.user_id)
    return user

# PydanticAI sees the Pydantic model in the signature
agent = Agent("openai:gpt-4", tools=[get_user_details])
```

### Reference
- [PydanticAI Output Documentation](https://ai.pydantic.dev/output/)
- [Pydantic Validation Decorator](https://docs.pydantic.dev/latest/concepts/validation_decorator/)

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

    Args:
        python_code: The Python code to execute
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

```python
# ❌ This fails: LLM sends "42" (string)
def process(count: int) -> int:
    return count * 2

# ✅ This works: Accept string and convert
def process(count: str) -> int:
    return int(count) * 2
```

### Problem: Ghost arguments being stripped

**Cause:** LLM is hallucinating parameters that don't exist.

**Solution:** This is expected behavior! Airlock strips them by default. Use `strict_mode=True` to reject instead.

---

## Framework Support Matrix

| Framework | Status | Notes |
|-----------|--------|-------|
| LangChain | ✅ Full | Use `@tool` then `@Airlock` |
| CrewAI | ✅ Full | Use `@tool()` then `@Airlock` |
| AutoGen 0.2 | ✅ Full | Register after decoration |
| AutoGen 0.4+ | ✅ Full | Works with FunctionTool |
| PydanticAI | ✅ Full | Native Pydantic support |
| FastMCP | ✅ Full | Use `@secure_tool` for convenience |
| Claude Tools | ✅ Full | Standard decorator pattern |
| OpenAI Functions | ✅ Full | Schema generated correctly |

---

## Performance Notes

- **Validation overhead:** <50ms per call
- **E2B cold start:** ~125ms ([Firecracker MicroVM](https://e2b.dev/blog/firecracker-vs-qemu))
- **E2B warm pool:** <200ms (pre-warmed sandboxes)
- **Signature introspection:** Negligible (cached by frameworks)
