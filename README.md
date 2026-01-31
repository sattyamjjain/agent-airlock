<div align="center">

# 🛡️ Agent-Airlock

### Your AI Agent Just Tried to `rm -rf /`. We Stopped It.

**The open-source firewall for AI agents. One decorator. Zero trust. Full control.**

[![PyPI version](https://img.shields.io/pypi/v/agent-airlock?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/agent-airlock/)
[![Downloads](https://img.shields.io/pypi/dm/agent-airlock?style=for-the-badge&logo=python&logoColor=white)](https://pypistats.org/packages/agent-airlock)
[![CI](https://img.shields.io/github/actions/workflow/status/sattyamjjain/agent-airlock/ci.yml?style=for-the-badge&logo=github&label=CI)](https://github.com/sattyamjjain/agent-airlock/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/sattyamjjain/agent-airlock?style=for-the-badge&logo=codecov&logoColor=white)](https://codecov.io/gh/sattyamjjain/agent-airlock)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/sattyamjjain/agent-airlock?style=for-the-badge&logo=github)](https://github.com/sattyamjjain/agent-airlock/stargazers)

[📦 Install](#install) • [🚀 Quick Start](#what-this-actually-does) • [🔌 Frameworks](#-framework-compatibility) • [📖 Docs](#documentation) • [🤝 Contribute](#contributing)

</div>

---

<!--
🎬 DEMO GIF PLACEHOLDER
Record with: asciinema rec demo.cast && agg demo.cast demo.gif
Show: Agent tries dangerous command → Airlock blocks with red shield
-->

<!--
<div align="center">
  <img src="docs/assets/demo.gif" alt="Agent-Airlock Demo" width="600">
</div>
-->

## 📋 Table of Contents

<details>
<summary>Click to expand</summary>

- [🚨 The Problem](#-the-reality-no-one-talks-about)
- [🚀 Quick Start](#-what-this-actually-does)
- [🔒 E2B Sandbox](#-when-you-need-the-big-guns)
- [📜 Security Policies](#-the-policies-youll-actually-use)
- [💰 Cost Control](#-the-cost-problem-and-how-we-solve-it)
- [🔐 PII Masking](#-the-security-you-forgot-you-needed)
- [⚡ FastMCP Integration](#-fastmcp-integration-the-clean-way)
- [🔌 Framework Compatibility](#-framework-compatibility) — LangChain, OpenAI, PydanticAI, LlamaIndex, CrewAI, AutoGen, smolagents
- [🏆 Comparison](#-why-not-just-use-insert-enterprise-vendor)
- [📦 Install](#-install)
- [🛡️ OWASP Compliance](#️-owasp-llm-top-10-compliance-2025)
- [📊 The Numbers](#-the-numbers)
- [📖 Documentation](#-documentation)
- [🤝 Contributing](#-contributing)
- [⭐ Star History](#-star-history)

</details>

---

```
Agent: "I'll help you clean up disk space..."
       ↓
       rm -rf / --no-preserve-root
       ↓
┌─────────────────────────────────────────┐
│  🛡️ AIRLOCK_BLOCK: Operation Denied     │
│                                         │
│  Reason: Matches denied pattern 'rm_*'  │
│  Policy: PRODUCTION_POLICY              │
│  Fix: Use approved cleanup tools only   │
└─────────────────────────────────────────┘
```

**Agent-Airlock is the open-source firewall for MCP servers.**
One decorator. Zero trust. Full control.

```bash
pip install agent-airlock
```

<br>

<table>
<tr>
<td align="center">🚫<br><b>Ghost Args</b><br><sub>Strip hallucinated params</sub></td>
<td align="center">✅<br><b>Strict Types</b><br><sub>No silent coercion</sub></td>
<td align="center">🔄<br><b>Self-Healing</b><br><sub>LLM-friendly errors</sub></td>
<td align="center">🔒<br><b>E2B Sandbox</b><br><sub>Isolated execution</sub></td>
<td align="center">📜<br><b>RBAC</b><br><sub>Role-based access</sub></td>
<td align="center">🔐<br><b>PII Mask</b><br><sub>Auto-redact secrets</sub></td>
</tr>
</table>

---

## 🚨 The Reality No One Talks About

In January 2026, MCP has 16,000+ servers on GitHub. OpenAI adopted it. The Linux Foundation hosts it.

But here's what the hype cycle ignores:

**LLMs hallucinate tool calls.** Every. Single. Day.

- Claude invents arguments that don't exist in your function signature
- GPT-4 sends `"100"` when your code expects `100`
- Agents chain 47 tool calls before you notice one deleted production data

The enterprise vendors saw this coming. Prompt Security charges $50K/year. Pangea wants your data flowing through their proxy. Cisco is "coming soon."

**We built the alternative.**

---

## 🚀 What This Actually Does

```python
from agent_airlock import Airlock

@Airlock()
def transfer_funds(from_account: str, to_account: str, amount: int) -> dict:
    # Your banking logic here
    return {"status": "transferred", "amount": amount}
```

That's it. One line. Now your function has:

| Protection | What It Stops |
|------------|---------------|
| **Ghost Argument Stripping** | LLM sends `force=True` that doesn't exist → stripped silently |
| **Strict Type Validation** | LLM sends `amount="500"` → blocked, not silently coerced to 500 |
| **Self-Healing Errors** | Instead of crashing, returns `{"fix_hint": "amount must be int"}` |

The LLM gets a structured error. It retries correctly. Your system stays alive.

---

## 🔒 When You Need the Big Guns

```python
from agent_airlock import Airlock, STRICT_POLICY

@Airlock(sandbox=True, policy=STRICT_POLICY)
def execute_code(code: str) -> str:
    """This runs in an E2B Firecracker MicroVM. Not on your machine."""
    exec(code)
    return "executed"
```

**sandbox=True** means:
- Code executes in an isolated VM (125ms boot time)
- No access to your filesystem, network, or secrets
- Warm pool keeps latency under 200ms after first call

**policy=STRICT_POLICY** means:
- Rate limited to 100 calls/hour
- Requires agent identity tracking
- Every call logged for audit

---

## 📜 The Policies You'll Actually Use

```python
from agent_airlock import (
    PERMISSIVE_POLICY,      # Development - no restrictions
    STRICT_POLICY,          # Production - rate limited, requires agent ID
    READ_ONLY_POLICY,       # Analytics agents - can query, can't mutate
    BUSINESS_HOURS_POLICY,  # Dangerous ops only during 9-5
)
```

Or build your own:

```python
from agent_airlock import SecurityPolicy

MY_POLICY = SecurityPolicy(
    allowed_tools=["read_*", "query_*", "search_*"],
    denied_tools=["delete_*", "drop_*", "rm_*"],
    rate_limits={"*": "1000/hour", "write_*": "100/hour"},
    time_restrictions={"deploy_*": "09:00-17:00"},
)
```

---

## 💰 The Cost Problem (And How We Solve It)

A single runaway agent can burn $500 in API costs before you notice.

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    max_output_chars=5000,    # Truncate before token explosion
    max_output_tokens=2000,   # Hard limit on response size
)

@Airlock(config=config)
def query_logs(query: str) -> str:
    # Even if this returns 10MB of logs,
    # Airlock truncates to 5000 chars before the LLM sees it
    return massive_log_query(query)
```

**Result:** Token costs drop dramatically when you:
- Truncate 10MB logs to 5KB before tokenization
- Prevent infinite retry loops from validation errors
- Block runaway agent chains with rate limiting

*Math: 10MB = ~2.5M tokens at $0.01/1K = $25 per response. Truncated to 5KB = ~1.25K tokens = $0.01. That's 99.96% reduction per bloated response.*

---

## 🔐 The Security You Forgot You Needed

Your agent just queried a user's profile. The LLM is about to see their SSN.

```python
config = AirlockConfig(
    mask_pii=True,      # SSN, credit cards, phone numbers
    mask_secrets=True,  # API keys, passwords, connection strings
)

@Airlock(config=config)
def get_user(user_id: str) -> dict:
    return db.users.find_one({"id": user_id})

# What the LLM sees:
# {"name": "John", "ssn": "[REDACTED]", "api_key": "sk-...XXXX"}
```

The data exists in your database. The LLM never sees it. The audit log has the masked version.

---

## ⚡ FastMCP Integration (The Clean Way)

```python
from fastmcp import FastMCP
from agent_airlock.mcp import secure_tool, STRICT_POLICY

mcp = FastMCP("production-server")

@secure_tool(mcp, policy=STRICT_POLICY)
def delete_user(user_id: str) -> dict:
    """One decorator. MCP registration + Airlock protection."""
    return db.users.delete(user_id)
```

No ceremony. No boilerplate. The `@secure_tool` decorator handles:
1. MCP tool registration
2. Ghost argument stripping
3. Type validation
4. Policy enforcement
5. Output sanitization

---

## 🔌 Framework Compatibility

**The Golden Rule:** `@Airlock` must be closest to the function definition.

```
@framework_decorator    ← Framework sees the secured function
@Airlock()             ← Security layer (innermost)
def my_function():     ← Your code
```

### LangChain / LangGraph

```python
from langchain_core.tools import tool
from agent_airlock import Airlock

@tool
@Airlock()
def search(query: str) -> str:
    """Search for information."""
    return f"Results for: {query}"

# Use with LangGraph ToolNode
from langgraph.prebuilt import ToolNode
tool_node = ToolNode([search])
```

### OpenAI Agents SDK

```python
from agents import Agent, function_tool
from agent_airlock import Airlock, STRICT_POLICY

@function_tool
@Airlock(policy=STRICT_POLICY)
def get_weather(city: str) -> str:
    """Get weather for a city."""
    return f"Weather in {city}: 22°C, Sunny"

agent = Agent(
    name="weather_agent",
    tools=[get_weather],
    model="gpt-4o-mini",
)
```

### PydanticAI

```python
from pydantic_ai import Agent
from agent_airlock import Airlock

# Option 1: Pre-secure, then pass to Agent
@Airlock()
def get_stock_price(symbol: str) -> str:
    return f"Stock {symbol}: $150.25"

agent = Agent("openai:gpt-4o", tools=[get_stock_price])

# Option 2: With @agent.tool_plain
@agent.tool_plain
@Airlock()
def get_forecast(city: str) -> str:
    return f"Forecast for {city}: Sunny"
```

### LlamaIndex

```python
from llama_index.core.tools import FunctionTool
from llama_index.core.agent import ReActAgent
from agent_airlock import Airlock

@Airlock()
def calculate(expression: str) -> int:
    return eval(expression, {"__builtins__": {}})

# Wrap with FunctionTool
calc_tool = FunctionTool.from_defaults(fn=calculate)
agent = ReActAgent.from_tools([calc_tool], llm=llm)
```

### CrewAI

```python
from crewai import Agent, Task, Crew
from crewai.tools import tool
from agent_airlock import Airlock, READ_ONLY_POLICY

@tool
@Airlock(policy=READ_ONLY_POLICY)
def search_documents(query: str) -> str:
    """Search internal documents."""
    return f"Found 5 docs for: {query}"

researcher = Agent(
    role="Researcher",
    tools=[search_documents],
    llm="gpt-4o",
)
```

### AutoGen

```python
from autogen import ConversableAgent
from agent_airlock import Airlock

@Airlock()
def analyze_data(dataset: str, metric: str = "mean") -> str:
    return f"Analysis of {dataset}: {metric}=42.5"

assistant = ConversableAgent(
    name="analyst",
    llm_config={"model": "gpt-4o"},
)
assistant.register_for_llm()(analyze_data)
```

### Hugging Face smolagents

```python
from smolagents import CodeAgent, tool
from agent_airlock import Airlock

@tool
@Airlock(sandbox=True, sandbox_required=True)
def execute_code(code: str) -> str:
    """Execute Python in E2B sandbox."""
    exec(code)
    return "Executed"

agent = CodeAgent(tools=[execute_code], model=model)
```

### Anthropic Claude (Direct API)

```python
import anthropic
from agent_airlock import Airlock

client = anthropic.Anthropic()

@Airlock()
def get_weather(city: str) -> str:
    return f"Weather in {city}: 22°C"

# Register as tool definition
tools = [{
    "name": "get_weather",
    "description": get_weather.__doc__,
    "input_schema": {...}
}]

# Execute with Airlock protection
def handle_tool_call(name, inputs):
    if name == "get_weather":
        return get_weather(**inputs)  # Airlock validates
```

### Full Examples

See the [examples/](./examples/) directory for complete, runnable integrations:

| Framework | Example File | Features Demonstrated |
|-----------|--------------|----------------------|
| LangChain | `langchain_integration.py` | @tool, AgentExecutor, chains |
| LangGraph | `langgraph_integration.py` | StateGraph, ToolNode, multi-agent |
| OpenAI Agents | `openai_agents_sdk_integration.py` | Handoffs, manager pattern |
| PydanticAI | `pydanticai_integration.py` | Dependencies, structured output |
| LlamaIndex | `llamaindex_integration.py` | ReActAgent, QueryEngineTool |
| CrewAI | `crewai_integration.py` | Crews, tasks, role-based |
| AutoGen | `autogen_integration.py` | ConversableAgent, group chat |
| smolagents | `smolagents_integration.py` | CodeAgent, E2B sandbox |
| Anthropic | `anthropic_integration.py` | Direct API, streaming |

---

## 🏆 Why Not Just Use [Insert Enterprise Vendor]?

| | Prompt Security | Pangea | **Agent-Airlock** |
|---|---|---|---|
| **Pricing** | $50K+/year | Enterprise | **Free forever** |
| **Integration** | Proxy gateway | Proxy gateway | **One decorator** |
| **Self-Healing** | No | No | **Yes** |
| **E2B Sandboxing** | No | No | **Native** |
| **Your Data** | Through their servers | Through their servers | **Never leaves your infra** |
| **Source Code** | Closed | Closed | **MIT Licensed** |

We're not anti-enterprise. We're anti-gatekeeping.

Security for AI agents shouldn't require a procurement process.

---

## 📦 Install

```bash
# Core (validation + policies + sanitization)
pip install agent-airlock

# With E2B sandbox support
pip install agent-airlock[sandbox]

# With FastMCP integration
pip install agent-airlock[mcp]

# Everything
pip install agent-airlock[all]
```

Set your E2B key (if using sandbox):
```bash
export E2B_API_KEY="your-key-here"
```

---

## 🛡️ OWASP LLM Top 10 Compliance (2025)

Agent-Airlock directly mitigates the top security risks identified by OWASP:

| OWASP Risk | Mitigation |
|------------|------------|
| **[LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)** | Strict type validation prevents injected payloads from exploiting type coercion |
| **[LLM05: Improper Output Handling](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** | PII/secret masking sanitizes outputs before they reach the LLM |
| **[LLM06: Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** | Rate limiting + time restrictions + RBAC prevent runaway agent actions |
| **[LLM09: Misinformation](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** | Ghost argument rejection prevents hallucinated parameters from executing |

> Reference: [OWASP Top 10 for LLMs v2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)

---

## 📊 The Numbers

- **187 tests** passing
- **84% coverage**
- **9 framework integrations** — LangChain, LangGraph, OpenAI, PydanticAI, LlamaIndex, CrewAI, AutoGen, smolagents, Anthropic
- **<50ms** validation overhead
- **~125ms** sandbox cold start ([E2B Firecracker](https://e2b.dev/blog/firecracker-vs-qemu))
- **<200ms** sandbox execution (warm pool)
- **0** external dependencies for core functionality

---

## 📖 Documentation

- **[Examples](./examples/)** — 9 framework integrations with copy-paste code
- **[Compatibility Guide](./docs/COMPATIBILITY.md)** — Detailed patterns for all major frameworks
- **[Security Guide](./docs/SECURITY.md)** — Production deployment checklist
- **[API Reference](#api-reference)** — Every function, every parameter

### Quick Links

| I want to... | Go to |
|--------------|-------|
| Integrate with LangChain | [langchain_integration.py](./examples/langchain_integration.py) |
| Use with LangGraph | [langgraph_integration.py](./examples/langgraph_integration.py) |
| Secure OpenAI Agents SDK | [openai_agents_sdk_integration.py](./examples/openai_agents_sdk_integration.py) |
| Add to PydanticAI | [pydanticai_integration.py](./examples/pydanticai_integration.py) |
| Protect LlamaIndex tools | [llamaindex_integration.py](./examples/llamaindex_integration.py) |
| Secure CrewAI agents | [crewai_integration.py](./examples/crewai_integration.py) |
| Use with AutoGen | [autogen_integration.py](./examples/autogen_integration.py) |
| Integrate smolagents | [smolagents_integration.py](./examples/smolagents_integration.py) |
| Direct Anthropic API | [anthropic_integration.py](./examples/anthropic_integration.py) |
| Build MCP servers | [fastmcp_integration.py](./examples/fastmcp_integration.py) |

---

## 👤 Who Built This

[Sattyam Jain](https://github.com/sattyamjjain) — Building AI infrastructure at scale.

This started as an internal tool after watching an agent hallucinate its way through a production database. Now it's yours.

---

## 🤝 Contributing

We review every PR within 48 hours.

```bash
git clone https://github.com/sattyamjjain/agent-airlock
cd agent-airlock
pip install -e ".[dev]"
pytest tests/ -v
```

Found a bug? [Open an issue](https://github.com/sattyamjjain/agent-airlock/issues).
Have a feature idea? [Start a discussion](https://github.com/sattyamjjain/agent-airlock/discussions).

---

## 📄 License

MIT. Use it. Fork it. Ship it. No strings.

---

## ⭐ Star History

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=sattyamjjain/agent-airlock&type=Date)](https://star-history.com/#sattyamjjain/agent-airlock&Date)

</div>

---

## 💖 Support

If Agent-Airlock saved your production database from an LLM hallucination:

- ⭐ **Star this repo** — It helps others discover the project
- 🐛 **Report bugs** — [Open an issue](https://github.com/sattyamjjain/agent-airlock/issues)
- 💡 **Request features** — [Start a discussion](https://github.com/sattyamjjain/agent-airlock/discussions)
- 🔀 **Contribute** — PRs reviewed within 48 hours
- 📣 **Spread the word** — Tweet about it, write a blog post

---

<div align="center">

**Built with 🛡️ by [Sattyam Jain](https://github.com/sattyamjjain)**

<sub>Making AI agents safe, one decorator at a time.</sub>

[![GitHub](https://img.shields.io/badge/GitHub-sattyamjjain-181717?style=flat-square&logo=github)](https://github.com/sattyamjjain)
[![Twitter](https://img.shields.io/badge/Twitter-@sattyamjjain-1DA1F2?style=flat-square&logo=twitter&logoColor=white)](https://twitter.com/sattyamjjain)

</div>
