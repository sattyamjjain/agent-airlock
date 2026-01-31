<div align="center">

<!-- Animated Typing Header -->
<a href="https://github.com/sattyamjjain/agent-airlock">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=28&duration=3000&pause=1000&color=00D4FF&center=true&vCenter=true&multiline=true&repeat=true&width=700&height=100&lines=%F0%9F%9B%A1%EF%B8%8F+Agent-Airlock;Your+AI+Agent+Just+Tried+rm+-rf+%2F.+We+Stopped+It." alt="Agent-Airlock Typing Animation" />
</a>

### The Open-Source Firewall for AI Agents

**One decorator. Zero trust. Full control.**

<!-- Primary Badges Row -->
[![PyPI version](https://img.shields.io/pypi/v/agent-airlock?style=for-the-badge&logo=pypi&logoColor=white&color=3775A9)](https://pypi.org/project/agent-airlock/)
[![Downloads](https://img.shields.io/pypi/dm/agent-airlock?style=for-the-badge&logo=python&logoColor=white&color=success)](https://pypistats.org/packages/agent-airlock)
[![CI](https://img.shields.io/github/actions/workflow/status/sattyamjjain/agent-airlock/ci.yml?style=for-the-badge&logo=github&label=CI&color=success)](https://github.com/sattyamjjain/agent-airlock/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/github/sattyamjjain/agent-airlock?style=for-the-badge&logo=codecov&logoColor=white)](https://codecov.io/gh/sattyamjjain/agent-airlock)

<!-- Secondary Badges Row -->
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/sattyamjjain/agent-airlock?style=flat-square&logo=github)](https://github.com/sattyamjjain/agent-airlock/stargazers)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

<br/>

[**Get Started in 30 Seconds**](#-30-second-quickstart) · [**Why Airlock?**](#-the-problem-no-one-talks-about) · [**All Frameworks**](#-framework-compatibility) · [**Docs**](#-documentation)

<br/>

</div>

---

<!-- Hero Visual Block -->
<div align="center">

```
┌────────────────────────────────────────────────────────────────┐
│  🤖 AI Agent: "Let me help clean up disk space..."            │
│                           ↓                                    │
│               rm -rf / --no-preserve-root                      │
│                           ↓                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  🛡️ AIRLOCK: BLOCKED                                     │  │
│  │                                                          │  │
│  │  Reason: Matches denied pattern 'rm_*'                   │  │
│  │  Policy: STRICT_POLICY                                   │  │
│  │  Fix: Use approved cleanup tools only                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

</div>

---

## 🎯 30-Second Quickstart

```bash
pip install agent-airlock
```

```python
from agent_airlock import Airlock

@Airlock()
def transfer_funds(account: str, amount: int) -> dict:
    return {"status": "transferred", "amount": amount}

# LLM sends amount="500" (string) → BLOCKED with fix_hint
# LLM sends force=True (invented arg) → STRIPPED silently
# LLM sends amount=500 (correct) → EXECUTED safely
```

**That's it.** Your function now has ghost argument stripping, strict type validation, and self-healing errors.

---

## 🧠 The Problem No One Talks About

<table>
<tr>
<td width="50%">

### The Hype

> *"MCP has 16,000+ servers on GitHub!"*
> *"OpenAI adopted it!"*
> *"Linux Foundation hosts it!"*

</td>
<td width="50%">

### The Reality

**LLMs hallucinate tool calls. Every. Single. Day.**

- Claude invents arguments that don't exist
- GPT-4 sends `"100"` when you need `100`
- Agents chain 47 calls before one deletes prod data

</td>
</tr>
</table>

**Enterprise solutions exist:** Prompt Security ($50K/year), Pangea (proxy your data), Cisco ("coming soon").

**We built the open-source alternative.** One decorator. No vendor lock-in. Your data never leaves your infrastructure.

---

## ✨ What You Get

<table>
<tr>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/delete-shield.png" alt="shield"/>
<br/><b>Ghost Args</b>
<br/><sub>Strip LLM-invented params</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/checked.png" alt="check"/>
<br/><b>Strict Types</b>
<br/><sub>No silent coercion</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/refresh.png" alt="refresh"/>
<br/><b>Self-Healing</b>
<br/><sub>LLM-friendly errors</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/lock.png" alt="lock"/>
<br/><b>E2B Sandbox</b>
<br/><sub>Isolated execution</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/user-shield.png" alt="user"/>
<br/><b>RBAC</b>
<br/><sub>Role-based access</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/privacy.png" alt="privacy"/>
<br/><b>PII Mask</b>
<br/><sub>Auto-redact secrets</sub>
</td>
</tr>
</table>

---

## 📋 Table of Contents

<details>
<summary><b>Click to expand full navigation</b></summary>

- [30-Second Quickstart](#-30-second-quickstart)
- [The Problem](#-the-problem-no-one-talks-about)
- [What You Get](#-what-you-get)
- [Core Features](#-core-features)
  - [E2B Sandbox](#-e2b-sandbox-execution)
  - [Security Policies](#-security-policies)
  - [Cost Control](#-cost-control)
  - [PII Masking](#-pii--secret-masking)
- [Framework Compatibility](#-framework-compatibility)
- [FastMCP Integration](#-fastmcp-integration)
- [Comparison](#-why-not-enterprise-vendors)
- [Installation](#-installation)
- [OWASP Compliance](#️-owasp-compliance)
- [Performance](#-performance)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [Support](#-support)

</details>

---

## 🔥 Core Features

### 🔒 E2B Sandbox Execution

```python
from agent_airlock import Airlock, STRICT_POLICY

@Airlock(sandbox=True, sandbox_required=True, policy=STRICT_POLICY)
def execute_code(code: str) -> str:
    """Runs in an E2B Firecracker MicroVM. Not on your machine."""
    exec(code)
    return "executed"
```

| Feature | Value |
|---------|-------|
| Boot time | ~125ms cold, <200ms warm |
| Isolation | Firecracker MicroVM |
| Fallback | `sandbox_required=True` blocks local execution |

---

### 📜 Security Policies

```python
from agent_airlock import (
    PERMISSIVE_POLICY,      # Dev - no restrictions
    STRICT_POLICY,          # Prod - rate limited, agent ID required
    READ_ONLY_POLICY,       # Analytics - query only
    BUSINESS_HOURS_POLICY,  # Dangerous ops 9-5 only
)

# Or build your own:
from agent_airlock import SecurityPolicy

MY_POLICY = SecurityPolicy(
    allowed_tools=["read_*", "query_*"],
    denied_tools=["delete_*", "drop_*", "rm_*"],
    rate_limits={"*": "1000/hour", "write_*": "100/hour"},
    time_restrictions={"deploy_*": "09:00-17:00"},
)
```

---

### 💰 Cost Control

A runaway agent can burn $500 in API costs before you notice.

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    max_output_chars=5000,    # Truncate before token explosion
    max_output_tokens=2000,   # Hard limit on response size
)

@Airlock(config=config)
def query_logs(query: str) -> str:
    return massive_log_query(query)  # 10MB → 5KB
```

**ROI:** 10MB logs = ~2.5M tokens = $25/response. Truncated = ~1.25K tokens = $0.01. **99.96% savings.**

---

### 🔐 PII & Secret Masking

```python
config = AirlockConfig(
    mask_pii=True,      # SSN, credit cards, phones, emails
    mask_secrets=True,  # API keys, passwords, JWTs
)

@Airlock(config=config)
def get_user(user_id: str) -> dict:
    return db.users.find_one({"id": user_id})

# LLM sees: {"name": "John", "ssn": "[REDACTED]", "api_key": "sk-...XXXX"}
```

**12 PII types detected** · **4 masking strategies** · **Zero data leakage**

---

## 🔌 Framework Compatibility

> **The Golden Rule:** `@Airlock` must be closest to the function definition.

```python
@framework_decorator    # ← Framework sees secured function
@Airlock()             # ← Security layer (innermost)
def my_function():     # ← Your code
```

<table>
<tr>
<td>

### LangChain / LangGraph

```python
from langchain_core.tools import tool
from agent_airlock import Airlock

@tool
@Airlock()
def search(query: str) -> str:
    """Search for information."""
    return f"Results for: {query}"
```

</td>
<td>

### OpenAI Agents SDK

```python
from agents import function_tool
from agent_airlock import Airlock

@function_tool
@Airlock()
def get_weather(city: str) -> str:
    """Get weather for a city."""
    return f"Weather in {city}: 22°C"
```

</td>
</tr>
<tr>
<td>

### PydanticAI

```python
from pydantic_ai import Agent
from agent_airlock import Airlock

@Airlock()
def get_stock(symbol: str) -> str:
    return f"Stock {symbol}: $150"

agent = Agent("openai:gpt-4o", tools=[get_stock])
```

</td>
<td>

### CrewAI

```python
from crewai.tools import tool
from agent_airlock import Airlock

@tool
@Airlock()
def search_docs(query: str) -> str:
    """Search internal docs."""
    return f"Found 5 docs for: {query}"
```

</td>
</tr>
</table>

<details>
<summary><b>More frameworks: LlamaIndex, AutoGen, smolagents, Anthropic</b></summary>

### LlamaIndex

```python
from llama_index.core.tools import FunctionTool
from agent_airlock import Airlock

@Airlock()
def calculate(expression: str) -> int:
    return eval(expression, {"__builtins__": {}})

calc_tool = FunctionTool.from_defaults(fn=calculate)
```

### AutoGen

```python
from autogen import ConversableAgent
from agent_airlock import Airlock

@Airlock()
def analyze_data(dataset: str) -> str:
    return f"Analysis of {dataset}: mean=42.5"

assistant = ConversableAgent(name="analyst", llm_config={"model": "gpt-4o"})
assistant.register_for_llm()(analyze_data)
```

### smolagents

```python
from smolagents import tool
from agent_airlock import Airlock

@tool
@Airlock(sandbox=True)
def run_code(code: str) -> str:
    """Execute in E2B sandbox."""
    exec(code)
    return "Executed"
```

### Anthropic (Direct API)

```python
from agent_airlock import Airlock

@Airlock()
def get_weather(city: str) -> str:
    return f"Weather in {city}: 22°C"

# Use in tool handler
def handle_tool_call(name, inputs):
    if name == "get_weather":
        return get_weather(**inputs)  # Airlock validates
```

</details>

### Complete Examples

| Framework | Example | Key Features |
|-----------|---------|--------------|
| LangChain | [`langchain_integration.py`](./examples/langchain_integration.py) | @tool, AgentExecutor |
| LangGraph | [`langgraph_integration.py`](./examples/langgraph_integration.py) | StateGraph, ToolNode |
| OpenAI Agents | [`openai_agents_sdk_integration.py`](./examples/openai_agents_sdk_integration.py) | Handoffs, manager pattern |
| PydanticAI | [`pydanticai_integration.py`](./examples/pydanticai_integration.py) | Dependencies, structured output |
| LlamaIndex | [`llamaindex_integration.py`](./examples/llamaindex_integration.py) | ReActAgent |
| CrewAI | [`crewai_integration.py`](./examples/crewai_integration.py) | Crews, roles |
| AutoGen | [`autogen_integration.py`](./examples/autogen_integration.py) | ConversableAgent |
| smolagents | [`smolagents_integration.py`](./examples/smolagents_integration.py) | CodeAgent, E2B |
| Anthropic | [`anthropic_integration.py`](./examples/anthropic_integration.py) | Direct API |

---

## ⚡ FastMCP Integration

```python
from fastmcp import FastMCP
from agent_airlock.mcp import secure_tool, STRICT_POLICY

mcp = FastMCP("production-server")

@secure_tool(mcp, policy=STRICT_POLICY)
def delete_user(user_id: str) -> dict:
    """One decorator: MCP registration + Airlock protection."""
    return db.users.delete(user_id)
```

---

## 🏆 Why Not Enterprise Vendors?

| | Prompt Security | Pangea | **Agent-Airlock** |
|---|:---:|:---:|:---:|
| **Pricing** | $50K+/year | Enterprise | **Free forever** |
| **Integration** | Proxy gateway | Proxy gateway | **One decorator** |
| **Self-Healing** | ❌ | ❌ | **✅** |
| **E2B Sandboxing** | ❌ | ❌ | **✅ Native** |
| **Your Data** | Their servers | Their servers | **Never leaves you** |
| **Source Code** | Closed | Closed | **MIT Licensed** |

> We're not anti-enterprise. We're anti-gatekeeping.
> **Security for AI agents shouldn't require a procurement process.**

---

## 📦 Installation

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

```bash
# E2B key for sandbox execution
export E2B_API_KEY="your-key-here"
```

---

## 🛡️ OWASP Compliance

Agent-Airlock mitigates the [OWASP Top 10 for LLMs (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| OWASP Risk | Mitigation |
|------------|------------|
| **LLM01: Prompt Injection** | Strict type validation blocks injected payloads |
| **LLM05: Improper Output Handling** | PII/secret masking sanitizes outputs |
| **LLM06: Excessive Agency** | Rate limits + RBAC prevent runaway agents |
| **LLM09: Misinformation** | Ghost argument rejection blocks hallucinated params |

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| **Tests** | 629 passing |
| **Coverage** | 86% (80% enforced in CI) |
| **Validation overhead** | <50ms |
| **Sandbox cold start** | ~125ms |
| **Sandbox warm pool** | <200ms |
| **Framework integrations** | 9 |
| **Core dependencies** | 0 (Pydantic only) |

---

## 📖 Documentation

| Resource | Description |
|----------|-------------|
| [**Examples**](./examples/) | 9 framework integrations with copy-paste code |
| [**Security Guide**](./docs/SECURITY.md) | Production deployment checklist |
| [**API Reference**](./docs/API.md) | Every function, every parameter |

---

## 👤 About

Built by [**Sattyam Jain**](https://github.com/sattyamjjain) — AI infrastructure engineer.

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

- **Bug?** [Open an issue](https://github.com/sattyamjjain/agent-airlock/issues)
- **Feature idea?** [Start a discussion](https://github.com/sattyamjjain/agent-airlock/discussions)
- **Want to contribute?** [See open issues](https://github.com/sattyamjjain/agent-airlock/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)

---

## 💖 Support

If Agent-Airlock saved your production database:

- ⭐ **Star this repo** — Helps others discover it
- 🐛 **Report bugs** — [Open an issue](https://github.com/sattyamjjain/agent-airlock/issues)
- 📣 **Spread the word** — Tweet, blog, share

---

## ⭐ Star History

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=sattyamjjain/agent-airlock&type=Date)](https://star-history.com/#sattyamjjain/agent-airlock&Date)

</div>

---

<div align="center">

**Built with 🛡️ by [Sattyam Jain](https://github.com/sattyamjjain)**

<sub>Making AI agents safe, one decorator at a time.</sub>

[![GitHub](https://img.shields.io/badge/GitHub-sattyamjjain-181717?style=flat-square&logo=github)](https://github.com/sattyamjjain)
[![Twitter](https://img.shields.io/badge/Twitter-@sattyamjjain-1DA1F2?style=flat-square&logo=twitter&logoColor=white)](https://twitter.com/sattyamjjain)

</div>

---

<div align="center">
<sub>

**Sources:** This README follows best practices from [awesome-readme](https://github.com/matiassingers/awesome-readme), [Best-README-Template](https://github.com/othneildrew/Best-README-Template), and the [GitHub Blog](https://github.blog/open-source/maintainers/marketing-for-maintainers-how-to-promote-your-project-to-both-users-and-contributors/).

</sub>
</div>
