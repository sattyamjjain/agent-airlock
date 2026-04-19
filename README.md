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
<tr>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/network-card.png" alt="network"/>
<br/><b>Network Guard</b>
<br/><sub>Block data exfiltration</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/folder-invoices.png" alt="folder"/>
<br/><b>Path Validation</b>
<br/><sub>CVE-resistant traversal</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/restart.png" alt="circuit"/>
<br/><b>Circuit Breaker</b>
<br/><sub>Fault tolerance</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/analytics.png" alt="otel"/>
<br/><b>OpenTelemetry</b>
<br/><sub>Enterprise observability</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/money-bag.png" alt="cost"/>
<br/><b>Cost Tracking</b>
<br/><sub>Budget limits</sub>
</td>
<td align="center" width="16%">
<img width="40" src="https://img.icons8.com/fluency/48/syringe.png" alt="vaccine"/>
<br/><b>Vaccination</b>
<br/><sub>Auto-secure frameworks</sub>
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
  - [Network Airgap](#-network-airgap-v030)
  - [Framework Vaccination](#-framework-vaccination-v030)
  - [Circuit Breaker](#-circuit-breaker-v040)
  - [OpenTelemetry](#-opentelemetry-observability-v040)
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

> **Running an MCP server with STDIO transport?** Also wire the
> [Ox MCP STDIO sanitizer](#️-owasp-compliance) via
> `stdio_guard_ox_defaults()` — it blocks the entire
> CVE-2026-30616 class (shell metacharacter injection,
> non-allowlisted binaries, Trojan-Source RTL overrides, and
> inline-code flags) before `subprocess.Popen`.

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

### 🌐 Network Airgap (V0.3.0)

Block data exfiltration during tool execution:

```python
from agent_airlock import network_airgap, NO_NETWORK_POLICY

# Block ALL network access
with network_airgap(NO_NETWORK_POLICY):
    result = untrusted_tool()  # Any socket call → NetworkBlockedError

# Or allow specific hosts only
from agent_airlock import NetworkPolicy

INTERNAL_ONLY = NetworkPolicy(
    allow_egress=True,
    allowed_hosts=["api.internal.com", "*.company.local"],
    allowed_ports=[443],
)
```

---

### 💉 Framework Vaccination (V0.3.0)

Secure existing code **without changing a single line**:

```python
from agent_airlock import vaccinate, STRICT_POLICY

# Before: Your existing LangChain tools are unprotected
vaccinate("langchain", policy=STRICT_POLICY)

# After: ALL @tool decorators now include Airlock security
# No code changes required!
```

**Supported:** LangChain, OpenAI Agents SDK, PydanticAI, CrewAI

---

### ⚡ Circuit Breaker (V0.4.0)

Prevent cascading failures with fault tolerance:

```python
from agent_airlock import CircuitBreaker, AGGRESSIVE_BREAKER

breaker = CircuitBreaker("external_api", config=AGGRESSIVE_BREAKER)

@breaker
def call_external_api(query: str) -> dict:
    return external_service.query(query)

# After 5 failures → circuit OPENS → fast-fails for 30s
# Then HALF_OPEN → allows 1 test request → recovers or reopens
```

---

### 📈 OpenTelemetry Observability (V0.4.0)

Enterprise-grade monitoring:

```python
from agent_airlock import configure_observability, observe

configure_observability(
    service_name="my-agent",
    otlp_endpoint="http://otel-collector:4317",
)

@observe(name="critical_operation")
def process_data(data: dict) -> dict:
    # Automatic span creation, metrics, and audit logging
    return transform(data)
```

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
| Claude Agent SDK | [`anthropic_integration.py`](./examples/anthropic_integration.py) (Example 7) | Agent SDK tools as in-process MCP servers |

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

Agent-Airlock maps to the [**OWASP Top 10 for Agentic Applications (2026)**](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
— the agentic-era successor to the old LLM Top 10. Coverage is
reported honestly: **Full** means the primitive ships and blocks the
class in tests; **Partial** means agent-airlock covers the runtime
leg but something upstream (client UI, IAM, training data) is out of
scope; **Monitor-only** means we surface the signal but do not
actually prevent the risk.

| Risk | Implemented in agent-airlock | Module / preset | Coverage |
|------|------------------------------|-----------------|----------|
| **ASI01 Agent Goal Hijack** | Pydantic strict validation + ghost-arg rejection + `UnknownArgsMode.BLOCK` | `validator`, `unknown_args`, `core` | Partial |
| **ASI02 Tool Misuse and Exploitation** | Deny-by-default `SecurityPolicy`, RBAC, rate limits, `SafePath` / `SafeURL` | `policy`, `safe_types`, `filesystem`, `network` | **Full** |
| **ASI03 Identity and Privilege Abuse** | `AgentIdentity`, `MCPProxyGuard` token-passthrough prevention, `CredentialScope` | `policy`, `mcp_proxy_guard` | Partial |
| **ASI04 Agentic Supply Chain Vulnerabilities** | Ox MCP STDIO sanitizer + CVE regression suite (8 CVEs tracked) | `mcp_spec.stdio_guard`, `policy_presets.stdio_guard_ox_defaults`, `tests/cves/` | Partial |
| **ASI05 Unexpected Code Execution (RCE)** | E2B Firecracker sandbox, pluggable `SandboxBackend`, capability gating for `PROCESS_SHELL` | `sandbox`, `sandbox_backend`, `capabilities` | **Full** |
| **ASI06 Memory & Context Poisoning** | `AirlockContext` `contextvars` isolation, `ConversationConstraints` budget caps, audit logging | `context`, `conversation`, `sanitizer` | Partial |
| **ASI07 Insecure Inter-Agent Communication** | A2A middleware Pydantic strict validation, method allow-lists | `a2a` | Partial |
| **ASI08 Cascading Failures** | `CircuitBreaker`, `RetryPolicy`, token-bucket rate limits | `circuit_breaker`, `retry`, `policy` | **Full** |
| **ASI09 Human-Agent Trust Exploitation** | Honeypot deception, audit-log attribution, structured `fix_hints` | `honeypot`, `audit_otel` | Partial |
| **ASI10 Rogue Agents** | Audit telemetry + anomaly detector; no quarantine primitive | `observability`, `anomaly` | Monitor-only |

### MCP-specific mapping

The [OWASP MCP Top 10 (2026 beta)](https://owasp.org/www-project-mcp-top-10/)
is covered end-to-end by the `OWASP_MCP_TOP_10_2026` policy preset:

| MCP risk | Ships in agent-airlock |
|----------|------------------------|
| **MCP01 Token Mismanagement** | `MCPProxyGuard` rejects passthrough headers, enforces audience |
| **MCP02 Excessive Permissions** | `SecurityPolicy` + `CredentialScope` |
| **MCP03 Tool Poisoning** | ghost-arg rejection + `SafePath`/`SafeURL` |
| **MCP04 Supply Chain** | `stdio_guard_ox_defaults()` (Ox 2026-04-16 advisory) |
| **MCP05 Command Injection** | `stdio_guard` shell-metachar + deny-pattern rules |
| **MCP07 Insufficient Authentication** | OAuth 2.1 + PKCE S256 helpers in `mcp_spec.oauth` |
| **MCP10 Context Oversharing** | PII/secret sanitizer + workspace-scoped config |

Use it directly:

```python
from agent_airlock import Airlock
from agent_airlock.policy_presets import owasp_mcp_top_10_2026_policy

@Airlock(policy=owasp_mcp_top_10_2026_policy())
def my_mcp_tool(...):
    ...
```

> **Ox Security STDIO advisory** (2026-04-16, CVE-2026-30616): see
> [`docs/cves/index.md#cve-2026-30616`](docs/cves/index.md#cve-2026-30616)
> and the `stdio_guard_ox_defaults()` preset above. agent-airlock
> blocks 3 of 4 Ox attack classes at the runtime seam.

---

## 🏢 Used By

Agent-Airlock secures AI agent systems in production:

| Project | Use Case |
|---------|----------|
| [**FerrumDeck**](https://github.com/sattyamjjain/FerrumDeck) | AgentOps control plane — deny-by-default tool execution |
| [**Mnemo**](https://github.com/sattyamjjain/Mnemo) | MCP-native memory database — secure tool call validation |

> Using Agent-Airlock in production? [Open a PR](https://github.com/sattyamjjain/agent-airlock/edit/main/README.md) to add your project!

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| **Tests** | 1,157 passing |
| **Coverage** | 79%+ (enforced in CI) |
| **Lines of Code** | ~25,900 |
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
