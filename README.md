# Agent-Airlock

### Your AI Agent Just Tried to `rm -rf /`. We Stopped It.

[![CI](https://github.com/sattyamjjain/agent-airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/sattyamjjain/agent-airlock/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/sattyamjjain/agent-airlock/branch/main/graph/badge.svg)](https://codecov.io/gh/sattyamjjain/agent-airlock)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

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

---

## The Reality No One Talks About

In January 2026, MCP has 16,000+ servers on GitHub. OpenAI adopted it. The Linux Foundation hosts it.

But here's what the hype cycle ignores:

**LLMs hallucinate tool calls.** Every. Single. Day.

- Claude invents arguments that don't exist in your function signature
- GPT-4 sends `"100"` when your code expects `100`
- Agents chain 47 tool calls before you notice one deleted production data

The enterprise vendors saw this coming. Prompt Security charges $50K/year. Pangea wants your data flowing through their proxy. Cisco is "coming soon."

**We built the alternative.**

---

## What This Actually Does

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

## When You Need the Big Guns

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

## The Policies You'll Actually Use

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

## The Cost Problem (And How We Solve It)

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

**Result:** Agents that cost 70% less to run. Not a marketing number—it's what happens when you stop feeding 10MB responses to a tokenizer.

---

## The Security You Forgot You Needed

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

## FastMCP Integration (The Clean Way)

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

## Why Not Just Use [Insert Enterprise Vendor]?

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

## Install

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

## The Numbers

- **182 tests** passing
- **84% coverage**
- **<50ms** validation overhead
- **<200ms** sandbox execution (warm pool)
- **0** external dependencies for core functionality

---

## Documentation

- **[Examples](./examples/)** — Copy-paste patterns for common use cases
- **[Security Guide](./docs/SECURITY.md)** — Production deployment checklist
- **[API Reference](#api-reference)** — Every function, every parameter

---

## Who Built This

[Sattyam Jain](https://github.com/sattyamjjain) — Building AI infrastructure at scale.

This started as an internal tool after watching an agent hallucinate its way through a production database. Now it's yours.

---

## Contributing

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

## License

MIT. Use it. Fork it. Ship it. No strings.

---

<p align="center">
  <strong>If this saved your production database from an LLM hallucination, consider a ⭐</strong>
  <br><br>
  <a href="https://github.com/sattyamjjain/agent-airlock">github.com/sattyamjjain/agent-airlock</a>
</p>
