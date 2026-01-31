# Agent-Airlock 🛡️

**The Pydantic-based Firewall for MCP Servers. Stops Hallucinated Tool Calls Before They Wreck Your System.**

[![PyPI version](https://badge.fury.io/py/agent-airlock.svg)](https://badge.fury.io/py/agent-airlock)
[![CI](https://github.com/sattyamjain/agent-airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/sattyamjain/agent-airlock/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/sattyamjain/agent-airlock/branch/main/graph/badge.svg)](https://codecov.io/gh/sattyamjain/agent-airlock)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## The Problem

In 2026, AI agents are executing real-world actions through MCP (Model Context Protocol) servers. But LLMs hallucinate. They send:
- Wrong argument types (`"100"` instead of `100`)
- Arguments that don't exist in the function signature
- Dangerous commands without authorization

**One bad tool call can delete your database, drain your budget, or expose sensitive data.**

## The Solution

Agent-Airlock is a security middleware that sits between your MCP server and dangerous tool execution:

```python
from agent_airlock import Airlock
from pydantic import BaseModel, Field

class DeployArgs(BaseModel):
    service_name: str = Field(..., pattern=r"^[a-z0-9-]+$")
    replicas: int = Field(..., gt=0, lt=10)

@Airlock(sandbox=True)
def deploy_service(args: DeployArgs) -> dict:
    """Deploy a microservice - runs in isolated E2B sandbox."""
    return {"status": "deployed", "service": args.service_name}

# Agent tries: deploy_service(service_name="prod; DROP TABLE", replicas=1000)
# Airlock returns: {"error": "BLOCKED", "fix_hint": "replicas must be < 10"}
```

## Features

- **Ghost Argument Stripper**: Removes hallucinated arguments that don't exist in the function signature
- **Strict Schema Validation**: Pydantic V2 with `strict=True` - no type coercion allowed
- **Self-Healing Errors**: Returns structured fix hints to the LLM instead of crashing
- **E2B Sandbox Execution**: Dangerous operations run in isolated Firecracker MicroVMs
- **Policy Engine**: RBAC for AI agents with time restrictions and rate limits
- **Output Sanitization**: Masks PII, API keys, and truncates large outputs

## Installation

```bash
# Core (validation + self-healing)
pip install agent-airlock

# With E2B sandbox support
pip install agent-airlock[sandbox]

# With MCP/FastMCP integration
pip install agent-airlock[mcp]

# Everything
pip install agent-airlock[all]
```

## Quick Start

### Basic Validation

```python
from agent_airlock import Airlock

@Airlock()
def read_file(filename: str, encoding: str = "utf-8") -> str:
    with open(filename, encoding=encoding) as f:
        return f.read()

# LLM sends: read_file(filename="data.txt", force=True)
# Airlock: Strips 'force' (ghost argument), executes successfully

# LLM sends: read_file(filename=123)
# Airlock: Returns {"error": "...", "fix_hint": "filename must be a string"}
```

### Sandbox Execution

```python
from agent_airlock import Airlock

@Airlock(sandbox=True)
def run_code(code: str) -> str:
    """Execute code in isolated E2B MicroVM."""
    exec(code)  # Safe - runs in sandbox, not on your machine
    return "executed"
```

### With FastMCP

```python
from fastmcp import FastMCP
from agent_airlock import Airlock, STRICT_POLICY

mcp = FastMCP("secure-server")

@mcp.tool
@Airlock(policy=STRICT_POLICY)
def delete_records(table: str, where: str) -> dict:
    # Validated, policy-checked, and logged
    ...
```

## Configuration

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    strict_mode=True,           # Reject unknown arguments (vs strip)
    max_output_tokens=5000,     # Truncate large outputs
    mask_pii=True,              # Auto-mask SSN, credit cards, etc.
    e2b_api_key="...",          # Or use E2B_API_KEY env var
)

@Airlock(config=config)
def my_tool(...):
    ...
```

## Why Agent-Airlock?

| Feature | LangChain | AutoGen | Prompt Security | **Agent-Airlock** |
|---------|-----------|---------|-----------------|-------------------|
| Schema Validation | Manual | Manual | Enterprise | **Automatic** |
| Self-Healing Errors | No | No | No | **Yes** |
| Sandbox Execution | No | No | No | **E2B Native** |
| MCP Native | No | No | Gateway | **Decorator** |
| Pricing | Open Source | Open Source | Enterprise $$ | **Open Source** |

## Predefined Policies

```python
from agent_airlock import (
    PERMISSIVE_POLICY,      # No restrictions
    STRICT_POLICY,          # Requires agent ID
    READ_ONLY_POLICY,       # Blocks write/delete operations
    BUSINESS_HOURS_POLICY,  # 9 AM - 5 PM only
)

# Custom policy
from agent_airlock import SecurityPolicy

PRODUCTION_POLICY = SecurityPolicy(
    allowed_tools=["read_*", "query_*"],
    denied_tools=["delete_*", "drop_*"],
    rate_limits={"*": "100/minute"},
    time_restrictions={"write_*": "09:00-17:00"},
)
```

## Output Sanitization

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    mask_pii=True,          # Masks SSN, credit cards, emails
    mask_secrets=True,      # Masks API keys, passwords
    max_output_chars=5000,  # Prevents token explosion
)

@Airlock(config=config)
def query_users(name: str) -> dict:
    # Output automatically sanitized:
    # {"ssn": "123-45-6789"} → {"ssn": "***-**-6789"}
    # {"api_key": "sk-live-xxx"} → {"api_key": "***REDACTED***"}
    return db.find_user(name)
```

## Documentation

- [Examples](./examples) - Usage patterns and integrations
- [Security Best Practices](./docs/SECURITY.md) - Production deployment guide
- [API Reference](https://github.com/sattyamjain/agent-airlock#api-reference)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`pytest tests/ -v`)
4. Run linting (`ruff check src/ tests/`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

MIT License - see [LICENSE](./LICENSE)

---

**Built with ❤️ for the AI agent security community.**

*If Agent-Airlock saved your production database from an LLM hallucination, consider giving us a ⭐!*
