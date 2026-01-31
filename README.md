# Agent-Airlock

**The Pydantic-based Firewall for MCP Servers. Stops 99% of Hallucinated Tool Calls.**

[![PyPI version](https://badge.fury.io/py/agent-airlock.svg)](https://badge.fury.io/py/agent-airlock)
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
from agent_airlock import Airlock, SecurityPolicy

mcp = FastMCP("secure-server")

@mcp.tool
@Airlock(policy=SecurityPolicy.STRICT)
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

| Feature | LangChain | AutoGen | Agent-Airlock |
|---------|-----------|---------|---------------|
| Schema Validation | Manual | Manual | **Automatic** |
| Self-Healing | No | No | **Yes** |
| Sandbox Execution | No | No | **E2B Native** |
| Open Source | Yes | Yes | **Yes** |
| MCP Native | No | No | **Yes** |

## Documentation

- [Full Documentation](https://github.com/sattyamjain/agent-airlock)
- [Examples](./examples)
- [Security Best Practices](./docs/SECURITY.md)

## License

MIT License - see [LICENSE](./LICENSE)
