# Installation

## Requirements

- Python 3.10 or higher
- pip, uv, or poetry

## Basic Installation

Install the core package:

=== "pip"
    ```bash
    pip install agent-airlock
    ```

=== "uv"
    ```bash
    uv add agent-airlock
    ```

=== "poetry"
    ```bash
    poetry add agent-airlock
    ```

## Optional Dependencies

Agent-Airlock supports optional features through extras:

### E2B Sandbox Support

For executing code in isolated Firecracker MicroVMs:

```bash
pip install agent-airlock[sandbox]
```

This installs:
- `e2b>=1.0` - E2B SDK
- `cloudpickle>=3.0` - Function serialization

!!! note "E2B API Key Required"
    You'll need an E2B API key. Set it via environment variable:
    ```bash
    export E2B_API_KEY="your-key-here"
    ```

### FastMCP Integration

For seamless integration with FastMCP servers:

```bash
pip install agent-airlock[mcp]
```

This installs:
- `mcp>=1.0` - MCP SDK
- `fastmcp>=2.0,<3.0` - FastMCP framework

### Full Installation

Install everything:

```bash
pip install agent-airlock[all]
```

### Development Installation

For contributing to Agent-Airlock:

```bash
git clone https://github.com/attri-ai/agent-airlock.git
cd agent-airlock
pip install -e ".[dev,all]"
```

This includes:
- pytest and coverage tools
- mypy for type checking
- ruff for linting/formatting
- bandit for security scanning

## Verify Installation

```python
import agent_airlock
print(agent_airlock.__version__)
```

Or test the decorator:

```python
from agent_airlock import Airlock

@Airlock()
def test_func(x: int) -> int:
    return x * 2

result = test_func(x=5)
print(result)  # 10
```

## Troubleshooting

### Import Errors

If you get import errors, ensure you have the correct Python version:

```bash
python --version  # Should be 3.10+
```

### E2B Connection Issues

If E2B sandbox fails to connect:

1. Verify your API key is set correctly
2. Check your network connection
3. Ensure you have the `[sandbox]` extra installed

### Type Checking Errors

Agent-Airlock uses strict typing. If mypy complains:

```bash
pip install types-all  # Install type stubs
mypy your_code.py --ignore-missing-imports
```
