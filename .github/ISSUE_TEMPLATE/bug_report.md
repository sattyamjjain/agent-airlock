---
name: Bug Report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

## Describe the Bug
A clear and concise description of what the bug is.

## To Reproduce
Steps to reproduce the behavior:

```python
from agent_airlock import Airlock

@Airlock()
def my_tool(x: int) -> int:
    return x

# Describe what you did
result = my_tool(...)
```

## Expected Behavior
A clear and concise description of what you expected to happen.

## Actual Behavior
What actually happened instead.

## Environment
- **Python version**: [e.g., 3.11.0]
- **agent-airlock version**: [e.g., 0.1.0]
- **OS**: [e.g., Ubuntu 22.04, macOS 14.0, Windows 11]
- **Installation method**: [pip, uv, poetry]

## Additional Context
- Are you using E2B sandboxing? Yes/No
- Are you using FastMCP integration? Yes/No
- Any relevant configuration:

```python
config = AirlockConfig(
    strict_mode=True,
    # ...
)
```

## Logs
If applicable, add relevant log output (with sensitive data redacted).

```
[paste logs here]
```
