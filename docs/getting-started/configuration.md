# Configuration

Agent-Airlock provides flexible configuration through multiple sources.

## Configuration Priority

Configuration values are loaded in this order (highest priority first):

1. **Environment variables** (`AIRLOCK_*`)
2. **Constructor arguments** (`AirlockConfig(...)`)
3. **Configuration file** (`airlock.toml`)
4. **Default values**

## AirlockConfig Options

```python
from agent_airlock import AirlockConfig

config = AirlockConfig(
    # Validation
    strict_mode=False,        # If True, reject ghost args; if False, strip them

    # Output Sanitization
    sanitize_output=False,    # Enable output sanitization
    mask_pii=False,           # Mask PII (emails, phones, SSN, etc.)
    mask_secrets=False,       # Mask secrets (API keys, passwords, etc.)
    max_output_chars=None,    # Truncate output if exceeds limit
    max_output_tokens=None,   # Truncate based on token count

    # E2B Sandbox
    e2b_api_key=None,         # E2B API key (prefer env var)
    sandbox_timeout=30,       # Sandbox execution timeout in seconds

    # Error Hooks
    on_validation_error=None, # Callback for validation errors
    on_blocked=None,          # Callback for blocked calls
    on_rate_limit=None,       # Callback for rate limit events
)
```

## Environment Variables

All configuration options can be set via environment variables:

```bash
# Validation
export AIRLOCK_STRICT_MODE=true

# Output Sanitization
export AIRLOCK_SANITIZE_OUTPUT=true
export AIRLOCK_MASK_PII=true
export AIRLOCK_MASK_SECRETS=true
export AIRLOCK_MAX_OUTPUT_CHARS=10000

# E2B Sandbox
export E2B_API_KEY=your-key-here
export AIRLOCK_SANDBOX_TIMEOUT=60
```

## Configuration File

Create an `airlock.toml` in your project root:

```toml
[airlock]
strict_mode = true
sanitize_output = true
mask_pii = true
mask_secrets = true
max_output_chars = 10000

[airlock.sandbox]
timeout = 30

[airlock.policy]
default_rate_limit = "100/hour"
```

## Per-Tool Configuration

Override configuration for specific tools:

```python
from agent_airlock import Airlock, AirlockConfig

# Global config
default_config = AirlockConfig(strict_mode=False)

# Strict config for sensitive operations
strict_config = AirlockConfig(strict_mode=True, mask_pii=True)

@Airlock(config=default_config)
def search_users(query: str) -> list:
    return [...]

@Airlock(config=strict_config)
def delete_user(user_id: int) -> dict:
    return [...]
```

## Masking Strategies

Configure how sensitive data is masked:

```python
from agent_airlock import AirlockConfig, MaskingStrategy

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    masking_strategy=MaskingStrategy.PARTIAL,  # Show partial data
)
```

Available strategies:

| Strategy | Example | Result |
|----------|---------|--------|
| `FULL` | `john@example.com` | `[EMAIL REDACTED]` |
| `PARTIAL` | `john@example.com` | `j***@e***.com` |
| `TYPE_ONLY` | `john@example.com` | `[EMAIL]` |
| `HASH` | `john@example.com` | `[EMAIL:a1b2c3]` |

## Sensitive Data Types

Configure which data types to detect:

```python
from agent_airlock import AirlockConfig, SensitiveDataType

config = AirlockConfig(
    sanitize_output=True,
    enabled_types=[
        SensitiveDataType.EMAIL,
        SensitiveDataType.SSN,
        SensitiveDataType.CREDIT_CARD,
    ],
    disabled_types=[
        SensitiveDataType.IP_ADDRESS,  # Don't mask IPs
    ],
)
```

Available types:

- `EMAIL` - Email addresses
- `PHONE` - Phone numbers
- `SSN` - Social Security Numbers
- `CREDIT_CARD` - Credit card numbers
- `IP_ADDRESS` - IP addresses
- `API_KEY` - API keys (various patterns)
- `AWS_KEY` - AWS access keys
- `PASSWORD` - Password patterns
- `JWT` - JSON Web Tokens
- `CONNECTION_STRING` - Database connection strings
- `PRIVATE_KEY` - Private key markers
- `BEARER_TOKEN` - Bearer tokens

## Workspace Configuration

For multi-tenant applications:

```python
from agent_airlock import WorkspacePIIConfig, sanitize_with_workspace_config

config = WorkspacePIIConfig(
    workspace_id="enterprise-acme",
    allow_email_domains=["acme.com"],  # Don't mask internal emails
    mask_email_domains=["competitor.com"],  # Always mask these
    custom_patterns={
        "employee_id": r"EMP-\d{6}",
    },
)

result = sanitize_with_workspace_config(content, config)
```

## Error Hooks

Register callbacks for monitoring:

```python
from agent_airlock import AirlockConfig
from pydantic import ValidationError

def log_validation_error(tool_name: str, error: ValidationError):
    print(f"Validation failed for {tool_name}: {error}")

def log_blocked(tool_name: str, reason: str, context: dict):
    print(f"Blocked {tool_name}: {reason}")

def log_rate_limit(tool_name: str, retry_after: int):
    print(f"Rate limited {tool_name}, retry in {retry_after}s")

config = AirlockConfig(
    on_validation_error=log_validation_error,
    on_blocked=log_blocked,
    on_rate_limit=log_rate_limit,
)
```
