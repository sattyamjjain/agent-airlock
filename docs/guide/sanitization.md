# PII & Secret Masking

Agent-Airlock detects and masks sensitive data in tool outputs.

## Why Sanitize Outputs?

LLMs can leak sensitive data through:
- Conversation history
- Training data extraction
- Prompt injection attacks
- Logging and monitoring

Sanitizing outputs prevents accidental exposure.

## Quick Start

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    mask_secrets=True,
)

@Airlock(config=config)
def get_customer(customer_id: int) -> dict:
    return {
        "name": "John Doe",
        "email": "john@example.com",
        "ssn": "123-45-6789",
        "api_key": "sk-1234567890",
    }

result = get_customer(customer_id=123)
# Returns:
# {
#     "name": "John Doe",
#     "email": "[EMAIL REDACTED]",
#     "ssn": "[SSN REDACTED]",
#     "api_key": "[API_KEY REDACTED]"
# }
```

## Sensitive Data Types

### PII (Personally Identifiable Information)

| Type | Pattern Example | Masked As |
|------|-----------------|-----------|
| Email | `john@example.com` | `[EMAIL REDACTED]` |
| Phone | `555-123-4567` | `[PHONE REDACTED]` |
| SSN | `123-45-6789` | `[SSN REDACTED]` |
| Credit Card | `4111-1111-1111-1111` | `[CREDIT_CARD REDACTED]` |
| IP Address | `192.168.1.100` | `[IP_ADDRESS REDACTED]` |

### Secrets

| Type | Pattern Example | Masked As |
|------|-----------------|-----------|
| API Key | `sk-1234567890abcdef` | `[API_KEY REDACTED]` |
| AWS Key | `AKIA1234567890` | `[AWS_KEY REDACTED]` |
| Password | `password=secret123` | `[PASSWORD REDACTED]` |
| JWT | `eyJhbGciOi...` | `[JWT REDACTED]` |
| Connection String | `postgres://user:pass@host` | `[CONNECTION_STRING REDACTED]` |
| Private Key | `-----BEGIN PRIVATE KEY-----` | `[PRIVATE_KEY REDACTED]` |
| Bearer Token | `Bearer eyJ...` | `[BEARER_TOKEN REDACTED]` |

## Masking Strategies

Choose how sensitive data is masked:

```python
from agent_airlock import AirlockConfig, MaskingStrategy

# Full redaction (default)
config = AirlockConfig(
    sanitize_output=True,
    masking_strategy=MaskingStrategy.FULL,
)
# john@example.com → [EMAIL REDACTED]

# Partial masking
config = AirlockConfig(
    sanitize_output=True,
    masking_strategy=MaskingStrategy.PARTIAL,
)
# john@example.com → j***@e***.com

# Type only
config = AirlockConfig(
    sanitize_output=True,
    masking_strategy=MaskingStrategy.TYPE_ONLY,
)
# john@example.com → [EMAIL]

# Hash (for correlation)
config = AirlockConfig(
    sanitize_output=True,
    masking_strategy=MaskingStrategy.HASH,
)
# john@example.com → [EMAIL:a1b2c3d4]
```

## Selective Detection

Enable/disable specific data types:

```python
from agent_airlock import AirlockConfig, SensitiveDataType

# Only mask specific types
config = AirlockConfig(
    sanitize_output=True,
    enabled_types=[
        SensitiveDataType.SSN,
        SensitiveDataType.CREDIT_CARD,
    ],
)

# Mask all except specific types
config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    disabled_types=[
        SensitiveDataType.IP_ADDRESS,
    ],
)
```

## Workspace-Specific Rules

For multi-tenant applications:

```python
from agent_airlock import WorkspacePIIConfig, sanitize_with_workspace_config

# Enterprise workspace: Don't mask internal emails
enterprise_config = WorkspacePIIConfig(
    workspace_id="acme-corp",
    allow_email_domains=["acme.com", "acme.internal"],
)

# Sales workspace: Mask competitor emails
sales_config = WorkspacePIIConfig(
    workspace_id="sales",
    mask_email_domains=["competitor1.com", "competitor2.com"],
)

# HR workspace: Custom patterns
hr_config = WorkspacePIIConfig(
    workspace_id="hr",
    custom_patterns={
        "employee_id": r"EMP-\d{6}",
        "salary": r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
    },
    custom_strategies={
        "salary": MaskingStrategy.FULL,
    },
)

# Apply workspace config
content = "Contact: alice@acme.com or bob@competitor1.com"
result = sanitize_with_workspace_config(content, sales_config)
# "Contact: alice@acme.com or [EMAIL REDACTED]"
```

## Phone Number Filtering

Allow specific phone prefixes:

```python
from agent_airlock import WorkspacePIIConfig

config = WorkspacePIIConfig(
    workspace_id="support",
    allow_phone_prefixes=["+1800", "1800", "+1888"],  # Toll-free
)

content = "Call us: 1-800-555-1234 or 555-123-4567"
result = sanitize_with_workspace_config(content, config)
# "Call us: 1-800-555-1234 or [PHONE REDACTED]"
```

## Output Truncation

Limit output size to prevent token bloat:

```python
from agent_airlock import AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    max_output_chars=10000,  # Character limit
    max_output_tokens=2000,  # Token limit
)
```

When truncated, a notice is appended:
```
[OUTPUT TRUNCATED - 15,000 chars exceeded 10,000 limit]
```

## Streaming Support

Sanitize streaming outputs:

```python
from agent_airlock import StreamingAirlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
)

streaming = StreamingAirlock(config)

def generate_report():
    yield "Customer: john@example.com"
    yield "Phone: 555-123-4567"

for chunk in streaming.wrap_generator(generate_report()):
    print(chunk)
# Customer: [EMAIL REDACTED]
# Phone: [PHONE REDACTED]
```

## Sanitization Results

Get details about what was masked:

```python
from agent_airlock import sanitize_output

content = "Email: john@example.com, SSN: 123-45-6789"
result = sanitize_output(content, mask_pii=True)

print(result.content)
# "Email: [EMAIL REDACTED], SSN: [SSN REDACTED]"

print(result.detection_count)
# 2

print(result.detections)
# [
#     {"type": "EMAIL", "original": "john@example.com", "masked": "[EMAIL REDACTED]"},
#     {"type": "SSN", "original": "123-45-6789", "masked": "[SSN REDACTED]"}
# ]
```
