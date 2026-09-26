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
    }

result = get_customer(customer_id=123)
# Returns (default masking strategies):
# {
#     "name": "John Doe",
#     "email": "j***@example.com",
#     "ssn": "[REDACTED]"
# }
```

## What Gets Masked

- **A string result** is masked and, past `max_output_chars`, truncated.
- **A dict, list, tuple or set** is masked value by value and keeps its type and its
  keys. It is never truncated, because truncating its serialized form would hand back a
  different type.
- **Any other object** (a Pydantic model, a dataclass) is returned as it is, since
  rebuilding it with masked fields could break its own invariants. What was detected in
  it is logged as `output_sensitive_data_unmasked` and returned as a warning that says it
  was *not* masked. Return a dict or a string to have it masked.

Until 0.10.11 only string results were masked. Every other result was reported as
masked, in the log, the warnings and the audit record, and returned raw.

## Sensitive Data Types

"Masked As" is what `@Airlock` returns, using each type's default strategy.

### PII (Personally Identifiable Information)

Masked when `mask_pii=True` (the default).

| Type | Pattern Example | Masked As |
|------|-----------------|-----------|
| Email | `john@example.com` | `j***@example.com` |
| Phone | `555-123-4567` | `555***567` |
| SSN | `123-45-6789` | `[REDACTED]` |
| Credit Card | `4111111111111111` | `**** **** **** 1111` |
| IP Address | `192.168.1.100` | `192***100` |

A card number may be split by one consistent `-` or space (`4111-1111-1111-1111`,
`4111 1111 1111 1111`). `pii_locales=["in"]` adds Aadhaar, PAN, UPI ID, IFSC, Devanagari names and Indian
mobile numbers.

### Secrets

Masked when `mask_secrets=True` (the default).

| Type | Pattern Example | Masked As |
|------|-----------------|-----------|
| API Key | `sk-abcdefghijklmnopqrstuvwxyz` | `sk-abcd...wxyz` |
| AWS Key | `AKIAIOSFODNN7EXAMPLE` | `AKIAIOS...MPLE` |
| Password | `password=secret123` | `password=[REDACTED]` |
| JWT | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc` | `eyJhbGciOi...[JWT]` |
| Connection String | `postgres://user:pass@host` | `[REDACTED]` |
| Private Key | `-----BEGIN PRIVATE KEY-----` | `[REDACTED]` |

Detection is by known shape. An API key is an OpenAI key (legacy `sk-...`, or
`sk-proj-`/`sk-svcacct-`/`sk-admin-`), an Anthropic `sk-ant-...` key, a Google `AIza` key, a
GitHub `ghp_`/`gho_`/`github_pat_` token or a Slack `xox` token; a shorter or unrecognised key
passes through. A password is
the value (8+ characters) after `password`, `passwd`, `pwd`, `secret` or `token` and `=` or
`:`. The private-key rule masks the whole PEM block, or the header and the base64 lines after it
when the `END` line is missing. There is no separate
bearer-token type: the JWT in `Bearer eyJ...` is masked by the JWT rule.

## Masking Strategies

`@Airlock` masks each type with its default strategy, the one the tables above show:
`FULL` for SSN, password, private key and connection string, `TYPE_ONLY` for IFSC, and
`PARTIAL` for the rest. `AirlockConfig` has no strategy setting. To choose a strategy, run
the standalone sanitizer with a `mask_config` mapping:

```python
from agent_airlock import MaskingStrategy, SensitiveDataType, sanitize_output

def mask_email(strategy: MaskingStrategy) -> str:
    config = {SensitiveDataType.EMAIL: strategy}
    return sanitize_output("john@example.com", mask_config=config).content

# Full redaction
mask_email(MaskingStrategy.FULL)       # [REDACTED]

# Partial masking (the default for email)
mask_email(MaskingStrategy.PARTIAL)    # j***@example.com

# Type only
mask_email(MaskingStrategy.TYPE_ONLY)  # [EMAIL]

# Hash (for correlation)
mask_email(MaskingStrategy.HASH)       # [SHA256:855f96e9...]
```

The mapping replaces the defaults: a type you leave out of it is masked `FULL`.

## Selective Detection

`AirlockConfig` switches detection by group: `mask_pii`, `mask_secrets` and
`pii_locales`. To enable or disable specific data types, use the standalone functions:

```python
from agent_airlock import (
    SensitiveDataType, WorkspacePIIConfig, mask_sensitive_data, sanitize_with_workspace_config,
)

text = "john@example.com, SSN 123-45-6789, card 4111111111111111"

# Only mask specific types
masked, detections = mask_sensitive_data(
    text,
    types=[SensitiveDataType.SSN, SensitiveDataType.CREDIT_CARD],
)
# john@example.com, SSN [REDACTED], card **** **** **** 1111

# Mask all except specific types
config = WorkspacePIIConfig(
    workspace_id="ops",
    disabled_types=[SensitiveDataType.IP_ADDRESS],
)
sanitize_with_workspace_config("host 10.0.0.12, owner ops@example.com", config).content
# host 10.0.0.12, owner o***@example.com
```

## Workspace-Specific Rules

For multi-tenant applications. `sanitize_with_workspace_config` returns a
`SanitizationResult`; the masked text is its `content`.

```python
from agent_airlock import MaskingStrategy, WorkspacePIIConfig, sanitize_with_workspace_config

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
# result.content == "Contact: alice@acme.com or b***@competitor1.com"
```

A custom pattern is masked as `[REDACTED]`, or as `[EMPLOYEE_ID]` (its name in capitals)
when its strategy is `TYPE_ONLY`.

## Phone Number Filtering

Allow specific phone prefixes:

```python
from agent_airlock import WorkspacePIIConfig, sanitize_with_workspace_config

config = WorkspacePIIConfig(
    workspace_id="support",
    allow_phone_prefixes=["+1800", "1800", "+1888"],  # Toll-free
)

content = "Call us: 1-800-555-1234 or 555-123-4567"
result = sanitize_with_workspace_config(content, config)
# result.content == "Call us: 1-800-555-1234 or 555***567"
```

## Output Truncation

Limit the size of string results to prevent token bloat (structured results are
masked but not truncated; see above):

```python
from agent_airlock import AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    max_output_chars=10000,  # Character limit (default 20000; 0 = no limit)
)
```

`max_output_chars` is the only limit applied. `AirlockConfig` also has a
`max_output_tokens` field, but `@Airlock` does not truncate on it, and setting it warns.

When truncated, a notice is appended, inside the limit:
```
[OUTPUT TRUNCATED: Showing 10,000 of 15,000 characters]
```

## Streaming Support

`@Airlock` does not mask what a generator yields. Sanitize streaming outputs by wrapping
the generator:

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
# Customer: j***@example.com
# Phone: 555***567
```

## Sanitization Results

Get details about what was masked:

```python
from agent_airlock import sanitize_output

content = "Email: john@example.com, SSN: 123-45-6789"
result = sanitize_output(content, mask_pii=True)

print(result.content)
# "Email: j***@example.com, SSN: [REDACTED]"

print(result.detection_count)
# 2

print(result.detections)
# [
#     {"type": "email", "value": "john@example.com", "start": 7, "end": 23,
#      "full_match": "john@example.com", "masked_as": "j***@example.com"},
#     {"type": "ssn", "value": "123-45-6789", "start": 30, "end": 41,
#      "full_match": "123-45-6789", "masked_as": "[REDACTED]"}
# ]
```

Each detection holds the original `value`, so treat the list as sensitive.
