# PII Masking Examples

## Basic PII Masking

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
)

@Airlock(config=config)
def get_customer(id: int) -> dict:
    return {
        "id": id,
        "name": "John Doe",
        "email": "john@example.com",
        "phone": "555-123-4567",
        "ssn": "123-45-6789",
    }

result = get_customer(id=123)
# {
#     "id": 123,
#     "name": "John Doe",
#     "email": "j***@example.com",
#     "phone": "555***567",
#     "ssn": "[REDACTED]"
# }
```

## Secret Masking

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_secrets=True,
)

@Airlock(config=config)
def get_config() -> dict:
    return {
        "api_key": "sk-1234567890abcdefghijklmnop",
        "aws_key": "AKIAIOSFODNN7EXAMPLE",
        "db_url": "postgres://user:pass@localhost/db",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc",
    }

result = get_config()
# {
#     "api_key": "sk-1234...mnop",
#     "aws_key": "AKIAIOS...MPLE",
#     "db_url": "[REDACTED]",
#     "jwt": "eyJhbGciOi...[JWT]"
# }
```

Secrets are matched by shape: a value that does not fit a known key format (for example an
`sk-` key with fewer than 20 characters after the prefix) is returned unmasked.

## Masking Strategies

`@Airlock` uses each type's default strategy (`PARTIAL` for email, as above);
`AirlockConfig` has no strategy setting. To pick one, call `sanitize_output` with a
`mask_config` mapping. A type left out of the mapping is masked `FULL`.

```python
from agent_airlock import MaskingStrategy, SensitiveDataType, sanitize_output

def mask_email(strategy: MaskingStrategy) -> str:
    config = {SensitiveDataType.EMAIL: strategy}
    return sanitize_output("john@example.com", mask_config=config).content

# Full redaction
mask_email(MaskingStrategy.FULL)       # [REDACTED]

# Partial masking
mask_email(MaskingStrategy.PARTIAL)    # j***@example.com

# Type only
mask_email(MaskingStrategy.TYPE_ONLY)  # [EMAIL]

# Hash (for correlation)
mask_email(MaskingStrategy.HASH)       # [SHA256:855f96e9...]
```

## Selective Type Masking

`AirlockConfig` has no per-type switch, only `mask_pii`, `mask_secrets` and
`pii_locales`. Select types with the standalone functions:

```python
from agent_airlock import (
    SensitiveDataType, WorkspacePIIConfig, mask_sensitive_data, sanitize_with_workspace_config,
)

text = "john@example.com, SSN 123-45-6789, card 4111111111111111"

# Only mask specific types
masked, detections = mask_sensitive_data(
    text,
    types=[
        SensitiveDataType.SSN,
        SensitiveDataType.CREDIT_CARD,
    ],
)
# john@example.com, SSN [REDACTED], card **** **** **** 1111
# (email NOT masked)

# Disable specific types
config = WorkspacePIIConfig(
    workspace_id="ops",
    disabled_types=[
        SensitiveDataType.IP_ADDRESS,   # Don't mask IPs
    ],
)
sanitize_with_workspace_config("host 10.0.0.12, owner ops@example.com", config).content
# host 10.0.0.12, owner o***@example.com
```

## Workspace-Specific Rules

```python
from agent_airlock import (
    WorkspacePIIConfig,
    sanitize_with_workspace_config,
)

# Enterprise workspace - allow internal emails
enterprise = WorkspacePIIConfig(
    workspace_id="acme-corp",
    allow_email_domains=["acme.com", "acme.internal"],
)

content = "Contact alice@acme.com or bob@gmail.com"
result = sanitize_with_workspace_config(content, enterprise)
# result.content == "Contact alice@acme.com or b***@gmail.com"

# Sales workspace - mask competitor emails
sales = WorkspacePIIConfig(
    workspace_id="sales",
    mask_email_domains=["competitor1.com", "competitor2.com"],
)

content = "Lead: prospect@company.com, Spy: mole@competitor1.com"
result = sanitize_with_workspace_config(content, sales)
# result.content == "Lead: prospect@company.com, Spy: m***@competitor1.com"
```

## Phone Number Filtering

```python
from agent_airlock import WorkspacePIIConfig, sanitize_with_workspace_config

config = WorkspacePIIConfig(
    workspace_id="support",
    allow_phone_prefixes=["+1800", "1800", "+1888", "1888"],
)

content = """
Toll-free: 1-800-555-1234 (keep visible)
Personal: 555-123-4567 (mask this)
Support: +1888-555-9999 (keep visible)
"""

result = sanitize_with_workspace_config(content, config)
# result.content: toll-free numbers preserved, personal masked as 555***567
```

## Custom Patterns

```python
from agent_airlock import MaskingStrategy, WorkspacePIIConfig, sanitize_with_workspace_config

config = WorkspacePIIConfig(
    workspace_id="hr-department",
    custom_patterns={
        "employee_id": r"EMP-\d{6}",
        "badge_number": r"BADGE-[A-Z]{2}\d{4}",
        "salary": r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
    },
    custom_strategies={
        "employee_id": MaskingStrategy.TYPE_ONLY,
        "salary": MaskingStrategy.FULL,
    },
)

content = """
Employee: EMP-123456
Badge: BADGE-AB1234
Salary: $85,000.00
"""

result = sanitize_with_workspace_config(content, config)
# result.content:
# Employee: [EMPLOYEE_ID]
# Badge: [REDACTED]
# Salary: [REDACTED]
```

A custom pattern with no strategy is masked `FULL`. Only `TYPE_ONLY` shows the pattern's
name; every other strategy gives `[REDACTED]`.

## Streaming Sanitization

```python
from agent_airlock import StreamingAirlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    max_output_chars=1000,
)

streaming = StreamingAirlock(config)

def generate_report():
    yield "Customer: john@example.com\n"
    yield "Phone: 555-123-4567\n"
    yield "SSN: 123-45-6789\n"

for chunk in streaming.wrap_generator(generate_report()):
    print(chunk, end="")
# Customer: j***@example.com
# Phone: 555***567
# SSN: [REDACTED]

print(f"\nTruncated: {streaming.state.truncated}")
# Truncated: False
```

## Direct Sanitization

```python
from agent_airlock import sanitize_output

content = """
User data:
- Email: john@example.com
- Phone: (555) 123-4567
- SSN: 123-45-6789
- API Key: sk-abcdef123456
"""

result = sanitize_output(
    content,
    mask_pii=True,
    mask_secrets=True,
)

print(result.content)
print(f"Detections: {result.detection_count}")

# Each detection is a dict: type, value, start, end, full_match, masked_as
for detection in result.detections:
    print(f"  {detection['type']}: {detection['value']} → {detection['masked_as']}")
```

Output:

```
User data:
- Email: j***@example.com
- Phone: (555***567
- SSN: [REDACTED]
- API Key: sk-abcdef123456

Detections: 3
  email: john@example.com → j***@example.com
  phone: 555) 123-4567 → 555***567
  ssn: 123-45-6789 → [REDACTED]
```

The API key is left as it is: the `sk-` pattern needs at least 20 characters after the
prefix. The phone match starts after the opening parenthesis, which stays in the output.
