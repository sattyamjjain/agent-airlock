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
#     "email": "[EMAIL REDACTED]",
#     "phone": "[PHONE REDACTED]",
#     "ssn": "[SSN REDACTED]"
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
        "api_key": "sk-1234567890abcdef",
        "aws_key": "AKIA1234567890EXAMPLE",
        "db_url": "postgres://user:pass@localhost/db",
        "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx",
    }

result = get_config()
# {
#     "api_key": "[API_KEY REDACTED]",
#     "aws_key": "[AWS_KEY REDACTED]",
#     "db_url": "[CONNECTION_STRING REDACTED]",
#     "jwt": "[JWT REDACTED]"
# }
```

## Masking Strategies

```python
from agent_airlock import Airlock, AirlockConfig, MaskingStrategy

# Full redaction
config_full = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    masking_strategy=MaskingStrategy.FULL,
)
# john@example.com → [EMAIL REDACTED]

# Partial masking
config_partial = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    masking_strategy=MaskingStrategy.PARTIAL,
)
# john@example.com → j***@e***.com

# Type only
config_type = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    masking_strategy=MaskingStrategy.TYPE_ONLY,
)
# john@example.com → [EMAIL]

# Hash (for correlation)
config_hash = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    masking_strategy=MaskingStrategy.HASH,
)
# john@example.com → [EMAIL:a1b2c3d4]
```

## Selective Type Masking

```python
from agent_airlock import Airlock, AirlockConfig, SensitiveDataType

# Only mask specific types
config = AirlockConfig(
    sanitize_output=True,
    enabled_types=[
        SensitiveDataType.SSN,
        SensitiveDataType.CREDIT_CARD,
    ],
)

@Airlock(config=config)
def get_data() -> dict:
    return {
        "email": "john@example.com",    # NOT masked
        "ssn": "123-45-6789",           # Masked
        "card": "4111111111111111",     # Masked
    }

# Disable specific types
config2 = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    disabled_types=[
        SensitiveDataType.IP_ADDRESS,   # Don't mask IPs
    ],
)
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
# "Contact alice@acme.com or [EMAIL REDACTED]"

# Sales workspace - mask competitor emails
sales = WorkspacePIIConfig(
    workspace_id="sales",
    mask_email_domains=["competitor1.com", "competitor2.com"],
)

content = "Lead: prospect@company.com, Spy: mole@competitor1.com"
result = sanitize_with_workspace_config(content, sales)
# "Lead: prospect@company.com, Spy: [EMAIL REDACTED]"
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
# Toll-free numbers preserved, personal masked
```

## Custom Patterns

```python
from agent_airlock import WorkspacePIIConfig, MaskingStrategy

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
# Employee: [employee_id]
# Badge: [badge_number]
# Salary: [salary REDACTED]
```

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
# Customer: [EMAIL REDACTED]
# Phone: [PHONE REDACTED]
# SSN: [SSN REDACTED]

print(f"\nTruncated: {streaming.state.was_truncated}")
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

for detection in result.detections:
    print(f"  {detection.type}: {detection.original} → {detection.masked}")
```
