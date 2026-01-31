# Configuration API

Configuration options for Agent-Airlock.

## AirlockConfig

```python
from agent_airlock import AirlockConfig
```

### Signature

```python
@dataclass
class AirlockConfig:
    # Validation
    strict_mode: bool = False

    # Output Sanitization
    sanitize_output: bool = False
    mask_pii: bool = False
    mask_secrets: bool = False
    max_output_chars: int | None = None
    max_output_tokens: int | None = None
    masking_strategy: MaskingStrategy = MaskingStrategy.FULL
    enabled_types: list[SensitiveDataType] | None = None
    disabled_types: list[SensitiveDataType] = field(default_factory=list)

    # E2B Sandbox
    e2b_api_key: str | None = None
    sandbox_timeout: int = 30

    # Callbacks
    on_validation_error: Callable[[str, ValidationError], None] | None = None
    on_blocked: Callable[[str, str, dict], None] | None = None
    on_rate_limit: Callable[[str, int], None] | None = None
```

### Attributes

#### Validation

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `strict_mode` | `bool` | `False` | Reject ghost arguments instead of stripping |

#### Output Sanitization

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `sanitize_output` | `bool` | `False` | Enable output sanitization |
| `mask_pii` | `bool` | `False` | Mask PII in outputs |
| `mask_secrets` | `bool` | `False` | Mask secrets in outputs |
| `max_output_chars` | `int \| None` | `None` | Truncate at character limit |
| `max_output_tokens` | `int \| None` | `None` | Truncate at token limit |
| `masking_strategy` | `MaskingStrategy` | `FULL` | How to mask data |
| `enabled_types` | `list` | `None` | Only detect these types |
| `disabled_types` | `list` | `[]` | Don't detect these types |

#### Sandbox

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `e2b_api_key` | `str \| None` | `None` | E2B API key (prefer env var) |
| `sandbox_timeout` | `int` | `30` | Execution timeout in seconds |

#### Callbacks

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `on_validation_error` | `Callable` | `None` | Called on validation errors |
| `on_blocked` | `Callable` | `None` | Called when calls are blocked |
| `on_rate_limit` | `Callable` | `None` | Called on rate limit |

### Example

```python
from agent_airlock import AirlockConfig, MaskingStrategy, SensitiveDataType

config = AirlockConfig(
    strict_mode=True,
    sanitize_output=True,
    mask_pii=True,
    mask_secrets=True,
    max_output_chars=10000,
    masking_strategy=MaskingStrategy.PARTIAL,
    disabled_types=[SensitiveDataType.IP_ADDRESS],
)
```

## MaskingStrategy

```python
from agent_airlock import MaskingStrategy
```

### Values

| Value | Example Input | Example Output |
|-------|---------------|----------------|
| `FULL` | `john@example.com` | `[EMAIL REDACTED]` |
| `PARTIAL` | `john@example.com` | `j***@e***.com` |
| `TYPE_ONLY` | `john@example.com` | `[EMAIL]` |
| `HASH` | `john@example.com` | `[EMAIL:a1b2c3d4]` |

## SensitiveDataType

```python
from agent_airlock import SensitiveDataType
```

### Values

#### PII Types

| Value | Description |
|-------|-------------|
| `EMAIL` | Email addresses |
| `PHONE` | Phone numbers |
| `SSN` | Social Security Numbers |
| `CREDIT_CARD` | Credit card numbers |
| `IP_ADDRESS` | IP addresses |

#### Secret Types

| Value | Description |
|-------|-------------|
| `API_KEY` | Generic API keys |
| `AWS_KEY` | AWS access keys |
| `PASSWORD` | Password patterns |
| `JWT` | JSON Web Tokens |
| `CONNECTION_STRING` | Database URLs |
| `PRIVATE_KEY` | Private key markers |
| `BEARER_TOKEN` | Bearer tokens |

## Environment Variables

All configuration can be set via environment variables:

| Variable | Config Attribute |
|----------|------------------|
| `AIRLOCK_STRICT_MODE` | `strict_mode` |
| `AIRLOCK_SANITIZE_OUTPUT` | `sanitize_output` |
| `AIRLOCK_MASK_PII` | `mask_pii` |
| `AIRLOCK_MASK_SECRETS` | `mask_secrets` |
| `AIRLOCK_MAX_OUTPUT_CHARS` | `max_output_chars` |
| `AIRLOCK_SANDBOX_TIMEOUT` | `sandbox_timeout` |
| `E2B_API_KEY` | `e2b_api_key` |

## Configuration File

Create `airlock.toml` in your project root:

```toml
[airlock]
strict_mode = true
sanitize_output = true
mask_pii = true
mask_secrets = true
max_output_chars = 10000

[airlock.sandbox]
timeout = 60
```
