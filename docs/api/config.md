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
    unknown_args: UnknownArgsMode = UnknownArgsMode.STRIP_AND_LOG
    strict_mode: bool = False  # deprecated, use unknown_args

    # Output Sanitization
    max_output_tokens: int = 5000
    max_output_chars: int = 20000
    mask_pii: bool = True
    mask_secrets: bool = True
    sanitize_output: bool = True
    pii_locales: list[str] = field(default_factory=list)

    # Audit
    enable_audit_log: bool = True
    audit_log_path: Path = Path("airlock_audit.json")
    audit_otel_enabled: bool = False
    audit_otel_endpoint: str | None = None
    audit_include_args_hash: bool = True

    # E2B Sandbox
    e2b_api_key: str | None = None
    sandbox_timeout: int = 60
    sandbox_pool_size: int = 2

    # Callbacks
    on_validation_error: Callable[[str, ValidationError], None] | None = None
    on_blocked: Callable[[str, str, dict], None] | None = None
    on_rate_limit: Callable[[str, int], None] | None = None

    # Security policies
    filesystem_policy: FilesystemPolicy | None = None
    network_policy: NetworkPolicy | None = None
    honeypot_config: HoneypotConfig | None = None
    capability_policy: CapabilityPolicy | None = None
    endpoint_policies: dict[str, EndpointPolicy] = field(default_factory=dict)
    anomaly_config: AnomalyDetectorConfig | None = None
    require_done_receipt: bool = False
```

### Attributes

#### Validation

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `unknown_args` | `UnknownArgsMode` | `STRIP_AND_LOG` | Arguments the function does not declare: `BLOCK` rejects the call, `STRIP_AND_LOG` drops them and logs a warning, `STRIP_SILENT` drops them without one |
| `strict_mode` | `bool` | `False` | Deprecated; emits a `DeprecationWarning`. `True` maps to `unknown_args=BLOCK` |

#### Output Sanitization

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `sanitize_output` | `bool` | `True` | Enable output sanitization |
| `mask_pii` | `bool` | `True` | Mask PII in outputs |
| `mask_secrets` | `bool` | `True` | Mask secrets in outputs |
| `pii_locales` | `list[str]` | `[]` | `["in"]` adds the India PII types |
| `max_output_chars` | `int` | `20000` | Truncate string results at this many characters; `0` means no limit |
| `max_output_tokens` | `int` | `5000` | Stored (and read from `AIRLOCK_MAX_OUTPUT_TOKENS`), but `@Airlock` does not truncate on it |

Each detected type is masked with its default strategy (see
[MaskingStrategy](#maskingstrategy)). `AirlockConfig` has no field for choosing a strategy
or for picking individual types.

#### Audit

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_audit_log` | `bool` | `True` | Append JSON Lines audit records to `audit_log_path` |
| `audit_log_path` | `Path` | `airlock_audit.json` | Audit log file |

#### Sandbox

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `e2b_api_key` | `str \| None` | `None` | E2B API key; the `E2B_API_KEY` env var is used when unset |
| `sandbox_timeout` | `int` | `60` | Execution timeout in seconds |
| `sandbox_pool_size` | `int` | `2` | Warm sandboxes kept ready |

#### Callbacks

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `on_validation_error` | `Callable` | `None` | Called on validation errors |
| `on_blocked` | `Callable` | `None` | Called when calls are blocked |
| `on_rate_limit` | `Callable` | `None` | Called on rate limit |

#### Security Policies

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `filesystem_policy` | `FilesystemPolicy \| None` | `None` | Validates path-like arguments |
| `network_policy` | `NetworkPolicy \| None` | `None` | Egress control while the tool runs |
| `honeypot_config` | `HoneypotConfig \| None` | `None` | Deception for blocked calls, e.g. fake success |
| `capability_policy` | `CapabilityPolicy \| None` | `None` | Checked against `@requires`; a `SecurityPolicy`'s own `capability_policy` takes precedence |
| `endpoint_policies` | `dict[str, EndpointPolicy]` | `{}` | Per-tool URL rules |

`audit_otel_enabled`, `audit_otel_endpoint`, `audit_include_args_hash`, `anomaly_config` and
`require_done_receipt` are accepted and stored, but `@Airlock` does not read them.

### Example

```python
from agent_airlock import AirlockConfig, UnknownArgsMode

config = AirlockConfig(
    unknown_args=UnknownArgsMode.BLOCK,
    sanitize_output=True,
    mask_pii=True,
    mask_secrets=True,
    max_output_chars=10000,
)
```

## MaskingStrategy

```python
from agent_airlock import MaskingStrategy
```

### Values

| Value | Example Input | Example Output |
|-------|---------------|----------------|
| `FULL` | `john@example.com` | `[REDACTED]` |
| `PARTIAL` | `john@example.com` | `j***@example.com` |
| `TYPE_ONLY` | `john@example.com` | `[EMAIL]` |
| `HASH` | `john@example.com` | `[SHA256:855f96e9...]` |

`@Airlock` uses a fixed default per type: `FULL` for SSN, password, private key and
connection string, `TYPE_ONLY` for IFSC, `PARTIAL` for the rest. To choose, call the
standalone sanitizer with a `mask_config` mapping. A type left out of the mapping is masked
`FULL`:

```python
from agent_airlock import MaskingStrategy, SensitiveDataType, sanitize_output

result = sanitize_output(
    "john@example.com",
    mask_config={SensitiveDataType.EMAIL: MaskingStrategy.TYPE_ONLY},
)
result.content  # "[EMAIL]"
```

## SensitiveDataType

```python
from agent_airlock import SensitiveDataType
```

### Values

#### PII Types

Masked when `mask_pii=True`.

| Value | Description |
|-------|-------------|
| `EMAIL` | Email addresses |
| `PHONE` | Phone numbers |
| `SSN` | Social Security Numbers |
| `CREDIT_CARD` | Credit card numbers (unbroken digits) |
| `IP_ADDRESS` | IP addresses |

#### India PII Types

Added when `mask_pii=True` and `pii_locales=["in"]`.

| Value | Description |
|-------|-------------|
| `AADHAAR` | Aadhaar numbers (Verhoeff-checked) |
| `PAN` | Permanent Account Numbers |
| `UPI_ID` | UPI IDs |
| `IFSC` | Bank IFSC codes |
| `PERSONAL_NAME_DEVANAGARI` | Names in Devanagari script |
| `INDIA_MOBILE` | Mobile numbers with a `+91`, `91` or `0` prefix |

#### Secret Types

Masked when `mask_secrets=True`.

| Value | Description |
|-------|-------------|
| `API_KEY` | Known API key formats (OpenAI, Anthropic, Google, GitHub, Slack) |
| `AWS_KEY` | AWS access keys |
| `PASSWORD` | Password patterns |
| `JWT` | JSON Web Tokens |
| `CONNECTION_STRING` | Database URLs |
| `PRIVATE_KEY` | Private key markers |

## Environment Variables

Only these are read. They are read when an `AirlockConfig` is built, and the first three
override the constructor and the TOML file. `@Airlock()` with no `config` uses
`DEFAULT_CONFIG`, which is built when `agent_airlock` is imported, so set them before the
import.

| Variable | Config Attribute |
|----------|------------------|
| `AIRLOCK_UNKNOWN_ARGS` | `unknown_args` (`block`, `strip_and_log` or `strip_silent`) |
| `AIRLOCK_MAX_OUTPUT_TOKENS` | `max_output_tokens` |
| `AIRLOCK_STRICT_MODE` | `strict_mode` (deprecated; `true` maps to `block`, any other value to `strip_and_log`) |
| `E2B_API_KEY` | `e2b_api_key`, when it is not set in code or TOML |

## Configuration File

Nothing loads `airlock.toml` automatically. Load it with
`AirlockConfig.from_toml("airlock.toml")`, or `AirlockConfig.from_toml_if_exists()`, which
returns the defaults when the file is missing. Keys go under `[airlock]`; unknown keys are
logged and ignored.

```toml
[airlock]
unknown_args = "block"
sanitize_output = true
mask_pii = true
mask_secrets = true
max_output_chars = 10000
sandbox_timeout = 60
```
