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
from agent_airlock import AirlockConfig, UnknownArgsMode

config = AirlockConfig(
    # Validation (V0.4.0 - replaces strict_mode)
    unknown_args_mode=UnknownArgsMode.BLOCK,  # BLOCK / STRIP_AND_LOG / STRIP_SILENT

    # Output Sanitization
    sanitize_output=False,    # Enable output sanitization
    mask_pii=False,           # Mask PII (emails, phones, SSN, Aadhaar, PAN, etc.)
    mask_secrets=False,       # Mask secrets (API keys, passwords, etc.)
    max_output_chars=None,    # Truncate output if exceeds limit
    max_output_tokens=None,   # Truncate based on token count

    # E2B Sandbox
    e2b_api_key=None,         # E2B API key (prefer env var)
    sandbox_timeout=30,       # Sandbox execution timeout in seconds

    # Filesystem (V0.3.0)
    filesystem_policy=None,   # FilesystemPolicy for path validation

    # Network (V0.3.0)
    network_policy=None,      # NetworkPolicy for egress control

    # Honeypot (V0.3.0)
    honeypot_config=None,     # HoneypotConfig for deception

    # Error Hooks
    on_validation_error=None, # Callback for validation errors
    on_blocked=None,          # Callback for blocked calls
    on_rate_limit=None,       # Callback for rate limit events
)
```

## Unknown Arguments Mode (V0.4.0)

The `UnknownArgsMode` enum provides explicit control over ghost argument handling:

```python
from agent_airlock import UnknownArgsMode, get_recommended_mode

# Explicit modes
UnknownArgsMode.BLOCK         # Reject calls with unknown args (production)
UnknownArgsMode.STRIP_AND_LOG # Strip and log warnings (staging)
UnknownArgsMode.STRIP_SILENT  # Silently strip (development)

# Predefined mode constants
from agent_airlock import PRODUCTION_MODE, STAGING_MODE, DEVELOPMENT_MODE

# Auto-detect based on environment
mode = get_recommended_mode()  # Uses AIRLOCK_ENV or defaults to BLOCK
```

## Environment Variables

All configuration options can be set via environment variables:

```bash
# Unknown Args Mode (V0.4.0)
export AIRLOCK_UNKNOWN_ARGS_MODE=BLOCK  # or STRIP_AND_LOG, STRIP_SILENT

# Output Sanitization
export AIRLOCK_SANITIZE_OUTPUT=true
export AIRLOCK_MASK_PII=true
export AIRLOCK_MASK_SECRETS=true
export AIRLOCK_MAX_OUTPUT_CHARS=10000

# E2B Sandbox
export E2B_API_KEY=your-key-here
export AIRLOCK_SANDBOX_TIMEOUT=60

# Filesystem (V0.3.0)
export AIRLOCK_FILESYSTEM_ALLOWED_ROOTS=/app/data,/tmp
export AIRLOCK_FILESYSTEM_DENY_PATTERNS=*.env,**/.git/**

# Network (V0.3.0)
export AIRLOCK_NETWORK_ALLOW_EGRESS=false
```

## Configuration File

Create an `airlock.toml` in your project root:

```toml
[airlock]
unknown_args_mode = "BLOCK"
sanitize_output = true
mask_pii = true
mask_secrets = true
max_output_chars = 10000

[airlock.sandbox]
timeout = 30

[airlock.policy]
default_rate_limit = "100/hour"

# V0.3.0 Filesystem
[airlock.filesystem]
allowed_roots = ["/app/data", "/tmp"]
deny_patterns = ["*.env", "**/.git/**"]
allow_symlinks = false

# V0.3.0 Network
[airlock.network]
allow_egress = false
allowed_hosts = ["api.company.com"]
allowed_ports = [443]

# V0.3.0 Honeypot
[airlock.honeypot]
strategy = "honeypot"
fake_delay_ms = 100
```

## Per-Tool Configuration

Override configuration for specific tools:

```python
from agent_airlock import Airlock, AirlockConfig, UnknownArgsMode

# Global config (permissive for development)
default_config = AirlockConfig(unknown_args_mode=UnknownArgsMode.STRIP_SILENT)

# Strict config for sensitive operations
strict_config = AirlockConfig(
    unknown_args_mode=UnknownArgsMode.BLOCK,
    mask_pii=True,
)

@Airlock(config=default_config)
def search_users(query: str) -> list:
    return [...]

@Airlock(config=strict_config)
def delete_user(user_id: int) -> dict:
    return [...]
```

## Capability Gating (V0.4.0)

Configure fine-grained permissions per tool:

```python
from agent_airlock import (
    Airlock, Capability, requires,
    STRICT_CAPABILITY_POLICY, READ_ONLY_CAPABILITY_POLICY,
)

# Using decorator
@Airlock()
@requires(Capability.FILESYSTEM_READ)
def read_file(path: str) -> str: ...

@Airlock()
@requires(Capability.FILESYSTEM_READ | Capability.NETWORK_HTTP)
def fetch_and_save(url: str, path: str) -> bool: ...

# Using predefined policies
@Airlock(capability_policy=READ_ONLY_CAPABILITY_POLICY)
def safe_tool(query: str) -> list: ...
```

## Safe Types (V0.4.0)

Use built-in safe types for automatic validation:

```python
from agent_airlock import SafePath, SafePathStrict, SafeURL, SafeURLAllowHttp

# Path types
def read_file(path: SafePath) -> str:
    """Validates against traversal attacks."""
    ...

def write_config(path: SafePathStrict) -> bool:
    """Stricter validation with deny patterns."""
    ...

# URL types
def fetch_api(url: SafeURL) -> dict:
    """Validates HTTPS only."""
    ...

def fetch_legacy(url: SafeURLAllowHttp) -> dict:
    """Allows both HTTP and HTTPS."""
    ...
```

## Circuit Breaker (V0.4.0)

Configure fault tolerance for external dependencies:

```python
from agent_airlock import (
    Airlock, CircuitBreaker, CircuitBreakerConfig,
    AGGRESSIVE_BREAKER, CONSERVATIVE_BREAKER,
)

# Predefined configs
@Airlock(circuit_breaker=AGGRESSIVE_BREAKER)  # Fast failure detection
def risky_external_call(query: str) -> dict: ...

# Custom config
breaker = CircuitBreaker(CircuitBreakerConfig(
    failure_threshold=5,      # Open after 5 failures
    recovery_timeout=30.0,    # Try again after 30s
    half_open_requests=2,     # Allow 2 test requests
))
```

## Cost Tracking (V0.4.0)

Monitor and limit API spending:

```python
from agent_airlock import CostTracker, BudgetConfig, BudgetExceededError

tracker = CostTracker(budget=BudgetConfig(
    hard_limit=100.0,         # Fail if exceeded
    soft_limit=80.0,          # Alert at this threshold
    alert_callback=my_alert,  # Called when soft limit reached
))

@Airlock(cost_tracker=tracker)
def expensive_tool(query: str) -> str: ...
```

## Retry Policies (V0.4.0)

Configure automatic retry with backoff:

```python
from agent_airlock import (
    Airlock, RetryPolicy, RetryConfig,
    FAST_RETRY, STANDARD_RETRY, PATIENT_RETRY,
)

# Predefined policies
@Airlock(retry_policy=STANDARD_RETRY)
def flaky_api_call(query: str) -> dict: ...

# Custom policy
policy = RetryPolicy(RetryConfig(
    max_attempts=3,
    initial_delay=0.1,
    max_delay=5.0,
    exponential_base=2.0,
    jitter=True,
))
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
        # India-specific (V0.3.0)
        SensitiveDataType.AADHAAR,
        SensitiveDataType.PAN,
        SensitiveDataType.UPI_ID,
        SensitiveDataType.IFSC,
    ],
)
```

Available types:

**Standard:**
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

**India-Specific (V0.3.0):**
- `AADHAAR` - 12-digit Aadhaar numbers (with Verhoeff validation)
- `PAN` - Permanent Account Number
- `UPI_ID` - UPI identifiers
- `IFSC` - Bank IFSC codes

## OpenTelemetry Observability (V0.4.0)

Configure enterprise-grade monitoring:

```python
from agent_airlock import configure_observability, OpenTelemetryProvider

configure_observability(OpenTelemetryProvider(
    service_name="my-agent-service",
    endpoint="http://otel-collector:4317",  # Optional
))

# Use observe() context manager
from agent_airlock import observe

with observe("my_operation", tool_name="my_tool") as span:
    span.set_attribute("key", "value")
    result = do_work()
```

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
