# Configuration

Agent-Airlock provides flexible configuration through multiple sources.

## Configuration Priority

Configuration values are loaded in this order (highest priority first):

1. **Environment variables**: only the few listed [below](#environment-variables).
   `E2B_API_KEY` is the exception: it is used only when no key was given in code or TOML.
2. **Constructor arguments** (`AirlockConfig(...)`), or the values
   `AirlockConfig.from_toml()` reads from a **configuration file** (`airlock.toml`)
3. **Default values**

`@Airlock()` with no `config` uses `DEFAULT_CONFIG`, an `AirlockConfig()` built when
`agent_airlock` is imported, so environment variables meant for it must be set before
the import.

## AirlockConfig Options

The values shown are the defaults.

```python
from agent_airlock import AirlockConfig, UnknownArgsMode

config = AirlockConfig(
    # Validation (V0.4.0 - replaces strict_mode)
    unknown_args=UnknownArgsMode.STRIP_AND_LOG,  # BLOCK / STRIP_AND_LOG / STRIP_SILENT

    # Output Sanitization
    sanitize_output=True,     # Enable output sanitization
    mask_pii=True,            # Mask PII (email, phone, SSN, credit card, IP address)
    pii_locales=[],           # ["in"] also masks Aadhaar, PAN, UPI, IFSC, etc.
    mask_secrets=True,        # Mask secrets (API keys, passwords, etc.)
    max_output_chars=20000,   # Truncate string results past this (0 = no limit)
    max_output_tokens=5000,   # Stored, but @Airlock does not truncate on it

    # E2B Sandbox
    e2b_api_key=None,         # E2B API key (prefer the E2B_API_KEY env var)
    sandbox_timeout=60,       # Sandbox execution timeout in seconds

    # Filesystem (V0.3.0)
    filesystem_policy=None,   # FilesystemPolicy for path validation

    # Network (V0.3.0)
    network_policy=None,      # NetworkPolicy for egress control

    # Honeypot (V0.3.0)
    honeypot_config=None,     # HoneypotConfig for deception

    # Capability gating (V0.4.0)
    capability_policy=None,   # CapabilityPolicy that @requires is checked against

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
UnknownArgsMode.STRIP_AND_LOG # Strip and log warnings (staging; the default)
UnknownArgsMode.STRIP_SILENT  # Silently strip (development)

# Predefined mode constants
from agent_airlock import PRODUCTION_MODE, STAGING_MODE, DEVELOPMENT_MODE

# Recommended mode for an environment name you pass in
mode = get_recommended_mode("production")  # BLOCK
# "staging" and "development" give STRIP_AND_LOG; an unrecognised name gives BLOCK
```

## Environment Variables

Only these variables are read. Everything else (sanitization, output limits, sandbox
timeout, filesystem and network policy) is set in code or in `airlock.toml`.

```bash
# Unknown Args Mode (V0.4.0); overrides the constructor and the TOML file
export AIRLOCK_UNKNOWN_ARGS=block  # or strip_and_log, strip_silent

# Stored as max_output_tokens (which @Airlock does not truncate on)
export AIRLOCK_MAX_OUTPUT_TOKENS=5000

# E2B Sandbox; used when no e2b_api_key is set in code or TOML
export E2B_API_KEY=your-key-here

# Deprecated: AIRLOCK_STRICT_MODE=true still maps to block, with a DeprecationWarning
```

## Configuration File

Nothing reads `airlock.toml` on its own. Create one in your project root and load it:

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig.from_toml("airlock.toml")  # from_toml_if_exists() falls back to defaults

@Airlock(config=config)
def my_tool(x: int) -> int:
    return x * 2
```

Keys go under `[airlock]`; unknown keys are logged and ignored. Rate limits are not a TOML
setting: they belong to `SecurityPolicy(rate_limits=...)`.

```toml
[airlock]
unknown_args = "block"
sanitize_output = true
mask_pii = true
mask_secrets = true
max_output_chars = 10000
sandbox_timeout = 30

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
default_config = AirlockConfig(unknown_args=UnknownArgsMode.STRIP_SILENT)

# Strict config for sensitive operations
strict_config = AirlockConfig(
    unknown_args=UnknownArgsMode.BLOCK,
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

Configure fine-grained permissions per tool. `@requires` declares what a tool needs;
`@Airlock` checks that against a capability policy, taken from the `SecurityPolicy`
passed as `policy=` or, when that has none, from `AirlockConfig(capability_policy=...)`.
With no capability policy set, `@requires` is not enforced.

```python
from agent_airlock import (
    Airlock, AirlockConfig, Capability, requires,
    STRICT_CAPABILITY_POLICY, READ_ONLY_CAPABILITY_POLICY,
)

# Using predefined policies
config = AirlockConfig(capability_policy=READ_ONLY_CAPABILITY_POLICY)

# Using decorator
@Airlock(config=config)
@requires(Capability.FILESYSTEM_READ)
def read_file(path: str) -> str: ...  # allowed: FILESYSTEM_READ is granted

@Airlock(config=config)
@requires(Capability.FILESYSTEM_READ | Capability.NETWORK_HTTP)
def fetch_and_save(url: str, path: str) -> bool: ...  # blocked: NETWORK_HTTP is not granted
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
    """Same checks, and also rejects absolute paths."""
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

Configure fault tolerance for external dependencies. `Airlock` takes no circuit-breaker
argument: `CircuitBreaker(name, config)` is its own decorator. Stack it under `@Airlock`
so it sees the tool's exceptions; Airlock turns an exception into a blocked response, so a
breaker stacked above it never counts a failure.

```python
from agent_airlock import (
    Airlock, CircuitBreaker, CircuitBreakerConfig,
    AGGRESSIVE_BREAKER, CONSERVATIVE_BREAKER,
)

# Predefined configs
breaker = CircuitBreaker("external-api", AGGRESSIVE_BREAKER)  # Opens after 3 failures

@Airlock()
@breaker
def risky_external_call(query: str) -> dict: ...

# Custom config
breaker = CircuitBreaker("payments-api", CircuitBreakerConfig(
    failure_threshold=5,      # Open after 5 consecutive failures
    timeout=30.0,             # Allow a trial call after 30s
    success_threshold=2,      # Close again after 2 successes
))
```

## Cost Tracking (V0.4.0)

Monitor and limit API spending. `Airlock` takes no cost-tracker argument: a `CostTracker`
records the token usage you report to it, and raises `BudgetExceededError` when a recorded
call breaks a limit. Amounts are `Decimal`.

```python
from decimal import Decimal
from agent_airlock import CostTracker, BudgetConfig, BudgetExceededError

tracker = CostTracker(budget=BudgetConfig(
    max_cost_per_session=Decimal("100"),  # Fail if exceeded
    warn_at_percentage=80.0,              # Log a budget_warning from 80%
))
tracker.add_callback(my_alert)            # Called with every CostRecord

with tracker.track("expensive_tool") as call:
    result = call_expensive_api(query)
    call.set_tokens(input_tokens=1200, output_tokens=300)
```

The budget `@Airlock` itself checks before a call runs is the per-model-tier one,
`SecurityPolicy(model_tier_budget=...)`, with each call tagged through `AirlockContext`
metadata rather than its arguments. See the [Policy API](../api/policy.md).

## Retry Policies (V0.4.0)

Configure automatic retry with backoff. `Airlock` takes no retry argument: `RetryPolicy`
is its own decorator. Stack it under `@Airlock`, so it retries the tool body and never a
call Airlock has already rejected.

```python
from agent_airlock import (
    Airlock, RetryPolicy, RetryConfig,
    FAST_RETRY, STANDARD_RETRY, PATIENT_RETRY,
)

# Predefined configs
@Airlock()
@RetryPolicy(STANDARD_RETRY)  # 3 retries, 1s base delay
def flaky_api_call(query: str) -> dict: ...

# Custom policy
policy = RetryPolicy(RetryConfig(
    max_retries=3,            # Retries after the first attempt
    base_delay=0.1,
    max_delay=5.0,
    exponential_base=2.0,
    jitter=True,
    retryable_exceptions=(ConnectionError, TimeoutError),
))
```

When the retries run out, `RetryExhaustedError` is raised.

## Masking Strategies

`@Airlock` masks each detected value with that type's default strategy: `FULL` for SSN,
password, private key and connection string, `TYPE_ONLY` for IFSC, `PARTIAL` for the rest.
`AirlockConfig` has no strategy setting. To choose one, run the standalone sanitizer with
a `mask_config` mapping; a type left out of the mapping is masked `FULL`:

```python
from agent_airlock import MaskingStrategy, SensitiveDataType, sanitize_output

result = sanitize_output(
    "john@example.com",
    mask_config={SensitiveDataType.EMAIL: MaskingStrategy.PARTIAL},  # Show partial data
)
```

Available strategies:

| Strategy | Example | Result |
|----------|---------|--------|
| `FULL` | `john@example.com` | `[REDACTED]` |
| `PARTIAL` | `john@example.com` | `j***@example.com` |
| `TYPE_ONLY` | `john@example.com` | `[EMAIL]` |
| `HASH` | `john@example.com` | `[SHA256:855f96e9...]` |

## Sensitive Data Types

`AirlockConfig` selects types by group only: `mask_pii`, `mask_secrets` and `pii_locales`.
To mask specific types, call the standalone `mask_sensitive_data`, or use
`WorkspacePIIConfig(enabled_types=...)` (see [Workspace Configuration](#workspace-configuration)):

```python
from agent_airlock import SensitiveDataType, mask_sensitive_data

masked, detections = mask_sensitive_data(
    "john@example.com, SSN 123-45-6789",
    types=[SensitiveDataType.SSN, SensitiveDataType.CREDIT_CARD],
)
# masked == "john@example.com, SSN [REDACTED]"
```

Available types:

**Standard** (`mask_pii=True`):
- `EMAIL` - Email addresses
- `PHONE` - Phone numbers
- `SSN` - Social Security Numbers
- `CREDIT_CARD` - Credit card numbers
- `IP_ADDRESS` - IP addresses

**Secrets** (`mask_secrets=True`):
- `API_KEY` - API keys (OpenAI, Anthropic, Google, GitHub, Slack formats)
- `AWS_KEY` - AWS access keys
- `PASSWORD` - Password patterns
- `JWT` - JSON Web Tokens
- `CONNECTION_STRING` - Database connection strings
- `PRIVATE_KEY` - Private key markers

**India-Specific** (`mask_pii=True` with `pii_locales=["in"]`):
- `AADHAAR` - 12-digit Aadhaar numbers (with Verhoeff validation)
- `PAN` - Permanent Account Number
- `UPI_ID` - UPI identifiers
- `IFSC` - Bank IFSC codes
- `PERSONAL_NAME_DEVANAGARI` - Names in Devanagari script
- `INDIA_MOBILE` - Mobile numbers with a `+91`, `91` or `0` prefix

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
    mask_email_domains=["competitor.com"],  # Mask only these; other emails stay
    custom_patterns={
        "employee_id": r"EMP-\d{6}",
    },
)

result = sanitize_with_workspace_config(content, config)  # masked text: result.content
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
