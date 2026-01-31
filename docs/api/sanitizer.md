# Sanitizer API

PII and secret detection and masking.

## sanitize_output

```python
from agent_airlock import sanitize_output
```

### Signature

```python
def sanitize_output(
    content: str,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    masking_strategy: MaskingStrategy = MaskingStrategy.FULL,
    enabled_types: list[SensitiveDataType] | None = None,
    disabled_types: list[SensitiveDataType] | None = None,
) -> SanitizationResult:
    """
    Sanitize content by masking sensitive data.

    Args:
        content: Text to sanitize
        mask_pii: Mask PII (emails, phones, etc.)
        mask_secrets: Mask secrets (API keys, passwords, etc.)
        masking_strategy: How to mask (FULL, PARTIAL, etc.)
        enabled_types: Only detect these types
        disabled_types: Don't detect these types

    Returns:
        SanitizationResult with masked content and detections
    """
```

### Example

```python
from agent_airlock import sanitize_output

content = "Email: john@example.com, API: sk-1234567890"
result = sanitize_output(content, mask_pii=True, mask_secrets=True)

print(result.content)
# "Email: [EMAIL REDACTED], API: [API_KEY REDACTED]"

print(result.detection_count)
# 2
```

## SanitizationResult

```python
from agent_airlock import SanitizationResult
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `content` | `str` | Sanitized content |
| `detection_count` | `int` | Number of items masked |
| `detections` | `list[Detection]` | Details of each detection |
| `was_truncated` | `bool` | If output was truncated |

### Detection

```python
@dataclass
class Detection:
    type: SensitiveDataType
    original: str
    masked: str
    start: int
    end: int
```

## WorkspacePIIConfig

```python
from agent_airlock import WorkspacePIIConfig
```

### Signature

```python
@dataclass
class WorkspacePIIConfig:
    workspace_id: str

    # Email filtering
    mask_email_domains: list[str] = field(default_factory=list)
    allow_email_domains: list[str] = field(default_factory=list)

    # Phone filtering
    mask_phone_prefixes: list[str] = field(default_factory=list)
    allow_phone_prefixes: list[str] = field(default_factory=list)

    # Custom patterns
    custom_patterns: dict[str, str] = field(default_factory=dict)
    custom_strategies: dict[str, MaskingStrategy] = field(default_factory=dict)

    # Type filtering
    disabled_types: list[SensitiveDataType] = field(default_factory=list)
    enabled_types: list[SensitiveDataType] | None = None
```

### Example

```python
from agent_airlock import WorkspacePIIConfig, sanitize_with_workspace_config

config = WorkspacePIIConfig(
    workspace_id="enterprise",
    allow_email_domains=["company.com"],
    custom_patterns={
        "employee_id": r"EMP-\d{6}",
    },
)

result = sanitize_with_workspace_config(content, config)
```

## sanitize_with_workspace_config

```python
from agent_airlock import sanitize_with_workspace_config
```

### Signature

```python
def sanitize_with_workspace_config(
    content: str,
    config: WorkspacePIIConfig,
) -> SanitizationResult:
    """
    Sanitize content with workspace-specific rules.

    Args:
        content: Text to sanitize
        config: Workspace configuration

    Returns:
        SanitizationResult with masked content
    """
```

## StreamingAirlock

```python
from agent_airlock import StreamingAirlock
```

### Signature

```python
class StreamingAirlock:
    def __init__(self, config: AirlockConfig):
        """
        Wrapper for streaming/generator sanitization.

        Args:
            config: Airlock configuration
        """

    def wrap_generator(
        self,
        gen: Generator[str, None, None],
    ) -> Generator[str, None, None]:
        """Wrap a sync generator with sanitization."""

    async def wrap_async_generator(
        self,
        gen: AsyncGenerator[str, None],
    ) -> AsyncGenerator[str, None]:
        """Wrap an async generator with sanitization."""
```

### Example

```python
from agent_airlock import StreamingAirlock, AirlockConfig

config = AirlockConfig(sanitize_output=True, mask_pii=True)
streaming = StreamingAirlock(config)

def my_generator():
    yield "Email: john@example.com"
    yield "More content..."

for chunk in streaming.wrap_generator(my_generator()):
    print(chunk)
# "Email: [EMAIL REDACTED]"
# "More content..."
```

### State

```python
streaming = StreamingAirlock(config)
wrapped = streaming.wrap_generator(gen)

# After consuming...
print(streaming.state.was_truncated)
print(streaming.state.chunks_processed)
print(streaming.state.total_chars)
```

## create_streaming_wrapper

```python
from agent_airlock import create_streaming_wrapper
```

### Signature

```python
def create_streaming_wrapper(
    gen_func: Callable[..., Generator[str, None, None]],
    config: AirlockConfig,
) -> Callable[..., Generator[str, None, None]]:
    """
    Create a sanitized wrapper for a generator function.

    Args:
        gen_func: Generator function to wrap
        config: Airlock configuration

    Returns:
        Wrapped generator function
    """
```

### Example

```python
from agent_airlock import create_streaming_wrapper, AirlockConfig

config = AirlockConfig(sanitize_output=True, mask_pii=True)

def my_stream(query: str):
    yield f"Results for {query}..."
    yield "email: user@example.com"

wrapped = create_streaming_wrapper(my_stream, config)

for chunk in wrapped(query="test"):
    print(chunk)
```
