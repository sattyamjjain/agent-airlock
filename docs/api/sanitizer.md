# Sanitizer API

PII and secret detection and masking.

## sanitize_output

```python
from agent_airlock import sanitize_output
```

### Signature

```python
def sanitize_output(
    content: Any,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    max_chars: int | None = None,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
    pii_locales: list[str] | None = None,
) -> SanitizationResult:
    """
    Sanitize content by masking sensitive data.

    Args:
        content: Text to sanitize. Anything else is converted to text first (JSON when
            it can be), so the result's content is always a string.
        mask_pii: Mask PII (emails, phones, etc.)
        mask_secrets: Mask secrets (API keys, passwords, etc.)
        max_chars: Truncate the masked text to this many characters
        mask_config: A masking strategy per data type, in place of the defaults
        pii_locales: Extra PII locales to detect, e.g. ["in"] for India-specific types

    Returns:
        SanitizationResult with masked content and detections
    """
```

`@Airlock` does not go through this conversion for a dict, list, tuple or set result: it masks
the values and keeps the type. See [What Gets Masked](../guide/sanitization.md#what-gets-masked).

### Example

```python
from agent_airlock import sanitize_output

content = "Email: john@example.com, API: sk-abcdefghij0123456789"
result = sanitize_output(content, mask_pii=True, mask_secrets=True)

print(result.content)
# "Email: j***@example.com, API: sk-abcd...6789"

print(result.detection_count)
# 2
```

To choose the strategy for a type:

```python
from agent_airlock import MaskingStrategy, SensitiveDataType, sanitize_output

result = sanitize_output(
    "john@example.com",
    mask_config={SensitiveDataType.EMAIL: MaskingStrategy.FULL},
)
print(result.content)
# "[REDACTED]"
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
| `detections` | `list[dict]` | Details of each detection (below) |
| `was_truncated` | `bool` | Whether `max_chars` truncated the content |
| `original_length` | `int` | Length of the text before masking |
| `sanitized_length` | `int` | Length of `content` |

### Detections

Each entry in `detections` is a dict:

| Key | Description |
|-----|-------------|
| `type` | The data type, such as `"email"` or `"api_key"` |
| `value` | The detected text |
| `full_match` | The whole text the pattern matched |
| `masked_as` | What it was replaced with |
| `start`, `end` | Its position in the original text |

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

result = sanitize_with_workspace_config("alice@company.com, bob@gmail.com, EMP-123456", config)
print(result.content)
# "alice@company.com, b***@gmail.com, [REDACTED]"
```

## sanitize_with_workspace_config

```python
from agent_airlock import sanitize_with_workspace_config
```

### Signature

```python
def sanitize_with_workspace_config(
    content: Any,
    workspace_config: WorkspacePIIConfig,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    max_chars: int | None = None,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
) -> SanitizationResult:
    """Sanitize content with workspace-specific rules."""
```

## StreamingAirlock

```python
from agent_airlock import StreamingAirlock
```

### Signature

```python
class StreamingAirlock:
    def __init__(self, config: AirlockConfig | None = None, *, tool_name: str = "unknown"):
        """
        Wrapper for streaming/generator sanitization.

        Args:
            config: Airlock configuration
            tool_name: Name used in logs
        """

    def wrap_generator(self, gen: Generator[T, None, None]) -> Generator[T, None, None]:
        """Wrap a sync generator with sanitization."""

    async def wrap_async_generator(self, gen: AsyncGenerator[T, None]) -> AsyncGenerator[T, None]:
        """Wrap an async generator with sanitization."""

    def reset(self) -> None:
        """Clear the state before reusing the wrapper."""
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
# "Email: j***@example.com"
# "More content..."
```

### State

```python
streaming = StreamingAirlock(config)
wrapped = streaming.wrap_generator(gen)

# After consuming...
print(streaming.state.truncated)
print(streaming.state.total_chunks)
print(streaming.state.total_chars)
print(streaming.state.sanitized_count)
```

## create_streaming_wrapper

```python
from agent_airlock import create_streaming_wrapper
```

### Signature

```python
def create_streaming_wrapper(
    func: Callable[..., Generator | AsyncGenerator],
    config: AirlockConfig | None = None,
) -> Callable[..., Generator | AsyncGenerator]:
    """
    Create a sanitized wrapper for a generator function.

    Args:
        func: Generator function to wrap
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
# "Results for test..."
# "email: u***@example.com"
```
