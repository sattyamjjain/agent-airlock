# Agent-Airlock: Enterprise Production Roadmap

## Current Status Assessment

### What's Already Implemented (v0.1.5)

| Feature | Status | Notes |
|---------|--------|-------|
| Ghost argument stripping | ✅ Complete | Works with strict/permissive modes |
| Pydantic V2 strict validation | ✅ Complete | No type coercion |
| Self-healing error responses | ✅ Complete | fix_hints for LLM retry |
| Async function support | ✅ Complete | Proper async/await wrapper |
| Streaming support | ✅ Complete | StreamingAirlock class, sync/async generators |
| Context propagation | ✅ Complete | AirlockContext with contextvars |
| Dynamic policy resolution | ✅ Complete | `Callable[[AirlockContext], SecurityPolicy]` |
| Audit logging | ✅ Complete | JSON Lines format, thread-safe |
| PII detection (12 types) | ✅ Complete | Email, phone, SSN, credit card, etc. |
| Secret masking | ✅ Complete | API keys, passwords, JWT, AWS keys |
| E2B sandbox integration | ✅ Complete | Warm pool, cloudpickle serialization |
| Rate limiting (local) | ✅ Complete | Token bucket algorithm |
| Time-based restrictions | ✅ Complete | TimeWindow with overnight support |
| RBAC (local) | ✅ Complete | Agent roles, allow/deny lists |
| FastMCP integration | ✅ Complete | MCPAirlock, secure_tool decorator |
| Workspace PII config | ✅ Complete | Per-workspace masking rules |
| Conversation tracking | ✅ Complete | Multi-turn state management |

### What's Actually Missing for Enterprise Production

| Feature | Priority | Impact |
|---------|----------|--------|
| Distributed rate limiting (Redis) | P0 | Multi-worker deployments broken |
| OpenAI Agents SDK Guardrails bridge | P1 | Integration friction |
| India-specific PII (Aadhaar, PAN, UPI) | P1 | Regional compliance |
| Observability hooks (Datadog/OTEL) | P1 | Production monitoring |
| Circuit breaker pattern | P1 | Resilience under load |
| Performance benchmarks | P2 | Trust verification |
| Cost tracking callbacks | P2 | Budget management |
| Anthropic SDK integration | P2 | Framework coverage |
| Retry policies | P2 | Transient failure handling |
| Health check endpoints | P3 | Kubernetes readiness |
| Prometheus metrics | P3 | Infrastructure monitoring |

---

## Phase 1: Multi-Tenant & Distributed Support (Week 1-2)

### 1.1 Redis-Backed Distributed Rate Limiting

**Problem**: Current rate limiting is per-process. Multiple Gunicorn workers have separate limits.

**Solution**: Add optional Redis backend for rate limiting.

```python
# New: src/agent_airlock/backends/__init__.py
# New: src/agent_airlock/backends/redis.py

from agent_airlock import SecurityPolicy
from agent_airlock.backends.redis import RedisRateLimiter

# Usage
policy = SecurityPolicy(
    rate_limits={"*": "1000/hour"},
    rate_limiter_backend=RedisRateLimiter(
        redis_url="redis://localhost:6379",
        key_prefix="airlock:ratelimit:",
    ),
)
```

**Files to Create**:
- `src/agent_airlock/backends/__init__.py`
- `src/agent_airlock/backends/redis.py`
- `src/agent_airlock/backends/memory.py` (current behavior, default)
- `tests/test_redis_backend.py`

**Dependencies**: `redis>=5.0` (optional)

### 1.2 OpenAI Agents SDK Guardrails Bridge

**Problem**: OpenAI SDK has its own Guardrails system that doesn't integrate with Airlock.

**Solution**: Create a bridge that allows Airlock validations to work as OpenAI Guardrails.

```python
# New: src/agent_airlock/integrations/openai_agents.py

from agents import Agent, InputGuardrail, OutputGuardrail
from agent_airlock.integrations.openai_agents import (
    AirlockInputGuardrail,
    AirlockOutputGuardrail,
    RunContextBridge,
)

# Usage
agent = Agent(
    name="my_agent",
    tools=[my_tool],
    input_guardrails=[
        AirlockInputGuardrail(policy=STRICT_POLICY),
    ],
    output_guardrails=[
        AirlockOutputGuardrail(config=AirlockConfig(mask_pii=True)),
    ],
)

# Context bridge for RunContextWrapper
@function_tool
@Airlock(context_bridge=RunContextBridge())  # Auto-extracts workspace_id, user_id
async def my_tool(ctx: RunContextWrapper[WorkspaceContext], query: str) -> str:
    ...
```

**Files to Create**:
- `src/agent_airlock/integrations/__init__.py`
- `src/agent_airlock/integrations/openai_agents.py`
- `tests/test_openai_agents_integration.py`
- `examples/openai_agents_guardrails.py`

### 1.3 Dynamic Policy from Workspace Context

**Problem**: Need to resolve policies per-workspace/tenant dynamically.

**Solution**: Enhance existing PolicyResolver to work seamlessly with workspace contexts.

```python
# Enhanced usage pattern
from agent_airlock import Airlock, SecurityPolicy, AirlockContext

def workspace_policy_resolver(ctx: AirlockContext) -> SecurityPolicy:
    """Resolve policy based on workspace tier."""
    workspace_id = ctx.workspace_id

    # Example: Load from database/cache
    if workspace_id == "enterprise":
        return SecurityPolicy(
            rate_limits={"*": "10000/hour"},
            allowed_roles=["admin", "developer"],
        )
    elif workspace_id == "startup":
        return SecurityPolicy(
            rate_limits={"*": "1000/hour"},
        )
    return PERMISSIVE_POLICY

@function_tool
@Airlock(policy=workspace_policy_resolver)
async def my_tool(ctx: RunContextWrapper[WorkspaceContext], query: str) -> str:
    ...
```

This is already supported but needs better documentation and examples.

---

## Phase 2: Regional Compliance & PII (Week 2-3)

### 2.1 India-Specific PII Patterns

**Problem**: Missing Aadhaar, PAN, UPI, IFSC code detection for Indian compliance.

**Solution**: Add India-specific detectors to sanitizer.

```python
# New patterns in src/agent_airlock/sanitizer.py

class SensitiveDataType(str, Enum):
    # Existing...
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"

    # New India-specific
    AADHAAR = "aadhaar"           # 12-digit, Verhoeff checksum
    PAN = "pan"                   # AAAAA0000A format
    UPI_ID = "upi_id"             # user@bank format
    IFSC = "ifsc"                 # AAAA0000000 format
    INDIAN_PASSPORT = "in_passport"  # A0000000 format
    GSTIN = "gstin"               # 22 chars, state code + PAN + entity

# Patterns with validation
INDIA_PATTERNS = {
    SensitiveDataType.AADHAAR: {
        "pattern": r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b",
        "validator": validate_aadhaar_checksum,  # Verhoeff algorithm
    },
    SensitiveDataType.PAN: {
        "pattern": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        "validator": validate_pan_format,
    },
    SensitiveDataType.UPI_ID: {
        "pattern": r"\b[\w.]+@[a-z]+\b",
        "validator": validate_upi_handle,
    },
    # ...
}
```

**Files to Modify**:
- `src/agent_airlock/sanitizer.py` - Add patterns
- `tests/test_india_pii.py` - New test file

### 2.2 Regional PII Presets

```python
from agent_airlock import AirlockConfig
from agent_airlock.regions import INDIA_PII_CONFIG, US_PII_CONFIG, EU_PII_CONFIG

# Usage
config = AirlockConfig(
    pii_config=INDIA_PII_CONFIG,  # Enables Aadhaar, PAN, UPI detection
)

# Or combine
config = AirlockConfig(
    pii_config=INDIA_PII_CONFIG | US_PII_CONFIG,
)
```

**Files to Create**:
- `src/agent_airlock/regions/__init__.py`
- `src/agent_airlock/regions/india.py`
- `src/agent_airlock/regions/us.py`
- `src/agent_airlock/regions/eu.py`

---

## Phase 3: Observability & Monitoring (Week 3-4)

### 3.1 Observability Hooks

**Problem**: Audit logs are files only. Need integration with Datadog, PostHog, OTEL.

**Solution**: Pluggable observability backends.

```python
# New: src/agent_airlock/observability/__init__.py
# New: src/agent_airlock/observability/datadog.py
# New: src/agent_airlock/observability/otel.py
# New: src/agent_airlock/observability/posthog.py

from agent_airlock.observability.datadog import DatadogObserver
from agent_airlock.observability.otel import OpenTelemetryObserver

config = AirlockConfig(
    observers=[
        DatadogObserver(
            service_name="my-agent-service",
            tags={"env": "production"},
        ),
        OpenTelemetryObserver(
            endpoint="http://otel-collector:4317",
        ),
    ],
)

# Each tool call emits:
# - Span with duration, tool_name, blocked status
# - Metrics: airlock.calls, airlock.blocked, airlock.latency_ms
# - Events: ghost_args_stripped, pii_detected, rate_limited
```

**Observer Protocol**:
```python
from typing import Protocol

class AirlockObserver(Protocol):
    def on_call_start(self, tool_name: str, context: AirlockContext) -> None: ...
    def on_call_end(
        self,
        tool_name: str,
        context: AirlockContext,
        duration_ms: float,
        blocked: bool,
        block_reason: str | None,
        sanitized_count: int,
    ) -> None: ...
    def on_error(self, tool_name: str, error: Exception) -> None: ...
```

### 3.2 Prometheus Metrics Export

```python
# New: src/agent_airlock/observability/prometheus.py

from agent_airlock.observability.prometheus import PrometheusMetrics

metrics = PrometheusMetrics()

# Exposed metrics:
# airlock_calls_total{tool="...", blocked="true/false"}
# airlock_latency_seconds{tool="..."}
# airlock_pii_detections_total{type="email/phone/..."}
# airlock_rate_limit_hits_total{tool="..."}

# Usage with FastAPI
from fastapi import FastAPI
app = FastAPI()
app.add_route("/metrics", metrics.expose)
```

### 3.3 Cost Tracking Callbacks

**Problem**: Need to track token/API costs saved by truncation.

**Solution**: Cost callback hooks.

```python
from agent_airlock import AirlockConfig

async def cost_callback(
    tool_name: str,
    original_tokens: int,
    truncated_tokens: int,
    tokens_saved: int,
    estimated_cost_saved: float,
) -> None:
    """Called after each truncation."""
    await billing_service.record_savings(
        tool_name=tool_name,
        tokens_saved=tokens_saved,
    )

config = AirlockConfig(
    max_output_tokens=4000,
    token_cost_callback=cost_callback,
    token_cost_per_1k=0.03,  # For estimation
)
```

---

## Phase 4: Resilience & Performance (Week 4-5)

### 4.1 Circuit Breaker Pattern

**Problem**: If E2B sandbox or external services fail repeatedly, need graceful degradation.

**Solution**: Add circuit breaker for sandbox execution.

```python
# New: src/agent_airlock/resilience.py

from agent_airlock.resilience import CircuitBreaker

config = AirlockConfig(
    sandbox_circuit_breaker=CircuitBreaker(
        failure_threshold=5,        # Open after 5 failures
        recovery_timeout=30,        # Try again after 30s
        half_open_requests=2,       # Allow 2 test requests
    ),
)

# Behavior:
# - CLOSED: Normal operation
# - OPEN: Fail fast, return error without trying sandbox
# - HALF_OPEN: Allow limited requests to test recovery
```

### 4.2 Retry Policies

```python
from agent_airlock.resilience import RetryPolicy, ExponentialBackoff

config = AirlockConfig(
    sandbox_retry_policy=RetryPolicy(
        max_retries=3,
        backoff=ExponentialBackoff(
            initial_delay=0.1,
            max_delay=5.0,
            multiplier=2.0,
        ),
        retryable_exceptions=[SandboxTimeoutError, ConnectionError],
    ),
)
```

### 4.3 Performance Benchmarks

**Problem**: Need verified performance numbers.

**Solution**: Add benchmark suite with published results.

```python
# New: benchmarks/benchmark_validation.py
# New: benchmarks/benchmark_sanitization.py
# New: benchmarks/benchmark_sandbox.py

# Target metrics (to be validated):
# - Validation overhead: <5ms for simple tools
# - PII scanning: <10ms per 10KB text
# - Sandbox cold start: <500ms
# - Sandbox warm execution: <200ms
```

**Benchmark CI Job**:
```yaml
# .github/workflows/benchmarks.yml
benchmark:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - run: pip install -e ".[dev,sandbox]"
    - run: pytest benchmarks/ --benchmark-json=results.json
    - uses: benchmark-action/github-action-benchmark@v1
      with:
        tool: pytest
        output-file-path: results.json
        fail-on-alert: true
        alert-threshold: "150%"  # Fail if 50% slower
```

---

## Phase 5: Framework Integrations (Week 5-6)

### 5.1 Anthropic SDK Integration

```python
# New: src/agent_airlock/integrations/anthropic.py
# New: examples/anthropic_sdk_integration.py

from anthropic import Anthropic
from agent_airlock.integrations.anthropic import AirlockToolWrapper

client = Anthropic()

@AirlockToolWrapper(config=config, policy=policy)
def get_weather(location: str) -> str:
    """Get weather for a location."""
    return f"Weather in {location}: Sunny, 25°C"

# The wrapper ensures tool calls are validated
response = client.messages.create(
    model="claude-sonnet-4-20250514",
    tools=[get_weather.to_anthropic_tool()],
    messages=[{"role": "user", "content": "What's the weather in Paris?"}],
)
```

### 5.2 LangChain Integration

```python
# New: src/agent_airlock/integrations/langchain.py

from langchain.tools import StructuredTool
from agent_airlock.integrations.langchain import airlock_tool

@airlock_tool(config=config, policy=policy)
def search_web(query: str, max_results: int = 10) -> list[str]:
    """Search the web."""
    ...

# Automatically creates a LangChain StructuredTool with Airlock protection
agent = create_react_agent(llm, [search_web])
```

### 5.3 LangGraph Integration

```python
# New: src/agent_airlock/integrations/langgraph.py

from langgraph.prebuilt import create_react_agent
from agent_airlock.integrations.langgraph import AirlockNode

# Wrap entire nodes with Airlock protection
graph = StateGraph()
graph.add_node("search", AirlockNode(search_func, policy=READ_ONLY_POLICY))
graph.add_node("process", AirlockNode(process_func, config=config))
```

---

## Phase 6: Documentation & Testing (Week 6-7)

### 6.1 Integration Tests with Real Frameworks

```python
# tests/integration/test_openai_agents.py
# tests/integration/test_langchain.py
# tests/integration/test_langgraph.py
# tests/integration/test_anthropic.py

@pytest.mark.integration
@pytest.mark.skipif(not HAS_OPENAI_AGENTS, reason="openai-agents not installed")
async def test_openai_agents_end_to_end():
    """Test full agent workflow with Airlock protection."""
    ...
```

### 6.2 Load Testing

```python
# tests/load/test_concurrent_validation.py
# tests/load/test_rate_limiting_under_load.py

async def test_1000_concurrent_validations():
    """Verify Airlock handles concurrent requests."""
    tasks = [
        validate_tool_call(f"tool_{i}", {"arg": i})
        for i in range(1000)
    ]
    results = await asyncio.gather(*tasks)
    assert all(r.success for r in results)
```

### 6.3 Documentation

- **Migration Guide**: `docs/migration-from-v0.1.md`
- **Framework Guides**:
  - `docs/integrations/openai-agents.md`
  - `docs/integrations/langchain.md`
  - `docs/integrations/anthropic.md`
- **Best Practices**: `docs/best-practices.md`
- **Security Considerations**: `docs/security.md`

---

## Implementation Priority Matrix

```
                    HIGH IMPACT
                        │
    ┌───────────────────┼───────────────────┐
    │                   │                   │
    │  P0: Do First     │  P1: Do Next      │
    │  ─────────────    │  ──────────       │
    │  • Redis Rate     │  • OpenAI         │
    │    Limiting       │    Guardrails     │
    │  • India PII      │  • Observability  │
    │                   │  • Circuit        │
    │                   │    Breaker        │
────┼───────────────────┼───────────────────┼────
    │                   │                   │
    │  P3: Nice to Have │  P2: Should Have  │
    │  ───────────────  │  ─────────────    │
    │  • Prometheus     │  • Cost Tracking  │
    │  • Health Check   │  • Benchmarks     │
    │                   │  • Anthropic SDK  │
    │                   │  • Retry Policy   │
    │                   │                   │
    └───────────────────┼───────────────────┘
                        │
                    LOW IMPACT
```

---

## Version Targets

| Version | Features | Timeline |
|---------|----------|----------|
| **0.2.0** | Redis rate limiting, India PII, Performance benchmarks | Week 2 |
| **0.3.0** | OpenAI Guardrails bridge, Observability hooks | Week 4 |
| **0.4.0** | Circuit breaker, Retry policies, LangChain integration | Week 6 |
| **1.0.0** | All integrations, Full documentation, Production certified | Week 8 |

---

## Success Criteria for v1.0.0

1. **Reliability**: 99.9% uptime in production deployments
2. **Performance**: <10ms overhead per tool call (p99)
3. **Coverage**: 95%+ test coverage including integrations
4. **Adoption**: 100+ GitHub stars, 10+ production users
5. **Security**: OWASP LLM Top 10 compliance documented
6. **Documentation**: Complete guides for all major frameworks

---

## Immediate Next Steps

1. **Create Redis backend** for distributed rate limiting (highest priority)
2. **Add India PII patterns** with Verhoeff validation for Aadhaar
3. **Set up benchmark suite** with GitHub Actions integration
4. **Write OpenAI Agents Guardrails bridge** example

---

## Dependencies to Add

```toml
# pyproject.toml additions

[project.optional-dependencies]
redis = ["redis>=5.0"]
observability = [
    "opentelemetry-api>=1.20",
    "opentelemetry-sdk>=1.20",
    "ddtrace>=2.0",
]
langchain = ["langchain>=0.2"]
anthropic = ["anthropic>=0.40"]
all = [
    "agent-airlock[sandbox,mcp,redis,observability]",
]
```

---

*Last Updated: 2026-02-01*
*Author: Agent-Airlock Team*
