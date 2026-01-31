# Agent-Airlock: Production Readiness Plan

> **Reality Check**: Created 2 days ago. 0 stars. 0 external users. 0 security audits.
> This plan addresses every gap to make agent-airlock truly production-ready.

---

## Executive Summary

### Current State (Honest Assessment)

| Metric | Claim | Reality |
|--------|-------|---------|
| GitHub Stars | - | **0** |
| Production Users | - | **0** |
| Security Audits | - | **0** |
| Test Count | 182 | **196** (better than claimed) |
| Coverage | 84% | **Unknown** (not verified) |
| Audit Logging | "Implemented" | **CONFIG ONLY - Never writes to disk** |
| Async Support | Not claimed | **Broken** - decorator doesn't preserve async |
| Streaming | Not claimed | **Not implemented** |
| RunContext | Not claimed | **Not implemented** |

### What Actually Works

- Ghost argument stripping/rejection
- Pydantic V2 strict validation
- Self-healing error responses with fix_hints
- E2B sandbox execution with warm pool
- RBAC policy engine (rate limits, time windows)
- PII/secret detection (12 types, 4 masking strategies)
- FastMCP integration
- Output truncation

### What's Broken/Missing

1. **Audit Logging** - Config exists, implementation doesn't
2. **Async Function Support** - Decorator breaks async semantics
3. **Streaming Support** - No generator/yield support
4. **RunContext Preservation** - No session/request context
5. **Workspace-Specific Policies** - Static policies only
6. **Multi-Agent Conversation Validation** - No state across turns
7. **Performance Benchmarks** - Claims unverified
8. **Integration Tests** - Unit tests only
9. **Azure OpenAI Compatibility** - Untested

---

## Phase 0: Critical Fixes (Week 1)

> Fix things that are claimed but broken

### P0.1: Implement Audit Logging

**Problem**: Config fields exist but nothing writes to disk.

```python
# Current (BROKEN):
config = AirlockConfig(enable_audit_log=True, audit_log_path="audit.json")
# Result: No file created, no logs written
```

**Implementation**:

```python
# src/agent_airlock/audit.py (NEW FILE)
from __future__ import annotations
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from .self_heal import AirlockResponse

class AuditLogger:
    """Thread-safe JSON Lines audit logger."""

    _lock = threading.Lock()

    def __init__(self, path: Path | str, enabled: bool = True):
        self.path = Path(path) if path else None
        self.enabled = enabled and self.path is not None

    def log(
        self,
        tool_name: str,
        args: dict[str, Any],
        result: Any,
        blocked: bool,
        block_reason: str | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        duration_ms: float | None = None,
        sanitized_fields: list[str] | None = None,
    ) -> None:
        """Write audit record to JSON Lines file."""
        if not self.enabled:
            return

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_name": tool_name,
            "args": self._redact_sensitive(args),
            "result_type": type(result).__name__,
            "result_preview": self._preview(result),
            "blocked": blocked,
            "block_reason": block_reason,
            "agent_id": agent_id,
            "session_id": session_id,
            "duration_ms": duration_ms,
            "sanitized_fields": sanitized_fields or [],
        }

        with self._lock:
            with open(self.path, "a") as f:
                f.write(json.dumps(record) + "\n")

    @staticmethod
    def _redact_sensitive(args: dict) -> dict:
        """Redact sensitive parameter values for audit."""
        sensitive_names = {"password", "secret", "token", "api_key", "key", "credential"}
        return {
            k: "[REDACTED]" if any(s in k.lower() for s in sensitive_names) else v
            for k, v in args.items()
        }

    @staticmethod
    def _preview(result: Any, max_len: int = 200) -> str:
        """Create preview of result for audit."""
        if isinstance(result, dict) and "blocked" in result:
            return f"BLOCKED: {result.get('reason', 'unknown')}"
        s = str(result)
        return s[:max_len] + "..." if len(s) > max_len else s
```

**Integration in core.py**:
```python
# Add to _airlock_wrapper:
audit_logger = AuditLogger(config.audit_log_path, config.enable_audit_log)
start_time = time.perf_counter()
# ... existing logic ...
audit_logger.log(
    tool_name=func.__name__,
    args=filtered_kwargs,
    result=result,
    blocked=isinstance(result, dict) and result.get("blocked"),
    block_reason=result.get("reason") if isinstance(result, dict) else None,
    duration_ms=(time.perf_counter() - start_time) * 1000,
)
```

**Tests Required**: 8 tests
- Log file creation
- Thread-safe concurrent writes
- Sensitive param redaction
- JSON Lines format validation
- Disabled logging behavior
- Large result preview truncation

---

### P0.2: Fix Async Function Support

**Problem**: Decorator wraps async functions but doesn't preserve async.

```python
# Current (BROKEN):
@Airlock()
async def my_async_tool(x: int) -> int:
    return await some_async_op()

# Result: Function is awaited synchronously inside decorator
```

**Implementation**:

```python
# In core.py, modify _airlock_wrapper:

def _create_airlock_decorator(...):
    def decorator(func: F) -> F:
        is_async = asyncio.iscoroutinefunction(func)

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # All validation logic (ghost args, policy, etc.)
                # Then:
                if sandbox:
                    result = await execute_in_sandbox_async(func, *args, **kwargs)
                else:
                    result = await func(*args, **kwargs)
                # Post-processing (sanitization, etc.)
                return result
            return async_wrapper  # type: ignore
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                # Existing sync logic
                ...
            return sync_wrapper  # type: ignore
    return decorator
```

**Tests Required**: 10 tests
- Async function detection
- Async sandbox execution
- Async validation error handling
- Mixed sync/async in same codebase
- Async rate limiting
- Async policy checking

---

### P0.3: Add Coverage Verification

**Problem**: "84% coverage" claim is unverified.

```bash
# Add to CI:
pytest tests/ -v --cov=agent_airlock --cov-report=html --cov-fail-under=80

# Add coverage badge to README
```

**Deliverables**:
- GitHub Action for coverage reporting
- Coverage badge in README
- HTML coverage report
- Enforce 80% minimum in CI

---

## Phase 1: Core Missing Features (Week 2)

### P1.1: Streaming Support

**Problem**: No support for generator functions or streaming responses.

```python
# Current (BROKEN):
@Airlock()
def stream_results():
    for item in large_dataset:
        yield item  # TypeError: generator not supported
```

**Implementation**:

```python
# src/agent_airlock/streaming.py (NEW FILE)
from typing import Generator, AsyncGenerator, TypeVar

T = TypeVar("T")

class StreamingAirlock:
    """Wrapper for streaming validation and sanitization."""

    def __init__(self, config: AirlockConfig, policy: SecurityPolicy | None = None):
        self.config = config
        self.policy = policy
        self.sanitizer = Sanitizer(config)
        self._char_count = 0

    def wrap_generator(
        self,
        gen: Generator[T, None, None]
    ) -> Generator[T, None, None]:
        """Wrap a generator with per-chunk sanitization."""
        for chunk in gen:
            if isinstance(chunk, str):
                # Incremental PII masking
                sanitized = self.sanitizer.sanitize_text(chunk)
                self._char_count += len(sanitized)

                # Check truncation limit
                if self.config.max_output_chars:
                    remaining = self.config.max_output_chars - self._char_count
                    if remaining <= 0:
                        yield "[OUTPUT TRUNCATED]"
                        return
                    elif remaining < len(sanitized):
                        yield sanitized[:remaining] + "[TRUNCATED]"
                        return

                yield sanitized
            else:
                yield chunk

    async def wrap_async_generator(
        self,
        gen: AsyncGenerator[T, None]
    ) -> AsyncGenerator[T, None]:
        """Wrap an async generator with per-chunk sanitization."""
        async for chunk in gen:
            if isinstance(chunk, str):
                sanitized = self.sanitizer.sanitize_text(chunk)
                self._char_count += len(sanitized)

                if self.config.max_output_chars:
                    remaining = self.config.max_output_chars - self._char_count
                    if remaining <= 0:
                        yield "[OUTPUT TRUNCATED]"
                        return

                yield sanitized
            else:
                yield chunk
```

**Usage**:
```python
@Airlock(config=config, streaming=True)
async def stream_data() -> AsyncGenerator[str, None]:
    async for chunk in data_source:
        yield chunk  # Each chunk sanitized, total truncated if needed
```

**Tests Required**: 12 tests

---

### P1.2: RunContext Preservation

**Problem**: No session/request context across decorator boundary.

```python
# Current (BROKEN):
@function_tool
@Airlock()
async def my_tool(ctx: RunContextWrapper[WorkspaceContext], query: str) -> str:
    # ctx might not be preserved correctly
    workspace_id = ctx.context.workspace_id  # May fail
```

**Implementation**:

```python
# src/agent_airlock/context.py (NEW FILE)
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

T = TypeVar("T")

# Context variable for current request/session
_current_context: ContextVar[dict[str, Any]] = ContextVar("airlock_context", default={})

@dataclass
class AirlockContext(Generic[T]):
    """Context holder for request-scoped data."""

    agent_id: str | None = None
    session_id: str | None = None
    workspace_id: str | None = None
    user_context: T | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def current(cls) -> "AirlockContext":
        return _current_context.get(cls())

    def __enter__(self) -> "AirlockContext":
        self._token = _current_context.set(self)
        return self

    def __exit__(self, *args) -> None:
        _current_context.reset(self._token)


# In core.py:
def _airlock_wrapper(*args, **kwargs):
    # Extract context from first arg if it's a RunContext-like object
    ctx_arg = args[0] if args and hasattr(args[0], "context") else None

    with AirlockContext(
        agent_id=_extract_agent_id(ctx_arg),
        session_id=_extract_session_id(ctx_arg),
        workspace_id=getattr(ctx_arg.context, "workspace_id", None) if ctx_arg else None,
        user_context=ctx_arg,
    ):
        # Now context is available throughout via AirlockContext.current()
        return func(*args, **kwargs)
```

**Tests Required**: 8 tests

---

### P1.3: Dynamic Policy Resolution

**Problem**: Policies are static, can't vary by workspace/user.

```python
# Current (LIMITED):
@Airlock(policy=STRICT_POLICY)  # Same policy for everyone
def my_tool(): ...
```

**Implementation**:

```python
# Add to core.py:
PolicyResolver = Callable[[AirlockContext], SecurityPolicy]

def Airlock(
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | PolicyResolver | None = None,  # Now accepts callable
    ...
):
    ...

# Usage:
def get_workspace_policy(ctx: AirlockContext) -> SecurityPolicy:
    if ctx.workspace_id == "enterprise-123":
        return STRICT_POLICY
    return PERMISSIVE_POLICY

@Airlock(policy=get_workspace_policy)
def my_tool(ctx, query: str) -> str:
    ...
```

**Tests Required**: 6 tests

---

## Phase 2: Production Hardening (Week 3)

### P2.1: Performance Benchmarks

**Problem**: "<50ms overhead" claim is unverified.

```python
# benchmarks/bench_airlock.py (NEW FILE)
import pytest
from pytest_benchmark.fixture import BenchmarkFixture

def test_validation_overhead(benchmark: BenchmarkFixture):
    """Measure validation overhead per call."""
    @Airlock()
    def simple_tool(x: int, y: str) -> str:
        return f"{x}-{y}"

    result = benchmark(simple_tool, x=42, y="test")
    assert result == "42-test"
    # Baseline should be <1ms, with Airlock <5ms

def test_pii_masking_overhead(benchmark: BenchmarkFixture):
    """Measure PII masking overhead."""
    config = AirlockConfig(mask_pii=True)
    @Airlock(config=config)
    def tool_with_pii() -> str:
        return "Contact john@example.com at 555-123-4567"

    result = benchmark(tool_with_pii)
    # Should be <10ms even with regex scanning

def test_sandbox_latency(benchmark: BenchmarkFixture):
    """Measure E2B sandbox cold/warm start."""
    @Airlock(sandbox=True)
    def sandboxed_tool(code: str) -> str:
        exec(code)
        return "done"

    # First call (cold): <500ms
    # Subsequent (warm): <200ms
```

**Deliverables**:
- pytest-benchmark integration
- CI job publishing benchmark results
- Benchmark badge in README
- Performance regression detection

---

### P2.2: Integration Tests

**Problem**: Only unit tests exist.

```python
# tests/integration/test_openai_agents.py (NEW FILE)
"""Integration tests with OpenAI Agents SDK."""

import pytest
from agents import Agent, Runner, function_tool
from agent_airlock import Airlock, AirlockConfig

@pytest.mark.integration
async def test_openai_agents_integration():
    """Verify @Airlock works with @function_tool."""

    @function_tool
    @Airlock()
    def weather_tool(city: str) -> str:
        return f"Weather in {city}: Sunny"

    agent = Agent(
        name="test",
        tools=[weather_tool],
        model="gpt-4o-mini",
    )

    # Verify tool schema is preserved
    assert "city" in weather_tool.schema["parameters"]["properties"]

    # Verify decorator doesn't break agent
    result = await Runner.run(agent, "What's the weather in Paris?")
    assert "Paris" in result.final_output

# tests/integration/test_pydanticai.py
# tests/integration/test_langchain.py
# tests/integration/test_smolagents.py
# tests/integration/test_fastmcp.py
```

**Tests Required**: 15 integration tests across 5 frameworks

---

### P2.3: Error Recovery Hooks

**Problem**: No hooks for custom error handling.

```python
# Add to config.py:
@dataclass
class AirlockConfig:
    ...
    on_validation_error: Callable[[str, ValidationError], None] | None = None
    on_blocked: Callable[[str, BlockReason, dict], None] | None = None
    on_rate_limit: Callable[[str, int], None] | None = None

# Usage:
def handle_validation_error(tool_name: str, error: ValidationError):
    # Send to Sentry, update session retry state, etc.
    sentry_sdk.capture_exception(error)

config = AirlockConfig(on_validation_error=handle_validation_error)
```

---

## Phase 3: Enterprise Features (Week 4)

### P3.1: Multi-Agent Conversation Validation

**Problem**: No state tracking across turns.

```python
# src/agent_airlock/conversation.py (NEW FILE)
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock

@dataclass
class ConversationState:
    """Track tool calls within a conversation."""

    session_id: str
    tool_calls: list[dict] = field(default_factory=list)
    last_call_time: datetime | None = None
    blocked_until: datetime | None = None

class ConversationTracker:
    """Thread-safe conversation state tracking."""

    def __init__(self):
        self._sessions: dict[str, ConversationState] = {}
        self._lock = Lock()

    def record_call(
        self,
        session_id: str,
        tool_name: str,
        blocked: bool
    ) -> None:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = ConversationState(session_id)
            state = self._sessions[session_id]
            state.tool_calls.append({
                "tool": tool_name,
                "time": datetime.now(),
                "blocked": blocked,
            })
            state.last_call_time = datetime.now()

    def should_block(
        self,
        session_id: str,
        tool_name: str,
        constraints: dict
    ) -> tuple[bool, str | None]:
        """Check if tool should be blocked based on conversation history."""
        state = self._sessions.get(session_id)
        if not state:
            return False, None

        # Example constraint: "delete_user" blocks all calls for 5 minutes
        if "after_delete_cooldown" in constraints:
            for call in state.tool_calls:
                if call["tool"] == "delete_user" and not call["blocked"]:
                    elapsed = (datetime.now() - call["time"]).total_seconds()
                    if elapsed < constraints["after_delete_cooldown"]:
                        return True, f"Cooldown after delete_user: {elapsed:.0f}s remaining"

        return False, None
```

---

### P3.2: Workspace-Specific PII Rules

**Problem**: Same PII rules for all workspaces.

```python
# Add to sanitizer.py:
@dataclass
class WorkspacePIIConfig:
    """Workspace-specific PII handling."""

    workspace_id: str
    mask_email_domains: list[str] = field(default_factory=list)  # Only mask these domains
    allowed_phone_formats: list[str] = field(default_factory=list)  # Don't mask these
    custom_patterns: dict[str, str] = field(default_factory=dict)  # Workspace-specific

# Usage:
config = AirlockConfig(
    pii_config_resolver=lambda ctx: WorkspacePIIConfig(
        workspace_id=ctx.workspace_id,
        mask_email_domains=["competitor.com"],  # Only mask competitor emails
    )
)
```

---

### P3.3: Azure OpenAI Compatibility

**Problem**: Untested with Azure.

```python
# tests/integration/test_azure_openai.py
import pytest
from openai import AsyncAzureOpenAI

@pytest.mark.integration
@pytest.mark.azure
async def test_azure_openai_compatibility():
    """Verify Airlock doesn't interfere with Azure OpenAI."""

    client = AsyncAzureOpenAI(
        api_version="2024-02-01",
        azure_endpoint="https://xxx.openai.azure.com/",
    )

    @function_tool
    @Airlock()
    def azure_tool(query: str) -> str:
        return f"Result: {query}"

    # Test with Azure client
    response = await client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Test"}],
        tools=[azure_tool.schema],
    )

    assert response.choices[0].message.tool_calls is not None
```

---

## Phase 4: Security & Compliance (Week 5)

### P4.1: Security Audit

**Actions**:
1. Run `bandit` on codebase
2. Run `safety check` on dependencies
3. Review cloudpickle deserialization (sandbox only)
4. Verify no secrets in logs
5. Check for timing attacks in rate limiter
6. Audit regex patterns for ReDoS

**Deliverables**:
- `SECURITY.md` with security considerations
- GitHub security advisory process
- CVE response plan

---

### P4.2: Compliance Documentation

**Deliverables**:
- GDPR data handling documentation
- CCPA compliance notes
- HIPAA considerations (if applicable)
- Data retention policies for audit logs

---

### P4.3: SBOM (Software Bill of Materials)

```bash
# Generate SBOM
pip install cyclonedx-bom
cyclonedx-py --format json --output sbom.json

# Add to CI:
- name: Generate SBOM
  run: cyclonedx-py --format json --output sbom.json
- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
```

---

## Phase 5: Community & Adoption (Week 6+)

### P5.1: Documentation Overhaul

**Deliverables**:
- `docs/` directory with MkDocs
- API reference (auto-generated)
- Framework integration guides (one per framework)
- Security best practices guide
- Troubleshooting guide
- Performance tuning guide

---

### P5.2: Examples Expansion

**Current**: 5 examples
**Target**: 15 examples

New examples needed:
- [ ] `examples/async_tools.py` - Async function patterns
- [ ] `examples/streaming.py` - Generator and streaming
- [ ] `examples/multi_tenant.py` - Workspace isolation
- [ ] `examples/audit_logging.py` - Compliance setup
- [ ] `examples/custom_validators.py` - Extending validation
- [ ] `examples/azure_openai.py` - Azure integration
- [ ] `examples/error_handling.py` - Custom error hooks
- [ ] `examples/conversation_tracking.py` - Multi-turn validation
- [ ] `examples/performance_tuning.py` - Optimization tips
- [ ] `examples/docker_deployment.py` - Container setup

---

### P5.3: Community Building

**Week 1-4**:
- [ ] Create GitHub Discussions
- [ ] Write launch blog post
- [ ] Submit to Python Weekly
- [ ] Tweet at E2B team
- [ ] Post on Hacker News
- [ ] Submit to r/Python, r/MachineLearning

**Month 1-3**:
- [ ] Respond to all GitHub issues within 24h
- [ ] Merge community PRs within 1 week
- [ ] Release monthly updates
- [ ] Publish case studies

**Success Metrics**:
| Metric | Month 1 | Month 3 | Month 6 |
|--------|---------|---------|---------|
| GitHub Stars | 100 | 500 | 2,000 |
| Contributors | 3 | 10 | 25 |
| Closed Issues | 10 | 50 | 200 |
| PyPI Downloads | 500 | 5,000 | 25,000 |

---

## Implementation Priority Matrix

| Feature | Impact | Effort | Priority |
|---------|--------|--------|----------|
| Fix Audit Logging | HIGH | LOW | **P0** |
| Fix Async Support | HIGH | MEDIUM | **P0** |
| Coverage Verification | MEDIUM | LOW | **P0** |
| Streaming Support | HIGH | HIGH | P1 |
| RunContext Preservation | HIGH | MEDIUM | **P1** |
| Dynamic Policy Resolution | MEDIUM | LOW | P1 |
| Performance Benchmarks | MEDIUM | MEDIUM | P2 |
| Integration Tests | HIGH | HIGH | **P2** |
| Error Recovery Hooks | MEDIUM | LOW | P2 |
| Conversation Tracking | MEDIUM | HIGH | P3 |
| Workspace PII Rules | LOW | MEDIUM | P3 |
| Azure Compatibility | MEDIUM | LOW | **P3** |
| Security Audit | HIGH | MEDIUM | **P4** |

---

## Timeline

```
Week 1: Phase 0 - Critical Fixes
├── P0.1: Audit Logging Implementation
├── P0.2: Async Function Support
└── P0.3: Coverage Verification

Week 2: Phase 1 - Core Features
├── P1.1: Streaming Support
├── P1.2: RunContext Preservation
└── P1.3: Dynamic Policy Resolution

Week 3: Phase 2 - Hardening
├── P2.1: Performance Benchmarks
├── P2.2: Integration Tests
└── P2.3: Error Recovery Hooks

Week 4: Phase 3 - Enterprise
├── P3.1: Conversation Tracking
├── P3.2: Workspace PII Rules
└── P3.3: Azure Compatibility

Week 5: Phase 4 - Security
├── P4.1: Security Audit
├── P4.2: Compliance Docs
└── P4.3: SBOM

Week 6+: Phase 5 - Community
├── P5.1: Documentation
├── P5.2: Examples
└── P5.3: Adoption
```

---

## Success Criteria

### Before calling it "Production Ready":

- [ ] Audit logging actually writes to disk
- [ ] Async functions work correctly
- [ ] Streaming functions work correctly
- [ ] RunContext preserved across boundaries
- [ ] 80%+ test coverage verified in CI
- [ ] Integration tests for 5 major frameworks
- [ ] Performance benchmarks published
- [ ] Security audit completed
- [ ] 50+ GitHub stars (community validation)
- [ ] 5+ closed issues (proven bug discovery/fix cycle)
- [ ] 1+ external contributor (not just author)

### Before recommending for "Enterprise Production":

- [ ] 500+ GitHub stars
- [ ] 10+ documented production users
- [ ] Independent security audit
- [ ] GDPR/CCPA compliance documented
- [ ] SLA for security patches
- [ ] LTS (Long Term Support) version

---

## Appendix: Honest README Update

The README should be updated to reflect reality:

```markdown
## Status

> **Beta (v0.1.x)**: Core features work. Some claimed features are incomplete.

| Feature | Status |
|---------|--------|
| Ghost Argument Validation | Production |
| PII/Secret Masking | Production |
| E2B Sandbox | Production |
| Audit Logging | **Config Only** |
| Async Support | **Partial** |
| Streaming | **Not Implemented** |
```

---

*Last Updated: 2026-01-31*
*Author: Sattyam Jain*
*Status: Draft - Awaiting Implementation*
