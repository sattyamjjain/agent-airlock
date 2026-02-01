"""Tests for V0.4.0 new features (circuit breaker, cost tracking, retry, observability)."""

from __future__ import annotations

import time
from decimal import Decimal

import pytest

from agent_airlock.circuit_breaker import (
    AGGRESSIVE_BREAKER,
    CONSERVATIVE_BREAKER,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerError,
    CircuitState,
    get_circuit_breaker,
    reset_all_circuit_breakers,
)
from agent_airlock.cost_tracking import (
    BudgetConfig,
    BudgetExceededError,
    CostRecord,
    CostSummary,
    CostTracker,
    TokenUsage,
    get_global_tracker,
)
from agent_airlock.observability import (
    NoOpProvider,
    OpenTelemetryProvider,
    SpanContext,
    end_span,
    get_provider,
    observe,
    start_span,
)
from agent_airlock.observability import (
    configure as configure_observability,
)
from agent_airlock.retry import (
    FAST_RETRY,
    NO_RETRY,
    STANDARD_RETRY,
    RetryConfig,
    RetryExhaustedError,
    RetryPolicy,
    calculate_delay,
    retry,
    should_retry,
)


class TestCircuitBreaker:
    """Tests for circuit breaker pattern."""

    def test_circuit_starts_closed(self) -> None:
        """Test circuit starts in closed state."""
        breaker = CircuitBreaker("test")
        assert breaker.state == CircuitState.CLOSED

    def test_circuit_opens_after_failures(self) -> None:
        """Test circuit opens after failure threshold."""
        config = CircuitBreakerConfig(failure_threshold=3, timeout=1.0)
        breaker = CircuitBreaker("test-open", config)

        for _ in range(3):
            with pytest.raises(ValueError):
                with breaker:
                    raise ValueError("fail")

        assert breaker.state == CircuitState.OPEN

    def test_circuit_blocks_when_open(self) -> None:
        """Test circuit blocks calls when open."""
        config = CircuitBreakerConfig(failure_threshold=1, timeout=10.0)
        breaker = CircuitBreaker("test-block", config)

        with pytest.raises(ValueError):
            with breaker:
                raise ValueError("fail")

        with pytest.raises(CircuitBreakerError):
            with breaker:
                pass

    def test_circuit_transitions_to_half_open(self) -> None:
        """Test circuit transitions to half-open after timeout."""
        config = CircuitBreakerConfig(failure_threshold=1, timeout=0.1)
        breaker = CircuitBreaker("test-half", config)

        with pytest.raises(ValueError):
            with breaker:
                raise ValueError("fail")

        time.sleep(0.15)
        assert breaker.state == CircuitState.HALF_OPEN

    def test_circuit_closes_after_success(self) -> None:
        """Test circuit closes after success in half-open."""
        config = CircuitBreakerConfig(failure_threshold=1, success_threshold=1, timeout=0.1)
        breaker = CircuitBreaker("test-close", config)

        with pytest.raises(ValueError):
            with breaker:
                raise ValueError("fail")

        time.sleep(0.15)

        with breaker:
            pass

        assert breaker.state == CircuitState.CLOSED

    def test_circuit_stats(self) -> None:
        """Test circuit statistics."""
        breaker = CircuitBreaker("test-stats")

        with breaker:
            pass

        stats = breaker.stats
        assert stats.total_calls == 1
        assert stats.total_successes == 1

    def test_decorator_pattern(self) -> None:
        """Test circuit breaker as decorator."""
        breaker = CircuitBreaker("test-decorator")

        @breaker
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(5)
        assert result == 10

    def test_get_circuit_breaker(self) -> None:
        """Test global circuit breaker registry."""
        reset_all_circuit_breakers()
        breaker1 = get_circuit_breaker("shared")
        breaker2 = get_circuit_breaker("shared")
        assert breaker1 is breaker2

    def test_predefined_configs(self) -> None:
        """Test predefined configurations."""
        assert AGGRESSIVE_BREAKER.failure_threshold == 3
        assert CONSERVATIVE_BREAKER.failure_threshold == 10

    def test_listener_error_callback(self) -> None:
        """Test on_listener_error callback is invoked when listener fails."""
        errors: list[tuple[str, Exception]] = []

        def capture_error(listener_name: str, error: Exception) -> None:
            errors.append((listener_name, error))

        config = CircuitBreakerConfig(
            failure_threshold=3,
            on_listener_error=capture_error,
        )
        breaker = CircuitBreaker("test-listener-error", config)

        # Add a failing listener
        def failing_listener(name: str, old: CircuitState, new: CircuitState) -> None:
            raise RuntimeError("Listener exploded")

        breaker.add_listener(failing_listener)

        # Trigger state transition via failures
        for _ in range(3):
            with pytest.raises(ValueError):
                with breaker:
                    raise ValueError("fail")

        # Callback should have been invoked
        assert len(errors) == 1
        assert errors[0][0] == "failing_listener"
        assert isinstance(errors[0][1], RuntimeError)

    def test_listener_error_does_not_propagate(self) -> None:
        """Test listener errors don't affect circuit operation."""
        config = CircuitBreakerConfig(failure_threshold=1, timeout=0.1)
        breaker = CircuitBreaker("test-listener-no-propagate", config)

        def bad_listener(name: str, old: CircuitState, new: CircuitState) -> None:
            raise RuntimeError("Should not propagate")

        breaker.add_listener(bad_listener)

        # This should open the circuit, listener error should be caught
        with pytest.raises(ValueError):
            with breaker:
                raise ValueError("fail")

        # Circuit should still be open despite listener error
        assert breaker.state == CircuitState.OPEN

    def test_listener_error_callback_error_is_swallowed(self) -> None:
        """Test errors in the error callback itself are swallowed."""

        def bad_callback(listener_name: str, error: Exception) -> None:
            raise RuntimeError("Callback also fails")

        config = CircuitBreakerConfig(
            failure_threshold=1,
            on_listener_error=bad_callback,
        )
        breaker = CircuitBreaker("test-callback-error", config)

        def failing_listener(name: str, old: CircuitState, new: CircuitState) -> None:
            raise RuntimeError("Listener fails")

        breaker.add_listener(failing_listener)

        # Should not raise, callback error is swallowed
        with pytest.raises(ValueError):
            with breaker:
                raise ValueError("fail")

        assert breaker.state == CircuitState.OPEN


class TestCostTracking:
    """Tests for cost tracking."""

    def test_token_usage(self) -> None:
        """Test TokenUsage dataclass."""
        usage = TokenUsage(input_tokens=100, output_tokens=50)
        assert usage.total_tokens == 150

    def test_cost_record(self) -> None:
        """Test CostRecord dataclass."""
        usage = TokenUsage(input_tokens=100, output_tokens=50)
        record = CostRecord(
            tool_name="test_tool",
            timestamp=time.time(),
            tokens=usage,
            cost_usd=Decimal("0.01"),
        )
        assert record.tool_name == "test_tool"
        result = record.to_dict()
        assert "tool_name" in result

    def test_cost_tracker_record(self) -> None:
        """Test recording costs."""
        tracker = CostTracker(model="default")
        tokens = TokenUsage(input_tokens=1000, output_tokens=500)
        record = tracker.record("test_tool", tokens)
        assert record.cost_usd > Decimal("0")

    def test_cost_tracker_summary(self) -> None:
        """Test cost summary."""
        tracker = CostTracker()
        tracker.record("tool1", TokenUsage(input_tokens=100))
        tracker.record("tool2", TokenUsage(input_tokens=200))

        summary = tracker.get_summary()
        assert summary.total_calls == 2
        assert summary.total_input_tokens == 300

    def test_budget_per_call_limit(self) -> None:
        """Test per-call budget limit."""
        budget = BudgetConfig(max_cost_per_call=Decimal("0.0001"))
        tracker = CostTracker(budget=budget)

        with pytest.raises(BudgetExceededError):
            tracker.record("expensive", TokenUsage(input_tokens=100000, output_tokens=100000))

    def test_cost_context_manager(self) -> None:
        """Test cost tracking context manager."""
        tracker = CostTracker()

        with tracker.track("my_tool") as ctx:
            ctx.set_tokens(input_tokens=100, output_tokens=50)

        summary = tracker.get_summary()
        assert summary.total_calls == 1

    def test_global_tracker(self) -> None:
        """Test global tracker."""
        tracker = get_global_tracker()
        assert tracker is not None


class TestRetryPolicy:
    """Tests for retry policies."""

    def test_calculate_delay(self) -> None:
        """Test delay calculation."""
        config = RetryConfig(base_delay=1.0, exponential_base=2.0, jitter=False)
        delay0 = calculate_delay(0, config)
        delay1 = calculate_delay(1, config)
        assert delay0 == 1.0
        assert delay1 == 2.0

    def test_should_retry(self) -> None:
        """Test retry condition."""
        config = RetryConfig(max_retries=3, retryable_exceptions=(ValueError,))
        assert should_retry(ValueError(), 0, config) is True
        assert should_retry(ValueError(), 3, config) is False
        assert should_retry(TypeError(), 0, config) is False

    def test_retry_succeeds(self) -> None:
        """Test successful retry."""
        policy = RetryPolicy(RetryConfig(max_retries=3, base_delay=0.01))
        counter = {"count": 0}

        def flaky_func() -> str:
            counter["count"] += 1
            if counter["count"] < 3:
                raise ValueError("not yet")
            return "success"

        result = policy.execute(flaky_func)
        assert result == "success"
        assert counter["count"] == 3

    def test_retry_exhausted(self) -> None:
        """Test retry exhaustion."""
        policy = RetryPolicy(RetryConfig(max_retries=2, base_delay=0.01))

        def always_fails() -> None:
            raise ValueError("always")

        with pytest.raises(RetryExhaustedError) as exc_info:
            policy.execute(always_fails)

        assert exc_info.value.attempts == 3  # Initial + 2 retries

    def test_retry_decorator(self) -> None:
        """Test retry as decorator."""
        counter = {"count": 0}

        @retry(max_retries=2, base_delay=0.01)
        def flaky() -> str:
            counter["count"] += 1
            if counter["count"] < 2:
                raise ValueError("retry me")
            return "done"

        result = flaky()
        assert result == "done"

    def test_predefined_configs(self) -> None:
        """Test predefined configurations."""
        assert NO_RETRY.max_retries == 0
        assert FAST_RETRY.base_delay == 0.1
        assert STANDARD_RETRY.max_retries == 3


class TestObservability:
    """Tests for observability."""

    def test_span_context(self) -> None:
        """Test SpanContext dataclass."""
        span = SpanContext(name="test", tool_name="my_tool")
        assert span.name == "test"
        assert span.status == "ok"

    def test_span_attributes(self) -> None:
        """Test span attribute setting."""
        span = SpanContext(name="test", tool_name="tool")
        span.set_attribute("key", "value")
        assert span.attributes["key"] == "value"

    def test_span_events(self) -> None:
        """Test span events."""
        span = SpanContext(name="test", tool_name="tool")
        span.add_event("something_happened", {"detail": "info"})
        assert len(span.events) == 1
        assert span.events[0]["name"] == "something_happened"

    def test_span_error(self) -> None:
        """Test span error setting."""
        span = SpanContext(name="test", tool_name="tool")
        span.set_error(ValueError("test error"))
        assert span.status == "error"
        assert span.error == "test error"

    def test_span_duration(self) -> None:
        """Test span duration."""
        span = SpanContext(name="test", tool_name="tool")
        time.sleep(0.05)
        span.finish()
        assert span.duration_ms >= 50

    def test_noop_provider(self) -> None:
        """Test NoOp provider."""
        provider = NoOpProvider()
        span = provider.start_span("test", "tool")
        provider.end_span(span)
        provider.record_metric("metric", 1.0)
        provider.track_event("event")

    def test_otel_provider_without_otel(self) -> None:
        """Test OTEL provider gracefully handles missing package."""
        provider = OpenTelemetryProvider()
        span = provider.start_span("test", "tool")
        provider.end_span(span)

    def test_configure_provider(self) -> None:
        """Test global provider configuration."""
        provider = NoOpProvider()
        configure_observability(provider)
        assert get_provider() is provider

    def test_observe_context_manager(self) -> None:
        """Test observe as context manager."""
        configure_observability(NoOpProvider())

        with observe("operation", tool_name="tool") as span:
            span.set_attribute("key", "value")

        assert span.end_time is not None

    def test_observe_decorator(self) -> None:
        """Test observe as decorator."""
        configure_observability(NoOpProvider())

        @observe("my_operation")
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(5)
        assert result == 10

    def test_global_functions(self) -> None:
        """Test global observability functions."""
        configure_observability(NoOpProvider())
        span = start_span("test", "tool")
        end_span(span)


class TestIntegrations:
    """Tests for framework integrations."""

    def test_langchain_integration_imports(self) -> None:
        """Test LangChain integration imports."""
        from agent_airlock.integrations.langchain import (
            AirlockCallbackHandler,
            SecureToolkit,
            secure_tool,
        )

        assert secure_tool is not None
        assert AirlockCallbackHandler is not None
        assert SecureToolkit is not None

    def test_anthropic_integration_imports(self) -> None:
        """Test Anthropic integration imports."""
        from agent_airlock.integrations.anthropic import (
            ToolRegistry,
            secure_tool,
        )

        assert secure_tool is not None
        assert ToolRegistry is not None

    def test_openai_guardrails_imports(self) -> None:
        """Test OpenAI guardrails integration imports."""
        from agent_airlock.integrations.openai_guardrails import (
            AirlockGuardrails,
            GuardrailResult,
            PIIGuardrail,
            PolicyGuardrail,
        )

        assert AirlockGuardrails is not None
        assert GuardrailResult is not None
        assert PIIGuardrail is not None
        assert PolicyGuardrail is not None

    def test_pii_guardrail(self) -> None:
        """Test PII guardrail."""
        from agent_airlock.integrations.openai_guardrails import PIIGuardrail

        guardrail = PIIGuardrail()
        result = guardrail.check("My email is test@example.com")
        assert result.passed is False
        assert "email" in (result.violations or [])

    def test_guardrail_result(self) -> None:
        """Test GuardrailResult."""
        from agent_airlock.integrations.openai_guardrails import GuardrailResult

        result = GuardrailResult(passed=True)
        assert result.passed is True
        assert result.message is None


class TestFileMounting:
    """Tests for file mounting in sandbox."""

    def test_mounted_file_dataclass(self) -> None:
        """Test MountedFile dataclass."""
        from agent_airlock.sandbox import MountedFile

        # With content
        file = MountedFile(
            local_path="test.txt",
            sandbox_path="/sandbox/test.txt",
            content=b"test content",
        )
        assert file.get_content() == b"test content"

    def test_mounted_file_from_local(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """Test MountedFile reading from local file."""
        from agent_airlock.sandbox import MountedFile

        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")

        file = MountedFile(
            local_path=str(test_file),
            sandbox_path="/sandbox/test.txt",
        )
        assert file.get_content() == b"hello world"


class TestLangChainIntegration:
    """Extended tests for LangChain integration."""

    def test_secure_tool_decorator(self) -> None:
        """Test secure_tool decorator factory."""
        from agent_airlock.integrations.langchain import secure_tool

        @secure_tool()
        def my_tool(x: int) -> int:
            return x * 2

        result = my_tool(x=5)
        assert result == 10

    def test_callback_handler_init(self) -> None:
        """Test AirlockCallbackHandler initialization."""
        from agent_airlock.integrations.langchain import AirlockCallbackHandler

        handler = AirlockCallbackHandler(log_inputs=True, log_outputs=True)
        assert handler.log_inputs is True
        assert handler.log_outputs is True

    def test_callback_handler_tool_start(self) -> None:
        """Test on_tool_start callback."""
        from agent_airlock.integrations.langchain import AirlockCallbackHandler

        handler = AirlockCallbackHandler(log_inputs=True)
        handler.on_tool_start({"name": "test_tool"}, "test input")
        # Should not raise

    def test_callback_handler_tool_end(self) -> None:
        """Test on_tool_end callback."""
        from agent_airlock.integrations.langchain import AirlockCallbackHandler

        handler = AirlockCallbackHandler(log_outputs=True)
        handler.on_tool_end("test output")
        # Should not raise

    def test_callback_handler_tool_error(self) -> None:
        """Test on_tool_error callback."""
        from agent_airlock.integrations.langchain import AirlockCallbackHandler

        handler = AirlockCallbackHandler()
        handler.on_tool_error(ValueError("test error"))
        # Should not raise

    def test_secure_toolkit_init(self) -> None:
        """Test SecureToolkit initialization."""
        from agent_airlock.integrations.langchain import SecureToolkit
        from agent_airlock.policy import STRICT_POLICY

        toolkit = SecureToolkit(policy=STRICT_POLICY, sandbox=False)
        assert toolkit.policy is STRICT_POLICY
        assert toolkit.sandbox is False


class TestAnthropicIntegration:
    """Extended tests for Anthropic integration."""

    def test_secure_tool_decorator(self) -> None:
        """Test Anthropic secure_tool decorator."""
        from agent_airlock.integrations.anthropic import secure_tool

        @secure_tool()
        def get_weather(location: str) -> str:
            return f"Weather in {location}: Sunny"

        result = get_weather(location="NYC")
        assert "NYC" in result

    def test_tool_registry_init(self) -> None:
        """Test ToolRegistry initialization."""
        from agent_airlock.integrations.anthropic import ToolRegistry
        from agent_airlock.policy import STRICT_POLICY

        registry = ToolRegistry(policy=STRICT_POLICY)
        assert registry.policy is STRICT_POLICY

    def test_tool_registry_register(self) -> None:
        """Test registering tools in registry."""
        from agent_airlock.integrations.anthropic import ToolRegistry

        registry = ToolRegistry()

        @registry.tool(name="get_time", description="Get current time")
        def get_time() -> str:
            return "12:00"

        assert "get_time" in registry._tools
        assert "get_time" in registry._schemas

    def test_tool_registry_get_definitions(self) -> None:
        """Test getting tool definitions."""
        from agent_airlock.integrations.anthropic import ToolRegistry

        registry = ToolRegistry()

        @registry.tool()
        def my_tool(arg: str) -> str:
            """Does something."""
            return arg

        definitions = registry.get_tool_definitions()
        assert len(definitions) == 1
        assert definitions[0]["name"] == "my_tool"

    def test_tool_registry_execute(self) -> None:
        """Test executing tools from registry."""
        from agent_airlock.integrations.anthropic import ToolRegistry

        registry = ToolRegistry()

        @registry.tool()
        def add_numbers(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        result = registry.execute_tool("add_numbers", {"a": 5, "b": 3})
        assert result == 8

    def test_tool_registry_execute_unknown(self) -> None:
        """Test executing unknown tool raises KeyError."""
        from agent_airlock.integrations.anthropic import ToolRegistry

        registry = ToolRegistry()

        with pytest.raises(KeyError, match="Unknown tool"):
            registry.execute_tool("nonexistent", {})

    def test_python_type_to_json_mapping(self) -> None:
        """Test Python type to JSON schema type mapping."""
        from agent_airlock.integrations.anthropic import ToolRegistry

        registry = ToolRegistry()
        assert registry._python_type_to_json(str) == "string"
        assert registry._python_type_to_json(int) == "integer"
        assert registry._python_type_to_json(float) == "number"
        assert registry._python_type_to_json(bool) == "boolean"
        assert registry._python_type_to_json(list) == "array"
        assert registry._python_type_to_json(dict) == "object"


class TestOpenAIGuardrailsIntegration:
    """Extended tests for OpenAI Guardrails integration."""

    def test_policy_guardrail(self) -> None:
        """Test PolicyGuardrail."""
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail
        from agent_airlock.policy import READ_ONLY_POLICY

        guardrail = PolicyGuardrail(READ_ONLY_POLICY, tool_name="read_file")
        result = guardrail.check({})
        assert result.passed is True

    def test_policy_guardrail_denied_tool(self) -> None:
        """Test PolicyGuardrail with denied tool."""
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail
        from agent_airlock.policy import SecurityPolicy

        policy = SecurityPolicy(denied_tools=["delete_*"])
        guardrail = PolicyGuardrail(policy, tool_name="delete_file")
        result = guardrail.check({})
        assert result.passed is False
        assert "denied" in result.violations[0]

    def test_airlock_guardrails_init(self) -> None:
        """Test AirlockGuardrails initialization."""
        from agent_airlock.integrations.openai_guardrails import AirlockGuardrails

        guardrails = AirlockGuardrails(detect_pii=True, pii_action="block")
        assert guardrails.detect_pii is True
        assert guardrails.pii_action == "block"

    def test_airlock_guardrails_secure_tool(self) -> None:
        """Test securing a tool with AirlockGuardrails."""
        from agent_airlock.integrations.openai_guardrails import AirlockGuardrails

        guardrails = AirlockGuardrails()

        @guardrails.secure_tool
        def my_tool(x: int) -> int:
            return x * 2

        assert "my_tool" in guardrails._tools
        result = my_tool(x=5)
        assert result == 10

    def test_airlock_guardrails_get_output_guardrails(self) -> None:
        """Test getting output guardrails."""
        from agent_airlock.integrations.openai_guardrails import AirlockGuardrails

        guardrails = AirlockGuardrails(detect_pii=True)

        @guardrails.secure_tool
        def test_tool() -> str:
            return "test"

        output_guardrails = guardrails.get_output_guardrails()
        assert len(output_guardrails) == 1

    def test_pii_guardrail_no_pii(self) -> None:
        """Test PIIGuardrail with clean input."""
        from agent_airlock.integrations.openai_guardrails import PIIGuardrail

        guardrail = PIIGuardrail()
        result = guardrail.check("Hello, this is a normal message")
        assert result.passed is True

    def test_pii_guardrail_with_phone(self) -> None:
        """Test PIIGuardrail with phone number."""
        from agent_airlock.integrations.openai_guardrails import PIIGuardrail

        guardrail = PIIGuardrail()
        result = guardrail.check("Call me at 555-123-4567")
        assert result.passed is False

    def test_pii_guardrail_warn_mode(self) -> None:
        """Test PIIGuardrail in warn mode."""
        from agent_airlock.integrations.openai_guardrails import PIIGuardrail

        guardrail = PIIGuardrail(action="warn")
        result = guardrail.check("Call me at 555-123-4567")
        # Warn mode should pass but still report violation
        assert result.passed is True
        assert result.violations is not None

    def test_guardrail_result_with_message(self) -> None:
        """Test GuardrailResult with message."""
        from agent_airlock.integrations.openai_guardrails import GuardrailResult

        result = GuardrailResult(passed=False, message="Blocked", violations=["pii"])
        assert result.passed is False
        assert result.message == "Blocked"
        assert "pii" in result.violations

    def test_policy_guardrail_pattern_matching(self) -> None:
        """Test PolicyGuardrail pattern matching."""
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail
        from agent_airlock.policy import SecurityPolicy

        policy = SecurityPolicy(allowed_tools=["read_*"])
        guardrail = PolicyGuardrail(policy, tool_name="read_file")
        result = guardrail.check({})
        assert result.passed is True

    def test_policy_guardrail_wildcard(self) -> None:
        """Test PolicyGuardrail wildcard pattern."""
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail
        from agent_airlock.policy import SecurityPolicy

        policy = SecurityPolicy(allowed_tools=["*"])
        guardrail = PolicyGuardrail(policy, tool_name="any_tool")
        result = guardrail.check({})
        assert result.passed is True


class TestRetryExtended:
    """Extended tests for retry module."""

    def test_retry_with_jitter(self) -> None:
        """Test delay calculation with jitter."""
        from agent_airlock.retry import RetryConfig, calculate_delay

        config = RetryConfig(base_delay=1.0, jitter=True)
        delays = [calculate_delay(0, config) for _ in range(10)]
        # With jitter, delays should vary
        assert len(set(delays)) > 1  # Some variation expected

    def test_retry_state_dataclass(self) -> None:
        """Test RetryState dataclass."""
        from agent_airlock.retry import RetryState

        state = RetryState()
        assert state.attempt == 0
        assert state.last_exception is None
        assert state.exceptions == []

    def test_retry_policy_simple(self) -> None:
        """Test RetryPolicy simple execution."""
        from agent_airlock.retry import RetryConfig, RetryPolicy

        config = RetryConfig(max_retries=2, base_delay=0.01)
        policy = RetryPolicy(config)

        counter = {"count": 0}

        def fail_once() -> str:
            counter["count"] += 1
            if counter["count"] == 1:
                raise ValueError("first")
            return "success"

        result = policy.execute(fail_once)
        assert result == "success"

    def test_retry_non_retryable_exception(self) -> None:
        """Test non-retryable exception is not retried."""
        from agent_airlock.retry import RetryConfig, RetryPolicy

        config = RetryConfig(max_retries=3, base_delay=0.01, retryable_exceptions=(ValueError,))
        policy = RetryPolicy(config)

        counter = {"count": 0}

        def fail_with_type_error() -> None:
            counter["count"] += 1
            raise TypeError("not retryable")

        with pytest.raises(TypeError):
            policy.execute(fail_with_type_error)

        # Should only have tried once since TypeError is not retryable
        assert counter["count"] == 1


class TestObservabilityExtended:
    """Extended tests for observability module."""

    def test_span_to_dict(self) -> None:
        """Test span serialization."""
        from agent_airlock.observability import SpanContext

        span = SpanContext(name="test", tool_name="my_tool")
        span.set_attribute("key", "value")
        span.add_event("event1", {"detail": "info"})
        span.finish()

        assert span.end_time is not None
        assert span.attributes["key"] == "value"
        assert len(span.events) == 1

    def test_observe_with_error(self) -> None:
        """Test observe captures errors."""
        from agent_airlock.observability import NoOpProvider, configure, observe

        configure(NoOpProvider())

        span_ref = {}

        try:
            with observe("error_op", tool_name="tool") as span:
                span_ref["span"] = span
                raise ValueError("test error")
        except ValueError:
            pass

        assert span_ref["span"].status == "error"
        assert span_ref["span"].error == "test error"

    def test_observe_decorator_with_args(self) -> None:
        """Test observe decorator with record_args."""
        from agent_airlock.observability import NoOpProvider, configure, observe

        configure(NoOpProvider())

        @observe("my_op", record_args=True)
        def my_func(a: int, b: str) -> str:
            return f"{a}-{b}"

        result = my_func(1, b="test")
        assert result == "1-test"

    def test_record_metric(self) -> None:
        """Test recording metrics."""
        from agent_airlock.observability import NoOpProvider, configure, record_metric

        configure(NoOpProvider())
        # Should not raise
        record_metric("test_metric", 42.0, tags={"env": "test"})

    def test_track_event(self) -> None:
        """Test tracking events."""
        from agent_airlock.observability import NoOpProvider, configure, track_event

        configure(NoOpProvider())
        # Should not raise
        track_event("test_event", {"key": "value"})


class TestCostTrackingExtended:
    """Extended tests for cost tracking module."""

    def test_cost_summary_to_dict(self) -> None:
        """Test CostSummary serialization."""

        summary = CostSummary(
            total_calls=5,
            total_input_tokens=1000,
            total_output_tokens=500,
        )
        data = summary.to_dict()
        assert data["total_calls"] == 5
        assert data["total_input_tokens"] == 1000

    def test_budget_tokens_per_call_limit(self) -> None:
        """Test per-call token budget limit."""

        from agent_airlock.cost_tracking import (
            BudgetConfig,
            BudgetExceededError,
            CostTracker,
            TokenUsage,
        )

        budget = BudgetConfig(max_tokens_per_call=100)
        tracker = CostTracker(budget=budget)

        # Exceeds per-call token limit
        with pytest.raises(BudgetExceededError):
            tracker.record("tool1", TokenUsage(input_tokens=150, output_tokens=50))

    def test_cost_tracker_by_tool(self) -> None:
        """Test getting costs by tool."""
        from agent_airlock.cost_tracking import CostTracker, TokenUsage

        tracker = CostTracker()
        tracker.record("tool1", TokenUsage(input_tokens=100))
        tracker.record("tool1", TokenUsage(input_tokens=200))
        tracker.record("tool2", TokenUsage(input_tokens=150))

        summary = tracker.get_summary()
        assert summary.total_calls == 3
        assert summary.total_input_tokens == 450


class TestCircuitBreakerExtended:
    """Extended tests for circuit breaker module."""

    def test_circuit_breaker_manual_reset(self) -> None:
        """Test manual circuit reset."""
        from agent_airlock.circuit_breaker import (
            CircuitBreaker,
            CircuitBreakerConfig,
            CircuitState,
        )

        config = CircuitBreakerConfig(failure_threshold=1, timeout=100.0)
        breaker = CircuitBreaker("test-reset", config)

        # Cause failure to open circuit
        with pytest.raises(ValueError):
            with breaker:
                raise ValueError("fail")

        assert breaker.state == CircuitState.OPEN

        # Manual reset
        breaker.reset()
        assert breaker.state == CircuitState.CLOSED

    def test_circuit_breaker_stats_reset(self) -> None:
        """Test circuit stats tracking."""
        from agent_airlock.circuit_breaker import CircuitBreaker

        breaker = CircuitBreaker("test-stats-reset")

        # Some successful calls
        for _ in range(5):
            with breaker:
                pass

        stats = breaker.stats
        assert stats.total_calls == 5
        assert stats.total_successes == 5
        assert stats.total_failures == 0

    def test_get_all_circuit_breakers(self) -> None:
        """Test getting all circuit breakers."""
        from agent_airlock.circuit_breaker import (
            get_all_circuit_breakers,
            get_circuit_breaker,
            reset_all_circuit_breakers,
        )

        reset_all_circuit_breakers()
        get_circuit_breaker("breaker1")
        get_circuit_breaker("breaker2")

        all_breakers = get_all_circuit_breakers()
        assert "breaker1" in all_breakers
        assert "breaker2" in all_breakers


class TestAuditOtel:
    """Tests for OTEL audit exporter."""

    def test_enhanced_audit_record(self) -> None:
        """Test EnhancedAuditRecord creation."""
        from agent_airlock.audit_otel import EnhancedAuditRecord

        record = EnhancedAuditRecord(
            timestamp="2026-02-01T00:00:00Z",
            tool_name="test_tool",
            blocked=False,
        )
        assert record.tool_name == "test_tool"
        assert record.blocked is False

    def test_create_enhanced_record(self) -> None:
        """Test creating enhanced record from function."""
        from agent_airlock.audit_otel import create_enhanced_record

        record = create_enhanced_record(
            tool_name="test",
            blocked=True,
            args={"key": "value"},
        )
        assert record.tool_name == "test"
        assert record.blocked is True


class TestMCPProxyGuard:
    """Tests for MCP Proxy Guard."""

    def test_mcp_session(self) -> None:
        """Test MCPSession creation."""
        from agent_airlock.mcp_proxy_guard import MCPSession

        session = MCPSession(session_id="test-123", user_id="user-1")
        assert session.session_id == "test-123"
        assert session.user_id == "user-1"

    def test_proxy_config(self) -> None:
        """Test MCPProxyConfig creation."""
        from agent_airlock.mcp_proxy_guard import MCPProxyConfig

        config = MCPProxyConfig(block_token_passthrough=True)
        assert config.block_token_passthrough is True

    def test_predefined_proxy_configs(self) -> None:
        """Test predefined proxy configurations."""
        from agent_airlock.mcp_proxy_guard import (
            DEFAULT_PROXY_CONFIG,
            PERMISSIVE_PROXY_CONFIG,
            STRICT_PROXY_CONFIG,
        )

        assert DEFAULT_PROXY_CONFIG is not None
        assert STRICT_PROXY_CONFIG.block_token_passthrough is True
        assert PERMISSIVE_PROXY_CONFIG is not None

    def test_mcp_session_methods(self) -> None:
        """Test MCPSession methods."""
        from agent_airlock.mcp_proxy_guard import MCPSession

        session = MCPSession(session_id="test")
        session.add_consent("tool1")
        assert session.has_consent("tool1") is True
        assert session.has_consent("tool2") is False
        session.touch()
        assert session.last_activity > 0


class TestSandboxBackend:
    """Tests for sandbox backend."""

    def test_sandbox_result(self) -> None:
        """Test SandboxResult creation."""
        from agent_airlock.sandbox_backend import SandboxResult

        result = SandboxResult(
            success=True,
            result="test output",
            stdout="",
            stderr="",
        )
        assert result.success is True
        assert result.result == "test output"

    def test_local_backend_init(self) -> None:
        """Test LocalBackend initialization."""
        from agent_airlock.sandbox_backend import LocalBackend

        backend = LocalBackend(allow_unsafe=True)
        assert backend is not None

    def test_get_default_backend(self) -> None:
        """Test getting default sandbox backend."""
        from agent_airlock.sandbox_backend import get_default_backend

        backend = get_default_backend()
        assert backend is not None


class TestCapabilities:
    """Tests for capability system."""

    def test_capability_flag(self) -> None:
        """Test Capability flag values."""
        from agent_airlock.capabilities import Capability

        # Capability is a Flag enum
        assert Capability.FILESYSTEM_READ is not None
        assert Capability.NETWORK_HTTPS is not None
        # Combine with |
        combined = Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS
        assert Capability.FILESYSTEM_READ in combined

    def test_capability_policy(self) -> None:
        """Test CapabilityPolicy."""
        from agent_airlock.capabilities import Capability, CapabilityPolicy

        policy = CapabilityPolicy(
            granted=Capability.FILESYSTEM_READ,
            denied=Capability.PROCESS_SHELL,
        )
        assert policy.granted is not None
        assert policy.denied is not None

    def test_predefined_capability_policies(self) -> None:
        """Test predefined capability policies."""
        from agent_airlock.capabilities import (
            NO_NETWORK_CAPABILITY_POLICY,
            PERMISSIVE_CAPABILITY_POLICY,
            READ_ONLY_CAPABILITY_POLICY,
            STRICT_CAPABILITY_POLICY,
        )

        assert PERMISSIVE_CAPABILITY_POLICY is not None
        assert STRICT_CAPABILITY_POLICY is not None
        assert READ_ONLY_CAPABILITY_POLICY is not None
        assert NO_NETWORK_CAPABILITY_POLICY is not None

    def test_capabilities_to_list(self) -> None:
        """Test converting capabilities to list."""
        from agent_airlock.capabilities import Capability, capabilities_to_list

        caps = Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS
        cap_list = capabilities_to_list(caps)
        assert isinstance(cap_list, list)

    def test_requires_decorator(self) -> None:
        """Test requires decorator."""
        from agent_airlock.capabilities import Capability, requires

        @requires(Capability.FILESYSTEM_READ)
        def read_file(path: str) -> str:
            return f"content of {path}"

        result = read_file("test.txt")
        assert "test.txt" in result

    def test_get_required_capabilities(self) -> None:
        """Test getting required capabilities from function."""
        from agent_airlock.capabilities import (
            Capability,
            get_required_capabilities,
            requires,
        )

        @requires(Capability.FILESYSTEM_READ)
        def my_func() -> None:
            pass

        caps = get_required_capabilities(my_func)
        assert caps is not None


class TestSafeTypes:
    """Tests for safe types."""

    def test_safe_path_basic(self) -> None:
        """Test SafePath basic creation."""

        # SafePath is a type alias, test the validator
        from agent_airlock.safe_types import SafePathValidator

        validator = SafePathValidator()
        assert validator is not None

    def test_safe_url_basic(self) -> None:
        """Test SafeURL basic creation."""
        from agent_airlock.safe_types import SafeURLValidator

        validator = SafeURLValidator()
        assert validator is not None

    def test_default_path_deny_patterns(self) -> None:
        """Test default deny patterns exist."""
        from agent_airlock.safe_types import DEFAULT_PATH_DENY_PATTERNS

        assert isinstance(DEFAULT_PATH_DENY_PATTERNS, (list, tuple))
        assert len(DEFAULT_PATH_DENY_PATTERNS) > 0


class TestUnknownArgsMode:
    """Tests for unknown args mode."""

    def test_unknown_args_modes(self) -> None:
        """Test UnknownArgsMode enum values."""
        from agent_airlock.unknown_args import UnknownArgsMode

        assert UnknownArgsMode.BLOCK is not None
        assert UnknownArgsMode.STRIP_AND_LOG is not None
        assert UnknownArgsMode.STRIP_SILENT is not None

    def test_mode_from_strict_bool(self) -> None:
        """Test converting strict_mode bool to UnknownArgsMode."""
        from agent_airlock.unknown_args import UnknownArgsMode, mode_from_strict_bool

        assert mode_from_strict_bool(True) == UnknownArgsMode.BLOCK
        assert mode_from_strict_bool(False) == UnknownArgsMode.STRIP_AND_LOG

    def test_predefined_modes(self) -> None:
        """Test predefined mode configurations."""
        from agent_airlock.unknown_args import (
            DEVELOPMENT_MODE,
            PRODUCTION_MODE,
            STAGING_MODE,
        )

        assert PRODUCTION_MODE is not None
        assert STAGING_MODE is not None
        assert DEVELOPMENT_MODE is not None
