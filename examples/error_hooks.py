"""Error Recovery Hooks Example - Custom error handling callbacks.

This example demonstrates how to use error recovery hooks to implement
custom error handling, logging, and alerting for Airlock events.

Run with: python examples/error_hooks.py
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import ValidationError

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy


# Simulated external services
class MetricsCollector:
    """Simulated metrics collection service."""

    def __init__(self) -> None:
        self.counters: Counter[str] = Counter()
        self.events: list[dict[str, Any]] = []

    def increment(self, metric: str) -> None:
        self.counters[metric] += 1

    def record_event(self, event: dict[str, Any]) -> None:
        self.events.append({"timestamp": datetime.now().isoformat(), **event})

    def print_summary(self) -> None:
        print("\nMetrics Summary:")
        for metric, count in self.counters.items():
            print(f"  {metric}: {count}")


class AlertService:
    """Simulated alerting service."""

    def __init__(self) -> None:
        self.alerts: list[str] = []

    def send_alert(self, message: str, severity: str = "warning") -> None:
        alert = f"[{severity.upper()}] {message}"
        self.alerts.append(alert)
        print(f"  ALERT: {alert}")


# Global instances
metrics = MetricsCollector()
alerts = AlertService()


# Error hook implementations
def on_validation_error(tool_name: str, error: ValidationError) -> None:
    """Handle validation errors.

    This hook is called when Pydantic validation fails.
    Use it to:
    - Log validation errors
    - Track error patterns
    - Alert on repeated errors
    """
    metrics.increment(f"validation_error.{tool_name}")
    metrics.record_event(
        {
            "type": "validation_error",
            "tool": tool_name,
            "error_count": error.error_count(),
            "errors": [e["msg"] for e in error.errors()],
        }
    )
    print(f"  Hook: Validation error in {tool_name} ({error.error_count()} errors)")


def on_blocked(tool_name: str, reason: str, context: dict[str, Any]) -> None:
    """Handle blocked tool calls.

    This hook is called when a tool call is blocked by policy.
    Use it to:
    - Log security events
    - Alert on suspicious activity
    - Track policy violations
    """
    metrics.increment(f"blocked.{tool_name}")
    metrics.record_event(
        {
            "type": "blocked",
            "tool": tool_name,
            "reason": reason,
            "context": context,
        }
    )

    # Send alert for potentially malicious activity
    if "ghost" in reason.lower():
        alerts.send_alert(
            f"Ghost arguments detected in {tool_name}: {context.get('ghost_args', [])}",
            severity="warning",
        )
    else:
        print(f"  Hook: Blocked {tool_name} - {reason[:50]}...")


def on_rate_limit(tool_name: str, retry_after: int) -> None:
    """Handle rate limit events.

    This hook is called when a rate limit is exceeded.
    Use it to:
    - Track rate limit hits
    - Implement backoff strategies
    - Alert on abuse patterns
    """
    metrics.increment(f"rate_limited.{tool_name}")
    metrics.record_event(
        {
            "type": "rate_limited",
            "tool": tool_name,
            "retry_after_seconds": retry_after,
        }
    )

    # Alert if rate limiting is happening frequently
    if metrics.counters[f"rate_limited.{tool_name}"] >= 3:
        alerts.send_alert(
            f"Repeated rate limiting on {tool_name} - possible abuse",
            severity="high",
        )
    else:
        print(f"  Hook: Rate limited {tool_name}, retry in {retry_after}s")


# Create config with hooks
config_with_hooks = AirlockConfig(
    strict_mode=True,
    on_validation_error=on_validation_error,
    on_blocked=on_blocked,
    on_rate_limit=on_rate_limit,
)


# Example tools
@Airlock(config=config_with_hooks)
def search_users(query: str, limit: int = 10) -> list[dict[str, str]]:
    """Search for users by name."""
    return [{"name": f"User matching '{query}'", "id": str(i)} for i in range(limit)]


# Tool with rate limiting
policy = SecurityPolicy(
    allowed_tools=["rate_limited_api"],
    rate_limits={"rate_limited_api": "2/minute"},  # Low limit for demo
)


@Airlock(config=config_with_hooks, policy=policy)
def rate_limited_api(endpoint: str) -> dict[str, str]:
    """An API with rate limiting."""
    return {"status": "ok", "endpoint": endpoint}


def demonstrate_validation_errors() -> None:
    """Demonstrate validation error hooks."""
    print("\n1. Validation Error Hooks:")
    print("-" * 40)

    # Trigger validation error with wrong type
    print("Calling search_users with invalid type...")
    result = search_users(query=123, limit="ten")  # type: ignore
    print(f"Result: {type(result).__name__}")


def demonstrate_blocked_calls() -> None:
    """Demonstrate blocked call hooks."""
    print("\n2. Blocked Call Hooks (Ghost Arguments):")
    print("-" * 40)

    # Trigger ghost argument block (strict mode)
    print("Calling search_users with ghost argument...")
    result = search_users(query="test", ghost_param="malicious")  # type: ignore
    print(f"Result: {type(result).__name__}")


def demonstrate_rate_limiting() -> None:
    """Demonstrate rate limit hooks."""
    print("\n3. Rate Limit Hooks:")
    print("-" * 40)

    print("Calling rate_limited_api multiple times...")
    for i in range(4):
        result = rate_limited_api(endpoint=f"/api/v1/resource/{i}")
        if isinstance(result, dict) and result.get("status") == "blocked":
            print(f"  Call {i + 1}: Rate limited")
        else:
            print(f"  Call {i + 1}: Success")


def demonstrate_chained_hooks() -> None:
    """Demonstrate hooks that trigger other actions."""
    print("\n4. Advanced: Chained Hooks:")
    print("-" * 40)

    # Custom hooks that implement more complex logic
    error_counts: dict[str, int] = {}

    def circuit_breaker_hook(tool_name: str, error: ValidationError) -> None:
        """Implement a circuit breaker pattern."""
        error_counts[tool_name] = error_counts.get(tool_name, 0) + 1

        if error_counts[tool_name] >= 3:
            alerts.send_alert(
                f"Circuit breaker triggered for {tool_name} after 3 errors",
                severity="critical",
            )
        else:
            print(f"  Circuit breaker: {tool_name} error count = {error_counts[tool_name]}")

    # Create new config with circuit breaker
    cb_config = AirlockConfig(
        on_validation_error=circuit_breaker_hook,
    )

    @Airlock(config=cb_config)
    def fragile_tool(x: int) -> int:
        return x * 2

    print("Triggering circuit breaker pattern...")
    for i in range(4):
        result = fragile_tool(x="bad")  # type: ignore
        print(f"  Attempt {i + 1}: Error handled by circuit breaker")


def main() -> None:
    """Run error hooks examples."""
    print("=" * 60)
    print("Error Recovery Hooks Example")
    print("=" * 60)

    demonstrate_validation_errors()
    demonstrate_blocked_calls()
    demonstrate_rate_limiting()
    demonstrate_chained_hooks()

    # Print collected metrics
    print("\n" + "=" * 60)
    metrics.print_summary()

    print("\nAlerts Generated:")
    for alert in alerts.alerts:
        print(f"  {alert}")

    print("\n" + "=" * 60)
    print("Error hooks examples completed!")
    print("\nKey features demonstrated:")
    print("- on_validation_error: Custom validation error handling")
    print("- on_blocked: Policy violation tracking")
    print("- on_rate_limit: Rate limit monitoring")
    print("- Circuit breaker pattern implementation")


if __name__ == "__main__":
    main()
