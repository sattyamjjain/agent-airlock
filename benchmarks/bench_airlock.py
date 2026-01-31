"""Performance benchmarks for Agent-Airlock.

Run with: pytest benchmarks/ -v --benchmark-only
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pytest_benchmark.fixture import BenchmarkFixture

from agent_airlock import (
    Airlock,
    AirlockConfig,
    PERMISSIVE_POLICY,
    SecurityPolicy,
)


# Baseline: undecorated function
def baseline_function(x: int, y: str) -> str:
    """Baseline function without any decoration."""
    return f"{x}-{y}"


class TestValidationOverhead:
    """Measure validation overhead per call."""

    def test_baseline_no_decorator(self, benchmark: BenchmarkFixture) -> None:
        """Baseline: No decorator overhead."""
        result = benchmark(baseline_function, 42, "test")
        assert result == "42-test"

    def test_airlock_minimal(self, benchmark: BenchmarkFixture) -> None:
        """Minimal Airlock with no sanitization."""
        config = AirlockConfig(sanitize_output=False)

        @Airlock(config=config)
        def simple_tool(x: int, y: str) -> str:
            return f"{x}-{y}"

        result = benchmark(simple_tool, x=42, y="test")
        assert result == "42-test"

    def test_airlock_default(self, benchmark: BenchmarkFixture) -> None:
        """Default Airlock configuration."""

        @Airlock()
        def simple_tool(x: int, y: str) -> str:
            return f"{x}-{y}"

        result = benchmark(simple_tool, x=42, y="test")
        assert result == "42-test"

    def test_airlock_with_policy(self, benchmark: BenchmarkFixture) -> None:
        """Airlock with policy checking."""
        policy = SecurityPolicy(allowed_tools=["policy_tool"])

        @Airlock(policy=policy)
        def policy_tool(x: int) -> int:
            return x * 2

        result = benchmark(policy_tool, x=21)
        assert result == 42


class TestPIIMaskingOverhead:
    """Measure PII masking overhead."""

    def test_no_pii_in_output(self, benchmark: BenchmarkFixture) -> None:
        """Output without PII - should be fast."""
        config = AirlockConfig(mask_pii=True, sanitize_output=True)

        @Airlock(config=config)
        def clean_output() -> str:
            return "Hello, this is a clean response with no sensitive data."

        result = benchmark(clean_output)
        assert "clean response" in result

    def test_with_pii_in_output(self, benchmark: BenchmarkFixture) -> None:
        """Output with PII - measures regex scanning overhead."""
        config = AirlockConfig(mask_pii=True, sanitize_output=True)

        @Airlock(config=config)
        def pii_output() -> str:
            return "Contact john@example.com at 555-123-4567 or use SSN 123-45-6789"

        result = benchmark(pii_output)
        # Verify PII was masked
        assert "john@example.com" not in result
        assert "123-45-6789" not in result

    def test_secret_masking(self, benchmark: BenchmarkFixture) -> None:
        """Output with secrets - measures secret detection."""
        config = AirlockConfig(mask_secrets=True, sanitize_output=True)

        @Airlock(config=config)
        def secret_output() -> str:
            return "API Key: sk-abcdefghijklmnopqrstuvwxyz12345"

        result = benchmark(secret_output)
        assert "sk-abcdefghijklmnopqrstuvwxyz12345" not in result


class TestGhostArgumentOverhead:
    """Measure ghost argument stripping overhead."""

    def test_no_ghost_args(self, benchmark: BenchmarkFixture) -> None:
        """No ghost arguments - minimal overhead."""

        @Airlock()
        def no_ghost(a: int, b: str, c: float = 1.0) -> str:
            return f"{a}-{b}-{c}"

        result = benchmark(no_ghost, a=1, b="test", c=2.0)
        assert result == "1-test-2.0"

    def test_with_ghost_args_permissive(self, benchmark: BenchmarkFixture) -> None:
        """Ghost arguments stripped - permissive mode."""
        config = AirlockConfig(strict_mode=False)

        @Airlock(config=config)
        def ghost_tool(a: int) -> int:
            return a

        # Pass extra ghost arguments
        result = benchmark(
            ghost_tool,
            a=42,
            ghost_arg="should be stripped",
            another_ghost=123,
        )
        assert result == 42


class TestOutputTruncation:
    """Measure output truncation overhead."""

    def test_small_output(self, benchmark: BenchmarkFixture) -> None:
        """Small output - no truncation needed."""
        config = AirlockConfig(max_output_chars=10000)

        @Airlock(config=config)
        def small_output() -> str:
            return "Small response"

        result = benchmark(small_output)
        assert result == "Small response"

    def test_large_output_truncated(self, benchmark: BenchmarkFixture) -> None:
        """Large output - truncation applied."""
        config = AirlockConfig(max_output_chars=1000)

        @Airlock(config=config)
        def large_output() -> str:
            return "x" * 5000

        result = benchmark(large_output)
        assert len(result) <= 1100  # Some buffer for truncation message


class TestAsyncOverhead:
    """Measure async function overhead."""

    def test_async_baseline(self, benchmark: BenchmarkFixture) -> None:
        """Baseline async function."""

        async def async_baseline(x: int) -> int:
            return x * 2

        # benchmark doesn't support async directly, so we create new event loop
        def run_async() -> int:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(async_baseline(21))
            finally:
                loop.close()

        result = benchmark(run_async)
        assert result == 42

    def test_async_airlock(self, benchmark: BenchmarkFixture) -> None:
        """Async function with Airlock."""

        @Airlock()
        async def async_tool(x: int) -> int:
            return x * 2

        def run_async() -> int:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(async_tool(x=21))
            finally:
                loop.close()

        result = benchmark(run_async)
        assert result == 42


class TestComplexValidation:
    """Measure complex type validation overhead."""

    def test_simple_types(self, benchmark: BenchmarkFixture) -> None:
        """Simple primitive types."""

        @Airlock()
        def simple_types(a: int, b: str, c: float, d: bool) -> str:
            return f"{a}-{b}-{c}-{d}"

        result = benchmark(simple_types, a=1, b="test", c=3.14, d=True)
        assert "1-test-3.14-True" == result

    def test_complex_types(self, benchmark: BenchmarkFixture) -> None:
        """Complex nested types."""

        @Airlock()
        def complex_types(
            data: dict[str, Any],
            items: list[int],
        ) -> str:
            return f"{len(data)}-{len(items)}"

        result = benchmark(
            complex_types,
            data={"a": 1, "b": 2, "c": 3},
            items=[1, 2, 3, 4, 5],
        )
        assert result == "3-5"


class TestPolicyOverhead:
    """Measure policy checking overhead."""

    def test_permissive_policy(self, benchmark: BenchmarkFixture) -> None:
        """Permissive policy - minimal checks."""

        @Airlock(policy=PERMISSIVE_POLICY)
        def permissive_tool(x: int) -> int:
            return x

        result = benchmark(permissive_tool, x=42)
        assert result == 42

    def test_strict_policy(self, benchmark: BenchmarkFixture) -> None:
        """Strict policy - more checks."""
        # Custom policy with allowed tools and denied tools
        policy = SecurityPolicy(
            allowed_tools=["strict_tool"],
            denied_tools=["delete_*", "drop_*"],
        )

        @Airlock(policy=policy)
        def strict_tool(x: int) -> int:
            return x

        result = benchmark(strict_tool, x=42)
        assert result == 42

    def test_rate_limited_policy(self, benchmark: BenchmarkFixture) -> None:
        """Policy with rate limiting."""
        # Use high limit to avoid exhaustion during benchmark iterations
        policy = SecurityPolicy(
            allowed_tools=["rated_tool"],
            rate_limits={"rated_tool": "100000/second"},
        )

        @Airlock(policy=policy)
        def rated_tool(x: int) -> int:
            return x

        result = benchmark(rated_tool, x=42)
        assert result == 42


class TestEndToEnd:
    """End-to-end realistic scenarios."""

    def test_realistic_tool_call(self, benchmark: BenchmarkFixture) -> None:
        """Realistic tool call with all features enabled."""
        config = AirlockConfig(
            strict_mode=False,
            sanitize_output=True,
            mask_pii=True,
            mask_secrets=True,
            max_output_chars=5000,
        )
        policy = SecurityPolicy(
            allowed_tools=["search_database"],
            rate_limits={"search_database": "100000/second"},
        )

        @Airlock(config=config, policy=policy)
        def search_database(query: str, limit: int = 10) -> str:
            return f"Found {limit} results for: {query}"

        result = benchmark(search_database, query="test query", limit=5)
        assert "Found 5 results" in result

    def test_high_volume_scenario(self, benchmark: BenchmarkFixture) -> None:
        """Simulate high volume of calls."""

        @Airlock()
        def quick_tool(x: int) -> int:
            return x * 2

        def batch_calls() -> int:
            total = 0
            for i in range(100):
                total += quick_tool(x=i)
            return total

        result = benchmark(batch_calls)
        assert result == sum(i * 2 for i in range(100))
