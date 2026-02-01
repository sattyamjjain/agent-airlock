"""Benchmarks for Airlock decorator overhead.

Run with: pytest benchmarks/benchmark_airlock.py --benchmark-only
"""

from __future__ import annotations

import pytest

from agent_airlock import Airlock
from agent_airlock.config import AirlockConfig
from agent_airlock.policy import PERMISSIVE_POLICY, STRICT_POLICY


# Simple function for baseline
def simple_function(x: int, y: int) -> int:
    """Simple function without Airlock."""
    return x + y


# Airlocked versions
config_minimal = AirlockConfig(strict_mode=False)
config_strict = AirlockConfig(strict_mode=True)


@Airlock(config=config_minimal)
def airlocked_minimal(x: int, y: int) -> int:
    """Function with minimal Airlock config."""
    return x + y


@Airlock(config=config_strict)
def airlocked_strict(x: int, y: int) -> int:
    """Function with strict Airlock config."""
    return x + y


@Airlock(config=config_strict, policy=STRICT_POLICY)
def airlocked_with_policy(x: int, y: int) -> int:
    """Function with Airlock and policy."""
    return x + y


class TestAirlockOverhead:
    """Benchmark Airlock decorator overhead."""

    def test_baseline_no_airlock(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Baseline: function without Airlock."""
        result = benchmark(simple_function, 1, 2)
        assert result == 3

    def test_airlock_minimal(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Airlock with minimal configuration."""
        result = benchmark(airlocked_minimal, x=1, y=2)
        assert result == 3

    def test_airlock_strict(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Airlock with strict mode."""
        result = benchmark(airlocked_strict, x=1, y=2)
        assert result == 3

    def test_airlock_with_policy(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Airlock with policy checking."""
        result = benchmark(airlocked_with_policy, x=1, y=2)
        assert result == 3

    def test_decorator_application(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Time to apply Airlock decorator."""

        def create_decorated() -> None:
            @Airlock(config=config_strict)
            def temp_func(x: int) -> int:
                return x

        benchmark(create_decorated)


class TestValidationOverhead:
    """Benchmark validation-specific overhead."""

    def test_ghost_arg_detection(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Ghost argument detection overhead."""

        @Airlock(config=config_minimal)
        def func_with_args(a: int, b: str, c: float = 1.0) -> str:
            return f"{a}-{b}-{c}"

        result = benchmark(func_with_args, a=1, b="test", c=2.0)
        assert result == "1-test-2.0"

    def test_type_validation(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Pydantic type validation overhead."""

        @Airlock(config=config_strict)
        def typed_func(name: str, count: int, enabled: bool = True) -> dict:  # type: ignore[type-arg]
            return {"name": name, "count": count, "enabled": enabled}

        result = benchmark(typed_func, name="test", count=42, enabled=False)
        assert result["name"] == "test"
