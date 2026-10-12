"""Regressions for 0.10.25: ``@requires`` keeps an async tool async.

- ``@requires`` wrapped every tool in a plain ``def``, so ``@Airlock`` (which picks its
  wrapper with ``asyncio.iscoroutinefunction``) treated an ``async def`` tool as sync. A
  capability refusal came back as a dict the caller then awaited (``TypeError``), and an
  allowed call returned the un-run coroutine: output sanitization and the audit never saw
  the real result.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import AsyncIterator

import pytest

from agent_airlock import Airlock, AirlockConfig
from agent_airlock.capabilities import (
    Capability,
    CapabilityPolicy,
    get_required_capabilities,
    requires,
)


def _config(*, grant: bool) -> AirlockConfig:
    policy = CapabilityPolicy(
        granted=Capability.NETWORK_HTTPS if grant else Capability.NONE,
        denied=Capability.NONE if grant else Capability.NETWORK_HTTPS,
    )
    return AirlockConfig(capability_policy=policy, enable_audit_log=False)


class TestRequiresKeepsFunctionKind:
    def test_async_tool_stays_a_coroutine_function(self) -> None:
        @requires(Capability.NETWORK_HTTPS)
        async def fetch(url: str) -> str:
            return url

        assert inspect.iscoroutinefunction(fetch)
        assert get_required_capabilities(fetch) == Capability.NETWORK_HTTPS

    def test_async_generator_stays_an_async_generator(self) -> None:
        @requires(Capability.NETWORK_HTTPS)
        async def stream(n: int) -> AsyncIterator[int]:
            for i in range(n):
                yield i

        assert inspect.isasyncgenfunction(stream)

        async def collect() -> list[int]:
            return [i async for i in stream(3)]

        assert asyncio.run(collect()) == [0, 1, 2]

    def test_sync_tool_unchanged(self) -> None:
        @requires(Capability.NETWORK_HTTPS)
        def fetch(url: str) -> str:
            return url

        assert not inspect.iscoroutinefunction(fetch)
        assert fetch("https://example.com") == "https://example.com"
        assert fetch.__name__ == "fetch"


class TestAirlockWithAsyncRequires:
    def test_airlock_builds_an_async_wrapper(self) -> None:
        @Airlock(config=_config(grant=True))
        @requires(Capability.NETWORK_HTTPS)
        async def fetch(url: str) -> str:
            return url

        assert inspect.iscoroutinefunction(fetch)

    def test_refusal_is_awaitable(self) -> None:
        @Airlock(config=_config(grant=False))
        @requires(Capability.NETWORK_HTTPS)
        async def fetch(url: str) -> str:
            return url

        result = asyncio.run(fetch(url="https://example.com"))
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["block_reason"] == "capability_denied"

    def test_allowed_call_runs_and_output_is_sanitized(self) -> None:
        ran: list[str] = []

        @Airlock(config=_config(grant=True))
        @requires(Capability.NETWORK_HTTPS)
        async def lookup(name: str) -> str:
            ran.append(name)
            return f"{name} can be reached at alice@example.com"

        result = asyncio.run(lookup(name="alice"))
        assert ran == ["alice"], "the tool body must run inside the call, not later"
        assert not inspect.iscoroutine(result)
        assert "alice@example.com" not in str(result), "output sanitization must apply"

    @pytest.mark.parametrize("order", ["requires_inside", "requires_outside"])
    def test_either_decorator_order_stays_async(self, order: str) -> None:
        async def body(url: str) -> str:
            return url

        if order == "requires_inside":
            tool = Airlock(config=_config(grant=True))(requires(Capability.NETWORK_HTTPS)(body))
        else:
            tool = requires(Capability.NETWORK_HTTPS)(Airlock(config=_config(grant=True))(body))
        assert inspect.iscoroutinefunction(tool)
        assert asyncio.run(tool(url="https://example.com")) == "https://example.com"
