"""The walker adapters' name-retagging proxy must carry the tool's call contract.

``crewai``, ``pydantic_ai`` and ``anthropic_claude_agent_sdk`` hand ``Airlock`` a proxy
re-tagged with the tool's name. It used to be ``(*args, **kwargs)`` and always sync, so
strict validation had no parameter to check, ghost-argument stripping saw a ``**kwargs``
that accepts everything, and an ``async`` tool got Airlock's sync wrapper, which returned
the un-awaited coroutine before the tool ran — its output never passed through
sanitisation. These tests pin the proxy and, through ``Airlock``, what it enables.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any

import pytest
from pydantic.errors import PydanticSchemaGenerationError

from agent_airlock import Airlock
from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations._tool_proxy import named_tool_proxy


class _Unschemaable:
    """Stands in for a framework-injected context object: no Pydantic schema exists."""


def _typed_tool(n: int, tags: list[str] | None = None) -> str:
    return f"{n}:{tags}"


def _context_tool(ctx: _Unschemaable, n: int) -> int:
    return n


def _two_args(a: int, b: str) -> str:
    return f"{a}{b}"


class _BaseToolShape:
    def _run(self, query: str) -> str:
        return query


class _CallableTool:
    def __call__(self, n: int) -> int:
        return n


class _AsyncCallableTool:
    async def __call__(self, n: int) -> int:
        return n


def _blocked(result: Any) -> bool:
    return isinstance(result, dict) and result.get("status") == "blocked"


class TestTheProxyCarriesTheToolContract:
    def test_signature_and_resolved_annotations_are_kept(self) -> None:
        # This module postpones annotations, so the tool's own are strings; the proxy
        # must carry them resolved or Pydantic cannot build a validator outside it.
        proxy = named_tool_proxy(_typed_tool, name="typed")

        params = inspect.signature(proxy).parameters
        assert list(params) == ["n", "tags"]
        assert params["n"].annotation is int
        assert params["tags"].annotation == (list[str] | None)
        assert params["tags"].default is None
        assert proxy.__annotations__ == {"n": int, "tags": list[str] | None, "return": str}

    def test_the_proxy_is_retagged_with_the_tool_name(self) -> None:
        proxy = named_tool_proxy(_typed_tool, name="search_web")

        assert proxy.__name__ == "search_web"
        assert proxy.__qualname__ == "search_web"

    def test_a_bound_method_loses_self(self) -> None:
        proxy = named_tool_proxy(_BaseToolShape()._run, name="search")

        assert list(inspect.signature(proxy).parameters) == ["query"]
        assert proxy.__annotations__["query"] is str

    def test_a_callable_object_uses_its_call_signature(self) -> None:
        proxy = named_tool_proxy(_CallableTool(), name="count")

        assert list(inspect.signature(proxy).parameters) == ["n"]
        assert proxy.__annotations__["n"] is int

    def test_a_partial_drops_its_bound_parameters(self) -> None:
        proxy = named_tool_proxy(functools.partial(_two_args, 1), name="two")

        assert list(inspect.signature(proxy).parameters) == ["b"]
        assert proxy.__annotations__["b"] is str

    def test_relaxed_parameters_become_any(self) -> None:
        proxy = named_tool_proxy(_context_tool, name="ctx_tool", relaxed_params={"ctx"})

        params = inspect.signature(proxy).parameters
        assert params["ctx"].annotation is Any
        assert params["n"].annotation is int

    def test_an_unreadable_signature_is_refused_not_waived(self) -> None:
        with pytest.raises(AirlockError, match="cannot read the signature"):
            named_tool_proxy(min, name="min")


class TestAsyncToolsStayAsync:
    def test_a_sync_tool_gets_a_sync_proxy(self) -> None:
        assert not inspect.iscoroutinefunction(named_tool_proxy(_typed_tool, name="t"))

    async def test_an_async_function_gets_an_async_proxy(self) -> None:
        async def fetch(n: int) -> int:
            return n * 2

        proxy = named_tool_proxy(fetch, name="fetch")

        assert inspect.iscoroutinefunction(proxy)
        assert await proxy(n=21) == 42

    async def test_an_async_call_object_gets_an_async_proxy(self) -> None:
        proxy = named_tool_proxy(_AsyncCallableTool(), name="count")

        assert inspect.iscoroutinefunction(proxy)
        assert await proxy(n=3) == 3


class TestAirlockEnforcesTheCarriedContract:
    def test_a_wrong_type_is_blocked(self) -> None:
        guarded = Airlock()(named_tool_proxy(_typed_tool, name="typed"))

        result = guarded(n="5")

        assert _blocked(result)
        assert "validation failed" in result["error"]

    def test_a_ghost_argument_is_stripped_before_the_tool_sees_it(self) -> None:
        # With the old (*args, **kwargs) proxy the ghost reached the tool, which raised
        # TypeError, and the call came back as a generic "unexpected error" block.
        guarded = Airlock()(named_tool_proxy(_typed_tool, name="typed"))

        assert guarded(n=5, ghost="x") == "5:None"

    async def test_async_tool_output_passes_through_sanitisation(self) -> None:
        async def lookup(n: int) -> str:
            return f"{n}: write to alice@example.com"

        guarded = Airlock()(named_tool_proxy(lookup, name="lookup"))

        assert inspect.iscoroutinefunction(guarded)
        result = await guarded(n=1)
        assert "alice@example.com" not in result

    def test_a_relaxed_context_passes_through_unvalidated(self) -> None:
        guarded = Airlock()(
            named_tool_proxy(_context_tool, name="ctx_tool", relaxed_params={"ctx"})
        )

        assert guarded(_Unschemaable(), n=5) == 5
        assert _blocked(guarded(_Unschemaable(), n="5"))

    def test_an_unrelaxed_unschemaable_parameter_fails_at_wrap_time(self) -> None:
        # Why relaxed_params exists: a context type with no schema cannot be validated,
        # and Airlock refuses to build the wrapper rather than run the tool unchecked.
        with pytest.raises(PydanticSchemaGenerationError):
            Airlock()(named_tool_proxy(_context_tool, name="ctx_tool"))
