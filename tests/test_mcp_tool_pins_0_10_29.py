"""0.10.29: a FastMCP server's own tools are checked against their pins, and so is every
listing a client receives.

Until 0.10.29 nothing wired ``ToolDefinitionPinGuard`` to FastMCP or to a ``tools/list``
result, and its pin left out ``annotations`` and ``outputSchema``. Raised in
openai/codex#36381, CycloneDX/specification#1016 and pyranthus-hq/mora#473. These tests run
a real FastMCP server and an in-memory client, so the file is in the CI step that fails on
any skip.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

pytest.importorskip("fastmcp")

from fastmcp import Client  # noqa: E402

from agent_airlock.mcp import (  # noqa: E402
    check_server_tools,
    create_secure_mcp_server,
    tool_definitions,
)
from agent_airlock.mcp_spec.tool_definition_pin_guard import (  # noqa: E402
    ToolDefinitionPinGuard,
    ToolDefinitionVerdict,
    ToolListingDriftError,
    list_tools_pinned,
)


def _server(guard: ToolDefinitionPinGuard) -> Any:
    server, secure = create_secure_mcp_server("pinned", pin_guard=guard)

    @secure
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    return server


def _pinned_server() -> tuple[Any, ToolDefinitionPinGuard]:
    guard = ToolDefinitionPinGuard()
    server = _server(guard)
    for definition in asyncio.run(tool_definitions(server)):
        guard.approve(definition)
    return server, guard


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


class TestTheServersOwnTools:
    def test_a_pinned_server_lists_and_runs_its_tools(self) -> None:
        server, _ = _pinned_server()

        async def go() -> tuple[list[str], Any]:
            async with Client(server) as client:
                names = [tool.name for tool in await client.list_tools()]
                return names, (await client.call_tool("add", {"a": 1, "b": 2})).data

        assert _run(go()) == (["add"], 3)

    def test_a_tool_added_after_startup_is_neither_listed_nor_run(self) -> None:
        server, _ = _pinned_server()

        async def go() -> tuple[list[str], str]:
            async with Client(server) as client:

                @server.tool()
                def sneaky(text: str) -> str:
                    """Do something new."""
                    return text

                names = [tool.name for tool in await client.list_tools()]
                with pytest.raises(Exception) as refused:
                    await client.call_tool("sneaky", {"text": "x"})
                return names, str(refused.value)

        names, refusal = _run(go())
        assert names == ["add"]
        assert "AIRLOCK_BLOCK" in refusal and "no approved definition" in refusal

    def test_annotations_changed_after_startup_are_refused(self) -> None:
        server, guard = _pinned_server()

        async def go() -> tuple[list[str], str]:
            async with Client(server) as client:

                @server.tool(name="add", annotations={"destructiveHint": True})
                def add_again(a: int, b: int) -> int:
                    """Add two numbers."""
                    return a + b

                names = [tool.name for tool in await client.list_tools()]
                with pytest.raises(Exception) as refused:
                    await client.call_tool("add", {"a": 1, "b": 2})
                return names, str(refused.value)

        names, refusal = _run(go())
        assert names == []
        assert "changed: annotations" in refusal
        definition = _run(tool_definitions(server))[0]
        assert guard.check(definition).verdict is ToolDefinitionVerdict.DENY_ANNOTATIONS_DRIFT

    def test_the_server_refuses_to_start_with_an_unpinned_tool(self) -> None:
        server = _server(ToolDefinitionPinGuard())

        async def go() -> None:
            async with Client(server):
                pass

        with pytest.raises(Exception, match="not admitted by the pins: add"):
            _run(go())

    def test_check_server_tools_reports_and_raises(self) -> None:
        server, guard = _pinned_server()
        assert _run(check_server_tools(server, guard)).allowed is True
        guard.revoke("add")
        with pytest.raises(ToolListingDriftError):
            _run(check_server_tools(server, guard))

    def test_observe_mode_serves_and_only_logs(self) -> None:
        server = _server(ToolDefinitionPinGuard(enforce=False))

        async def go() -> tuple[list[str], Any]:
            async with Client(server) as client:
                names = [tool.name for tool in await client.list_tools()]
                return names, (await client.call_tool("add", {"a": 2, "b": 2})).data

        assert _run(go()) == (["add"], 4)

    def test_the_pins_cover_annotations_and_output_schema(self) -> None:
        server, _ = create_secure_mcp_server("plain")

        @server.tool(annotations={"readOnlyHint": True})
        def read(path: str) -> dict[str, str]:
            """Read a file."""
            return {"path": path}

        (definition,) = _run(tool_definitions(server))
        assert definition["annotations"] == {"readOnlyHint": True}
        assert "outputSchema" in definition


class TestTheClientHelper:
    def _plain_server(self) -> Any:
        server, _ = create_secure_mcp_server("plain")

        @server.tool()
        def other(text: str) -> str:
            """Echo the text."""
            return text

        return server

    def test_an_unpinned_listing_is_refused_or_filtered(self) -> None:
        server = self._plain_server()
        guard = ToolDefinitionPinGuard()

        async def go() -> Any:
            async with Client(server) as client:
                with pytest.raises(ToolListingDriftError):
                    await list_tools_pinned(client, guard)
                return await list_tools_pinned(client, guard, on_drift="filter")

        assert _run(go()) == []

    def test_a_pinned_listing_comes_through(self) -> None:
        server = self._plain_server()
        guard = ToolDefinitionPinGuard()
        for definition in _run(tool_definitions(server)):
            guard.approve(definition)

        async def go() -> list[str]:
            async with Client(server) as client:
                return [tool.name for tool in await list_tools_pinned(client, guard)]

        assert _run(go()) == ["other"]
