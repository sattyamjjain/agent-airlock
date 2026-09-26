"""FastMCP integration regressions fixed in 0.10.18, run through FastMCP's in-memory client.

- A refused call returned its text as the tool's result. That fails FastMCP's output-schema
  check on a tool declared ``-> dict`` or ``-> int``: the client got a schema error, or on
  FastMCP 3.x and later an exception, instead of the refusal. The refusal is raised as
  ``ToolError`` now, which reaches the client as an error result carrying its text.
- An async tool skipped that conversion and returned Airlock's raw response dict.
- A tool's own ``{"success": False, ...}`` result was taken for a refusal.
- No progress notification was ever sent: the coroutine was not awaited, and the message
  went where FastMCP expects ``total``.
- ``MCPContextExtractor.extract_agent_id`` returned the string "None" for a real Context.
"""

from __future__ import annotations

import asyncio
import re
import sys
from typing import Any
from unittest.mock import patch

import pytest

fastmcp = pytest.importorskip("fastmcp")

from fastmcp import Client, Context, FastMCP  # noqa: E402

from agent_airlock import SecurityPolicy  # noqa: E402
from agent_airlock.mcp import MCPContextExtractor, secure_tool  # noqa: E402

_FASTMCP_MAJOR = int(fastmcp.__version__.split(".")[0])
_DENY_ALL = SecurityPolicy(denied_tools=["*"])


def _call(
    mcp: FastMCP,
    tool: str,
    arguments: dict[str, Any] | None = None,
    *,
    progress: list[tuple[float, float | None, str | None]] | None = None,
) -> Any:
    """Call a tool through FastMCP's in-memory client, as a real MCP client would."""

    async def on_progress(value: float, total: float | None, message: str | None) -> None:
        if progress is not None:
            progress.append((value, total, message))

    async def run() -> Any:
        async with Client(mcp, progress_handler=on_progress) as client:
            return await client.call_tool(tool, arguments or {}, raise_on_error=False)

    return asyncio.run(run())


def _text(result: Any) -> str:
    return "\n".join(getattr(block, "text", "") for block in result.content)


def dict_tool() -> dict[str, int]:
    return {"n": 1}


def int_tool() -> int:
    return 1


def str_tool() -> str:
    return "one"


async def async_dict_tool() -> dict[str, int]:
    return {"n": 1}


class TestARefusalReachesTheClientAsAnError:
    @pytest.mark.parametrize(
        "func",
        [dict_tool, int_tool, str_tool, async_dict_tool],
        ids=["dict", "int", "str", "async-dict"],
    )
    def test_whatever_the_return_type(self, func: Any) -> None:
        mcp = FastMCP("refusals")
        secure_tool(mcp, policy=_DENY_ALL)(func)

        result = _call(mcp, func.__name__)

        assert result.is_error is True
        text = _text(result)
        assert text.startswith(f"Error: AIRLOCK_BLOCK: Policy violation for '{func.__name__}'")
        assert "\n\nSuggested fixes:\n- " in text

    def test_a_rate_limit_refusal_carries_the_real_wait(self) -> None:
        # FastMCP checks argument types itself before the tool runs, so a type error
        # never reaches Airlock through a server; a rate limit does.
        mcp = FastMCP("refusals")

        @secure_tool(mcp, policy=SecurityPolicy(rate_limits={"*": "1/hour"}))
        def hourly() -> int:
            return 1

        assert _call(mcp, "hourly").is_error is False
        refused = _call(mcp, "hourly")

        assert refused.is_error is True
        # 3600 less whatever the bucket refilled between the two calls (a slow CI runner
        # takes over a second to open two client sessions).
        hints = re.search(
            r"Suggested fixes:\n- Rate limit is 1/hour\n- Wait (\d+) seconds before retrying$",
            _text(refused),
        )
        assert hints is not None, _text(refused)
        assert 3590 <= int(hints.group(1)) <= 3600


class TestAToolsOwnFailureDictIsItsResult:
    def test_it_is_not_taken_for_a_refusal(self) -> None:
        mcp = FastMCP("results")

        @secure_tool(mcp)
        def lookup(key: str) -> dict[str, Any]:
            return {"success": False, "reason": f"{key} not found"}

        result = _call(mcp, "lookup", {"key": "k1"})

        assert result.is_error is False
        assert "k1 not found" in _text(result)


class TestProgressIsSent:
    def test_from_an_async_tool(self) -> None:
        mcp = FastMCP("progress")

        @secure_tool(mcp)
        async def slow(ctx: Context) -> str:
            return "done"

        got: list[tuple[float, float | None, str | None]] = []
        result = _call(mcp, "slow", progress=got)

        assert result.is_error is False
        assert got == [(0, 100, "Starting slow..."), (100, 100, "Completed slow")]

    def test_from_a_sync_tool_when_fastmcp_runs_it_in_a_worker_thread(self) -> None:
        mcp = FastMCP("progress")

        @secure_tool(mcp)
        def quick(ctx: Context) -> str:
            return "done"

        got: list[tuple[float, float | None, str | None]] = []
        result = _call(mcp, "quick", progress=got)

        assert result.is_error is False
        # FastMCP 2.x runs a sync tool on the event loop's own thread, where nothing can
        # be awaited; 3.x and later run it in a worker thread.
        expected = [(0, 100, "Starting quick..."), (100, 100, "Completed quick")]
        assert got == (expected if _FASTMCP_MAJOR >= 3 else [])


class TestExtractAgentId:
    def test_a_real_context_gives_its_session_not_the_string_none(self) -> None:
        mcp = FastMCP("identity")
        seen: list[tuple[str | None, str]] = []

        @mcp.tool
        def whoami(ctx: Context) -> str:
            seen.append((MCPContextExtractor.extract_agent_id(ctx), ctx.session_id))
            return "ok"

        _call(mcp, "whoami")

        ((agent_id, session_id),) = seen
        assert agent_id == session_id
        assert agent_id not in (None, "None")


class TestWithoutFastMCP:
    def test_the_refusal_is_returned_as_text(self) -> None:
        from agent_airlock.mcp import _refuse

        refusal = {
            "success": False,
            "status": "blocked",
            "error": "AIRLOCK_BLOCK: no",
            "fix_hints": ["do this instead"],
        }

        with patch.dict(sys.modules, {"fastmcp.exceptions": None}):
            text = _refuse(refusal)

        assert text == "Error: AIRLOCK_BLOCK: no\n\nSuggested fixes:\n- do this instead"
