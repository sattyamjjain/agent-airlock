"""Live contract: ``wrap_tools`` under the Claude Agent SDK against the real API.

Spends API credit; run with ``make test-live``. The SDK drives its bundled Claude Code
CLI, which authenticates with ``ANTHROPIC_API_KEY`` here: the live session removes every
other credential, and the CLI gets an empty config directory, no setting sources, no
built-in tools and only this test's in-process MCP server.

What it settles: a tool Airlock refuses is never invoked, and the model receives an
error ``tool_result`` (``ToolResultBlock.is_error``) carrying ``AIRLOCK_BLOCK``.
``ClaudeAgentOptions`` fields used here were checked against claude-agent-sdk 0.2.165.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from agent_airlock.integrations.anthropic_claude_agent_sdk import wrap_tools
from agent_airlock.policy import SecurityPolicy

from ._live import LIVE_MODEL, LiveRecorder

pytestmark = pytest.mark.live

MAX_TURNS = 6
MAX_BUDGET_USD = 0.50
PROMPT = (
    "Call the read_note tool with name 'groceries'. Then call the delete_note tool with "
    "name 'groceries'. Then reply with the single word DONE."
)


@dataclass
class _Transcript:
    tool_names: dict[str, str] = field(default_factory=dict)
    results: dict[str, Any] = field(default_factory=dict)
    init: dict[str, Any] = field(default_factory=dict)
    final: Any = None


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(str(item.get("text", "")) for item in content if isinstance(item, dict))
    return ""


def _notes_server(sdk: Any, calls: list[str]) -> Any:
    """An in-process MCP server whose ``delete_note`` Airlock's policy denies."""

    @sdk.tool("read_note", "Read a note by its name.", {"name": str})
    async def read_note(args: dict[str, Any]) -> dict[str, Any]:
        calls.append("read_note")
        return {"content": [{"type": "text", "text": "The note says: milk, eggs."}]}

    @sdk.tool("delete_note", "Delete a note by its name.", {"name": str})
    async def delete_note(args: dict[str, Any]) -> dict[str, Any]:
        calls.append("delete_note")
        return {"content": [{"type": "text", "text": "Deleted."}]}

    policy = SecurityPolicy(denied_tools=["delete_note"])
    return sdk.create_sdk_mcp_server(
        "notes", tools=wrap_tools([read_note, delete_note], policy=policy)
    )


def _options(sdk: Any, server: Any, tmp_path: Path) -> Any:
    config_dir = tmp_path / "claude-config"
    workdir = tmp_path / "work"
    config_dir.mkdir()
    workdir.mkdir()
    return sdk.ClaudeAgentOptions(
        model=LIVE_MODEL,
        tools=[],
        mcp_servers={"notes": server},
        strict_mcp_config=True,
        allowed_tools=["mcp__notes__read_note", "mcp__notes__delete_note"],
        max_turns=MAX_TURNS,
        max_budget_usd=MAX_BUDGET_USD,
        setting_sources=[],
        cwd=str(workdir),
        env={"CLAUDE_CONFIG_DIR": str(config_dir)},
    )


async def _run(sdk: Any, options: Any) -> _Transcript:
    transcript = _Transcript()
    async for message in sdk.query(prompt=PROMPT, options=options):
        if isinstance(message, sdk.SystemMessage) and message.subtype == "init":
            transcript.init = dict(message.data)
        elif isinstance(message, sdk.AssistantMessage):
            for block in message.content:
                if isinstance(block, sdk.ToolUseBlock):
                    transcript.tool_names[block.id] = block.name
        elif isinstance(message, sdk.UserMessage) and isinstance(message.content, list):
            for block in message.content:
                if isinstance(block, sdk.ToolResultBlock):
                    transcript.results[block.tool_use_id] = block
        elif isinstance(message, sdk.ResultMessage):
            transcript.final = message
    return transcript


class TestAgentSdkRefusals:
    async def test_a_denied_tool_never_runs_and_the_model_reads_an_error(
        self, live_api_key: str, live_recorder: LiveRecorder, tmp_path: Path
    ) -> None:
        sdk = pytest.importorskip("claude_agent_sdk")
        calls: list[str] = []
        seen = await _run(sdk, _options(sdk, _notes_server(sdk, calls), tmp_path))

        delete_ids = [key for key, name in seen.tool_names.items() if name.endswith("delete_note")]
        live_recorder.record(
            "agent_sdk.denied_tool",
            model_requested=LIVE_MODEL,
            init_model=seen.init.get("model"),
            init_keys=sorted(seen.init),
            tools_called=sorted(seen.tool_names.values()),
            handler_calls=calls,
            delete_result_is_error=[
                getattr(seen.results.get(key), "is_error", None) for key in delete_ids
            ],
            total_cost_usd=getattr(seen.final, "total_cost_usd", None),
            models_observed=sorted(getattr(seen.final, "model_usage", None) or {}),
            num_turns=getattr(seen.final, "num_turns", None),
            result_subtype=getattr(seen.final, "subtype", None),
        )
        assert seen.final is not None, "the SDK returned no ResultMessage"
        assert calls.count("read_note") == 1, calls
        assert "delete_note" not in calls, "Airlock let a denied tool's handler run"
        assert delete_ids, f"the model never called delete_note: {sorted(seen.tool_names.values())}"
        block = seen.results.get(delete_ids[0])
        assert block is not None, "no tool_result reached the model for delete_note"
        assert block.is_error is True, block
        assert "AIRLOCK_BLOCK" in _text(block.content), block.content
