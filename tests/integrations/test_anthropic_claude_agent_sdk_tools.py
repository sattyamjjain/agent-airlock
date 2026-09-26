"""Claude Agent SDK tools (``SdkMcpTool``) routed through Airlock by ``wrap_tools``.

``claude_agent_sdk.tool`` returns an ``SdkMcpTool`` whose ``handler`` takes one ``args``
dict. Until 0.10.12 the adapter could not wrap one at all: ``wrap_agent`` raised
"exposes neither `forward` nor `__call__`" for every SDK tool. No CI job installs the SDK,
so ``_SdkTool`` mirrors the 0.2.160 dataclass and ``_run_tool`` mirrors what
``create_sdk_mcp_server`` does after its own JSON-schema check: await the handler and
build the reply from ``content`` and ``is_error``. The same cases were run against the
real SDK through an MCP client session before release.
"""

from __future__ import annotations

import sys
import types
import warnings
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import pytest
from typing_extensions import NotRequired, TypedDict

from agent_airlock import core as airlock_core
from agent_airlock.config import AirlockConfig
from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.anthropic_claude_agent_sdk import (
    SUPPORTED_SDK_VERSIONS,
    AnthropicClaudeAgentSDKAdapter,
    ClaudeAgentSDKMissingError,
    wrap_tools,
)
from agent_airlock.policy import SecurityPolicy

EMAIL = "alice@example.com"


@dataclass
class _SdkTool:
    """The shape of ``claude_agent_sdk.SdkMcpTool`` (0.2.160)."""

    name: str
    description: str
    input_schema: Any
    handler: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]
    annotations: Any = None


@dataclass
class _Recorder:
    """A handler that records the ``args`` dict it was given."""

    reply: str = "ok"
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def __call__(self, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(dict(args))
        return {"content": [{"type": "text", "text": self.reply}]}


def _tool(input_schema: Any, *, name: str = "greet", reply: str = "ok") -> _SdkTool:
    return _SdkTool(name, "A tool", input_schema, _Recorder(reply))


async def _run_tool(tool: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    """``create_sdk_mcp_server``'s ``run_tool`` after its schema check (0.2.160)."""
    try:
        result = await tool.handler(arguments)
    except Exception as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "is_error": True}
    return {"content": result.get("content", []), "is_error": result.get("is_error", False)}


def _text(reply: dict[str, Any]) -> str:
    return "\n".join(block["text"] for block in reply["content"])


class _Lookup(TypedDict):
    key: str
    page: NotRequired[int]


class TestArgumentsAreChecked:
    async def test_a_value_the_sdk_schema_admits_is_still_refused_when_the_type_is_wrong(
        self,
    ) -> None:
        # JSON Schema's "integer" admits 3.0, so the SDK's own check lets it through.
        tool = _tool({"n": int})
        (guarded,) = wrap_tools([tool])

        reply = await _run_tool(guarded, {"n": 3.0})

        assert reply["is_error"] is True
        assert "AIRLOCK_BLOCK" in _text(reply)
        assert "Fix hints:" in _text(reply)
        assert tool.handler.calls == []  # type: ignore[attr-defined]

    async def test_a_ghost_key_is_stripped_before_the_handler_sees_it(self) -> None:
        tool = _tool({"n": int})
        (guarded,) = wrap_tools([tool])

        reply = await _run_tool(guarded, {"n": 1, "ghost": "x"})

        assert reply["is_error"] is False
        assert tool.handler.calls == [{"n": 1}]  # type: ignore[attr-defined]

    async def test_a_float_field_receives_the_number_unconverted(self) -> None:
        tool = _tool({"ratio": float})
        (guarded,) = wrap_tools([tool])

        await _run_tool(guarded, {"ratio": 3})

        (seen,) = tool.handler.calls  # type: ignore[attr-defined]
        assert type(seen["ratio"]) is int

    async def test_a_type_the_sdk_sends_as_a_string_is_checked_as_one(self) -> None:
        # The SDK advertises and checks a datetime field as a string, and hands the
        # handler that string; checking it as a datetime would refuse every call.
        tool = _tool({"when": datetime})
        (guarded,) = wrap_tools([tool])

        reply = await _run_tool(guarded, {"when": "2026-09-26"})

        assert reply["is_error"] is False
        assert tool.handler.calls == [{"when": "2026-09-26"}]  # type: ignore[attr-defined]

    async def test_an_omitted_optional_json_schema_key_stays_omitted(self) -> None:
        schema = {
            "type": "object",
            "properties": {"q": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["q"],
        }
        tool = _tool(schema)
        (guarded,) = wrap_tools([tool])

        await _run_tool(guarded, {"q": "x"})
        refused = await _run_tool(guarded, {"q": "x", "limit": "10"})

        assert tool.handler.calls == [{"q": "x"}]  # type: ignore[attr-defined]
        assert refused["is_error"] is True

    async def test_a_json_schema_key_outside_properties_is_a_ghost(self) -> None:
        # JSON Schema admits it when additionalProperties is absent, and so does the
        # SDK's check; Airlock does not take that default.
        schema = {"type": "object", "properties": {"q": {"type": "string"}}}
        tool = _tool(schema)
        (guarded,) = wrap_tools([tool])

        await _run_tool(guarded, {"q": "x", "evil": 1})

        assert tool.handler.calls == [{"q": "x"}]  # type: ignore[attr-defined]

    async def test_additional_properties_admits_undeclared_keys(self) -> None:
        schema = {
            "type": "object",
            "properties": {"q": {"type": "string"}},
            "additionalProperties": True,
        }
        tool = _tool(schema)
        (guarded,) = wrap_tools([tool])

        await _run_tool(guarded, {"q": "x", "extra": 1})

        assert tool.handler.calls == [{"q": "x", "extra": 1}]  # type: ignore[attr-defined]

    async def test_a_not_required_typeddict_key_may_be_left_out(self) -> None:
        # Under `from __future__ import annotations`, as in this module, __required_keys__
        # lists `page` as required; the NotRequired qualifier is read from the hints.
        assert "page" in _Lookup.__required_keys__
        tool = _tool(_Lookup)
        (guarded,) = wrap_tools([tool])

        reply = await _run_tool(guarded, {"key": "k"})
        missing = await _run_tool(guarded, {"page": 2})

        assert reply["is_error"] is False
        assert tool.handler.calls == [{"key": "k"}]  # type: ignore[attr-defined]
        assert missing["is_error"] is True


class TestRefusalsAndOutput:
    async def test_a_denied_tool_is_an_error_result_not_an_empty_success(self) -> None:
        # Returned as it is, Airlock's refusal dict has no `content`: the SDK would have
        # reported an empty, successful result.
        tool = _tool({"n": int})
        (guarded,) = wrap_tools([tool], policy=SecurityPolicy(denied_tools=["greet"]))

        reply = await _run_tool(guarded, {"n": 1})

        assert reply["is_error"] is True
        assert "denied" in _text(reply)
        assert tool.handler.calls == []  # type: ignore[attr-defined]

    async def test_a_ghost_key_is_refused_in_block_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIRLOCK_UNKNOWN_ARGS", "block")
        # Airlock() falls back to DEFAULT_CONFIG, which reads the environment once, when
        # agent_airlock is imported; rebuild it as a process started with the variable.
        monkeypatch.setattr(airlock_core, "DEFAULT_CONFIG", AirlockConfig())
        tool = _tool({"n": int})
        (guarded,) = wrap_tools([tool])

        reply = await _run_tool(guarded, {"n": 1, "ghost": "x"})

        assert reply["is_error"] is True
        assert "ghost" in _text(reply)
        assert tool.handler.calls == []  # type: ignore[attr-defined]

    async def test_a_handler_exception_is_reported_without_its_message(self) -> None:
        async def handler(args: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("db password is hunter2")

        (guarded,) = wrap_tools([_SdkTool("fail", "Fails", {"n": int}, handler)])

        reply = await _run_tool(guarded, {"n": 1})

        assert reply["is_error"] is True
        assert "Unexpected error" in _text(reply)
        assert "hunter2" not in _text(reply)

    async def test_the_handlers_output_is_masked(self) -> None:
        (guarded,) = wrap_tools([_tool({"n": int}, reply=f"write to {EMAIL}")])

        reply = await _run_tool(guarded, {"n": 1})

        assert reply["is_error"] is False
        assert EMAIL not in _text(reply)

    async def test_a_sync_handler_is_called_too(self) -> None:
        def handler(args: dict[str, Any]) -> dict[str, Any]:
            return {"content": [{"type": "text", "text": f"n={args['n']}"}]}

        tool = _SdkTool("count", "Count", {"n": int}, handler)  # type: ignore[arg-type]
        (guarded,) = wrap_tools([tool])

        assert _text(await _run_tool(guarded, {"n": 2})) == "n=2"


class TestWrapping:
    def test_the_original_tool_is_left_as_it_was(self) -> None:
        tool = _tool({"n": int})
        original = tool.handler

        (guarded,) = wrap_tools([tool])

        assert tool.handler is original
        assert guarded is not tool
        assert (guarded.name, guarded.description) == (tool.name, tool.description)

    @pytest.mark.parametrize(
        "schema",
        [{"from": str}, {"file-path": str}],
        ids=["keyword", "not-an-identifier"],
    )
    def test_a_key_that_cannot_be_a_parameter_is_refused_at_wrap_time(
        self, schema: dict[str, Any]
    ) -> None:
        with pytest.raises(AirlockError, match="renamed"):
            wrap_tools([_tool(schema)])

    def test_a_schema_airlock_cannot_read_is_refused_at_wrap_time(self) -> None:
        with pytest.raises(AirlockError, match="cannot derive"):
            wrap_tools([_tool(int)])

    def test_wrap_tools_takes_only_sdk_tools(self) -> None:
        with pytest.raises(AirlockError, match="SdkMcpTool"):
            wrap_tools([lambda args: args])

    async def test_wrap_agent_replaces_an_sdk_tool_with_a_guarded_copy(self) -> None:
        tool = _tool({"n": int})
        agent = types.SimpleNamespace(tools={"greet": tool})

        AnthropicClaudeAgentSDKAdapter().wrap_agent(agent)

        guarded = agent.tools["greet"]
        assert guarded is not tool
        assert (await _run_tool(guarded, {"n": "1"}))["is_error"] is True

    def test_a_tool_name_is_refused_with_a_pointer_to_wrap_tools(self) -> None:
        # ClaudeAgentOptions.tools holds the names of Claude Code's built-in tools.
        agent = types.SimpleNamespace(tools=["Read"])

        with pytest.raises(AirlockError, match="wrap_tools"):
            AnthropicClaudeAgentSDKAdapter().wrap_agent(agent)


class TestSdkVersionCheck:
    @staticmethod
    def _sdk_tool(monkeypatch: pytest.MonkeyPatch, version: str | None) -> _SdkTool:
        """A tool whose class claims to come from the SDK, with ``version`` installed."""
        if version is None:
            monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)
        else:
            sdk = types.ModuleType("claude_agent_sdk")
            sdk.__version__ = version  # type: ignore[attr-defined]
            monkeypatch.setitem(sys.modules, "claude_agent_sdk", sdk)
        sdk_class = type("SdkMcpTool", (_SdkTool,), {"__module__": "claude_agent_sdk"})
        return sdk_class("greet", "A tool", {"n": int}, _Recorder())  # type: ignore[no-any-return]

    def test_an_unverified_version_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = self._sdk_tool(monkeypatch, "0.0.1")

        with pytest.warns(UserWarning, match="outside SUPPORTED_SDK_VERSIONS"):
            (guarded,) = wrap_tools([tool])

        assert guarded.handler is not tool.handler

    def test_a_verified_version_does_not(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tool = self._sdk_tool(monkeypatch, SUPPORTED_SDK_VERSIONS[-1])

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            wrap_tools([tool])

    def test_a_missing_sdk_raises_with_the_install_hint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = self._sdk_tool(monkeypatch, None)

        with pytest.raises(ClaudeAgentSDKMissingError, match="claude-agent"):
            wrap_tools([tool])
