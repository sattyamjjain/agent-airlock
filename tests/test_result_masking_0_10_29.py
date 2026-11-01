"""0.10.29: MCP tool results and model results are masked, not passed through.

Raised in modelcontextprotocol/modelcontextprotocol#3354 (``structuredContent`` outside the
attested output) and google/adk-python#7311 (``model_dump(mode="json")`` renders every
field, ``repr=False`` ones included). On 0.10.28, reproduced before the change:

- ``_sanitize_tool_output`` masked strings and containers and returned any other object
  as it was, so a tool returning ``mcp.types.CallToolResult`` with an API key in both its
  text block and its ``structuredContent`` handed both back unmasked (the same data as a
  dict was masked).
- The Anthropic adapter serialized a model result with ``model_dump`` into the
  ``tool_result`` text, ``Field(repr=False)`` fields included, unmasked.

Now an MCP result (duck-typed: ``content`` plus ``structured_content`` /
``structuredContent``, so ``mcp.types.CallToolResult`` and FastMCP's ``ToolResult``) is
rebuilt with ``model_copy`` and its text blocks, structured content and ``_meta`` masked,
FastMCP's raw wire copy included; the Anthropic adapter masks the serialized JSON; and
``AirlockConfig(withhold_unmaskable_output=True)`` refuses an object result whose detected
data cannot be masked. Imports ``mcp`` and ``fastmcp``, so it runs in CI's extra-backed step.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest
from pydantic import BaseModel, Field

mcp_types = pytest.importorskip("mcp.types")
fastmcp_tools = pytest.importorskip("fastmcp.tools")

from agent_airlock import Airlock, AirlockConfig  # noqa: E402 - after the importorskips
from agent_airlock.integrations.anthropic import ToolRegistry  # noqa: E402
from agent_airlock.policy_presets import (  # noqa: E402
    capsule_indirect_injection_cve_2026_21520_defaults,
    context7_contextcrush_cve_2026_75130_defaults,
)

# Assembled, so no secret scanner files this module.
KEY = "sk-proj-" + "FAKEFAKEFAKEFAKEFAKEFAKE1234"
BODY = "FAKEFAKEFAKEFAKE"


def _wire(result: Any) -> str:
    """Everything the result would put on the wire, as text."""
    return result.model_dump_json(by_alias=True)


def _call_tool_result() -> Any:
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=f"the key is {KEY}")],
        structuredContent={"key": KEY, "nested": [{"token": KEY}]},
        _meta={"trace": KEY},
    )


class TestCallToolResult:
    def test_text_structured_content_and_meta_are_masked(self) -> None:
        @Airlock(config=AirlockConfig(sanitize_output=True))
        def tool() -> Any:
            return _call_tool_result()

        result = tool()
        assert isinstance(result, mcp_types.CallToolResult)
        assert BODY not in _wire(result)
        assert result.content[0].text.startswith("the key is ")
        assert set(result.structured_content) == {"key", "nested"}

    def test_the_same_data_as_a_dict_was_already_masked(self) -> None:
        """Control: the container path, unchanged."""

        @Airlock(config=AirlockConfig(sanitize_output=True))
        def tool() -> dict[str, Any]:
            return {"key": KEY}

        assert BODY not in json.dumps(tool())

    def test_a_non_text_block_is_reported_not_masked(self) -> None:
        resource = mcp_types.EmbeddedResource(
            type="resource",
            resource=mcp_types.TextResourceContents(uri="file:///notes.txt", text=KEY),
        )

        @Airlock(config=AirlockConfig(sanitize_output=True))
        def tool() -> Any:
            return mcp_types.CallToolResult(content=[resource])

        result = tool()
        assert isinstance(result, mcp_types.CallToolResult)
        assert result.content[0] is resource  # left as it is, and reported

    def test_withhold_refuses_a_non_text_block_it_cannot_mask(self) -> None:
        resource = mcp_types.EmbeddedResource(
            type="resource",
            resource=mcp_types.TextResourceContents(uri="file:///notes.txt", text=KEY),
        )
        config = AirlockConfig(sanitize_output=True, withhold_unmaskable_output=True)

        @Airlock(config=config)
        def tool() -> Any:
            return mcp_types.CallToolResult(content=[resource])

        result = tool()
        assert isinstance(result, dict)
        assert result["block_reason"] == "output_unreadable"
        assert BODY not in json.dumps(result)

    def test_sanitize_output_off_leaves_it_alone(self) -> None:
        """Control: masking is still governed by sanitize_output."""

        @Airlock(config=AirlockConfig(sanitize_output=False))
        def tool() -> Any:
            return _call_tool_result()

        assert BODY in _wire(tool())


class TestFastMCPToolResult:
    def test_the_raw_wire_copy_is_masked_too(self) -> None:
        @Airlock(config=AirlockConfig(sanitize_output=True))
        def tool() -> Any:
            return fastmcp_tools.ToolResult.from_mcp_result(_call_tool_result())

        result = tool()
        assert isinstance(result, fastmcp_tools.ToolResult)
        assert BODY not in result.model_dump_json()
        assert BODY not in _wire(result.to_mcp_result())


class _Account(BaseModel):
    name: str
    api_key: str = Field(repr=False)


class TestAnthropicAdapter:
    def test_a_repr_false_secret_never_reaches_the_tool_result_text(self) -> None:
        registry = ToolRegistry(config=AirlockConfig(sanitize_output=True))

        @registry.tool
        def account() -> _Account:
            """Look up the account."""
            return _Account(name="alice", api_key=KEY)

        assert KEY not in repr(_Account(name="alice", api_key=KEY))  # the repr hides it
        block = registry.process_tool_use(
            {"type": "tool_use", "id": "toolu_1", "name": "account", "input": {}}
        )
        assert BODY not in json.dumps(block)
        assert "alice" in block["content"]

    def test_with_sanitize_output_off_the_json_is_sent_as_it_is(self) -> None:
        """Control."""
        registry = ToolRegistry(config=AirlockConfig(sanitize_output=False))

        @registry.tool
        def account() -> _Account:
            """Look up the account."""
            return _Account(name="alice", api_key=KEY)

        block = registry.process_tool_use(
            {"type": "tool_use", "id": "toolu_1", "name": "account", "input": {}}
        )
        assert BODY in block["content"]


@dataclasses.dataclass
class _Credentials:
    user: str
    token: str


@dataclasses.dataclass
class _Note:
    user: str
    text: str


class TestWithholdUnmaskableOutput:
    def test_a_dataclass_holding_a_key_is_refused_when_withholding(self) -> None:
        config = AirlockConfig(sanitize_output=True, withhold_unmaskable_output=True)

        @Airlock(config=config)
        def creds() -> _Credentials:
            return _Credentials(user="alice", token=KEY)

        result = creds()
        assert isinstance(result, dict)
        assert result["block_reason"] == "output_unreadable"
        assert "withheld" in result["error"]
        assert BODY not in json.dumps(result)

    def test_by_default_it_is_returned_with_the_warning(self) -> None:
        """Control: off by default."""

        @Airlock(config=AirlockConfig(sanitize_output=True))
        def creds() -> _Credentials:
            return _Credentials(user="alice", token=KEY)

        assert isinstance(creds(), _Credentials)

    def test_a_key_value_shape_in_a_dataclass_repr_is_still_detected(self) -> None:
        """The str() reading stays: a ``token='...'`` field is caught as before."""
        config = AirlockConfig(sanitize_output=True, withhold_unmaskable_output=True)

        @Airlock(config=config)
        def creds() -> _Credentials:
            return _Credentials(user="alice", token="hunter2hunter2")

        result = creds()
        assert isinstance(result, dict)
        assert result["block_reason"] == "output_unreadable"

    def test_a_model_hiding_a_key_from_repr_is_still_detected(self) -> None:
        config = AirlockConfig(sanitize_output=True, withhold_unmaskable_output=True)

        @Airlock(config=config)
        def account() -> _Account:
            return _Account(name="alice", api_key=KEY)

        result = account()
        assert isinstance(result, dict)
        assert result["block_reason"] == "output_unreadable"

    def test_a_clean_object_is_returned(self) -> None:
        """Control: nothing detected, nothing withheld."""
        config = AirlockConfig(sanitize_output=True, withhold_unmaskable_output=True)

        @Airlock(config=config)
        def note() -> _Note:
            return _Note(user="alice", text="see you at noon")

        assert isinstance(note(), _Note)

    def test_an_object_inside_a_container_is_withheld_too(self) -> None:
        config = AirlockConfig(sanitize_output=True, withhold_unmaskable_output=True)

        @Airlock(config=config)
        def creds() -> dict[str, Any]:
            return {"credentials": _Credentials(user="alice", token=KEY)}

        result = creds()
        assert isinstance(result, dict)
        assert result.get("block_reason") == "output_unreadable"

    def test_the_injection_presets_turn_it_on(self) -> None:
        for preset in (
            capsule_indirect_injection_cve_2026_21520_defaults(),
            context7_contextcrush_cve_2026_75130_defaults(),
        ):
            assert preset["airlock_config"].withhold_unmaskable_output is True

    def test_toml_reads_it(self, tmp_path: Any) -> None:
        toml = tmp_path / "airlock.toml"
        toml.write_text("[airlock]\nwithhold_unmaskable_output = true\n")
        assert AirlockConfig.from_toml(toml).withhold_unmaskable_output is True


class _Rows(BaseModel):
    rows: Any


class TestDetectionReadsWithoutConsuming:
    def test_a_generator_field_is_still_there_after_detection(self) -> None:
        """Detection reads each field with repr(); serializing it would drain a generator."""

        @Airlock(config=AirlockConfig(sanitize_output=True))
        def page() -> _Rows:
            return _Rows(rows=(n for n in range(3)))

        result = page()
        assert isinstance(result, _Rows)
        assert list(result.rows) == [0, 1, 2]
