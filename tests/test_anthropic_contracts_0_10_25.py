"""0.10.25: what the Anthropic adapters send back to the model.

Tools are defined at module level, as a real tool module defines them, so their string
annotations (``from __future__ import annotations``) resolve against this module's globals.
"""

from __future__ import annotations

import dataclasses
import json
import warnings
from types import SimpleNamespace
from typing import Annotated, Any, Literal

import pytest
from pydantic import BaseModel, Field

from agent_airlock import Airlock, AirlockConfig, is_refusal, refusal_text
from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations._claude_sdk_tools import _sdk_error_result
from agent_airlock.integrations.anthropic import (
    SecureAnthropicClient,
    ToolRegistry,
    aprocess_message_tools,
    process_message_tools,
)
from agent_airlock.integrations.anthropic_claude_agent_sdk import AnthropicClaudeAgentSDKAdapter
from agent_airlock.integrations.claude_auto_memory import AutoMemoryAccessPolicy
from agent_airlock.integrations.claude_managed_agents import ManagedAgentsAuditConfig
from agent_airlock.self_heal import AirlockResponse, BlockReason

RAN: list[str] = []


def _typed(count: int) -> int:
    return count


def _old_sdk_text(refusal: dict[str, Any]) -> str:
    """``_sdk_error_result``'s text as 0.10.24 built it, kept to pin byte-identity."""
    lines = [str(refusal.get("error") or "AIRLOCK_BLOCK: call refused")]
    hints = refusal.get("fix_hints") or []
    if hints:
        lines.append("Fix hints:")
        lines.extend(f"- {hint}" for hint in hints)
    return "\n".join(lines)


class Address(BaseModel):
    city: str
    zip_code: str | None = None


@dataclasses.dataclass
class Point:
    x: int
    y: int


class Opaque:
    """A plain class: Pydantic cannot describe it in a JSON schema."""


def read_note(path: str, max_chars: int = 200) -> str:
    """Read a note."""
    RAN.append("read_note")
    return f"{path}:{max_chars}"


def every_type(
    name: str,
    count: int,
    ratio: float,
    enabled: bool,
    mode: Literal["fast", "slow"] = "fast",
    limit: Annotated[int, Field(ge=1, le=10, description="how many")] = 1,
    maybe: int | None = None,
    tags: list[str] | None = None,
    address: Address | None = None,
    marker: object = Opaque,
) -> str:
    """Take every kind of parameter."""
    return name


def open_ended(query: str, *args: Any, **kwargs: Any) -> str:
    return query


def method_like(self: Any, value: int) -> int:
    return value


def positional_only(value: int, /) -> int:
    return value


def takes_opaque(thing: Opaque) -> str:
    return "x"


def returns_dict(n: int) -> dict[str, Any]:
    return {"n": n, "half": n / 2, "ok": True, "items": [1, 2]}


def returns_model() -> Address:
    return Address(city="Pune")


def returns_dataclass() -> Point:
    return Point(1, 2)


def returns_set() -> set[int]:
    return {3, 1, 2}


def returns_blocks() -> list[dict[str, Any]]:
    return [{"type": "text", "text": "first"}, {"type": "text", "text": "second"}]


def returns_empty_list() -> list[int]:
    return []


def returns_email() -> str:
    return "write to alice@example.com"


def raises_with_secret() -> str:
    raise RuntimeError("connection string postgres://admin:hunter2@db/prod")


async def async_note(path: str) -> str:
    RAN.append("async_note")
    return f"async:{path}"


def _registry(*tools: Any) -> ToolRegistry:
    registry = ToolRegistry()
    for tool in tools:
        registry.tool()(tool)
    return registry


def _schema(tool: Any) -> dict[str, Any]:
    return _registry(tool).get_tool_definitions()[0]["input_schema"]


def _block(name: str, inputs: Any, tool_use_id: str = "toolu_1") -> dict[str, Any]:
    return {"type": "tool_use", "id": tool_use_id, "name": name, "input": inputs}


@pytest.fixture(autouse=True)
def _clear_runs() -> None:
    RAN.clear()


class TestRefusalHelpers:
    """B0: one rendering of a refusal, shared by every adapter that returns one to a model."""

    @staticmethod
    def _real_refusal() -> dict[str, Any]:
        guarded = Airlock()(_typed)
        result = guarded(count="not a number")
        assert is_refusal(result), result
        return result

    def test_a_real_block_is_a_refusal(self) -> None:
        assert is_refusal(self._real_refusal())

    @pytest.mark.parametrize(
        "value",
        [
            {"success": False},
            {"success": False, "status": "failed"},
            {"success": True, "status": "blocked"},
            {"status": "blocked"},
            "blocked",
            None,
            [("success", False), ("status", "blocked")],
        ],
    )
    def test_a_tool_that_returns_success_false_is_not_a_refusal(self, value: Any) -> None:
        assert not is_refusal(value)

    def test_the_text_is_the_error_then_the_hints(self) -> None:
        refusal = AirlockResponse.blocked_response(
            reason=BlockReason.POLICY_VIOLATION,
            error="AIRLOCK_BLOCK: no",
            fix_hints=["first", "second"],
            metadata={"resolved_path": "/home/someone/.ssh/id_rsa"},
        ).to_dict()
        assert refusal_text(refusal) == "AIRLOCK_BLOCK: no\nFix hints:\n- first\n- second"

    def test_the_text_never_carries_the_metadata(self) -> None:
        refusal = AirlockResponse.blocked_response(
            reason=BlockReason.PATH_VIOLATION,
            error="AIRLOCK_BLOCK: Path blocked",
            metadata={"resolved_path": "/home/someone/.ssh/id_rsa", "pattern": "**/.ssh/**"},
        ).to_dict()
        text = refusal_text(refusal)
        assert "/home/someone" not in text
        assert ".ssh/**" not in text

    def test_no_hints_means_no_hints_heading(self) -> None:
        assert refusal_text({"error": "AIRLOCK_BLOCK: x"}) == "AIRLOCK_BLOCK: x"

    def test_a_refusal_without_an_error_still_says_it_was_refused(self) -> None:
        assert refusal_text({}).startswith("AIRLOCK_BLOCK")

    def test_a_string_hint_is_one_hint_not_one_per_character(self) -> None:
        assert refusal_text({"error": "e", "fix_hints": "do this"}) == "e\nFix hints:\n- do this"

    def test_the_sdk_adapter_text_is_byte_identical_to_0_10_24(self) -> None:
        refusal = self._real_refusal()
        result = _sdk_error_result(refusal)
        assert result["is_error"] is True
        assert result["content"] == [{"type": "text", "text": _old_sdk_text(refusal)}]
        assert result["content"][0]["text"] == refusal_text(refusal)


class TestTheSchemaIsTheContract:
    """B2: the model is told the types Airlock enforces, not ``"string"`` for everything."""

    def test_scalar_types(self) -> None:
        props = _schema(every_type)["properties"]
        assert props["name"]["type"] == "string"
        assert props["count"]["type"] == "integer"
        assert props["ratio"]["type"] == "number"
        assert props["enabled"]["type"] == "boolean"

    def test_literal_is_an_enum(self) -> None:
        assert _schema(every_type)["properties"]["mode"]["enum"] == ["fast", "slow"]

    def test_constraints_and_descriptions_are_carried(self) -> None:
        limit = _schema(every_type)["properties"]["limit"]
        assert (limit["minimum"], limit["maximum"]) == (1, 10)
        assert limit["description"] == "how many"

    def test_optional_is_any_of_with_null(self) -> None:
        maybe = _schema(every_type)["properties"]["maybe"]
        assert {"type": "integer"} in maybe["anyOf"]
        assert {"type": "null"} in maybe["anyOf"]

    def test_lists_carry_their_item_type(self) -> None:
        tags = _schema(every_type)["properties"]["tags"]
        assert {"type": "array", "items": {"type": "string"}} in tags["anyOf"]

    def test_nested_models_go_to_defs(self) -> None:
        schema = _schema(every_type)
        assert "Address" in schema["$defs"]
        assert {"$ref": "#/$defs/Address"} in schema["properties"]["address"]["anyOf"]

    def test_required_is_the_parameters_without_defaults(self) -> None:
        assert _schema(every_type)["required"] == ["name", "count", "ratio", "enabled"]

    def test_json_serialisable_defaults_are_published(self) -> None:
        props = _schema(every_type)["properties"]
        assert props["mode"]["default"] == "fast"
        assert props["limit"]["default"] == 1
        assert props["maybe"]["default"] is None
        assert "default" not in props["marker"]  # a class is not JSON

    def test_no_top_level_title_and_an_object_type(self) -> None:
        schema = _schema(every_type)
        assert "title" not in schema
        assert schema["type"] == "object"

    def test_undeclared_arguments_are_not_invited(self) -> None:
        assert _schema(every_type)["additionalProperties"] is False

    def test_kwargs_and_args_are_not_parameters(self) -> None:
        schema = _schema(open_ended)
        assert list(schema["properties"]) == ["query"]
        assert "additionalProperties" not in schema  # **kwargs takes any key

    def test_self_is_skipped(self) -> None:
        assert list(_schema(method_like)["properties"]) == ["value"]

    def test_an_unresolvable_annotation_fails_at_registration(self) -> None:
        def broken(value: int) -> int:
            return value

        broken.__annotations__ = {"value": "NoSuchTypeAnywhere", "return": "int"}
        with pytest.raises(AirlockError, match="cannot resolve the annotations"):
            ToolRegistry().tool()(broken)

    def test_an_undescribable_annotation_fails_and_names_the_parameter(self) -> None:
        with pytest.raises(AirlockError, match="'thing'"):
            ToolRegistry().tool()(takes_opaque)

    def test_a_positional_only_parameter_fails_at_registration(self) -> None:
        with pytest.raises(AirlockError, match="positional-only"):
            ToolRegistry().tool()(positional_only)

    def test_a_value_matching_the_schema_passes_the_contract(self) -> None:
        registry = _registry(read_note)
        result = registry.process_tool_use(_block("read_note", {"path": "a", "max_chars": 5}))
        assert result == {"type": "tool_result", "tool_use_id": "toolu_1", "content": "a:5"}

    def test_a_value_the_schema_rules_out_is_refused(self) -> None:
        registry = _registry(read_note)
        result = registry.process_tool_use(_block("read_note", {"path": "a", "max_chars": "5"}))
        assert result["is_error"] is True
        assert RAN == []


class TestProcessToolUse:
    def test_a_refusal_is_an_error_with_the_refusal_text(self) -> None:
        registry = _registry(read_note)
        result = registry.process_tool_use(_block("read_note", {"path": 7}))
        assert result["is_error"] is True
        assert result["tool_use_id"] == "toolu_1"
        assert result["content"].startswith("AIRLOCK_BLOCK")
        assert "Fix hints:" in result["content"]
        assert "{" not in result["content"].splitlines()[0]  # not str(dict)

    def test_the_refusal_text_is_refusal_text(self) -> None:
        registry = _registry(read_note)
        direct = registry.execute_tool("read_note", {"path": 7})
        result = registry.process_tool_use(_block("read_note", {"path": 7}))
        assert result["content"] == refusal_text(direct)

    def test_an_sdk_shaped_block_works(self) -> None:
        registry = _registry(read_note)
        block = SimpleNamespace(
            type="tool_use", id="toolu_9", name="read_note", input={"path": "x"}
        )
        assert registry.process_tool_use(block)["content"] == "x:200"

    def test_a_string_is_sent_as_it_is(self) -> None:
        result = _registry(read_note).process_tool_use(_block("read_note", {"path": "p"}))
        assert result["content"] == "p:200"
        assert "is_error" not in result

    def test_a_dict_is_json_and_its_numbers_stay_numbers(self) -> None:
        result = _registry(returns_dict).process_tool_use(_block("returns_dict", {"n": 4}))
        assert json.loads(result["content"]) == {"n": 4, "half": 2.0, "ok": True, "items": [1, 2]}

    @pytest.mark.parametrize(
        ("tool", "expected"),
        [
            (returns_model, {"city": "Pune", "zip_code": None}),
            (returns_dataclass, {"x": 1, "y": 2}),
            (returns_set, [1, 2, 3]),
            (returns_empty_list, []),
        ],
    )
    def test_other_values_are_json(self, tool: Any, expected: Any) -> None:
        result = _registry(tool).process_tool_use(_block(tool.__name__, {}))
        assert json.loads(result["content"]) == expected

    def test_content_blocks_pass_through(self) -> None:
        result = _registry(returns_blocks).process_tool_use(_block("returns_blocks", {}))
        assert result["content"] == returns_blocks()

    def test_an_unknown_tool_is_an_error_naming_the_registered_ones(self) -> None:
        result = _registry(read_note, returns_dict).process_tool_use(_block("rm_rf", {}))
        assert result["is_error"] is True
        assert "'rm_rf'" in result["content"]
        assert "read_note, returns_dict" in result["content"]

    def test_input_that_is_not_an_object_is_an_error(self) -> None:
        result = _registry(read_note).process_tool_use(_block("read_note", ["a"]))
        assert result["is_error"] is True
        assert RAN == []

    def test_a_block_without_an_id_cannot_be_answered(self) -> None:
        with pytest.raises(AirlockError, match="'id'"):
            _registry(read_note).process_tool_use({"name": "read_note", "input": {}})

    def test_an_async_tool_in_the_sync_path_is_an_error_and_never_runs(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # an un-awaited coroutine would warn
            result = _registry(async_note).process_tool_use(_block("async_note", {"path": "p"}))
        assert result["is_error"] is True
        assert "aprocess_tool_use" in result["content"]
        assert RAN == []

    def test_a_tool_error_does_not_reach_the_model(self) -> None:
        result = _registry(raises_with_secret).process_tool_use(_block("raises_with_secret", {}))
        assert result["is_error"] is True
        assert "hunter2" not in result["content"]


class TestAsyncProcessing:
    async def test_an_async_tool_is_awaited(self) -> None:
        result = await _registry(async_note).aprocess_tool_use(_block("async_note", {"path": "p"}))
        assert result["content"] == "async:p"
        assert RAN == ["async_note"]

    async def test_a_sync_tool_runs_in_the_async_path(self) -> None:
        result = await _registry(read_note).aprocess_tool_use(_block("read_note", {"path": "p"}))
        assert result["content"] == "p:200"

    async def test_an_async_refusal_is_an_error(self) -> None:
        result = await _registry(async_note).aprocess_tool_use(_block("async_note", {"path": 3}))
        assert result["is_error"] is True
        assert RAN == []

    async def test_aprocess_message_tools(self) -> None:
        message = {"content": [_block("async_note", {"path": "a"}, "toolu_a")]}
        results = await aprocess_message_tools(message, _registry(async_note))
        assert [r["content"] for r in results] == ["async:a"]


class TestProcessMessageTools:
    def test_only_tool_use_blocks_are_run_in_order(self) -> None:
        message = SimpleNamespace(
            content=[
                SimpleNamespace(type="text", text="thinking aloud"),
                SimpleNamespace(type="tool_use", id="t1", name="read_note", input={"path": "a"}),
                SimpleNamespace(type="tool_use", id="t2", name="read_note", input={"path": "b"}),
            ]
        )
        results = process_message_tools(message, _registry(read_note))
        assert [(r["tool_use_id"], r["content"]) for r in results] == [
            ("t1", "a:200"),
            ("t2", "b:200"),
        ]

    def test_a_dict_message_works(self) -> None:
        results = process_message_tools(
            {"content": [_block("read_note", {"path": "a"})]}, _registry(read_note)
        )
        assert results[0]["content"] == "a:200"

    def test_string_content_is_sanitized(self) -> None:
        results = process_message_tools(
            {"content": [_block("returns_email", {})]}, _registry(returns_email)
        )
        assert "alice@example.com" not in results[0]["content"]

    def test_sanitizing_can_be_turned_off(self) -> None:
        registry = ToolRegistry(config=AirlockConfig(sanitize_output=False))
        registry.tool()(returns_email)
        results = process_message_tools(
            {"content": [_block("returns_email", {})]}, registry, should_sanitize=False
        )
        assert "alice@example.com" in results[0]["content"]

    def test_text_blocks_are_sanitized_one_by_one(self) -> None:
        def blocks_with_email() -> list[dict[str, Any]]:
            return [
                {"type": "text", "text": "mail bob@example.com"},
                {"type": "text", "text": "ok"},
            ]

        registry = ToolRegistry()
        registry.tool()(blocks_with_email)
        results = process_message_tools({"content": [_block("blocks_with_email", {})]}, registry)
        assert results[0]["content"][1] == {"type": "text", "text": "ok"}
        assert "bob@example.com" not in results[0]["content"][0]["text"]

    def test_a_refusal_survives_sanitizing_as_an_error(self) -> None:
        results = process_message_tools(
            {"content": [_block("read_note", {"path": 1})]}, _registry(read_note)
        )
        assert results[0]["is_error"] is True
        assert results[0]["content"].startswith("AIRLOCK_BLOCK")


class TestRegistration:
    def test_the_bare_decorator_registers(self) -> None:
        registry = ToolRegistry()

        @registry.tool
        def greet(name: str) -> str:
            """Greet someone."""
            return f"hi {name}"

        definition = registry.get_tool_definitions()[0]
        assert definition["name"] == "greet"
        assert definition["description"] == "Greet someone."
        assert greet(name="a") == "hi a"

    def test_a_positional_name_and_description(self) -> None:
        registry = ToolRegistry()
        registry.tool("custom", "Does a thing")(read_note)
        definition = registry.get_tool_definitions()[0]
        assert (definition["name"], definition["description"]) == ("custom", "Does a thing")

    def test_keyword_name_and_description(self) -> None:
        registry = ToolRegistry()
        registry.tool(name="n", description="d")(read_note)
        assert registry.get_tool_definitions()[0]["name"] == "n"


class TestAutoProcessToolsIsDeprecated:
    @pytest.mark.parametrize("value", [True, False])
    def test_passing_it_warns(self, value: bool) -> None:
        with pytest.warns(FutureWarning, match="removed in v1.0.0"):
            client = SecureAnthropicClient(object(), ToolRegistry(), auto_process_tools=value)
        assert client.auto_process_tools is value

    def test_leaving_it_out_does_not_warn(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            client = SecureAnthropicClient(object(), ToolRegistry())
        assert client.auto_process_tools is True

    def test_create_still_adds_the_tool_definitions(self) -> None:
        seen: dict[str, Any] = {}

        class _Messages:
            def create(self, **kwargs: Any) -> str:
                seen.update(kwargs)
                return "response"

        registry = _registry(read_note)
        client = SecureAnthropicClient(SimpleNamespace(messages=_Messages()), registry)
        assert client.messages.create(model="m") == "response"
        assert seen["tools"] == registry.get_tool_definitions()


class TestAgentSdkAdapterFieldsNothingReads:
    """B4: ``managed_audit`` and ``auto_memory_policy`` were stored and never read."""

    def test_managed_audit_warns_and_points_to_the_gate(self) -> None:
        with pytest.warns(FutureWarning, match="ManagedAgentToolGate") as record:
            AnthropicClaudeAgentSDKAdapter(managed_audit=ManagedAgentsAuditConfig())
        assert "removed in v1.0.0" in str(record[0].message)
        assert record[0].filename == __file__  # attributed to the caller

    def test_auto_memory_policy_warns(self) -> None:
        with pytest.warns(FutureWarning, match="guarded_read"):
            AnthropicClaudeAgentSDKAdapter(auto_memory_policy=AutoMemoryAccessPolicy("t1"))

    def test_the_defaults_do_not_warn(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            AnthropicClaudeAgentSDKAdapter()
            AnthropicClaudeAgentSDKAdapter(task_budget_total=64_000)
