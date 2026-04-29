"""Tests for the GPT-5.5 tool-shape adapter and ``gpt_5_5_spud`` preset."""

from __future__ import annotations

import json

import pytest

from agent_airlock.capabilities import ModelCapabilityTier
from agent_airlock.integrations.gpt5_5_tool_shape_adapter import (
    SCHEMA_PINNED_AT,
    GPT55ToolShapeAdapter,
    NormalizedToolCall,
)
from agent_airlock.integrations.model_tier import classify_model
from agent_airlock.policy_presets import gpt_5_5_spud_agent_defaults

# ---------------------------------------------------------------------------
# Fixtures captured from public GPT-5.5 docs (https://openai.com/index/gpt-5-5/).
# ---------------------------------------------------------------------------

_SINGLE_CALL_PAYLOAD: dict = {
    "choices": [
        {
            "message": {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": "call_a",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": '{"city": "SF"}',
                        },
                    }
                ],
            }
        }
    ]
}

_PARALLEL_CALLS_PAYLOAD: dict = {
    "tool_calls": [
        {
            "id": f"call_{i}",
            "type": "function",
            "function": {
                "name": "lookup",
                "arguments": json.dumps({"key": f"k{i}"}),
            },
        }
        for i in range(8)
    ]
}


@pytest.fixture
def adapter() -> GPT55ToolShapeAdapter:
    return GPT55ToolShapeAdapter()


class TestSchemaPin:
    def test_pinned_date_constant(self) -> None:
        assert SCHEMA_PINNED_AT == "2026-04-23"

    def test_class_attribute_matches_module_constant(self) -> None:
        assert GPT55ToolShapeAdapter.__schema_pinned_at__ == SCHEMA_PINNED_AT


class TestNormalize:
    def test_single_call(self, adapter: GPT55ToolShapeAdapter) -> None:
        out = adapter.normalize(_SINGLE_CALL_PAYLOAD)
        assert len(out) == 1
        assert out[0].call_id == "call_a"
        assert out[0].tool_name == "get_weather"
        assert out[0].arguments == {"city": "SF"}

    def test_parallel_calls(self, adapter: GPT55ToolShapeAdapter) -> None:
        out = adapter.normalize(_PARALLEL_CALLS_PAYLOAD)
        assert len(out) == 8
        assert {c.call_id for c in out} == {f"call_{i}" for i in range(8)}

    def test_empty_calls(self, adapter: GPT55ToolShapeAdapter) -> None:
        assert adapter.normalize({"tool_calls": []}) == []

    def test_missing_id_raises(self, adapter: GPT55ToolShapeAdapter) -> None:
        with pytest.raises(ValueError, match="missing required"):
            adapter.normalize(
                {"tool_calls": [{"type": "function", "function": {"name": "x", "arguments": "{}"}}]}
            )

    def test_invalid_arguments_json_raises(self, adapter: GPT55ToolShapeAdapter) -> None:
        with pytest.raises(ValueError, match="not valid JSON"):
            adapter.normalize(
                {
                    "tool_calls": [
                        {
                            "id": "x",
                            "type": "function",
                            "function": {"name": "y", "arguments": "{not json"},
                        }
                    ]
                }
            )

    def test_dict_arguments_passthrough(self, adapter: GPT55ToolShapeAdapter) -> None:
        # The SDK occasionally returns arguments as a pre-decoded dict
        # rather than the JSON-string form. Tolerate both.
        out = adapter.normalize(
            {
                "tool_calls": [
                    {
                        "id": "x",
                        "type": "function",
                        "function": {"name": "y", "arguments": {"a": 1}},
                    }
                ]
            }
        )
        assert out[0].arguments == {"a": 1}


class TestRoundTrip:
    """``normalize(denormalize(c)) == c``."""

    def test_round_trip_single(self, adapter: GPT55ToolShapeAdapter) -> None:
        original = [
            NormalizedToolCall(
                call_id="c1",
                tool_name="t1",
                arguments={"x": 1, "y": "two"},
            )
        ]
        out = adapter.normalize(adapter.denormalize(original))
        assert out == original

    def test_round_trip_parallel(self, adapter: GPT55ToolShapeAdapter) -> None:
        original = [
            NormalizedToolCall(
                call_id=f"c{i}",
                tool_name="lookup",
                arguments={"k": f"v{i}"},
            )
            for i in range(8)
        ]
        out = adapter.normalize(adapter.denormalize(original))
        assert out == original


class TestPresetDefaults:
    def test_preset_shape(self) -> None:
        preset = gpt_5_5_spud_agent_defaults()
        assert preset["preset_id"] == "gpt_5_5_spud_agent_defaults"
        assert preset["model_id"] == "openai.gpt-5.5-spud"
        assert preset["max_parallel_tool_calls"] == 8
        assert preset["per_call_egress_cap_kb"] == 512
        assert preset["context_window_budget_tokens"] == 900_000
        assert preset["requires_baseline"] is True
        assert preset["schema_pinned_at"] == SCHEMA_PINNED_AT
        assert "openai.com" in preset["advisory_url"]

    def test_preset_blocks_9_parallel_calls(self, adapter: GPT55ToolShapeAdapter) -> None:
        preset = gpt_5_5_spud_agent_defaults()
        nine_calls = {
            "tool_calls": [
                {
                    "id": f"c{i}",
                    "type": "function",
                    "function": {"name": "f", "arguments": "{}"},
                }
                for i in range(9)
            ]
        }
        normalized = adapter.normalize(nine_calls)
        assert len(normalized) > preset["max_parallel_tool_calls"]

    def test_preset_allows_8_parallel_calls(self, adapter: GPT55ToolShapeAdapter) -> None:
        preset = gpt_5_5_spud_agent_defaults()
        normalized = adapter.normalize(_PARALLEL_CALLS_PAYLOAD)
        assert len(normalized) == preset["max_parallel_tool_calls"]


class TestModelTierRow:
    def test_gpt_5_5_spud_classified_as_offensive_cyber(self) -> None:
        assert classify_model("gpt-5-5-spud") == ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE

    def test_gpt_5_5_prefix_match(self) -> None:
        assert classify_model("gpt-5-5") == ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE
