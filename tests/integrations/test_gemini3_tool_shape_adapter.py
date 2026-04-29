"""Tests for the Gemini 3 tool-shape adapter and ``gemini_3_agent_defaults``."""

from __future__ import annotations

import json

import pytest

from agent_airlock.capabilities import ModelCapabilityTier
from agent_airlock.integrations.gemini3_tool_shape_adapter import (
    SCHEMA_PINNED_AT,
    SUPPORTED_VERSIONS,
    UnsupportedModelVersion,
    normalise_gemini3_call,
    serialise_gemini3_response,
)
from agent_airlock.integrations.gpt5_5_tool_shape_adapter import NormalizedToolCall
from agent_airlock.integrations.model_tier import classify_model
from agent_airlock.policy_presets import gemini_3_agent_defaults

# Fixtures captured from public Gemini 3 Agent Mode docs.

_SINGLE_PAYLOAD: dict = {
    "candidates": [
        {
            "content": {
                "parts": [
                    {
                        "function_call": {
                            "name": "get_weather",
                            "args": {"city": "SF"},
                        },
                        "thought_signature": "secret-cot-marker",
                    }
                ]
            }
        }
    ]
}

_PARALLEL_PAYLOAD: dict = {
    "parts": [
        {
            "function_call": {"name": "lookup", "args": json.dumps({"k": f"v{i}"})},
            "thought_signature": f"cot-{i}",
        }
        for i in range(8)
    ]
}


class TestSchemaPin:
    def test_schema_date_constant(self) -> None:
        assert SCHEMA_PINNED_AT == "2026-04-25"

    def test_supported_versions_set(self) -> None:
        assert "gemini-3-agent" in SUPPORTED_VERSIONS


class TestNormalise:
    def test_single_call(self) -> None:
        out = normalise_gemini3_call(_SINGLE_PAYLOAD)
        assert len(out) == 1
        assert out[0].tool_name == "get_weather"
        assert out[0].arguments == {"city": "SF"}

    def test_parallel_calls(self) -> None:
        out = normalise_gemini3_call(_PARALLEL_PAYLOAD)
        assert len(out) == 8
        assert {c.tool_name for c in out} == {"lookup"}

    def test_empty_payload(self) -> None:
        assert normalise_gemini3_call({"candidates": []}) == []

    def test_missing_name_raises(self) -> None:
        with pytest.raises(ValueError, match="missing required 'name'"):
            normalise_gemini3_call({"parts": [{"function_call": {"args": {}}}]})

    def test_invalid_args_json_raises(self) -> None:
        with pytest.raises(ValueError, match="not valid JSON"):
            normalise_gemini3_call(
                {
                    "parts": [
                        {
                            "function_call": {
                                "name": "x",
                                "args": "{not json",
                            }
                        }
                    ]
                }
            )


class TestUnsupportedVersion:
    def test_unknown_model_id_raises(self) -> None:
        with pytest.raises(UnsupportedModelVersion) as excinfo:
            normalise_gemini3_call(_SINGLE_PAYLOAD, model_id="gemini-3-future")
        assert excinfo.value.model_id == "gemini-3-future"

    def test_supported_model_id_passes(self) -> None:
        out = normalise_gemini3_call(_SINGLE_PAYLOAD, model_id="gemini-3-agent")
        assert len(out) == 1


class TestRoundTrip:
    def test_round_trip_preserves_calls(self) -> None:
        original = [
            NormalizedToolCall(
                call_id="gemini3-call-0",
                tool_name="t1",
                arguments={"x": 1, "y": "two"},
            )
        ]
        out = normalise_gemini3_call(serialise_gemini3_response(original))
        assert out == original

    def test_round_trip_parallel(self) -> None:
        original = [
            NormalizedToolCall(
                call_id=f"gemini3-call-{i}",
                tool_name="lookup",
                arguments={"k": f"v{i}"},
            )
            for i in range(8)
        ]
        out = normalise_gemini3_call(serialise_gemini3_response(original))
        assert out == original


class TestThoughtSignatureRedaction:
    def test_redacted_by_default(self) -> None:
        calls = [NormalizedToolCall(call_id="gemini3-call-0", tool_name="t", arguments={})]
        out = serialise_gemini3_response(calls)
        parts = out["candidates"][0]["content"]["parts"]
        assert parts[0]["thought_signature"] == "<redacted by airlock>"

    def test_redaction_disabled(self) -> None:
        calls = [NormalizedToolCall(call_id="gemini3-call-0", tool_name="t", arguments={})]
        out = serialise_gemini3_response(calls, redact_thought_signature=False)
        parts = out["candidates"][0]["content"]["parts"]
        assert "thought_signature" not in parts[0]


class TestPreset:
    def test_preset_shape(self) -> None:
        preset = gemini_3_agent_defaults()
        assert preset["preset_id"] == "gemini_3_agent_defaults"
        assert preset["model_id"] == "gemini-3-agent"
        assert preset["fan_out_cap"] == 8
        assert preset["per_call_egress_cap_kb"] == 64
        assert preset["redact_thought_signature"] is True

    def test_preset_blocks_9_parallel_calls(self) -> None:
        preset = gemini_3_agent_defaults()
        nine_calls = {"parts": [{"function_call": {"name": "f", "args": {}}} for _ in range(9)]}
        normalised = normalise_gemini3_call(nine_calls)
        assert len(normalised) > preset["fan_out_cap"]


class TestModelTier:
    def test_gemini_3_agent_classified(self) -> None:
        assert classify_model("gemini-3-agent") == ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE
