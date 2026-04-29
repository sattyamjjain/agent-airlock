"""Tool-call shape adapter for OpenAI GPT-5.5 ("Spud") (v0.5.9+).

GPT-5.5 GA'd 2026-04-23 with an agent-native tool-call shape:

    {
      "tool_calls": [
        {"id": "tc_1", "type": "function", "function": {...}},
        {"id": "tc_2", "type": "function", "function": {...}}
      ]
    }

Historically OpenAI returned a split shape — a single ``function_call``
object plus a separate ``tool_calls`` list — which downstream guards
had to special-case. The 5.5 surface is uniform: every tool call is an
element of ``tool_calls`` regardless of fan-out.

This adapter normalises the raw payload into a sequence of
:class:`NormalizedToolCall` instances that existing airlock guards
inspect, and reverses the mapping so airlock can re-emit a payload
shape OpenAI accepts.

The schema id is pinned via :data:`SCHEMA_PINNED_AT` so a future
OpenAI rev surfaces as a single-file diff, not a silent breakage.

Reference
---------
* OpenAI GPT-5.5 announcement (2026-04-23):
  https://openai.com/index/gpt-5-5/
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.integrations.gpt5_5_tool_shape_adapter")

SCHEMA_PINNED_AT: str = "2026-04-23"
"""ISO date the GPT-5.5 tool-call schema was last verified."""


@dataclass(frozen=True)
class NormalizedToolCall:
    """Canonical airlock-internal tool call.

    Equivalent across every adapter (OpenAI legacy, GPT-5.5, Anthropic,
    LangChain). Airlock guards inspect this; never the raw vendor
    payload.
    """

    call_id: str
    tool_name: str
    arguments: dict[str, Any]
    type: str = "function"


class GPT55ToolShapeAdapter:
    """Round-trip adapter between GPT-5.5 raw payloads and ``NormalizedToolCall``."""

    __schema_pinned_at__: str = SCHEMA_PINNED_AT

    def normalize(self, payload: dict[str, Any]) -> list[NormalizedToolCall]:
        """Convert a raw GPT-5.5 response payload to ``list[NormalizedToolCall]``.

        Args:
            payload: The dict returned by the OpenAI Python SDK for a
                GPT-5.5 chat completion. Either the full response (with
                a ``"choices"`` list) or just the message dict
                (``{"tool_calls": [...]}``) is accepted.

        Returns:
            One :class:`NormalizedToolCall` per element of
            ``tool_calls``. Empty list when the model emitted no tool
            calls.

        Raises:
            ValueError: When a ``tool_calls`` element is missing
                required fields. We refuse to silently drop tool calls
                — that would create an audit blind spot.
        """
        message = self._extract_message(payload)
        raw_calls = message.get("tool_calls") or []
        if not isinstance(raw_calls, list):
            raise ValueError(f"tool_calls must be a list, got {type(raw_calls).__name__}")

        normalized: list[NormalizedToolCall] = []
        for idx, raw in enumerate(raw_calls):
            if not isinstance(raw, dict):
                raise ValueError(f"tool_calls[{idx}] must be a dict, got {type(raw).__name__}")
            call_id = raw.get("id")
            call_type = raw.get("type", "function")
            fn = raw.get("function") or {}
            tool_name = fn.get("name")
            args_raw = fn.get("arguments")

            if not call_id or not tool_name:
                raise ValueError(
                    f"tool_calls[{idx}] missing required id / function.name "
                    f"(got id={call_id!r}, name={tool_name!r})"
                )

            arguments: dict[str, Any]
            if isinstance(args_raw, dict):
                arguments = dict(args_raw)
            elif isinstance(args_raw, str) and args_raw:
                try:
                    parsed = json.loads(args_raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"tool_calls[{idx}].function.arguments is not valid JSON: {exc}"
                    ) from exc
                if not isinstance(parsed, dict):
                    raise ValueError(
                        f"tool_calls[{idx}].function.arguments must decode to a dict, "
                        f"got {type(parsed).__name__}"
                    )
                arguments = parsed
            else:
                arguments = {}

            normalized.append(
                NormalizedToolCall(
                    call_id=str(call_id),
                    tool_name=str(tool_name),
                    arguments=arguments,
                    type=str(call_type),
                )
            )
        return normalized

    def denormalize(self, calls: list[NormalizedToolCall]) -> dict[str, Any]:
        """Convert a list of normalized tool calls back to a GPT-5.5 message shape.

        Round-trip property: ``normalize(denormalize(c)) == c`` for any
        list of :class:`NormalizedToolCall` whose ``arguments`` are JSON-
        serialisable.
        """
        return {
            "tool_calls": [
                {
                    "id": c.call_id,
                    "type": c.type,
                    "function": {
                        "name": c.tool_name,
                        "arguments": json.dumps(c.arguments, sort_keys=True),
                    },
                }
                for c in calls
            ]
        }

    def _extract_message(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Tolerate both full-response and message-only payloads."""
        if "choices" in payload:
            choices = payload.get("choices") or []
            if isinstance(choices, list) and choices:
                first = choices[0]
                if isinstance(first, dict):
                    msg = first.get("message")
                    if isinstance(msg, dict):
                        return msg
        return payload


__all__ = [
    "SCHEMA_PINNED_AT",
    "GPT55ToolShapeAdapter",
    "NormalizedToolCall",
]
