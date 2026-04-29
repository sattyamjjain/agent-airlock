"""Tool-call shape adapter for Google Gemini 3 ("Agent Mode") (v0.6.0+).

Gemini 3 Agent Mode GA'd 2026-04-25 with a tool-call carrier that
differs from both GPT-5.5's homogenised array and Anthropic's
``tool_use`` blocks. The Gemini 3 shape is:

    {
      "candidates": [{
        "content": {
          "parts": [{
            "function_call": {"name": "...", "args": {...}},
            "thought_signature": "..."
          }]
        }
      }]
    }

For parallel tool calls, multiple ``parts[]`` entries each carry one
``function_call``. ``thought_signature`` is a chain-of-thought metadata
field that we redact by default — leaking it in audit logs would
recreate the privacy posture problem the model vendor is trying to
solve.

This adapter normalises into the same :class:`NormalizedToolCall`
dataclass the GPT-5.5 adapter exposes, so downstream guards stay
model-agnostic.

The version set is pinned via :data:`SUPPORTED_VERSIONS`. An unknown
``gemini-3-*`` model id raises :class:`UnsupportedModelVersion`
rather than silently passing through, so a Google rev surfaces as a
deterministic CI failure.

Reference
---------
* Gemini 3 Agent Mode GA (2026-04-25):
  https://blog.google/technology/google-deepmind/gemini-3-agent-mode-ga/
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from ..exceptions import AirlockError
from .gpt5_5_tool_shape_adapter import NormalizedToolCall

logger = structlog.get_logger("agent-airlock.integrations.gemini3_tool_shape_adapter")

SCHEMA_PINNED_AT: str = "2026-04-25"
SUPPORTED_VERSIONS: frozenset[str] = frozenset(
    {
        "gemini-3-agent",
        "gemini-3-agent-001",
        "gemini-3-agent-002",
    }
)

_REDACTED_THOUGHT = "<redacted by airlock>"


class UnsupportedModelVersion(AirlockError):
    """Raised when an unknown ``gemini-3-*`` model id is encountered."""

    def __init__(self, message: str, *, model_id: str) -> None:
        self.model_id = model_id
        super().__init__(message)


def _ensure_supported(model_id: str | None) -> None:
    if model_id is None:
        return
    if model_id not in SUPPORTED_VERSIONS:
        raise UnsupportedModelVersion(
            f"unknown Gemini 3 model id: {model_id!r}. Pinned set: {sorted(SUPPORTED_VERSIONS)}",
            model_id=model_id,
        )


def normalise_gemini3_call(
    raw: dict[str, Any],
    *,
    model_id: str | None = None,
) -> list[NormalizedToolCall]:
    """Convert a Gemini 3 response payload to ``list[NormalizedToolCall]``.

    Args:
        raw: Either the full response dict (``{"candidates": [...]}``)
            or a single message dict (``{"parts": [...]}``).
        model_id: Optional explicit model id. When supplied and
            unknown, :class:`UnsupportedModelVersion` is raised.

    Returns:
        One :class:`NormalizedToolCall` per ``parts[]`` entry that
        carries a ``function_call``. Empty list when the response had
        none.
    """
    _ensure_supported(model_id)

    parts = _extract_parts(raw)
    out: list[NormalizedToolCall] = []
    for idx, part in enumerate(parts):
        if not isinstance(part, dict):
            continue
        fn = part.get("function_call")
        if not isinstance(fn, dict):
            continue
        name = fn.get("name")
        args = fn.get("args")
        if not name:
            raise ValueError(f"parts[{idx}].function_call missing required 'name' field")
        if isinstance(args, str) and args:
            try:
                args_dict = json.loads(args)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"parts[{idx}].function_call.args is not valid JSON: {exc}"
                ) from exc
            if not isinstance(args_dict, dict):
                raise ValueError(
                    f"parts[{idx}].function_call.args must decode to a dict, "
                    f"got {type(args_dict).__name__}"
                )
        elif isinstance(args, dict):
            args_dict = dict(args)
        elif args is None:
            args_dict = {}
        else:
            raise ValueError(
                f"parts[{idx}].function_call.args has unsupported type {type(args).__name__}"
            )
        # Gemini 3 does not surface a per-call id; synthesise one so
        # downstream guards have stable provenance.
        call_id = f"gemini3-call-{idx}"
        out.append(
            NormalizedToolCall(
                call_id=call_id,
                tool_name=str(name),
                arguments=args_dict,
                type="function",
            )
        )
    return out


def serialise_gemini3_response(
    calls: list[NormalizedToolCall],
    *,
    redact_thought_signature: bool = True,
) -> dict[str, Any]:
    """Convert a list of normalized tool calls back to the Gemini 3 shape.

    Round-trip property: ``normalise_gemini3_call(serialise_gemini3_response(c))
    == c`` for any ``calls`` whose ``arguments`` are JSON-serialisable.
    """
    parts: list[dict[str, Any]] = []
    for c in calls:
        part: dict[str, Any] = {
            "function_call": {
                "name": c.tool_name,
                "args": dict(c.arguments),
            }
        }
        if redact_thought_signature:
            part["thought_signature"] = _REDACTED_THOUGHT
        parts.append(part)
    return {"candidates": [{"content": {"parts": parts}}]}


def _extract_parts(raw: dict[str, Any]) -> list[Any]:
    """Tolerate full-response and message-only shapes."""
    candidates = raw.get("candidates")
    if isinstance(candidates, list) and candidates:
        first = candidates[0]
        if isinstance(first, dict):
            content = first.get("content")
            if isinstance(content, dict):
                parts = content.get("parts")
                if isinstance(parts, list):
                    return list(parts)
    parts_top = raw.get("parts")
    if isinstance(parts_top, list):
        return list(parts_top)
    return []


__all__ = [
    "SCHEMA_PINNED_AT",
    "SUPPORTED_VERSIONS",
    "UnsupportedModelVersion",
    "normalise_gemini3_call",
    "serialise_gemini3_response",
]
