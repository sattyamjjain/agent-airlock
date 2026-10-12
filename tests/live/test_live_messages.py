"""Live contract: the Messages adapter and task-budget shape against the real API.

Spends API credit; run with ``make test-live``. Every request is on Claude Haiku 5.5,
which accepts a forced ``tool_choice``; no sampling parameter is sent.

What it settles, that only live traffic can:

* A refusal Airlock returns through ``process_message_tools`` is a ``tool_result`` with
  ``is_error: true`` that the API accepts back, and its text names the allowed root.
* The generated schema makes the model send ``max_chars`` as an integer, which Airlock's
  strict validation admits (a ``"string"`` schema made it send ``"50"``, refused).
* ``output_config={"task_budget": {...}}`` is accepted with the
  ``task-budgets-2026-03-13`` beta, and the pre-0.10.25 top-level shape is a 400.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import AirlockConfig
from agent_airlock.filesystem import FilesystemPolicy
from agent_airlock.integrations.anthropic import ToolRegistry, process_message_tools
from agent_airlock.integrations.claude_task_budget import (
    BETA_HEADER_VALUE,
    MIN_TASK_BUDGET_TOKENS,
    build_output_config,
)

from ._live import LIVE_MODEL, LiveRecorder

pytestmark = pytest.mark.live

OUTSIDE = "/opt/airlock-live/outside.txt"
MAX_TOKENS = 2048


def read_note(path: str, max_chars: int = 200) -> dict[str, Any]:
    """Read a note file and return its first max_chars characters."""
    text = Path(path).read_text(encoding="utf-8")
    return {"path": path, "max_chars": max_chars, "text": text[:max_chars]}


@pytest.fixture
def note_root() -> Iterator[Path]:
    """An allowed root under /tmp, resolved so no symlinked component is in it."""
    root = Path(tempfile.mkdtemp(prefix="airlock-live-", dir="/tmp")).resolve()
    (root / "note.txt").write_text("The note says: blue sky, green field.", encoding="utf-8")
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _registry(root: Path) -> ToolRegistry:
    policy = FilesystemPolicy(allowed_roots=[root])
    registry = ToolRegistry(config=AirlockConfig(filesystem_policy=policy))
    registry.tool(read_note)
    return registry


def _forced(client: Any, registry: ToolRegistry, prompt: str) -> Any:
    response = client.messages.create(
        model=LIVE_MODEL,
        max_tokens=MAX_TOKENS,
        tools=registry.get_tool_definitions(),
        tool_choice={"type": "tool", "name": "read_note"},
        messages=[{"role": "user", "content": prompt}],
    )
    if response.stop_reason == "refusal":
        pytest.fail(
            f"{LIVE_MODEL} returned stop_reason 'refusal'; the tool contract was not exercised"
        )
    return response


def _usage(response: Any) -> dict[str, Any]:
    usage = getattr(response, "usage", None)
    return {
        "model_requested": LIVE_MODEL,
        "model_observed": getattr(response, "model", None),
        "stop_reason": getattr(response, "stop_reason", None),
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
    }


def _tool_use(response: Any) -> Any:
    blocks = [block for block in response.content if block.type == "tool_use"]
    assert blocks, f"no tool_use block in the response (stop_reason {response.stop_reason})"
    return blocks[0]


class TestToolResults:
    def test_an_outside_read_is_an_error_the_api_accepts(
        self, anthropic_client: Any, live_recorder: LiveRecorder, note_root: Path
    ) -> None:
        registry = _registry(note_root)
        prompt = f"Read the note at {OUTSIDE}."
        response = _forced(anthropic_client, registry, prompt)
        tool_use = _tool_use(response)
        results = process_message_tools(response, registry)

        follow_up = anthropic_client.messages.create(
            model=LIVE_MODEL,
            max_tokens=MAX_TOKENS,
            tools=registry.get_tool_definitions(),
            messages=[
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": response.content},
                {"role": "user", "content": results},
            ],
        )
        live_recorder.record(
            "messages.outside_read",
            first=_usage(response),
            follow_up=_usage(follow_up),
            input_keys=sorted(tool_use.input),
            result_keys=sorted(results[0]) if results else [],
            is_error=results[0].get("is_error") if results else None,
            root_named=bool(results) and str(note_root) in str(results[0].get("content")),
        )
        assert results and results[0]["is_error"] is True, results
        assert results[0]["content"].startswith("AIRLOCK_BLOCK"), results[0]["content"]
        assert str(note_root) in results[0]["content"], (
            "the refusal does not name the allowed root: " + results[0]["content"]
        )
        assert follow_up.stop_reason != "refusal"

    def test_an_inside_read_returns_json_and_an_integer(
        self, anthropic_client: Any, live_recorder: LiveRecorder, note_root: Path
    ) -> None:
        registry = _registry(note_root)
        inside = note_root / "note.txt"
        response = _forced(
            anthropic_client, registry, f"Read the note at {inside} with max_chars set to 50."
        )
        tool_use = _tool_use(response)
        results = process_message_tools(response, registry)
        live_recorder.record(
            "messages.inside_read",
            usage=_usage(response),
            input_types={key: type(value).__name__ for key, value in tool_use.input.items()},
            is_error=results[0].get("is_error") if results else None,
        )
        assert results and "is_error" not in results[0], results
        payload = json.loads(results[0]["content"])
        assert type(payload["max_chars"]) is int, payload
        assert payload["text"].startswith("The note says")


class TestTaskBudgetWireShape:
    def test_the_output_config_shape_is_accepted(
        self, anthropic_client: Any, live_recorder: LiveRecorder
    ) -> None:
        response = anthropic_client.beta.messages.create(
            betas=[BETA_HEADER_VALUE],
            model=LIVE_MODEL,
            max_tokens=256,
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
            **build_output_config(MIN_TASK_BUDGET_TOKENS),
        )
        live_recorder.record("task_budget.new_shape", usage=_usage(response))
        assert response.stop_reason != "refusal"

    def test_the_pre_0_10_25_shape_is_rejected(
        self, anthropic_module: Any, anthropic_client: Any, live_recorder: LiveRecorder
    ) -> None:
        with pytest.raises(anthropic_module.BadRequestError) as exc:
            anthropic_client.beta.messages.create(
                betas=[BETA_HEADER_VALUE],
                model=LIVE_MODEL,
                max_tokens=256,
                messages=[{"role": "user", "content": "Reply with the single word OK."}],
                extra_body={
                    "task_budget": {
                        "total_tokens": MIN_TASK_BUDGET_TOKENS,
                        "remaining_tokens": MIN_TASK_BUDGET_TOKENS,
                        "policy": "soft",
                    }
                },
            )
        live_recorder.record(
            "task_budget.old_shape",
            status_code=exc.value.status_code,
            error=str(exc.value)[:500],
        )
        assert exc.value.status_code == 400
