"""0.10.25: what the Anthropic adapters send back to the model.

Tools are defined at module level, as a real tool module defines them, so their string
annotations (``from __future__ import annotations``) resolve against this module's globals.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock import Airlock, is_refusal, refusal_text
from agent_airlock.integrations._claude_sdk_tools import _sdk_error_result
from agent_airlock.self_heal import AirlockResponse, BlockReason


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
