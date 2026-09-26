"""Tool output that is not a string must be masked too, and never merely reported as masked.

Every non-string result used to be serialized to JSON, masked, and the masked text thrown
away: ``@Airlock`` returned the raw dict while logging ``output_sanitized``, warning
"Masked N sensitive value(s)" and writing ``sanitized_count: N`` into the audit record. A
dict is the ordinary shape of a tool result (the Claude Agent SDK's handlers return one),
so output masking silently did not apply to most structured tools.
"""

from __future__ import annotations

import json
from collections import namedtuple
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock
from agent_airlock.config import AirlockConfig
from agent_airlock.sanitizer import sanitize_structured

EMAIL = "alice@example.com"

_Pair = namedtuple("_Pair", "note n")


@dataclass
class _Record:
    note: str


class TestSanitizeStructured:
    def test_nested_strings_are_masked_and_the_shape_is_kept(self) -> None:
        value = {"content": [{"type": "text", "text": f"mail {EMAIL}"}], "is_error": False}

        masked, count = sanitize_structured(value)

        assert count == 1
        assert EMAIL not in json.dumps(masked)
        assert masked["content"][0]["type"] == "text"
        assert masked["is_error"] is False

    def test_keys_and_non_string_leaves_are_left_alone(self) -> None:
        value = {EMAIL: 1, "n": 3, "ok": True, "none": None}

        masked, count = sanitize_structured(value)

        assert count == 0
        assert masked is value

    @pytest.mark.parametrize(
        "value",
        [
            [f"mail {EMAIL}", 1],
            (f"mail {EMAIL}", 1),
            _Pair(f"mail {EMAIL}", 1),
            {f"mail {EMAIL}"},
            frozenset({f"mail {EMAIL}"}),
        ],
        ids=["list", "tuple", "namedtuple", "set", "frozenset"],
    )
    def test_each_container_keeps_its_type(self, value: Any) -> None:
        masked, count = sanitize_structured(value)

        assert count == 1
        assert type(masked) is type(value)
        assert EMAIL not in str(masked)

    def test_a_container_with_nothing_to_mask_comes_back_as_is(self) -> None:
        value = {"a": [1, "b"]}

        assert sanitize_structured(value) == (value, 0)
        assert sanitize_structured(value)[0] is value

    def test_a_cycle_does_not_recurse_forever(self) -> None:
        value: list[Any] = [f"mail {EMAIL}"]
        value.append(value)

        masked, count = sanitize_structured(value)

        assert count == 1
        assert EMAIL not in masked[0]

    def test_the_input_is_not_mutated(self) -> None:
        value = {"text": f"mail {EMAIL}"}

        sanitize_structured(value)

        assert value == {"text": f"mail {EMAIL}"}


class TestAirlockMasksStructuredResults:
    def test_a_dict_result_is_masked(self) -> None:
        def tool() -> dict[str, Any]:
            return {"content": [{"type": "text", "text": f"mail {EMAIL}"}]}

        result = Airlock()(tool)()

        assert isinstance(result, dict)
        assert EMAIL not in json.dumps(result)

    async def test_an_async_dict_result_is_masked(self) -> None:
        async def tool() -> dict[str, Any]:
            return {"text": f"mail {EMAIL}"}

        result = await Airlock()(tool)()

        assert EMAIL not in result["text"]

    def test_the_warning_counts_what_was_masked(self) -> None:
        def tool() -> list[str]:
            return [f"mail {EMAIL}", "and bob@example.org"]

        response = Airlock(return_dict=True)(tool)()

        assert response["warnings"] == ["Masked 2 sensitive value(s) in output"]

    def test_an_object_that_is_not_rebuilt_is_not_claimed_as_masked(self) -> None:
        record = _Record(f"mail {EMAIL}")

        def tool() -> _Record:
            return record

        response = Airlock(return_dict=True)(tool)()

        assert response["result"] is record
        assert response["warnings"] == [
            "Detected 1 sensitive value(s) in _Record output; not masked"
        ]

    def test_a_large_structured_result_is_not_reported_as_truncated(self) -> None:
        def tool() -> dict[str, str]:
            return {"text": "x" * 500}

        config = AirlockConfig(max_output_chars=100)
        response = Airlock(return_dict=True, config=config)(tool)()

        assert response["result"] == {"text": "x" * 500}
        assert not response.get("warnings")

    def test_the_audit_record_counts_only_what_was_masked(self, tmp_path: Path) -> None:
        # The record's result_preview is built from the returned result, so the raw
        # email of a dict result used to be written into the audit log itself.
        log = tmp_path / "audit.jsonl"
        config = AirlockConfig(enable_audit_log=True, audit_log_path=log)

        def dict_tool() -> dict[str, str]:
            return {"text": f"mail {EMAIL}"}

        def record_tool() -> _Record:
            return _Record(f"mail {EMAIL}")

        Airlock(config=config)(dict_tool)()
        Airlock(config=config)(record_tool)()

        lines = log.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines if line and not line.startswith("#")]
        assert [r["sanitized_count"] for r in records] == [1, 0]
        assert EMAIL not in records[0]["result_preview"]
