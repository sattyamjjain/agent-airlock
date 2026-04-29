"""Tests for the LangChain 0.4.0 ``tool_call_id`` fixture migration helper."""

from __future__ import annotations

import json
from pathlib import Path

from agent_airlock.integrations.lc_040_fixture_migration import (
    migrate_fixture_file,
    migrate_messages,
)


class TestMigrateMessages:
    def test_tool_message_without_id_is_filled(self) -> None:
        msgs = [
            {"role": "user", "content": "hi"},
            {"role": "tool", "content": "result"},
        ]
        out = migrate_messages(msgs)
        assert out[0] == msgs[0]  # untouched
        assert out[1]["tool_call_id"] == "synth-tcid-0000"

    def test_existing_tool_call_id_preserved(self) -> None:
        msgs = [{"role": "tool", "content": "r", "tool_call_id": "tc-existing"}]
        out = migrate_messages(msgs)
        assert out[0]["tool_call_id"] == "tc-existing"

    def test_idempotent(self) -> None:
        msgs = [{"role": "tool", "content": "r"}]
        once = migrate_messages(msgs)
        twice = migrate_messages(once)
        assert once == twice

    def test_type_tool_surface(self) -> None:
        # langchain_core surface uses ``type`` rather than ``role``.
        msgs = [{"type": "tool", "content": "r"}]
        out = migrate_messages(msgs)
        assert out[0]["tool_call_id"] == "synth-tcid-0000"

    def test_non_dict_passthrough(self) -> None:
        msgs = ["not-a-dict", {"role": "tool", "content": "r"}]
        out = migrate_messages(msgs)
        assert out[0] == "not-a-dict"
        assert out[1]["tool_call_id"] == "synth-tcid-0000"


class TestMigrateFile:
    def test_list_shape(self, tmp_path: Path) -> None:
        path = tmp_path / "fixture.json"
        path.write_text(json.dumps([{"role": "tool", "content": "r"}]), encoding="utf-8")
        n = migrate_fixture_file(path)
        assert n == 1
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded[0]["tool_call_id"]

    def test_dict_with_messages_shape(self, tmp_path: Path) -> None:
        path = tmp_path / "fixture.json"
        path.write_text(
            json.dumps({"meta": "x", "messages": [{"role": "tool", "content": "r"}]}),
            encoding="utf-8",
        )
        n = migrate_fixture_file(path)
        assert n == 1
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded["messages"][0]["tool_call_id"]

    def test_no_op_for_clean_fixture(self, tmp_path: Path) -> None:
        path = tmp_path / "fixture.json"
        original = [{"role": "tool", "content": "r", "tool_call_id": "tc-a"}]
        path.write_text(json.dumps(original), encoding="utf-8")
        n = migrate_fixture_file(path)
        assert n == 0

    def test_unknown_shape_returns_zero(self, tmp_path: Path) -> None:
        path = tmp_path / "fixture.json"
        path.write_text(json.dumps({"unrelated": "thing"}), encoding="utf-8")
        assert migrate_fixture_file(path) == 0
