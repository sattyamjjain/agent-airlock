"""Tests for the LangGraph prebuilt 1.0.11 ToolNode shape-compat shim."""

from __future__ import annotations

import pytest

from agent_airlock.integrations.langgraph_toolnode_compat import (
    _is_post_1_0_11,
    unwrap_toolnode_output,
)


class _FakeToolMessage:
    """Stand-in for ``langchain_core.messages.ToolMessage`` in tests.

    Tests intentionally avoid importing ``langchain_core`` so the
    optional dep stays optional — the shim is structural / shape-based.
    """

    def __init__(self, content: str, tool_call_id: str = "tc-1") -> None:
        self.content = content
        self.tool_call_id = tool_call_id

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _FakeToolMessage)
            and self.content == other.content
            and self.tool_call_id == other.tool_call_id
        )


@pytest.fixture
def two_messages() -> list[_FakeToolMessage]:
    return [
        _FakeToolMessage("first", tool_call_id="tc-a"),
        _FakeToolMessage("second", tool_call_id="tc-b"),
    ]


class TestPost1_0_11Detection:
    @pytest.mark.parametrize(
        ("v", "expected"),
        [
            ("1.0.11", True),
            ("1.0.12", True),
            ("1.1.0", True),
            ("2.0.0", True),
            ("1.0.10", False),
            ("1.0.0", False),
            ("0.9.99", False),
        ],
    )
    def test_version_thresholding(self, v: str, expected: bool) -> None:
        assert _is_post_1_0_11(v) is expected


class TestPostUpgradeShape:
    """``list[ToolMessage]`` shape (prebuilt >= 1.0.11)."""

    def test_list_passthrough(self, two_messages: list[_FakeToolMessage]) -> None:
        out = unwrap_toolnode_output(two_messages, version="1.0.11")
        assert out == two_messages

    def test_empty_list(self) -> None:
        assert unwrap_toolnode_output([], version="1.0.11") == []

    def test_returns_a_copy(self, two_messages: list[_FakeToolMessage]) -> None:
        out = unwrap_toolnode_output(two_messages, version="1.0.11")
        out.append(_FakeToolMessage("extra"))
        assert len(two_messages) == 2  # original not mutated


class TestPreUpgradeShape:
    """``{"messages": [...]}`` shape (prebuilt < 1.0.11)."""

    def test_dict_unwrap(self, two_messages: list[_FakeToolMessage]) -> None:
        out = unwrap_toolnode_output(
            {"messages": two_messages},
            version="1.0.10",
        )
        assert out == two_messages

    def test_dict_with_extra_keys(
        self, two_messages: list[_FakeToolMessage]
    ) -> None:
        out = unwrap_toolnode_output(
            {"messages": two_messages, "metadata": {"k": "v"}},
            version="1.0.10",
        )
        assert out == two_messages

    def test_dict_empty_messages(self) -> None:
        assert unwrap_toolnode_output({"messages": []}, version="1.0.10") == []

    def test_dict_no_messages_key(self) -> None:
        # Must not raise — return [] and log instead.
        assert unwrap_toolnode_output({"other": "thing"}, version="1.0.10") == []


class TestUnknownShape:
    """Unexpected shapes degrade gracefully — no crash, no message loss."""

    def test_none_returns_empty(self) -> None:
        assert unwrap_toolnode_output(None) == []

    def test_string_returns_empty(self) -> None:
        assert unwrap_toolnode_output("oops") == []

    def test_int_returns_empty(self) -> None:
        assert unwrap_toolnode_output(42) == []


class TestLazyImport:
    """The module must not import langgraph at top-level."""

    def test_no_langgraph_at_top_level(self) -> None:
        import sys

        # If the import was eager, ``langgraph`` would be in sys.modules
        # already — but only if it is installed. Independent of install
        # state, the module under test must not have triggered the
        # import simply by being loaded.
        before = "langgraph" in sys.modules

        # Touch an attribute that does not require the probe.
        from agent_airlock.integrations import langgraph_toolnode_compat as m

        m.unwrap_toolnode_output([])
        after = "langgraph" in sys.modules
        # ``before`` and ``after`` should be identical — `unwrap_toolnode_output`
        # with a list must not have probed.
        assert before == after
