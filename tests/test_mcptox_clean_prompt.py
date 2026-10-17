"""Tests for ``benchmarks.mcptox.clean``: tool blocks parsed from MCPTox-shaped prompts.

The prompts here are synthetic, written in MCPTox's block layout; none is MCPTox text.
"""

from __future__ import annotations

import dataclasses

from benchmarks.mcptox.clean import (
    CleanServer,
    clean_server,
    parse_tool_blocks,
    python_names,
)

PROMPT = """You can call these tools:


Tool: fetch_page
Description: Fetches a page.
- this bullet is description, not an argument: keep it out
Arguments:
- url: Address to fetch (required)
- timeout: Seconds to wait


Tool: notes-add
Description: Adds a note.
Arguments:
- body: Text of the note.
Spans two lines (required)
- from: Sender (required)
- tags: Tags, one of:
- SSH format: git@host:org/repo
- <code>https://example.invalid</code>

- color: Shown after a blank line


Tool: ping
Description: Takes nothing.
Arguments:


Trailer text the parser must not read.
"""


class TestParseToolBlocks:
    def test_blocks_names_and_order(self) -> None:
        tools = parse_tool_blocks(PROMPT)
        assert [t.name for t in tools] == ["fetch_page", "notes-add", "ping"]

    def test_description_bullets_are_not_parameters(self) -> None:
        fetch = parse_tool_blocks(PROMPT)[0]
        assert [p.name for p in fetch.params] == ["url", "timeout"]
        assert fetch.required == ("url",)
        assert fetch.description.startswith("Fetches a page.")

    def test_continuation_lines_and_required_marker(self) -> None:
        notes = parse_tool_blocks(PROMPT)[1]
        by_name = {p.name: p for p in notes.params}
        assert by_name["body"].required  # "(required)" ends the wrapped second line
        assert by_name["from"].required
        assert not by_name["tags"].required

    def test_sub_bullets_with_spaces_or_markup_are_rejected(self) -> None:
        names = [p.name for p in parse_tool_blocks(PROMPT)[1].params]
        assert "SSH format" not in names
        assert not any(n.startswith("<") for n in names)

    def test_arguments_after_a_blank_line_are_kept(self) -> None:
        names = [p.name for p in parse_tool_blocks(PROMPT)[1].params]
        assert names == ["body", "from", "tags", "color"]

    def test_keyword_argument_is_mangled(self) -> None:
        notes = parse_tool_blocks(PROMPT)[1]
        assert notes.param("from") is not None
        assert notes.param("from").py_name == "from_"  # type: ignore[union-attr]

    def test_tool_without_arguments(self) -> None:
        assert parse_tool_blocks(PROMPT)[2].params == ()

    def test_repeated_tool_keeps_first_block(self) -> None:
        prompt = "Tool: a\nArguments:\n- x: one\n\nTool: a\nArguments:\n- y: two\n"
        tools = parse_tool_blocks(prompt)
        assert len(tools) == 1
        assert [p.name for p in tools[0].params] == ["x"]

    def test_repeated_argument_keeps_first_and_ors_required(self) -> None:
        prompt = "Tool: a\nArguments:\n- x: one\n- x: again (required)\n"
        (tool,) = parse_tool_blocks(prompt)
        assert [(p.name, p.required) for p in tool.params] == [("x", True)]


class TestPythonNames:
    def test_identifiers_keep_their_name(self) -> None:
        assert python_names(["path", "type", "maxLength"]) == {
            "path": "path",
            "type": "type",
            "maxLength": "maxLength",
        }

    def test_mangled_names_never_collide(self) -> None:
        mapping = python_names(["from", "from_", "file-path", "file_path", "1st"])
        assert mapping["from_"] == "from_"
        assert mapping["file_path"] == "file_path"
        assert mapping["from"] not in {"from", "from_"}
        assert mapping["file-path"] not in {"file-path", "file_path"}
        assert mapping["1st"] == "_1st"
        assert len(set(mapping.values())) == len(mapping)
        assert all(v.isidentifier() for v in mapping.values())


class TestCleanServer:
    def test_only_clean_fields_exist(self) -> None:
        fields = {f.name for f in dataclasses.fields(CleanServer)}
        assert fields == {
            "index",
            "key",
            "name",
            "category_id",
            "server_url",
            "tools",
            "listed_tool_names",
            "clean_queries",
        }

    def test_attack_side_is_never_read(self) -> None:
        raw = {
            "server_name": "Synthetic",
            "category_id": 3,
            "server_url": "https://example.invalid/repo",
            "tool_names": ["fetch_page"],
            "clean_system_promot": PROMPT,
            "clean_querys": ["first", 7, "second"],
            "malicious_instance": [{"datas": [{"system": "Tool: evil\nArguments:\n"}]}],
        }
        server = clean_server(4, "synthetic", raw)
        assert server.tool_names == ("fetch_page", "notes-add", "ping")
        assert "evil" not in server.tool_names
        assert server.clean_queries == ("first", "second")
        assert server.has_clean_queries
        assert server.listed_tool_names == ("fetch_page",)
        assert server.tool("ping") is not None
        assert server.tool("evil") is None
