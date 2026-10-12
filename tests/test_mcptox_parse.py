"""Tests for ``benchmarks.mcptox.parse``: recorded responses to tool calls.

Every response here is synthetic and shaped like the formats the recorded models used.
"""

from __future__ import annotations

import pytest
from benchmarks.mcptox import parse as parse_mod
from benchmarks.mcptox.parse import (
    CALLS,
    EMPTY,
    MALFORMED,
    NO_CALL,
    Call,
    canonical_call,
    canonical_sequence,
    normalize_tool_name,
    parse_response,
    parse_value,
)


def _tools(text: object) -> list[tuple[str, dict[str, object]]]:
    return [(c.tool, dict(c.arguments)) for c in parse_response(text).calls]


class TestShapes:
    def test_bare_json(self) -> None:
        r = parse_response('{"tool": "read_file", "arguments": {"path": "/a.txt"}}')
        assert r.status == CALLS
        assert _tools('{"tool": "read_file", "arguments": {"path": "/a.txt"}}') == [
            ("read_file", {"path": "/a.txt"})
        ]

    def test_fence_without_newline_and_end_token(self) -> None:
        text = '```json{"tool":"t","arguments":{"n":1}}```<|im_end|>'
        r = parse_response(text)
        assert r.status == CALLS
        assert "end_token" in r.notes
        assert _tools(text) == [("t", {"n": 1})]

    def test_python_literal(self) -> None:
        text = "Sure! {'tool': 't', 'arguments': {'flag': True, 'items': ('a', 'b')}}</s>"
        r = parse_response(text)
        assert r.status == CALLS
        assert "python_literal" in r.notes
        assert _tools(text) == [("t", {"flag": True, "items": ["a", "b"]})]

    def test_json_keywords_inside_a_literal(self) -> None:
        text = "{'tool': 't', 'arguments': {'isUrl': false, 'x': null}}"
        r = parse_response(text)
        assert "json_keywords_in_literal" in r.notes
        assert _tools(text) == [("t", {"isUrl": False, "x": None})]

    def test_several_calls_and_a_list(self) -> None:
        text = (
            '{"tool": "a", "arguments": {}}\n\nnarration\n\n{"tool": "b", "arguments": {"k": 2}}'
            '\n[{"tool": "c", "arguments": {}}, {"tool": "d", "arguments": {}}]'
        )
        r = parse_response(text)
        assert [c.tool for c in r.calls] == ["a", "b", "c", "d"]
        assert "call_list" in r.notes

    def test_prose_only(self) -> None:
        r = parse_response("I cannot help with that request.")
        assert r.status == NO_CALL
        assert r.calls == ()

    def test_non_call_json_is_not_a_call(self) -> None:
        r = parse_response('Here is the schema: {"type": "object", "properties": {}}')
        assert r.status == NO_CALL

    def test_json_comments_repaired(self) -> None:
        text = '{"tool": "t", "arguments": {"a": "x"  // changed\n}}'
        r = parse_response(text)
        assert r.status == CALLS
        assert "json_comments" in r.notes


class TestEmptyAndMalformed:
    @pytest.mark.parametrize("text", ["", "   \n", None])
    def test_empty(self, text: object) -> None:
        assert parse_response(text).status == EMPTY

    def test_non_string(self) -> None:
        assert parse_response(42).status == MALFORMED

    def test_call_shaped_but_unparseable(self) -> None:
        r = parse_response("{'tool': 'q', 'arguments': {'q': 'print('hi'')'}}")
        assert r.status == MALFORMED

    def test_apostrophe_inside_single_quotes_is_repaired(self) -> None:
        text = "{'tool': 'note', 'arguments': {'body': 'I'm done'}}"
        r = parse_response(text)
        assert r.status == CALLS
        assert "apostrophe_repair" in r.notes
        assert _tools(text) == [("note", {"body": "I'm done"})]

    def test_truncated_call_is_malformed(self) -> None:
        r = parse_response('{\n "tool": "open", "arguments": {"names": ["a"]\n')
        assert r.status == MALFORMED
        assert "unbalanced_call_text" in r.notes

    def test_non_json_values_are_refused(self) -> None:
        with pytest.raises(ValueError):
            parse_value("{'tool': 't', 'arguments': {1, 2}}")
        with pytest.raises(ValueError):
            parse_value("{'tool': 't', 'arguments': {'b': b'x'}}")
        assert parse_response("{'tool': 't', 'arguments': {'c': 1j}}").status == MALFORMED

    def test_oversized_span_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(parse_mod, "MAX_SPAN", 20)
        r = parse_response('{"tool": "t", "arguments": {"long": "' + "x" * 100 + '"}}')
        assert r.calls == ()
        assert r.status == MALFORMED


class TestArguments:
    def test_json_string_arguments_decoded(self) -> None:
        r = parse_response('{"tool": "t", "arguments": "{\\"a\\": 1}"}')
        assert _tools('{"tool": "t", "arguments": "{\\"a\\": 1}"}') == [("t", {"a": 1})]
        assert "arguments_json_string" in r.notes

    def test_name_and_parameters_variants(self) -> None:
        r = parse_response('{"name": "t", "parameters": {"a": 1}}')
        assert r.status == CALLS
        assert {"name_key", "parameters_key"} <= set(r.notes)

    def test_missing_or_null_arguments(self) -> None:
        assert _tools('{"tool": "t"}') == [("t", {})]
        assert "no_arguments_key" in parse_response('{"tool": "t"}').notes
        assert _tools('{"tool": "t", "arguments": null}') == [("t", {})]

    def test_list_arguments_are_malformed(self) -> None:
        assert parse_response('{"tool": "t", "arguments": [1]}').status == MALFORMED


class TestReasoningAndNative:
    def test_call_inside_think_is_not_a_call(self) -> None:
        text = (
            '<think>maybe {"tool": "bad", "arguments": {}}</think>{"tool": "good", "arguments": {}}'
        )
        assert [c.tool for c in parse_response(text).calls] == ["good"]

    def test_unterminated_think_and_orphan_close(self) -> None:
        r = parse_response('{"tool": "a", "arguments": {}}<think>later {"tool": "b"}')
        assert [c.tool for c in r.calls] == ["a"]
        assert "unterminated_think" in r.notes
        r = parse_response('reasoning {"tool": "x"} </think>{"tool": "y", "arguments": {}}')
        assert [c.tool for c in r.calls] == ["y"]
        assert "orphan_think_close" in r.notes

    def test_deepseek_native_arguments_only(self) -> None:
        text = (
            "Plan.<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>function<｜tool▁sep｜>get-store\n"
            '```json\n{"storeId": "s1"}\n```<｜tool▁call▁end｜><｜tool▁calls▁end｜>'
        )
        r = parse_response(text)
        assert r.status == CALLS
        assert _tools(text) == [("get-store", {"storeId": "s1"})]
        assert "native_call" in r.notes

    def test_deepseek_native_wrapping_a_full_call(self) -> None:
        text = (
            "<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>function<｜tool▁sep｜>think\n"
            '```json\n{"tool": "think", "arguments": {"n": 1}}\n```<｜tool▁call▁end｜>'
            "<｜tool▁calls▁end｜>"
        )
        call = parse_response(text).calls[0]
        assert (call.tool, dict(call.arguments)) == ("think", {"n": 1})
        assert "native_wraps_full_call" in call.notes


class TestNamesAndCanonical:
    @pytest.mark.parametrize(
        ("raw", "name"),
        [
            ("  read_file ", "read_file"),
            ("`read_file`", "read_file"),
            ('"read_file"', "read_file"),
            ("functions.read_file", "read_file"),
            ("default_api.tools.read_file", "read_file"),
        ],
    )
    def test_normalize_tool_name(self, raw: str, name: str) -> None:
        assert normalize_tool_name(raw) == name

    def test_canonical_equalities(self) -> None:
        def key(args: dict[str, object]) -> str:
            return canonical_call(Call("t", args))

        assert key({"b": 1, "a": 2}) == key({"a": 2, "b": 1})
        assert key({"a": "café"}) == key({"a": "café"})  # NFC
        assert key({"a": " v "}) == key({"a": "v"})
        assert key({"a": 1}) == key({"a": 1.0})
        assert key({"a": True}) != key({"a": 1})
        assert key({"a": None}) == key({})
        assert key({"a": [1, 2]}) != key({"a": [2, 1]})
        assert canonical_call(Call("functions.t", {})) == key({})

    def test_canonical_sequence_keeps_order(self) -> None:
        a, b = Call("a", {}), Call("b", {})
        assert canonical_sequence([a, b]) != canonical_sequence([b, a])
