"""Turn a recorded model response into the tool calls it made, with nothing dropped silently.

MCPTox asks models to answer with ``{"tool": ..., "arguments": {...}}`` as text, and the
27 models answered in many shapes: bare JSON, Python literals (single quotes, ``True``),
JSON keywords inside Python literals, fenced blocks, several calls in a row, a list of
calls, prose around any of these, DeepSeek's native tool tokens (the name outside the
JSON), ``<think>`` blocks (sometimes unterminated, sometimes only a closing tag) and chat
end tokens. :func:`parse_response` returns every call it can read and a status:

* ``calls`` - at least one call;
* ``no_call`` - readable text with no call in it (a refusal, an answer, a question);
* ``malformed`` - something call-shaped that does not parse into a call;
* ``empty`` - no text at all.

Each result carries notes naming every repair applied (``python_literal``,
``arguments_json_string``, ``native_call``, ...), so the published accounting can say how
many responses needed which one. Reasoning inside ``<think>`` is removed first: a call a
model only considered while thinking is not a call it made.

Parsing is bounded: a candidate span longer than :data:`MAX_SPAN` characters is skipped,
and values come only from :func:`json.loads` or :func:`ast.literal_eval` (never ``eval``),
with tuples turned into lists and sets, bytes and complex numbers refused.
"""

from __future__ import annotations

import ast
import json
import math
import re
import unicodedata
import warnings
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

MAX_SPAN = 200_000
END_TOKENS = (
    "<|im_end|>",
    "<|eot_id|>",
    "<end_of_turn>",
    "</s>",
    "<｜end▁of▁sentence｜>",
    "<|endoftext|>",
)
TOOL_PREFIXES = ("functions.", "default_api.", "tools.")

CALLS = "calls"
NO_CALL = "no_call"
MALFORMED = "malformed"
EMPTY = "empty"
STATUSES = (CALLS, NO_CALL, MALFORMED, EMPTY)

_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL)
_DS_CALL = re.compile(
    r"<｜tool▁call▁begin｜>(?P<kind>[^<]*?)<｜tool▁sep｜>(?P<name>[^\n`<]*)(?P<body>.*?)"
    r"<｜tool▁call▁end｜>",
    re.DOTALL,
)
_DS_TOKEN = re.compile(r"<｜[^｜>]{1,40}｜>")
_FENCE = re.compile(r"^```[A-Za-z0-9_-]*\s*(?P<inner>.*?)\s*```$", re.DOTALL)
_CALL_MARKER = re.compile(r"[\"']tool[\"']\s*:")
_APOSTROPHE = re.compile(r"(?<=[A-Za-z])'(?=[A-Za-z])")
_ARGUMENT_KEYS = ("arguments", "parameters", "args")


@dataclass(frozen=True)
class Call:
    """One tool call: a normalised tool name and its JSON-shaped arguments."""

    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParseResult:
    """Every call read from one response, its status and the repairs applied."""

    calls: tuple[Call, ...]
    status: str
    notes: tuple[str, ...] = ()


class _NotJSON(ValueError):
    """A literal held a value JSON cannot (a set, bytes, a complex number, a non-str key)."""


def normalize_tool_name(name: str) -> str:
    """Strip whitespace and quotes, then ``functions.`` / ``default_api.`` / ``tools.``."""
    name = name.strip().strip("\"'`").strip()
    changed = True
    while changed:
        changed = False
        for prefix in TOOL_PREFIXES:
            if name.startswith(prefix):
                name = name[len(prefix) :].strip()
                changed = True
    return name


def _jsonish(value: Any) -> Any:
    """Tuples to lists; refuse anything JSON cannot hold."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonish(v) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise _NotJSON(f"non-string key {type(key).__name__}")
            out[key] = _jsonish(item)
        return out
    raise _NotJSON(type(value).__name__)


def _json_keywords_to_python(text: str) -> str:
    """Rewrite bare ``true`` / ``false`` / ``null`` outside string literals."""
    out: list[str] = []
    quote: str | None = None
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is not None:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            out.append(ch)
            i += 1
            continue
        matched = False
        for word, repl in (("true", "True"), ("false", "False"), ("null", "None")):
            end = i + len(word)
            if (
                text.startswith(word, i)
                and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))
                and (end == len(text) or not (text[end].isalnum() or text[end] == "_"))
            ):
                out.append(repl)
                i = end
                matched = True
                break
        if not matched:
            out.append(ch)
            i += 1
    return "".join(out)


def _strip_line_comments(text: str) -> str:
    """Drop ``// ...`` comments outside string literals (a common JSON-ish quirk)."""
    out: list[str] = []
    quote: str | None = None
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is not None:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
        elif text.startswith("//", i):
            newline = text.find("\n", i)
            i = len(text) if newline == -1 else newline
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _literal(candidate: str) -> Any:
    with warnings.catch_warnings():
        # Invalid escapes such as "\." in recorded outputs warn at parse time.
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.literal_eval(candidate)


def parse_value(span: str) -> tuple[Any, tuple[str, ...]]:
    """Parse a JSON or Python-literal span. Returns ``(value, notes)``.

    Tries, in order: :func:`json.loads`; :func:`ast.literal_eval`; ``literal_eval`` with
    bare ``true`` / ``false`` / ``null`` rewritten; and, when the span has ``//``
    comments, the same three on the span with the comments removed.

    Raises:
        ValueError: No parser accepts it, or it holds a non-JSON value.
    """
    attempts: list[tuple[str, tuple[str, ...]]] = [(span, ())]
    uncommented = _strip_line_comments(span) if "//" in span else span
    if uncommented != span:
        attempts.append((uncommented, ("json_comments",)))
    for text, base in attempts:
        try:
            return _jsonish(json.loads(text)), base
        except _NotJSON:
            raise
        except (ValueError, RecursionError):
            pass
        literals: list[tuple[str, tuple[str, ...]]] = [(text, (*base, "python_literal"))]
        rewritten = _json_keywords_to_python(text)
        if rewritten != text:
            literals.append((rewritten, (*base, "python_literal", "json_keywords_in_literal")))
        for candidate, notes in literals:
            try:
                value = _literal(candidate)
            except (ValueError, SyntaxError, TypeError, RecursionError, MemoryError):
                continue
            return _jsonish(value), notes
    raise ValueError("not JSON or a Python literal")


def _match_end(text: str, start: int) -> int | None:
    """Index of the bracket closing the one at ``start``, string-aware, within MAX_SPAN."""
    stack: list[str] = []
    quote: str | None = None
    escape = False
    limit = min(len(text), start + MAX_SPAN)
    for j in range(start, limit):
        ch = text[j]
        if quote is not None:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]":
            if not stack or stack[-1] != ch:
                return None
            stack.pop()
            if not stack:
                return j
    return None


def _arguments(obj: Mapping[str, Any], notes: list[str]) -> Mapping[str, Any] | None:
    """The arguments of a call object, or None when they cannot be read as an object."""
    key = next((k for k in _ARGUMENT_KEYS if k in obj), None)
    if key is None:
        notes.append("no_arguments_key")
        return {}
    if key != "arguments":
        notes.append(f"{key}_key")
    raw = obj[key]
    if raw is None:
        notes.append("arguments_null")
        return {}
    if isinstance(raw, str):
        try:
            decoded, _ = parse_value(raw)
        except ValueError:
            notes.append("arguments_unparseable_string")
            return None
        if isinstance(decoded, dict):
            notes.append("arguments_json_string")
            return decoded
        notes.append("arguments_string_not_object")
        return None
    if isinstance(raw, dict):
        return raw
    notes.append("arguments_not_object")
    return None


def _call_from_object(obj: Mapping[str, Any]) -> tuple[Call | None, bool, list[str]]:
    """``(call, call_shaped, notes)`` for one parsed object."""
    notes: list[str] = []
    name: Any = obj.get("tool")
    if not isinstance(name, str):
        if isinstance(obj.get("name"), str) and any(k in obj for k in _ARGUMENT_KEYS):
            name = obj["name"]
            notes.append("name_key")
        else:
            return None, "tool" in obj, notes
    arguments = _arguments(obj, notes)
    if arguments is None:
        return None, True, notes
    tool = normalize_tool_name(name)
    if not tool:
        notes.append("empty_tool_name")
        return None, True, notes
    if tool != name:
        notes.append("tool_name_normalised")
    return Call(tool=tool, arguments=dict(arguments), notes=tuple(notes)), True, notes


def _calls_from_value(value: Any) -> tuple[list[Call], bool, list[str]]:
    """Calls in a parsed value (an object or a list of objects); ``(calls, malformed, notes)``."""
    notes: list[str] = []
    if isinstance(value, dict):
        call, shaped, call_notes = _call_from_object(value)
        notes.extend(call_notes)
        if call is not None:
            return [call], False, notes
        return [], shaped, notes
    if isinstance(value, list):
        calls: list[Call] = []
        malformed = False
        for item in value:
            if isinstance(item, dict):
                call, shaped, call_notes = _call_from_object(item)
                if call is not None:
                    calls.append(call)
                elif shaped:
                    malformed = True
                notes.extend(call_notes)
        if calls:
            notes.append("call_list")
        return calls, malformed and not calls, notes
    return [], False, notes


def _strip_reasoning(text: str, notes: list[str]) -> str:
    text, pairs = _THINK_BLOCK.subn("\n", text)
    if pairs:
        notes.append("think_block")
    if "</think>" in text:
        text = text[text.rfind("</think>") + len("</think>") :]
        notes.append("orphan_think_close")
    if "<think>" in text:
        text = text[: text.find("<think>")]
        notes.append("unterminated_think")
    return text


def _native_calls(text: str, notes: list[str]) -> tuple[str, list[Call], bool]:
    """DeepSeek native tool blocks: ``(text without them, calls, malformed)``."""
    calls: list[Call] = []
    malformed = False

    def take(match: re.Match[str]) -> str:
        nonlocal malformed
        name = normalize_tool_name(match.group("name"))
        body = match.group("body").strip()
        fenced = _FENCE.match(body)
        if fenced is not None:
            body = fenced.group("inner").strip()
        call_notes = ["native_call"]
        arguments: Mapping[str, Any] | None = {}
        if body:
            try:
                value, value_notes = parse_value(body)
            except ValueError:
                value = None
                value_notes = ()
            call_notes.extend(value_notes)
            if isinstance(value, dict) and isinstance(value.get("tool"), str):
                inner, _, inner_notes = _call_from_object(value)
                call_notes.append("native_wraps_full_call")
                call_notes.extend(inner_notes)
                if inner is not None and inner.tool != name:
                    call_notes.append("native_name_mismatch")
                arguments = inner.arguments if inner is not None else None
            elif isinstance(value, dict):
                arguments = value
            else:
                arguments = None
        if not name or arguments is None:
            malformed = True
            notes.append("native_call_unparseable")
        else:
            calls.append(Call(tool=name, arguments=dict(arguments), notes=tuple(call_notes)))
        return "\n"

    text = _DS_CALL.sub(take, text)
    if "<｜tool▁call▁begin｜>" in text:
        malformed = True
        notes.append("native_call_unterminated")
    text = _DS_TOKEN.sub("\n", text)
    if calls:
        notes.append("native_call")
    return text, calls, malformed


def _scan(text: str, notes: list[str]) -> tuple[list[Call], bool]:
    """Every call in the top-level bracketed spans of ``text``; ``(calls, malformed)``."""
    calls: list[Call] = []
    malformed = False
    i = 0
    while i < len(text):
        if text[i] not in "{[":
            i += 1
            continue
        end = _match_end(text, i)
        if end is None:
            i += 1
            continue
        span = text[i : end + 1]
        try:
            value, value_notes = parse_value(span)
        except ValueError:
            # Not parseable as a whole: only call-shaped junk counts as malformed, and
            # a call nested inside it may still be read by scanning on from i + 1.
            if '"tool"' in span or "'tool'" in span:
                malformed = True
                notes.append("unparseable_call_span")
            i += 1
            continue
        found, span_malformed, call_notes = _calls_from_value(value)
        notes.extend(value_notes)
        notes.extend(call_notes)
        if found:
            calls.extend(found)
            i = end + 1
            continue
        malformed = malformed or span_malformed
        i = end + 1 if isinstance(value, dict) else i + 1
    return calls, malformed


def parse_response(text: Any) -> ParseResult:
    """Every call in one recorded response, its status and the repairs applied."""
    if text is None or (isinstance(text, str) and not text.strip()):
        return ParseResult((), EMPTY)
    if not isinstance(text, str):
        return ParseResult((), MALFORMED, ("non_string_response",))
    notes: list[str] = []
    for token in END_TOKENS:
        if token in text:
            text = text.replace(token, "\n")
            notes.append("end_token")
    text = _strip_reasoning(text, notes)
    text, native, native_bad = _native_calls(text, notes)
    found, scan_bad = _scan(text, notes)
    if not found and _CALL_MARKER.search(text):
        # An apostrophe inside a single-quoted literal ('I'm done') opens a string that
        # never closes, so nothing balances. Escape apostrophes that sit between two
        # letters and scan once more; whatever still fails is malformed, not prose.
        repaired = _APOSTROPHE.sub(r"\\'", text)
        if repaired != text:
            retry_notes: list[str] = []
            found, _ = _scan(repaired, retry_notes)
            if found:
                notes.extend(retry_notes)
                notes.append("apostrophe_repair")
        if not found and not scan_bad:
            scan_bad = True
            notes.append("unbalanced_call_text")
    calls = native + found
    if calls:
        status = CALLS
        if native_bad or scan_bad:
            notes.append("partial")
    elif native_bad or scan_bad:
        status = MALFORMED
    else:
        status = NO_CALL
    return ParseResult(tuple(calls), status, tuple(dict.fromkeys(notes)))


def _canon_value(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value.strip())
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        return int(value) if value.is_integer() else value
    if isinstance(value, list):
        return [_canon_value(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _canon_value(v) for k, v in value.items() if v is not None}
    return repr(value)


def canonical_call(call: Call) -> str:
    """A comparison key for a call.

    Keys sorted; strings stripped and NFC-normalised; booleans kept distinct from numbers;
    ``1 == 1.0``; ``None``-valued keys dropped (so ``{}`` equals no arguments); lists keep
    their order.
    """
    return json.dumps(
        [normalize_tool_name(call.tool), _canon_value(dict(call.arguments))],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def canonical_sequence(calls: Iterable[Call]) -> tuple[str, ...]:
    """The canonical keys of a response's calls, in order."""
    return tuple(canonical_call(c) for c in calls)
