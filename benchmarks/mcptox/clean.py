"""Parse MCPTox's clean system prompts into tool contracts, and hold the clean side only.

MCPTox prompts declare each tool as a text block (no types)::

    Tool: <name>
    Description: <free text, possibly several lines, possibly with "- " bullets>
    Arguments:
    - <arg>: <description> (required)
    - <arg>: <description>

Arguments are read only inside a block's ``Arguments:`` section, so bullets in a
description never become parameters. Inside the section a line ``- <name>: ...`` declares
an argument when ``<name>`` is an identifier-like token (letters, digits, ``_``, ``$``,
``.``, ``-``); anything else (a sub-bullet such as ``- SSH format: ...``, an HTML snippet,
a wrapped sentence) continues the previous argument's description. The section runs to
the next ``Tool:`` header, because some descriptions contain blank lines. An argument is
required when its description ends with ``(required)``.

:class:`CleanServer` keeps only the clean fields of a server (its tool blocks, clean
queries, name and repository URL). The policy tiers are derived from it, so by
construction they cannot see a poisoned tool, an attack query or a recorded outcome.
"""

from __future__ import annotations

import keyword
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

_TOOL_HEADER = re.compile(r"^Tool:[ \t]*(?P<name>[^\n]*?)[ \t]*$", re.MULTILINE)
_ARGS_HEADER = re.compile(r"^[ \t]*Arguments:[ \t]*$", re.MULTILINE)
_DESC_PREFIX = re.compile(r"^[ \t]*Description:[ \t]?", re.MULTILINE)
_ARG_LINE = re.compile(r"^- (?P<name>[^:\n]+?):(?:[ \t]+(?P<desc>.*))?[ \t]*$")
_ARG_NAME = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$.\-]*$")
_REQUIRED = "(required)"
_NON_IDENTIFIER = re.compile(r"[^0-9A-Za-z_]")


@dataclass(frozen=True)
class ParamSpec:
    """One declared argument.

    Attributes:
        name: The argument name as the prompt declares it (the wire name).
        py_name: The Python identifier the stub's signature uses for it: ``name`` itself
            when that is a valid identifier, else a mangled form (``from`` -> ``from_``).
        required: The declaration ends with ``(required)``.
    """

    name: str
    py_name: str
    required: bool


@dataclass(frozen=True)
class ToolSpec:
    """One tool block: its name, its description and its declared arguments."""

    name: str
    params: tuple[ParamSpec, ...] = ()
    description: str = ""

    def param(self, name: str) -> ParamSpec | None:
        """The parameter declared under the wire name ``name``, if any."""
        for spec in self.params:
            if spec.name == name:
                return spec
        return None

    @property
    def required(self) -> tuple[str, ...]:
        """Wire names of the required parameters."""
        return tuple(p.name for p in self.params if p.required)


def python_names(names: Iterable[str]) -> dict[str, str]:
    """Map each wire name to a distinct Python identifier usable as a keyword parameter.

    Names that already are identifiers (and not keywords) keep themselves; the rest are
    mangled (non-identifier characters to ``_``, a leading digit prefixed, a keyword
    suffixed with ``_``) and suffixed further until they collide with nothing.
    """
    ordered = list(dict.fromkeys(names))
    out: dict[str, str] = {}
    taken: set[str] = set()
    for name in ordered:
        if name.isidentifier() and not keyword.iskeyword(name):
            out[name] = name
            taken.add(name)
    for name in ordered:
        if name in out:
            continue
        base = _NON_IDENTIFIER.sub("_", name) or "_"
        if base[0].isdigit():
            base = "_" + base
        if keyword.iskeyword(base):
            base += "_"
        candidate = base
        while candidate in taken:
            candidate += "_"
        out[name] = candidate
        taken.add(candidate)
    return out


def _parse_arguments(section: str) -> tuple[tuple[str, bool], ...]:
    """``(wire name, required)`` for each argument declared in an ``Arguments:`` section."""
    declared: list[list[Any]] = []  # [name, first_line_desc, last_line]
    current: list[Any] | None = None
    for line in section.split("\n"):
        match = _ARG_LINE.match(line)
        if match is not None and _ARG_NAME.match(match.group("name").strip()):
            desc = (match.group("desc") or "").rstrip()
            current = [match.group("name").strip(), desc, desc]
            declared.append(current)
        elif current is not None and line.strip():
            current[2] = line.rstrip()
    seen: dict[str, bool] = {}
    for name, first, last in declared:
        required = first.endswith(_REQUIRED) or last.endswith(_REQUIRED)
        # A repeated declaration keeps its first position; required if either says so.
        seen[name] = seen.get(name, False) or required
    return tuple(seen.items())


def _parse_block(name: str, body: str) -> ToolSpec:
    args_match = _ARGS_HEADER.search(body)
    if args_match is None:
        description, section = body, ""
    else:
        description, section = body[: args_match.start()], body[args_match.end() :]
    description = _DESC_PREFIX.sub("", description, count=1).strip()
    declared = _parse_arguments(section)
    mapping = python_names(n for n, _ in declared)
    params = tuple(ParamSpec(n, mapping[n], required) for n, required in declared)
    return ToolSpec(name=name, params=params, description=description)


def parse_tool_blocks(prompt: str) -> list[ToolSpec]:
    """Every ``Tool:`` block of a prompt, in order (a repeated name keeps its first block)."""
    headers = list(_TOOL_HEADER.finditer(prompt))
    out: dict[str, ToolSpec] = {}
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(prompt)
        name = header.group("name").strip()
        if not name or name in out:
            continue
        out[name] = _parse_block(name, prompt[header.end() : end])
    return list(out.values())


@dataclass(frozen=True)
class CleanServer:
    """The clean side of one MCPTox server, and nothing else.

    Attributes:
        index: The server's position in the file.
        key: Its key in ``servers``.
        name: ``server_name``.
        category_id: ``category_id``.
        server_url: ``server_url`` (the server's public repository).
        tools: Parsed blocks of ``clean_system_promot``. This, not ``tool_names``, is the
            allowlist: one server's prompt lists more tools than its ``tool_names``.
        listed_tool_names: ``tool_names`` as released, kept for the accounting.
        clean_queries: ``clean_querys`` (empty for ten servers).
    """

    index: int
    key: str
    name: str
    category_id: int | None
    server_url: str
    tools: tuple[ToolSpec, ...]
    listed_tool_names: tuple[str, ...]
    clean_queries: tuple[str, ...]

    @property
    def tool_names(self) -> tuple[str, ...]:
        return tuple(tool.name for tool in self.tools)

    def tool(self, name: str) -> ToolSpec | None:
        for spec in self.tools:
            if spec.name == name:
                return spec
        return None

    @property
    def has_clean_queries(self) -> bool:
        return bool(self.clean_queries)


def clean_server(index: int, key: str, raw: Mapping[str, Any]) -> CleanServer:
    """Build a :class:`CleanServer` from one raw server, reading clean fields only."""
    queries = raw.get("clean_querys") or []
    category = raw.get("category_id")
    return CleanServer(
        index=index,
        key=key,
        name=str(raw.get("server_name") or key),
        category_id=int(category) if isinstance(category, int) else None,
        server_url=str(raw.get("server_url") or ""),
        tools=tuple(parse_tool_blocks(str(raw.get("clean_system_promot") or ""))),
        listed_tool_names=tuple(str(n) for n in raw.get("tool_names") or []),
        clean_queries=tuple(str(q) for q in queries if isinstance(q, str)),
    )


def clean_servers(doc: Mapping[str, Any]) -> list[CleanServer]:
    """Every server's clean side, in file order."""
    return [
        clean_server(idx, str(key), raw) for idx, (key, raw) in enumerate(doc["servers"].items())
    ]
