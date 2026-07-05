"""Load MCP tool declarations from files, directories, or config bundles.

Accepted shapes (any nesting of the below is walked):

* A bare list of tool defs: ``[{"name": ..., "inputSchema": ...}, ...]``.
* A server card / tool-list export: ``{"tools": [...]}``.
* A single tool def: ``{"name": ..., "inputSchema": ...}``.
* An MCP client config with inlined tool schemas:
  ``{"mcpServers": {"srv": {"command": ..., "tools": [...]}}}``.
* A directory: every ``*.json`` inside is loaded and merged.

A config that only registers server *commands* (no inlined tool schemas) yields
zero tools for that server — there is nothing to statically type-check, and the
loader says so rather than inventing schemas.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["LoadedTools", "load_tool_defs"]

# Config filenames scan-tools recognizes when handed a directory.
_KNOWN_CONFIG_NAMES: tuple[str, ...] = (
    "mcp.json",
    "claude_desktop_config.json",
    ".mcp.json",
)


@dataclass
class LoadedTools:
    """Result of loading tool declarations from a path."""

    tools: list[dict[str, Any]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def load_tool_defs(path: str | Path) -> LoadedTools:
    """Load tool declarations from a file or directory.

    Args:
        path: A ``.json`` file or a directory containing tool-def / config JSON.

    Returns:
        A :class:`LoadedTools` with the flattened tool list, the source files
        touched, and any non-fatal warnings.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
    """
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"scan-tools: path not found: {root}")

    result = LoadedTools()
    files = _candidate_files(root)
    if not files:
        result.warnings.append(f"no JSON tool-definition files found under {root}")
        return result

    for file in files:
        _load_one_file(file, result)
    return result


def _candidate_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    # Directory: prefer known config names, then any *.json.
    known = [root / name for name in _KNOWN_CONFIG_NAMES if (root / name).is_file()]
    globbed = sorted(p for p in root.glob("*.json") if p.is_file())
    # De-duplicate while preserving "known first" ordering.
    seen: set[Path] = set()
    ordered: list[Path] = []
    for candidate in [*known, *globbed]:
        if candidate not in seen:
            seen.add(candidate)
            ordered.append(candidate)
    return ordered


def _load_one_file(file: Path, result: LoadedTools) -> None:
    try:
        raw = json.loads(file.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        result.warnings.append(f"{file}: could not parse JSON ({exc})")
        return
    before = len(result.tools)
    _extract_tools(raw, result)
    if len(result.tools) > before:
        result.sources.append(str(file))
    else:
        result.warnings.append(f"{file}: no tool declarations found")


def _extract_tools(node: Any, result: LoadedTools) -> None:
    """Walk a decoded JSON node and append any tool declarations found."""
    if isinstance(node, list):
        for item in node:
            if _looks_like_tool(item):
                result.tools.append(dict(item))
            else:
                _extract_tools(item, result)
        return
    if not isinstance(node, Mapping):
        return
    tools = node.get("tools")
    if isinstance(tools, list):
        for item in tools:
            if _looks_like_tool(item):
                result.tools.append(dict(item))
    servers = node.get("mcpServers")
    if isinstance(servers, Mapping):
        for server in servers.values():
            if isinstance(server, Mapping):
                _extract_tools(server, result)
    # A bare single tool def.
    if "tools" not in node and "mcpServers" not in node and _looks_like_tool(node):
        result.tools.append(dict(node))


def _looks_like_tool(node: Any) -> bool:
    """Heuristic: a tool def has a name and either a schema or a description."""
    if not isinstance(node, Mapping):
        return False
    if "name" not in node:
        return False
    return any(
        key in node
        for key in ("inputSchema", "input_schema", "parameters", "description", "annotations")
    )
