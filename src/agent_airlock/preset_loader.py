"""Declarative preset YAML loader (v0.5.7+).

A *restricted-grammar* YAML parser that handles exactly the shape
``presets/*.yaml`` files use — no PyYAML dependency, no full YAML
runtime, just enough to load the v1 preset schema.

The grammar accepted:

- Top-level scalar key/value pairs: ``key: value``
- Top-level multi-line block scalar values via simple line
  continuation (a value indented under its key)
- A single ``presets:`` list whose items are dicts of scalar fields
- Quoted-string values with ``"..."`` (rare; mostly for the
  ``description`` field that spans multiple words). Single-line
  strings without quotes are also accepted.
- ``# ...`` line comments
- Boolean ``true`` / ``false``
- Integers
- ``null``

This is **not** YAML — it's a restricted dialect that the agent-airlock
preset format adheres to. Anything outside this grammar raises
:class:`PresetParseError`.

Why no PyYAML? Adding a runtime dep for a 50-line config grammar
hurts the install footprint and the security-supply-chain story.
The agent-airlock package has 3 runtime deps (``pydantic``,
``structlog``, ``tomli`` for 3.10) — that's the keep-it-thin baseline.

Primary source for the OX umbrella preset:
  https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from .exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.preset_loader")


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class PresetParseError(AirlockError):
    """Raised when a preset YAML file does not conform to the v1 schema."""


# -----------------------------------------------------------------------------
# Tiny restricted-grammar parser
# -----------------------------------------------------------------------------


_SCALAR_LINE = re.compile(r"^(\s*)([A-Za-z_][\w]*)\s*:\s*(.*)$")
_LIST_ITEM_START = re.compile(r"^(\s*)-\s+(.*)$")


def _strip_comment(line: str) -> str:
    """Remove trailing ``# ...`` comments unless inside quotes."""
    in_quote = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_quote = not in_quote
        elif ch == "#" and not in_quote:
            return line[:i].rstrip()
    return line.rstrip()


def _coerce_scalar(raw: str) -> Any:
    """Coerce a raw YAML scalar value into a Python value.

    - ``"true"`` / ``"false"`` → ``bool``
    - ``"null"`` / empty → ``None``
    - integer literal → ``int``
    - quoted string → unquoted string
    - everything else → string
    """
    raw = raw.strip()
    if not raw or raw == "null":
        return None
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
        return raw[1:-1]
    if raw.lstrip("-").isdigit():
        return int(raw)
    return raw


def _split_lines(text: str) -> list[tuple[int, str]]:
    """Strip blank lines + comment-only lines; return ``[(lineno, content), ...]``.

    Lines retain their original trailing whitespace stripped but keep
    leading indentation so the parser can detect the indent level.
    """
    out: list[tuple[int, str]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        out.append((i, stripped))
    return out


def _parse_yaml_restricted(text: str) -> dict[str, Any]:
    """Parse a restricted-grammar YAML document.

    Returns a dict. Raises :class:`PresetParseError` on any line the
    parser doesn't understand.
    """
    lines = _split_lines(text)
    result: dict[str, Any] = {}
    i = 0
    while i < len(lines):
        lineno, line = lines[i]
        m = _SCALAR_LINE.match(line)
        if not m:
            raise PresetParseError(
                f"line {lineno}: expected ``key: value`` or ``key:`` "
                f"introducing a list, got {line!r}"
            )
        indent, key, value = m.group(1), m.group(2), m.group(3)
        if indent:
            raise PresetParseError(
                f"line {lineno}: top-level keys must not be indented; got {line!r}"
            )

        if value:
            # Same-line scalar
            # Special case: multi-line quoted string continuation. If
            # the value starts with ``"`` but has no closing ``"`` on
            # this line, glue subsequent lines until the closing quote.
            if value.startswith('"') and not (len(value) > 1 and value.endswith('"')):
                buf = [value[1:]]
                i += 1
                while i < len(lines):
                    _, cont = lines[i]
                    if cont.rstrip().endswith('"'):
                        buf.append(cont.rstrip()[:-1])
                        i += 1
                        break
                    buf.append(cont)
                    i += 1
                result[key] = " ".join(s.strip() for s in buf).strip()
                # ``i`` already advanced past every continuation line.
                continue
            result[key] = _coerce_scalar(value)
            i += 1
            continue

        # ``key:`` with no inline value — must introduce a list
        # (no nested-map support in the restricted grammar).
        list_items: list[dict[str, Any]] = []
        i += 1
        while i < len(lines):
            sub_lineno, sub_line = lines[i]
            list_match = _LIST_ITEM_START.match(sub_line)
            if not list_match:
                # End of list (next top-level key or EOF)
                break
            list_indent = list_match.group(1)
            first_kv = list_match.group(2)
            kv = _SCALAR_LINE.match("  " + first_kv)
            if not kv:
                raise PresetParseError(
                    f"line {sub_lineno}: list-item first line must be "
                    f"``- key: value``, got {sub_line!r}"
                )
            item: dict[str, Any] = {kv.group(2): _coerce_scalar(kv.group(3))}
            i += 1
            # Subsequent lines belonging to this item have indent
            # strictly greater than ``list_indent + 2``.
            while i < len(lines):
                nxt_lineno, nxt_line = lines[i]
                if _LIST_ITEM_START.match(nxt_line):
                    break
                nxt_kv = _SCALAR_LINE.match(nxt_line)
                if not nxt_kv:
                    break
                if len(nxt_kv.group(1)) <= len(list_indent):
                    break
                item[nxt_kv.group(2)] = _coerce_scalar(nxt_kv.group(3))
                i += 1
            list_items.append(item)
        result[key] = list_items
    return result


# -----------------------------------------------------------------------------
# Loader
# -----------------------------------------------------------------------------


@dataclass
class LoadedPreset:
    """The parsed preset YAML, lifted into a Python dataclass."""

    preset_id: str
    schema_version: int
    description: str
    primary_source: str
    disclosed_at: str
    presets: list[dict[str, Any]] = field(default_factory=list)


def _validate_schema(data: dict[str, Any]) -> None:
    if data.get("schema_version") != 1:
        raise PresetParseError(f"schema_version must be 1; got {data.get('schema_version')!r}")
    for required in ("preset_id", "presets", "primary_source", "disclosed_at"):
        if required not in data:
            raise PresetParseError(f"missing required top-level field: {required!r}")
    presets = data["presets"]
    if not isinstance(presets, list) or not presets:
        raise PresetParseError("``presets`` must be a non-empty list")
    for entry in presets:
        if not isinstance(entry, dict):
            raise PresetParseError(f"every ``presets`` entry must be a dict; got {entry!r}")
        for required in ("id", "factory", "primary_source"):
            if required not in entry:
                raise PresetParseError(
                    f"preset entry missing required field {required!r}: {entry!r}"
                )


def load_yaml_preset(path: Path) -> LoadedPreset:
    """Load + validate a v1 preset YAML file.

    Args:
        path: Filesystem path to the preset YAML.

    Returns:
        :class:`LoadedPreset` with a populated ``presets`` list. The
        loader does **not** import the named factories — that's the
        caller's job (typically :func:`compose_preset_factories`).

    Raises:
        PresetParseError: On schema violation or grammar error.
    """
    if not path.exists():
        raise PresetParseError(f"preset file not found: {path}")
    text = path.read_text(encoding="utf-8")
    parsed = _parse_yaml_restricted(text)
    _validate_schema(parsed)
    logger.info(
        "preset_yaml_loaded",
        path=str(path),
        preset_id=parsed["preset_id"],
        entry_count=len(parsed["presets"]),
    )
    return LoadedPreset(
        preset_id=parsed["preset_id"],
        schema_version=parsed["schema_version"],
        description=parsed.get("description", ""),
        primary_source=parsed["primary_source"],
        disclosed_at=parsed["disclosed_at"],
        presets=list(parsed["presets"]),
    )


def compose_preset_factories(loaded: LoadedPreset) -> dict[str, Any]:
    """Resolve each entry's ``factory`` against ``policy_presets`` and call it.

    Disabled entries (``enabled: false``) are skipped. Returns a dict
    keyed by preset entry id with the factory's return value. Unknown
    factories raise :class:`PresetParseError`.
    """
    from . import policy_presets  # late import to avoid module-level cycle

    composed: dict[str, Any] = {}
    for entry in loaded.presets:
        if entry.get("enabled") is False:
            continue
        factory_name = entry["factory"]
        factory = getattr(policy_presets, factory_name, None)
        if factory is None:
            raise PresetParseError(f"unknown factory {factory_name!r} for entry {entry['id']!r}")
        try:
            composed[entry["id"]] = factory()
        except TypeError:
            # Factory required an argument — caller must invoke
            # manually for those. Skip with a non-fatal warning.
            logger.warning(
                "preset_factory_skipped_needs_args",
                factory=factory_name,
                entry_id=entry["id"],
            )
    return composed


__all__ = [
    "LoadedPreset",
    "PresetParseError",
    "compose_preset_factories",
    "load_yaml_preset",
]
