"""Coverage matrix loader + Markdown / JSON renderers.

The renderer is byte-stable: identical input produces identical
output across runs (deterministic ordering by ``risk_id``). That
makes the docs page diff-friendly when CI regenerates it.

A restricted-grammar YAML parser is used to keep the runtime
dependency baseline at three (pydantic / structlog / tomli). The
grammar accepts:

* Top-level scalars (``key: value``).
* Top-level lists (``key:`` followed by ``- item:`` blocks).
* String, integer, ISO date scalar values.

Anything richer (anchors, nested mappings beyond two levels, flow
syntax) is rejected explicitly — the corpus loader uses the same
discipline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

COVERAGE_PATH: Path = Path(__file__).resolve().parent / "coverage.yaml"


@dataclass(frozen=True)
class CoverageEntry:
    """One OWASP-Agentic risk coverage row."""

    risk_id: str
    risk_name: str
    guard_module: str
    preset: str
    test_path: str
    last_verified: str
    advisory_url: str


@dataclass(frozen=True)
class Coverage:
    """The full coverage matrix."""

    spec_version: str
    spec_url: str
    last_verified_global: str
    entries: tuple[CoverageEntry, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Restricted YAML parser
# ---------------------------------------------------------------------------


def _parse_yaml(text: str) -> dict[str, Any]:  # noqa: C901 — straightforward state machine
    """Parse the restricted grammar described in the module docstring."""
    out: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if line.startswith(" "):
            raise ValueError(f"line {i + 1}: unexpected indentation outside a list block: {raw!r}")
        if ":" not in line:
            raise ValueError(f"line {i + 1}: missing ':' separator: {raw!r}")
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest:
            out[key] = _coerce_scalar(rest)
            i += 1
            continue

        # Block — either a list of mappings or empty.
        items: list[dict[str, Any]] = []
        i += 1
        while i < len(lines):
            sub = lines[i]
            stripped = sub.strip()
            if not stripped or stripped.startswith("#"):
                i += 1
                continue
            if not sub.startswith("  "):
                break
            if not stripped.startswith("- "):
                raise ValueError(f"line {i + 1}: list item must start with '- ': {sub!r}")
            item, i = _parse_mapping(lines, i)
            items.append(item)
        out[key] = items
    return out


def _parse_mapping(lines: list[str], i: int) -> tuple[dict[str, Any], int]:
    """Parse one ``- key: value`` block starting at ``lines[i]``."""
    item: dict[str, Any] = {}
    first = lines[i]
    inner = first.split("- ", 1)[1]
    indent = " " * (len(first) - len(first.lstrip()) + 2)
    if ":" in inner:
        key, _, rest = inner.partition(":")
        item[key.strip()] = _coerce_scalar(rest.strip())
    else:
        raise ValueError(f"line {i + 1}: list item missing ':' — {first!r}")
    i += 1
    while i < len(lines):
        sub = lines[i]
        stripped = sub.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if not sub.startswith(indent) or sub.startswith(indent + "-"):
            break
        if ":" not in sub:
            raise ValueError(f"line {i + 1}: missing ':' in mapping body: {sub!r}")
        key, _, rest = sub.partition(":")
        item[key.strip()] = _coerce_scalar(rest.strip())
        i += 1
    return item, i


def _coerce_scalar(value: str) -> str | int | bool:
    """Coerce a scalar token. Strings are unquoted from "..." or '...'."""
    if not value:
        return ""
    if (
        value.startswith('"')
        and value.endswith('"')
        and len(value) >= 2
        or value.startswith("'")
        and value.endswith("'")
        and len(value) >= 2
    ):
        return value[1:-1]
    if value.lstrip("-").isdigit():
        return int(value)
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_coverage(path: Path | None = None) -> Coverage:
    """Load and validate the coverage matrix.

    Returns a :class:`Coverage` whose ``entries`` are sorted by
    ``risk_id`` for deterministic downstream consumption.
    """
    target = path or COVERAGE_PATH
    raw = _parse_yaml(target.read_text(encoding="utf-8"))

    spec_version = str(raw.get("spec_version") or "")
    if not spec_version:
        raise ValueError(f"{target}: missing required key 'spec_version'")

    entries_raw = raw.get("entries") or []
    if not isinstance(entries_raw, list):
        raise ValueError(f"{target}: 'entries' must be a list")

    entries: list[CoverageEntry] = []
    for idx, entry_raw in enumerate(entries_raw):
        if not isinstance(entry_raw, dict):
            raise ValueError(f"{target}: entries[{idx}] must be a mapping")
        for required in (
            "risk_id",
            "risk_name",
            "guard_module",
            "preset",
            "test_path",
            "last_verified",
            "advisory_url",
        ):
            if not entry_raw.get(required):
                raise ValueError(f"{target}: entries[{idx}] missing required key {required!r}")
        entries.append(
            CoverageEntry(
                risk_id=str(entry_raw["risk_id"]),
                risk_name=str(entry_raw["risk_name"]),
                guard_module=str(entry_raw["guard_module"]),
                preset=str(entry_raw["preset"]),
                test_path=str(entry_raw["test_path"]),
                last_verified=str(entry_raw["last_verified"]),
                advisory_url=str(entry_raw["advisory_url"]),
            )
        )

    entries.sort(key=lambda e: e.risk_id)
    return Coverage(
        spec_version=spec_version,
        spec_url=str(raw.get("spec_url") or ""),
        last_verified_global=str(raw.get("last_verified_global") or ""),
        entries=tuple(entries),
    )


def render_markdown(coverage: Coverage) -> str:
    """Render the matrix as a deterministic Markdown table."""
    lines = [
        f"# OWASP Agentic {coverage.spec_version} coverage",
        "",
        f"Spec: {coverage.spec_url}",
        f"Last verified (global): {coverage.last_verified_global}",
        "",
        "| Risk ID | Risk | Guard module | Preset | Test | Last verified | Advisory |",
        "|---------|------|--------------|--------|------|---------------|----------|",
    ]
    for e in coverage.entries:
        lines.append(
            f"| {e.risk_id} | {e.risk_name} | `{e.guard_module}` | "
            f"`{e.preset}` | `{e.test_path}` | {e.last_verified} | "
            f"[link]({e.advisory_url}) |"
        )
    lines.append("")
    return "\n".join(lines)


def render_json(coverage: Coverage) -> str:
    """Render the matrix as a deterministic JSON document."""
    payload: dict[str, Any] = {
        "spec_version": coverage.spec_version,
        "spec_url": coverage.spec_url,
        "last_verified_global": coverage.last_verified_global,
        "entries": [
            {
                "risk_id": e.risk_id,
                "risk_name": e.risk_name,
                "guard_module": e.guard_module,
                "preset": e.preset,
                "test_path": e.test_path,
                "last_verified": e.last_verified,
                "advisory_url": e.advisory_url,
            }
            for e in coverage.entries
        ],
    }
    return json.dumps(payload, sort_keys=True, indent=2)


def stale_entries(coverage: Coverage, max_age_days: int = 30) -> list[CoverageEntry]:
    """Return entries whose ``last_verified`` is older than ``max_age_days``."""
    today = datetime.now(tz=timezone.utc).date()
    out: list[CoverageEntry] = []
    for e in coverage.entries:
        try:
            d = date.fromisoformat(e.last_verified)
        except ValueError as exc:
            raise ValueError(f"{e.risk_id}: invalid last_verified={e.last_verified!r}") from exc
        age = (today - d).days
        if age > max_age_days:
            out.append(e)
    return out


__all__ = [
    "COVERAGE_PATH",
    "Coverage",
    "CoverageEntry",
    "load_coverage",
    "render_json",
    "render_markdown",
    "stale_entries",
]
