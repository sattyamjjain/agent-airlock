#!/usr/bin/env python3
"""Docs API gate: every ``agent_airlock`` name a docs example uses must exist.

Why this exists
---------------
The docs examples were written against an API that drifted away under them, and nothing
ran them. At v0.10.13 the Python blocks under ``docs/`` made 109 references to names,
parameters and methods that do not exist — ``Airlock(unknown_args_mode=...)`` on the docs
home page, ``AirlockConfig(masking_strategy=...)`` in the sanitisation guide,
``SandboxPool(max_size=...)``, ``from agent_airlock import secure_tool`` — so a reader who
copied one got a ``TypeError`` or an ``ImportError`` before reaching the feature it
described. It is the failure class ``check_links.py`` closed for links: a public claim with
nothing watching it.

Scope, deliberately narrow
--------------------------
* **Static.** Blocks are parsed, never executed: most are fragments that assume names from
  the prose around them, and running them would need sandboxes, keys and servers.
* **Only names imported from ``agent_airlock`` in the same block are checked**: that the
  import resolves, that a call to one passes only keywords its signature accepts, and that
  an attribute read or called on one — or on a variable assigned from one of its classes —
  exists. A block that uses a name without importing it is not checked.
* **A module that needs an extra that is not installed is skipped**, not failed, so the
  gate reports the same thing on a bare install as on ``[all]``, just less of it.
* ``python`` and ``py`` fences only; ``console`` and shell blocks are not code.
* **Every authored markdown file plus every script under ``examples/``**, except
  ``CHANGELOG.md`` (its entries quote APIs as they were) and ``.github/`` (issue templates
  sketch APIs that do not exist yet).

Exit codes: ``0`` pass, ``1`` at least one finding.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import importlib
import inspect
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_SKIP_DIRS = {"site", ".git", "node_modules", ".venv", "htmlcov", ".github"}
_SKIP_FILES = {"CHANGELOG.md"}
_FENCE = re.compile(r"^```(?:python|py)[ \t]*\n(.*?)^```", re.S | re.M)
_SELF_ASSIGN = re.compile(r"\bself\.([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=\n]*)?=(?!=)")
_MISSING = object()
_UNCHECKABLE = object()


def python_blocks(path: Path) -> Iterator[tuple[int, str]]:
    """Yield ``(first line number, source)`` for each Python fence, or a whole ``.py`` file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".py":
        yield 1, text
        return
    for match in _FENCE.finditer(text):
        yield text.count("\n", 0, match.start(1)) + 1, match.group(1)


def _import(module: str) -> Any:
    """The module, ``None`` if it does not exist, or ``_UNCHECKABLE`` if an extra is missing."""
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing == module or module.startswith(missing + "."):
            return None if missing.split(".")[0] == "agent_airlock" else _UNCHECKABLE
        return _UNCHECKABLE
    except Exception:  # noqa: BLE001 - an import-time error in an optional backend
        return _UNCHECKABLE


def _instance_attributes(cls: type) -> set[str]:
    """Attributes a class or its bases assign to ``self`` in their own source."""
    names: set[str] = set()
    for klass in cls.__mro__:
        if klass.__module__.split(".")[0] != "agent_airlock":
            continue
        try:
            names |= set(_SELF_ASSIGN.findall(inspect.getsource(klass)))
        except (OSError, TypeError):
            continue
    return names


def _members(obj: Any) -> set[str]:
    names = set(dir(obj))
    if inspect.isclass(obj):
        if dataclasses.is_dataclass(obj):
            names |= {field.name for field in dataclasses.fields(obj)}
        for klass in obj.__mro__:
            names |= set(vars(klass).get("__annotations__", {}))
        names |= set(getattr(obj, "model_fields", {}) or {})
        names |= _instance_attributes(obj)
    return names


def _has_attribute(owner: Any, name: str) -> bool:
    # hasattr also finds what dir() leaves out, such as a Flag's composite members.
    return name in _members(owner) or hasattr(owner, name)


def _rejects_keyword(target: Any, keyword: str) -> bool:
    try:
        signature = inspect.signature(target)
    except (TypeError, ValueError):
        return False
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return False
    return keyword not in signature.parameters


def _imported_names(tree: ast.AST) -> tuple[dict[str, Any], list[tuple[int, str]]]:
    names: dict[str, Any] = {}
    findings: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and (node.module or "").split(".")[0] == "agent_airlock"
        ):
            module = _import(node.module or "")
            if module is None:
                findings.append((node.lineno, f"no module {node.module}"))
                continue
            if module is _UNCHECKABLE:
                continue
            for alias in node.names:
                obj = getattr(module, alias.name, _MISSING)
                if obj is _MISSING:
                    obj = _import(f"{node.module}.{alias.name}")
                if obj is None or obj is _MISSING:
                    findings.append((node.lineno, f"{node.module} has no {alias.name}"))
                elif obj is not _UNCHECKABLE:
                    names[alias.asname or alias.name] = obj
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] != "agent_airlock":
                    continue
                module = _import(alias.name)
                if module is None:
                    findings.append((node.lineno, f"no module {alias.name}"))
                elif module is not _UNCHECKABLE and alias.asname:
                    names[alias.asname] = module
    return names, findings


def _instances(tree: ast.AST, names: dict[str, Any]) -> dict[str, type]:
    """``var`` for each ``var = ImportedClass(...)`` in the block."""
    found: dict[str, type] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
            continue
        func = node.value.func
        cls = names.get(func.id) if isinstance(func, ast.Name) else None
        if inspect.isclass(cls):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = cls
    return found


def check_source(source: str) -> list[tuple[int, str]]:
    """Findings for one block, as ``(line within the block, message)``."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []  # prose-shaped pseudo-code; nothing checkable
    names, findings = _imported_names(tree)
    instances = _instances(tree, names)

    def owner_of(name: str) -> Any:
        return names.get(name, instances.get(name, _MISSING))

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            owner = owner_of(node.value.id)
            if owner is not _MISSING and not _has_attribute(owner, node.attr):
                findings.append((node.lineno, f"{node.value.id}.{node.attr} does not exist"))
        if not isinstance(node, ast.Call):
            continue
        func, target, label = node.func, _MISSING, ""
        if isinstance(func, ast.Name) and func.id in names:
            target, label = names[func.id], func.id
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            owner = owner_of(func.value.id)
            if owner is not _MISSING:
                target = getattr(owner, func.attr, _MISSING)
                label = f"{func.value.id}.{func.attr}"
        if target is _MISSING or not callable(target):
            continue
        for keyword in node.keywords:
            if keyword.arg is not None and _rejects_keyword(target, keyword.arg):
                findings.append((node.lineno, f"{label}() has no parameter {keyword.arg!r}"))
    return sorted(set(findings))


def findings_in(path: Path) -> list[tuple[int, str]]:
    """Findings for one file, as ``(line in the file, message)``."""
    return [
        (start + line - 1, message)
        for start, source in python_blocks(path)
        for line, message in check_source(source)
    ]


def doc_files(root: Path = _ROOT) -> list[Path]:
    """Every authored markdown file and example script the gate covers."""
    out = [
        path
        for path in [*root.rglob("*.md"), *(root / "examples").rglob("*.py")]
        if path.name not in _SKIP_FILES
        and not any(part in _SKIP_DIRS for part in path.relative_to(root).parts)
    ]
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("paths", nargs="*", type=Path, help="files to check (default: all)")
    args = parser.parse_args(argv)
    paths = args.paths or doc_files()
    total = 0
    for path in paths:
        for line, message in findings_in(path):
            total += 1
            shown = (
                path.resolve().relative_to(_ROOT) if path.resolve().is_relative_to(_ROOT) else path
            )
            print(f"{shown}:{line}: {message}")
    if total:
        print(
            f"\n{total} docs reference(s) to agent_airlock API that does not exist", file=sys.stderr
        )
        return 1
    print(f"OK ({len(paths)} files, every checked agent_airlock reference resolves)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
