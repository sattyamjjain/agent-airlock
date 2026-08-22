#!/usr/bin/env python3
"""Relative-link gate: every in-repo markdown link must resolve to something that exists.

Why this exists
---------------
Nothing checked links, so they rotted silently. At v0.8.79 the README carried **nine dead
links across eight targets** — ``docs/API.md``, ``docs/attest/receipt.md``,
``docs/cli/console.md``, ``docs/pack/policy-bundle-lock.md``, ``docs/studio/quickstart.md``,
``docs/graph.md``, ``docs/policy-as-prompt.md``, ``docs/kill-switch.md``. Two of those
directories (``docs/pack/``, ``docs/studio/``) had never existed at all. Every one of them
sat in the README's own documentation table, so the reader most likely to click them was the
reader evaluating whether to trust the project.

This is the same failure class as the Codecov badge that rendered "unknown" (removed in
v0.8.79) and the benchmark dates that sat a month past their run (gated in v0.8.75): a
public-facing claim with nothing watching it. The fix is the same shape — a gate, not a note
asking someone to remember.

Scope, deliberately narrow
--------------------------
* **Relative links only.** External URLs are not fetched: that needs network, turns a
  deterministic gate into a flaky one, and would fail on rate limits rather than on repo
  defects. Badge and advisory URLs are checked by hand at release.
* **Anchors are not resolved.** ``file.md#section`` is checked for ``file.md`` only.
* ``site/`` is skipped — it is generated build output, not source.

Exit codes: ``0`` pass, ``1`` at least one dead link.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

#: Directories whose markdown is generated or vendored, not authored here.
_SKIP_DIRS = {"site", ".git", "node_modules", ".venv", "htmlcov"}

#: ``[text](target)`` where target is not external, not a bare anchor, not a mail link.
_LINK_RE = re.compile(r"\[[^\]]*\]\((?P<target>(?!https?://|#|mailto:|data:)[^)\s]+)\)")

#: A fenced code block, so a ``foo(bar)`` call inside one is not mistaken for a link.
_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)

#: Inline code, same reason — `preset["check"](args)` is not a link.
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")


def _strip_code(text: str) -> str:
    """Blank out code spans so their parentheses cannot look like links.

    Replaced with same-length whitespace rather than deleted, so any line numbers a future
    caller wants to report stay meaningful.
    """
    text = _FENCE_RE.sub(lambda m: " " * len(m.group(0)), text)
    return _INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), text)


def markdown_files() -> list[Path]:
    """Every authored markdown file in the repo, newest-path-first for stable output."""
    out: list[Path] = []
    for path in _ROOT.rglob("*.md"):
        rel = path.relative_to(_ROOT)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        out.append(path)
    return sorted(out)


def dead_links(path: Path) -> list[tuple[int, str]]:
    """Return ``(line_number, target)`` for each relative link that does not resolve."""
    raw = path.read_text(encoding="utf-8", errors="ignore")
    stripped = _strip_code(raw)
    dead: list[tuple[int, str]] = []

    for match in _LINK_RE.finditer(stripped):
        target = match.group("target").split("#", 1)[0].strip()
        if not target:
            continue  # pure anchor, e.g. [x](#y) — nothing to resolve
        line_no = stripped.count("\n", 0, match.start()) + 1
        # Resolve relative to the file, then (for docs written against the repo root)
        # fall back to the root. Either resolving is enough.
        if (path.parent / target).exists() or (_ROOT / target).exists():
            continue
        dead.append((line_no, target))
    return dead


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quiet", action="store_true", help="only print failures, not the per-file tally"
    )
    args = parser.parse_args(argv)

    checked = 0
    failures: list[tuple[Path, int, str]] = []

    for path in markdown_files():
        checked += 1
        for line_no, target in dead_links(path):
            failures.append((path, line_no, target))

    if failures:
        print(
            f"FAIL: {len(failures)} dead relative link(s) in {checked} markdown files:\n",
            file=sys.stderr,
        )
        for path, line_no, target in failures:
            print(f"  {path.relative_to(_ROOT)}:{line_no}  ->  {target}", file=sys.stderr)
        print(
            "\nEvery in-repo markdown link must resolve. Point it at a file that exists, or "
            "remove it. Do not link a doc page that has not been written — a 404 in the "
            "README costs more trust than an absent link.",
            file=sys.stderr,
        )
        return 1

    if not args.quiet:
        print(f"OK ({checked} markdown files, all relative links resolve)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
