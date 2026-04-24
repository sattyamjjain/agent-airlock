#!/usr/bin/env python3
"""CHANGELOG.md drift gate (v0.5.5+).

Market signal for this script: the 2026-04-24 live-audit of
`sattyamjjain/agent-airlock` found `pyproject.toml` at `version =
"0.5.3"` while the `[Unreleased]` section of `CHANGELOG.md` was empty
header-only. Nothing to enforce yet, but the inverse is the bug we
*want* to catch: a release gets tagged without moving the
`[Unreleased]` entries into a versioned section.

Two modes:

1. **Default (post-release drift gate).** Pass iff either
   ``pyproject.toml`` version is a pre-release (``0.5.4rc1``,
   ``0.5.4.dev3``) OR the ``[Unreleased]`` section contains only
   the placeholder (``(no entries yet)`` / blank lines). Fail if
   the project is stamped with a released version but
   ``[Unreleased]`` still has meaningful entries — they should have
   been moved to a versioned section at tag time.

2. **--release (pre-tag gate).** Pass iff ``[Unreleased]`` has
   meaningful entries. Used right before ``git tag`` to ensure you
   aren't shipping a release with no release notes.

Usage::

    python scripts/check_changelog.py            # default drift check
    python scripts/check_changelog.py --release  # pre-tag check

Exit codes::

    0   check passed
    1   drift detected / release notes missing
    2   CHANGELOG.md / pyproject.toml unreadable or malformed
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# tomllib landed in 3.11; on 3.10 we rely on tomli (already a
# declared <3.11 dep in pyproject.toml).
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CHANGELOG = REPO_ROOT / "CHANGELOG.md"
DEFAULT_PYPROJECT = REPO_ROOT / "pyproject.toml"

# Version is a "released" (non-pre-release) semver iff it looks like
# ``X.Y.Z`` with nothing trailing. ``0.5.4rc1`` / ``0.5.4.dev3`` do NOT
# trigger the drift gate — they're dev tags, entries living in
# ``[Unreleased]`` are still OK.
_RELEASED_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

# "Meaningful" entries in the [Unreleased] body: any bullet, any
# subheading, or any non-empty / non-placeholder line.
_PLACEHOLDER_LINE_RE = re.compile(
    r"^\s*(?:\(no entries yet\)|\*?\s*n/?a\s*\*?)\s*$",
    re.IGNORECASE,
)


def read_version(pyproject_path: Path) -> str:
    try:
        with pyproject_path.open("rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise RuntimeError(f"cannot read {pyproject_path}: {exc}") from exc
    try:
        return str(data["project"]["version"])
    except KeyError as exc:
        raise RuntimeError(f"{pyproject_path} has no [project].version key") from exc


def is_released_version(version: str) -> bool:
    """Whether ``version`` is a plain ``X.Y.Z`` with no pre-release marker."""
    return bool(_RELEASED_VERSION_RE.match(version.strip()))


def extract_unreleased_body(changelog_path: Path) -> str:
    """Return the lines between ``## [Unreleased]`` and the next ``## [``.

    Leading/trailing blank lines are stripped but the body is otherwise
    preserved verbatim so downstream text checks work on the real
    content.
    """
    try:
        text = changelog_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"cannot read {changelog_path}: {exc}") from exc

    # Use re.search so we tolerate leading front-matter.
    m = re.search(r"^## \[Unreleased\]\s*$", text, flags=re.MULTILINE)
    if not m:
        raise RuntimeError(f"{changelog_path} has no ## [Unreleased] section")
    start = m.end()
    remainder = text[start:]
    # Stop at the next ``## [X.Y.Z]`` header.
    next_header = re.search(r"^## \[", remainder, flags=re.MULTILINE)
    end = len(remainder) if next_header is None else next_header.start()
    return remainder[:end].strip("\n")


def unreleased_has_entries(body: str) -> bool:
    """Whether the [Unreleased] body carries meaningful content."""
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("---"):
            # separator, ignore
            continue
        if _PLACEHOLDER_LINE_RE.match(line):
            continue
        # Anything else — bullet, heading, prose — counts as an entry.
        return True
    return False


def run(
    *,
    changelog_path: Path,
    pyproject_path: Path,
    release_mode: bool,
) -> tuple[int, str]:
    """Return ``(exit_code, message)``. Safe to unit-test."""
    try:
        version = read_version(pyproject_path)
        body = extract_unreleased_body(changelog_path)
    except RuntimeError as exc:
        return 2, str(exc)

    has_entries = unreleased_has_entries(body)
    if release_mode:
        if has_entries:
            return 0, (f"OK ({changelog_path.name} [Unreleased] has release notes)")
        return 1, (
            f"DRIFT: --release mode requires non-empty [Unreleased], "
            f"but {changelog_path.name} has none. Add release notes before tagging."
        )

    # Default: post-release drift gate.
    if not is_released_version(version):
        return 0, (f"OK (pre-release version {version!r} — drift gate N/A)")
    if has_entries:
        return 1, (
            f"DRIFT: pyproject version is {version!r} (a released tag) but "
            f"{changelog_path.name} [Unreleased] still has entries. Move "
            f"them into a versioned section before committing the tag."
        )
    return 0, (f"OK (version {version!r}, [Unreleased] placeholder only)")


def main() -> int:
    description = (__doc__ or "CHANGELOG drift gate").splitlines()[0]
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--release",
        action="store_true",
        help="Require [Unreleased] to be non-empty (pre-tag gate).",
    )
    parser.add_argument(
        "--changelog",
        default=str(DEFAULT_CHANGELOG),
        help="Path to CHANGELOG.md (default: %(default)s).",
    )
    parser.add_argument(
        "--pyproject",
        default=str(DEFAULT_PYPROJECT),
        help="Path to pyproject.toml (default: %(default)s).",
    )
    args = parser.parse_args()

    code, message = run(
        changelog_path=Path(args.changelog),
        pyproject_path=Path(args.pyproject),
        release_mode=args.release,
    )
    print(message, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
