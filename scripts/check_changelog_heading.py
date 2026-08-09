#!/usr/bin/env python3
"""CI release gate: the declared version must have a conformant dated CHANGELOG heading.

The failure this exists for: 0.8.65, 0.8.66 and 0.8.67 all shipped and were tagged while
their entries sat under ``## [Unreleased]``, so the newest *dated* heading (``0.8.64``)
lagged the shipped version by three releases and a reader could not tell from the changelog
what any of those three releases changed. This gate fails a release whose
``pyproject.toml`` version has no ``## [x.y.z] - YYYY-MM-DD`` heading in ``CHANGELOG.md``,
so a version can never be cut without its entry being promoted out of ``[Unreleased]`` first.

Companion to ``check_version_tagged.py`` (which fails an untagged version bump); this one
fails an unpromoted one. Both run in the ``version-tag-guard`` CI job.

Exit codes: 0 = a conformant dated heading exists · 1 = missing/unpromoted · 2 = usage.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"

# `## [x.y.z] - YYYY-MM-DD`, optionally followed by ` — "title"`. Three or four version
# components (0.5.7.1 and 0.5.6.1 shipped as historical hotfix releases).
_HEADING = re.compile(r"^## \[(\d+(?:\.\d+){2,3})\] - (\d{4}-\d{2}-\d{2})( .*)?$")


def _declared_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.M)
    if not match:
        print("check_changelog_heading: no version in pyproject.toml", file=sys.stderr)
        raise SystemExit(2)
    return match.group(1)


def main() -> int:
    version = _declared_version()
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        match = _HEADING.match(line)
        if match and match.group(1) == version:
            print(f"check_changelog_heading: OK — '{line.strip()}' present.")
            return 0
    print(
        f"check_changelog_heading: FAIL — pyproject declares {version} but CHANGELOG.md has "
        f"no conformant '## [{version}] - YYYY-MM-DD' heading. Promote the [Unreleased] "
        f"entry to a dated heading before cutting the release.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
