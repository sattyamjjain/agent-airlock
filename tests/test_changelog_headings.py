"""CHANGELOG heading conformance + the release gate, as tests.

0.8.65 through 0.8.67 shipped and were tagged with their entries stuck under
``[Unreleased]``, so the newest dated heading lagged the shipped version by three
releases. Two guards keep that from recurring:

1. every version section heading is either ``[Unreleased]`` or a dated
   ``## [x.y.z] - YYYY-MM-DD`` heading, and
2. the version declared in ``pyproject.toml`` has a dated heading (the same check
   ``scripts/check_changelog_heading.py`` runs as a release gate in CI).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
PYPROJECT = ROOT / "pyproject.toml"

# `## [x.y.z] - YYYY-MM-DD` (optionally ` — title`); 3 or 4 version components.
_DATED = re.compile(r"^## \[(\d+(?:\.\d+){2,3})\] - (\d{4}-\d{2}-\d{2})( .*)?$")
_LABEL = re.compile(r"^## \[([^\]]+)\]")


def _section_headings() -> list[str]:
    return [
        line
        for line in CHANGELOG.read_text(encoding="utf-8").splitlines()
        if line.startswith("## [")
    ]


def _pyproject_version() -> str:
    with PYPROJECT.open("rb") as fh:
        return str(tomllib.load(fh)["project"]["version"])


class TestChangelogHeadings:
    def test_every_version_heading_is_unreleased_or_dated(self) -> None:
        bad = []
        for line in _section_headings():
            label_match = _LABEL.match(line)
            label = label_match.group(1) if label_match else line
            if label == "Unreleased":
                continue
            if not _DATED.match(line):
                bad.append(line)
        assert not bad, (
            "Non-conformant CHANGELOG version heading(s) — use "
            "'## [x.y.z] - YYYY-MM-DD':\n" + "\n".join(bad)
        )

    def test_declared_version_has_a_dated_heading(self) -> None:
        version = _pyproject_version()
        dated = {match.group(1) for line in _section_headings() if (match := _DATED.match(line))}
        assert version in dated, (
            f"pyproject declares {version} but CHANGELOG.md has no "
            f"'## [{version}] - YYYY-MM-DD' heading. Promote [Unreleased] before release."
        )
