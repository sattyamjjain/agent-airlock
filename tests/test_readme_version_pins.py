"""README version pins must reference real releases, not stale or typo'd floors.

The README carries several ``pip install "agent-airlock>=X.Y.Z"`` snippets and a
``One CLI ... (vX.Y.Z)`` heading. Each of those version references is a promise: "this
feature exists from this release on." A pin that names a version which was never released
(a typo, or a floor left behind after a rename) reads as a real floor but is a lie. These
tests tie every such reference to a dated ``## [X.Y.Z]`` heading in ``CHANGELOG.md`` (the
release record) and forbid a pin above the current version, so a stale or invented floor
fails the suite instead of shipping.

This does not attempt to prove semantically that *the feature* landed in exactly that
release — that is not mechanically checkable — but it does prove the version is a real
release and not ahead of HEAD, which is the failure mode pins actually exhibit.
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
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
PYPROJECT = ROOT / "pyproject.toml"

_DATED_HEADING = re.compile(r"^## \[(\d+(?:\.\d+){2,3})\] - \d{4}-\d{2}-\d{2}", re.M)
_PIN = re.compile(r"agent-airlock>=(\d+\.\d+\.\d+)")
_CLI_HEADING = re.compile(r"^### .*One CLI.*\(.*v(\d+\.\d+\.\d+)\)", re.M)


def _released_versions() -> set[str]:
    return set(_DATED_HEADING.findall(CHANGELOG.read_text(encoding="utf-8")))


def _current_version() -> tuple[int, ...]:
    with PYPROJECT.open("rb") as fh:
        return tuple(int(p) for p in str(tomllib.load(fh)["project"]["version"]).split("."))


def _as_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


class TestReadmeVersionPins:
    def test_every_pin_is_a_real_release(self) -> None:
        readme = README.read_text(encoding="utf-8")
        pins = sorted(set(_PIN.findall(readme)))
        assert pins, "expected at least one `agent-airlock>=X.Y.Z` pin in the README"
        released = _released_versions()
        missing = [p for p in pins if p not in released]
        assert not missing, (
            "README pins a version with no dated CHANGELOG release heading "
            f"(stale or typo'd floor): {missing}. Known releases include "
            f"{sorted(released)[-6:]}."
        )

    def test_no_pin_is_ahead_of_the_current_version(self) -> None:
        readme = README.read_text(encoding="utf-8")
        current = _current_version()
        ahead = [p for p in set(_PIN.findall(readme)) if _as_tuple(p) > current]
        assert not ahead, (
            f"README pins a version ahead of the current {'.'.join(map(str, current))}: "
            f"{ahead}. A floor cannot require an unreleased version."
        )

    def test_cli_heading_names_a_real_release(self) -> None:
        readme = README.read_text(encoding="utf-8")
        match = _CLI_HEADING.search(readme)
        assert match, "could not find the `One CLI ... (vX.Y.Z)` heading in the README"
        version = match.group(1)
        assert version in _released_versions(), (
            f"the One CLI heading cites v{version}, which has no dated CHANGELOG "
            "release heading. Point it at the release the command set stabilised in."
        )
