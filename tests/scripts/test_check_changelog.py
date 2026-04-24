"""Tests for scripts/check_changelog.py (v0.5.5+).

The drift-gate script is treated as library code for test purposes: we
import ``run()`` via ``importlib`` and feed it tmp-path fixtures so the
tests don't depend on the real repo's CHANGELOG / pyproject.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "check_changelog.py"

_spec = importlib.util.spec_from_file_location("check_changelog", SCRIPT)
assert _spec is not None
check_changelog = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(check_changelog)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _pyproject(tmp: Path, version: str) -> Path:
    path = tmp / "pyproject.toml"
    _write(
        path,
        f'[project]\nname = "demo"\nversion = "{version}"\n',
    )
    return path


def _changelog(tmp: Path, unreleased_body: str) -> Path:
    path = tmp / "CHANGELOG.md"
    _write(
        path,
        "# Changelog\n\n"
        "## [Unreleased]\n\n"
        f"{unreleased_body}\n\n"
        "---\n\n"
        "## [0.5.3] - 2026-04-21\n\nOlder release body.\n",
    )
    return path


class TestDefaultMode:
    """Post-release drift gate: version released + [Unreleased] non-empty → FAIL."""

    def test_clean_release_passes(self, tmp_path: Path) -> None:
        code, msg = check_changelog.run(
            changelog_path=_changelog(tmp_path, "(no entries yet)"),
            pyproject_path=_pyproject(tmp_path, "0.5.4"),
            release_mode=False,
        )
        assert code == 0, msg
        assert "placeholder only" in msg

    def test_drift_detected_when_unreleased_has_entries(self, tmp_path: Path) -> None:
        code, msg = check_changelog.run(
            changelog_path=_changelog(tmp_path, "### Security presets\n- new preset X"),
            pyproject_path=_pyproject(tmp_path, "0.5.4"),
            release_mode=False,
        )
        assert code == 1
        assert "DRIFT" in msg
        assert "0.5.4" in msg

    def test_pre_release_version_is_exempt(self, tmp_path: Path) -> None:
        """A dev tag like 0.5.5rc1 with [Unreleased] entries is fine."""
        code, _msg = check_changelog.run(
            changelog_path=_changelog(tmp_path, "- work in progress"),
            pyproject_path=_pyproject(tmp_path, "0.5.5rc1"),
            release_mode=False,
        )
        assert code == 0


class TestReleaseMode:
    """``--release`` mode: [Unreleased] must have entries."""

    def test_release_with_notes_passes(self, tmp_path: Path) -> None:
        code, _msg = check_changelog.run(
            changelog_path=_changelog(tmp_path, "- added X\n- fixed Y"),
            pyproject_path=_pyproject(tmp_path, "0.5.5"),
            release_mode=True,
        )
        assert code == 0

    def test_release_without_notes_fails(self, tmp_path: Path) -> None:
        code, msg = check_changelog.run(
            changelog_path=_changelog(tmp_path, "(no entries yet)"),
            pyproject_path=_pyproject(tmp_path, "0.5.5"),
            release_mode=True,
        )
        assert code == 1
        assert "requires non-empty" in msg


class TestMalformedInput:
    """Exit code 2 for unreadable / malformed inputs."""

    def test_missing_changelog_exits_2(self, tmp_path: Path) -> None:
        code, _msg = check_changelog.run(
            changelog_path=tmp_path / "does-not-exist.md",
            pyproject_path=_pyproject(tmp_path, "0.5.5"),
            release_mode=False,
        )
        assert code == 2

    def test_missing_unreleased_section_exits_2(self, tmp_path: Path) -> None:
        changelog = tmp_path / "CHANGELOG.md"
        _write(changelog, "# Changelog\n\n## [0.5.3] - 2026-04-21\n\nbody\n")
        code, msg = check_changelog.run(
            changelog_path=changelog,
            pyproject_path=_pyproject(tmp_path, "0.5.5"),
            release_mode=False,
        )
        assert code == 2
        assert "Unreleased" in msg


@pytest.mark.parametrize(
    "version",
    ["0.5.4", "1.0.0", "0.5.100"],
)
def test_is_released_version(version: str) -> None:
    assert check_changelog.is_released_version(version) is True


@pytest.mark.parametrize(
    "version",
    ["0.5.4rc1", "0.5.4.dev3", "0.5.4a0", "1.0.0-beta", "0.5.5+local"],
)
def test_prereleases_are_not_released(version: str) -> None:
    assert check_changelog.is_released_version(version) is False
