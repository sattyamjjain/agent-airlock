"""Tests for scripts/check_bare_imports.py (0.10.26).

The bare-install gate imports every module under the package. In the test environment
every extra is installed, so the walk passing here shows only that it covers the whole
package; the failure path is driven with a synthetic package on ``sys.path``.
"""

from __future__ import annotations

import importlib.util
import pkgutil
import sys
from pathlib import Path

import pytest

import agent_airlock

SCRIPT = Path(__file__).resolve().parent.parent.parent / "scripts" / "check_bare_imports.py"

_spec = importlib.util.spec_from_file_location("check_bare_imports", SCRIPT)
assert _spec is not None
check_bare_imports = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(check_bare_imports)


def test_the_walk_covers_every_module_in_the_package() -> None:
    walked = {info.name for info in pkgutil.walk_packages(agent_airlock.__path__, "agent_airlock.")}
    assert "agent_airlock.sequence_guard" in walked
    assert "agent_airlock.action_contradiction_gate" in walked
    assert "agent_airlock.cli.console" in walked
    assert "agent_airlock.mcp_spec.attested_admission" in walked
    assert check_bare_imports.walk() == []


def test_a_module_that_raises_is_reported_and_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pkg = tmp_path / "fakepkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "fine.py").write_text("X = 1\n", encoding="utf-8")
    (pkg / "broken.py").write_text("import no_such_extra_xyz\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    for name in ("fakepkg", "fakepkg.fine", "fakepkg.broken"):
        sys.modules.pop(name, None)

    failures = check_bare_imports.walk("fakepkg")
    assert [name for name, _ in failures] == ["fakepkg.broken"]
    assert "ModuleNotFoundError" in failures[0][1]

    assert check_bare_imports.main(["fakepkg"]) == 1
    out = capsys.readouterr().out
    assert "FAIL: 1 of 2 modules" in out
    assert "fakepkg.broken" in out


def test_a_missing_package_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert check_bare_imports.main(["no_such_package_xyz"]) == 2
    assert "cannot import" in capsys.readouterr().out
