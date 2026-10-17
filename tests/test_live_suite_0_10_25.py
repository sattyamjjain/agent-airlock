"""0.10.25: the live API contract tests stay out of every run that did not ask for them.

``tests/live`` calls the Anthropic API and spends API credit. These checks run in the
ordinary suite and spend nothing: the default ``addopts`` ignore the directory, collecting
it explicitly needs no SDK, naming it without ``AIRLOCK_LIVE=1`` and a key skips every
test, and no module there imports ``anthropic`` or ``claude_agent_sdk`` at module level.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "tests" / "live"
SDKS = ("anthropic", "claude_agent_sdk")


def _pytest_ini() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return dict(tomllib.load(handle)["tool"]["pytest"]["ini_options"])


def _child_env(tmp_path: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("AIRLOCK_LIVE", "ANTHROPIC_API_KEY")
    }
    env["AIRLOCK_AUDIT_LOG_PATH"] = str(tmp_path / "audit.json")
    return env


def _module_level_statements(body: list[ast.stmt]) -> list[ast.stmt]:
    """Statements that run on import: the body, and inside if/try/with/class, not defs."""
    out: list[ast.stmt] = []
    for node in body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        out.append(node)
        for child in ("body", "orelse", "finalbody"):
            out.extend(_module_level_statements(getattr(node, child, []) or []))
        for handler in getattr(node, "handlers", []) or []:
            out.extend(_module_level_statements(handler.body))
    return out


def _imported_roots(node: ast.stmt) -> set[str]:
    if isinstance(node, ast.Import):
        return {alias.name.split(".")[0] for alias in node.names}
    if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
        return {node.module.split(".")[0]}
    return set()


def _live_modules() -> list[Path]:
    return sorted(LIVE.glob("*.py"))


class TestTheDefaultRunNeverCollectsThem:
    def test_addopts_ignore_tests_live(self) -> None:
        addopts = str(_pytest_ini()["addopts"])
        assert "--ignore=tests/live" in addopts.split()
        assert addopts.count("-m ") == 1, "keep a single marker expression in addopts"

    def test_the_live_marker_is_registered(self) -> None:
        markers = [str(marker) for marker in _pytest_ini()["markers"]]  # type: ignore[union-attr]
        assert any(marker.startswith("live:") for marker in markers), markers

    def test_make_test_live_names_the_directory_and_clears_addopts(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        recipe = re.search(r"^test-live:\n\t(.+)$", makefile, re.M)
        assert recipe, "no test-live target in the Makefile"
        command = recipe.group(1)
        assert command.startswith("AIRLOCK_LIVE=1 ")
        assert "tests/live" in command and '-o addopts=""' in command and "-m live" in command


class TestTheModulesStayInert:
    def test_there_are_live_modules(self) -> None:
        names = {path.name for path in _live_modules()}
        assert {
            "conftest.py",
            "test_live_messages.py",
            "test_live_agent_sdk.py",
            "test_live_managed_agents.py",
        } <= names

    @pytest.mark.parametrize("path", _live_modules(), ids=lambda p: p.name)
    def test_no_sdk_is_imported_at_module_level(self, path: Path) -> None:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in _module_level_statements(tree.body):
            imported |= _imported_roots(node)
        assert not imported & set(SDKS), f"{path.name} imports {sorted(imported & set(SDKS))}"

    @pytest.mark.parametrize(
        "path", [p for p in _live_modules() if p.name.startswith("test_")], ids=lambda p: p.name
    )
    def test_every_test_module_is_marked_live(self, path: Path) -> None:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        marked = any(
            isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in node.targets)
            and "live" in ast.unparse(node.value)
            for node in tree.body
        )
        assert marked, f"{path.name} lacks `pytestmark = pytest.mark.live`"


class TestNamingTheDirectorySpendsNothing:
    def test_it_collects_without_an_sdk_import_error(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests/live",
                "-o",
                "addopts=",
            ],  # fmt: skip
            cwd=ROOT,
            env=_child_env(tmp_path),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        collected = re.search(r"(\d+) tests? collected", result.stdout)
        assert collected and int(collected.group(1)) >= 4, result.stdout

    def test_without_the_opt_in_every_test_skips(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests/live",
                "-o",
                "addopts=",
                "-m",
                "live",
                "-rs",
            ],  # fmt: skip
            cwd=ROOT,
            env=_child_env(tmp_path),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert re.search(r"\b\d+ skipped\b", result.stdout), result.stdout
        assert " passed" not in result.stdout and " failed" not in result.stdout, result.stdout
        assert "AIRLOCK_LIVE=1" in result.stdout
