"""Regressions for 0.10.24: tooling that could report something that did not happen.

- ``blockrate``, ``toolprivbench`` and ``harness_injection`` stamped ``--date`` with the
  local day while ``check_benchmark_freshness.py`` reads the UTC day, so a run after
  midnight IST was dated tomorrow (#278 fixed the same thing in ``regen.py`` only).
- The blockrate sandbox arm counted a Docker daemon that answered a ping as an available
  backend, though ``@Airlock(sandbox=True)`` dispatches only to E2B, and its report said a
  backend "ran" whenever one was detected: it could publish "ran on `docker` ✅ yes" while
  every admitted call had failed in dispatch.
- The docker CI job grepped its log for the substring ``5 passed``, which ``15 passed`` and
  ``5 passed, 1 skipped`` also contain, so a skipped docker test could pass the gate.
- ``airlock egress-bench`` from an installed wheel raised ``FileNotFoundError``: the walker
  and its fixtures are not shipped, and ``spec_from_file_location`` does not check a path.
- ``agentdojo --force`` was documented as replacing a dated block; it appends another one,
  as the append-only marker requires.
"""

from __future__ import annotations

import datetime
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from benchmarks.agentdojo.run import _RUNS_MARKER, append_run_to_results
from benchmarks.agentdojo.run import main as agentdojo_main
from benchmarks.blockrate import sandbox_arm
from benchmarks.blockrate.report import render_sandbox_arm_section

from agent_airlock import Airlock
from agent_airlock._sandbox_errors import SandboxExecutionError
from agent_airlock.cli.egress_bench import egress_bench

REPO_ROOT = Path(__file__).resolve().parent.parent


def _zone_where_the_local_day_differs() -> tuple[str, datetime.date]:
    """A POSIX ``TZ`` whose local date differs from the UTC date right now, and that date.

    UTC+14 is a day ahead from 10:00 UTC on; UTC-11 is a day behind until 11:00 UTC. One of
    the two always disagrees with UTC, so the test below can tell a UTC stamp from a local
    one at any hour. POSIX offsets are inverted: ``AAA-14`` means fourteen hours ahead.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    if now.hour >= 10:
        return "AAA-14", (now + datetime.timedelta(hours=14)).date()
    return "AAA+11", (now - datetime.timedelta(hours=11)).date()


class TestHarnessDatesAreTheUtcDay:
    """The ``--date`` default is what ``check_benchmark_freshness.py`` will read as today."""

    @pytest.mark.parametrize("package", ["blockrate", "toolprivbench", "harness_injection"])
    def test_the_default_is_the_utc_day_not_the_local_one(
        self, package: str, tmp_path: Path
    ) -> None:
        tz, local_day = _zone_where_the_local_day_differs()
        before = datetime.datetime.now(datetime.timezone.utc).date()
        env = {
            **os.environ,
            "TZ": tz,
            "COLUMNS": "400",  # argparse breaks long help on hyphens; keep the date whole
            "PYTHONPATH": str(REPO_ROOT),
            "AIRLOCK_AUDIT_LOG_PATH": str(tmp_path / "audit.json"),
        }
        out = subprocess.run(
            [sys.executable, "-m", f"benchmarks.{package}", "--help"],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        ).stdout
        after = datetime.datetime.now(datetime.timezone.utc).date()

        assert local_day not in (before, after), "the chosen zone must disagree with UTC"
        stamped = re.search(r"today in UTC, (\d{4}-\d{2}-\d{2})\)", out)
        assert stamped is not None, out
        assert stamped.group(1) in (before.isoformat(), after.isoformat())
        assert stamped.group(1) != local_day.isoformat()


class TestTheSandboxArmReportsOnlyABackendThatRan:
    """Detection is not execution, and Docker is not on the decorator's dispatch path."""

    @pytest.fixture
    def docker_tripwire(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def pinged(self: Any) -> bool:
            raise AssertionError("the sandbox arm pinged a Docker daemon it never dispatches to")

        from agent_airlock import sandbox_backend

        monkeypatch.setattr(sandbox_backend.DockerBackend, "is_available", pinged)

    def test_detection_names_e2b_or_nothing_and_never_pings_docker(
        self, docker_tripwire: None
    ) -> None:
        name, available, reason = sandbox_arm._detect_backend()
        assert name in (None, "e2b")
        if not available:
            assert "dispatches only to E2B" in reason
            assert "Docker backend" not in reason

    @staticmethod
    def _section(
        monkeypatch: pytest.MonkeyPatch, *, detected: bool, dispatch_runs_the_body: bool
    ) -> tuple[sandbox_arm.SandboxArmReport, str]:
        backend = ("e2b", True, "") if detected else (None, False, "no backend in this test")
        monkeypatch.setattr(sandbox_arm, "_detect_backend", lambda: backend)

        def dispatch(self: Airlock, func: Any, *args: Any, **kwargs: Any) -> Any:
            if dispatch_runs_the_body:
                return func(*args, **kwargs)
            raise SandboxExecutionError("the backend did not run the call")

        monkeypatch.setattr(Airlock, "_execute_in_sandbox", dispatch)
        arm = sandbox_arm.run_sandbox_arm()
        return arm, render_sandbox_arm_section(arm)

    def test_a_detected_backend_that_ran_nothing_is_reported_as_not_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        arm, section = self._section(monkeypatch, detected=True, dispatch_runs_the_body=False)
        assert arm.backend_available and arm.backend_executions == 0
        assert "ran on" not in section
        assert "`e2b` was detected but no call returned from it" in section

    def test_a_backend_that_ran_calls_is_reported_with_the_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        arm, section = self._section(monkeypatch, detected=True, dispatch_runs_the_body=True)
        assert arm.backend_executions == arm.policy_admitted > 0
        assert f"ran on `e2b`: {arm.backend_executions} admitted calls returned from it" in section

    def test_bodies_that_ran_without_a_detected_backend_are_not_counted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no backend detected, a body that ran ran in-process, not in a sandbox."""
        arm, section = self._section(monkeypatch, detected=False, dispatch_runs_the_body=True)
        assert arm.backend_executions == 0
        assert "_not run — no backend in this test_" in section


def _real_pytest_summary(tmp_path: Path, *, passed: int, skipped: int) -> Path:
    """Run pytest on a throwaway suite the way the docker job does, return its log."""
    lines = ["import pytest"]
    lines += [f"@pytest.mark.docker\ndef test_p{i}(): pass" for i in range(passed)]
    lines += [
        f"@pytest.mark.docker\ndef test_s{i}(): pytest.skip('image missing')"
        for i in range(skipped)
    ]
    lines.append("def test_not_docker(): pass")  # deselected, as the real run's suite is
    (tmp_path / "test_docker_like.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\nmarkers = docker: d\n", encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-m", "docker", "-v"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    log = tmp_path / "docker-tests.log"
    log.write_text(out, encoding="utf-8")
    return log


class TestTheDockerGateReadsTheSummaryLine:
    """The pattern ci.yml greps with, run by grep against real pytest output."""

    @staticmethod
    def _ci_pattern() -> str:
        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        match = re.search(r"grep -qE '([^']+)' docker-tests\.plain\.log", workflow)
        assert match is not None, "the docker job's anchored grep is gone from ci.yml"
        return match.group(1)

    @pytest.mark.skipif(shutil.which("grep") is None, reason="needs a grep binary")
    @pytest.mark.parametrize(
        ("passed", "skipped", "gate_passes"),
        [(5, 0, True), (15, 0, False), (5, 1, False)],
        ids=["five-passed", "fifteen-passed", "five-passed-one-skipped"],
    )
    def test_only_exactly_five_passed_and_nothing_skipped_passes(
        self, tmp_path: Path, passed: int, skipped: int, gate_passes: bool
    ) -> None:
        log = _real_pytest_summary(tmp_path, passed=passed, skipped=skipped)
        result = subprocess.run(["grep", "-qE", self._ci_pattern(), str(log)], check=False)
        assert (result.returncode == 0) is gate_passes, log.read_text(encoding="utf-8")


class TestEgressBenchRunsInACheckout:
    """Until 0.10.24 ``airlock egress-bench`` raised in a checkout too, not only from a wheel.

    The walker was executed from an unregistered module, and its string-annotated
    dataclasses look themselves up in ``sys.modules``; only ``make egress-bench``, which runs
    the script directly, ever worked. The dispatcher's tests stop at ``--help``.
    """

    def test_the_function_walks_the_fixtures(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert egress_bench(output_format="json") == 0
        assert capsys.readouterr().out.lstrip().startswith(("{", "["))

    def test_the_airlock_subcommand_walks_the_fixtures(self, tmp_path: Path) -> None:
        env = {**os.environ, "AIRLOCK_AUDIT_LOG_PATH": str(tmp_path / "audit.json")}
        result = subprocess.run(
            [sys.executable, "-m", "agent_airlock.cli", "egress-bench", "--format", "tap"],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        assert "Traceback" not in result.stderr
        assert re.search(r"^ok \d+ ", result.stdout, flags=re.MULTILINE)


class TestEgressBenchOutsideACheckout:
    """An installed package has neither the walker nor its fixtures: exit 2, say why."""

    def test_no_walker_exits_2_with_one_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert egress_bench(source_root=tmp_path) == 2
        err = capsys.readouterr().err.strip()
        assert len(err.splitlines()) == 1
        assert "needs a source checkout" in err
        assert "egress_bench.py" in err

    def test_a_walker_without_its_fixtures_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "scripts").mkdir()
        shutil.copy(REPO_ROOT / "scripts" / "egress_bench.py", tmp_path / "scripts")
        assert egress_bench(source_root=tmp_path) == 2
        err = capsys.readouterr().err
        assert "needs a source checkout" in err
        assert str(Path("tests") / "cves" / "fixtures") in err

    def test_an_invalid_fixture_exits_2_instead_of_a_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The walker raises on a fixture with no ``disclosed_at``; the CLI maps it to 2."""
        fixtures = tmp_path / "fixtures"
        fixtures.mkdir()
        (fixtures / "no_date.json").write_text('{"advisory_class": "x"}', encoding="utf-8")
        assert egress_bench(fixture_dir=fixtures) == 2
        assert "invalid fixture" in capsys.readouterr().err


class TestAgentDojoForceAppends:
    """``--force`` adds a block under a repeated heading; a dated block is never edited."""

    def test_force_keeps_the_first_block_and_appends_a_second(self, tmp_path: Path) -> None:
        results = tmp_path / "RESULTS.md"
        results.write_text(f"# results\n\n{_RUNS_MARKER}\n", encoding="utf-8")
        first = "### 2026-10-10 · model-a\n\nfirst run"
        second = "### 2026-10-10 · model-a\n\nsecond run"
        append_run_to_results(results, first)
        with pytest.raises(ValueError, match="append another block"):
            append_run_to_results(results, second)
        text = append_run_to_results(results, second, force=True)
        assert text.count("### 2026-10-10 · model-a") == 2
        assert "first run" in text and "second run" in text

    def test_the_help_says_append(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit):
            agentdojo_main(["--help"])
        help_text = " ".join(capsys.readouterr().out.split())
        assert "Append another dated run block" in help_text
        assert "Replace" not in help_text
