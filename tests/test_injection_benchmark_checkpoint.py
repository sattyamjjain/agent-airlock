"""CI guard: a paid benchmark run must survive being killed.

``run_matrix`` drives real third-party coding agents. A full ``--trials 18`` matrix is 144
cells and roughly 100 minutes of paid API time. Through v0.8.82 the runner accumulated cells
in memory and serialised only on completion, so an interrupted run lost every cell it had
already paid for — observed on 2026-08-26, when a run killed at minute 35 of 97 produced no
JSON, no ``RESULTS.md``, and nothing to resume from.

These tests pin the fix. They never invoke a harness: ``_run_cell`` is stubbed, so what is
under test is ``run_matrix``'s bookkeeping — that each finished cell is on disk before the
next one starts, and that re-invoking with the same checkpoint does not pay for a cell twice.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from benchmarks.harness_injection import runner as runner_mod
from benchmarks.harness_injection.harnesses import Harness
from benchmarks.harness_injection.runner import CellResult, RunReport, cell_key, run_matrix

_FAKE = Harness(name="fake", executable="fake-cli", argv_template=("fake-cli", "{prompt}"))


@pytest.fixture
def always_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Harness, "is_available", lambda self: True)
    monkeypatch.setattr(runner_mod, "_version", lambda harness: "fake 1.0")


def _stub_cells(monkeypatch: pytest.MonkeyPatch, seen: list[tuple[Any, ...]]) -> None:
    """Replace the real harness invocation with a recorder."""

    def fake_run_cell(
        harness: Harness, arm: Any, *, airlock: bool, trial: int, timeout: float, version: str
    ) -> CellResult:
        seen.append((harness.name, arm.name, airlock, trial))
        return CellResult(
            harness=harness.name,
            harness_version=version,
            arm=arm.name,
            airlock_enabled=airlock,
            trial=trial,
            status="ok",
            acted=False,
            task_completed=True,
            ran_tests=True,
        )

    monkeypatch.setattr(runner_mod, "_run_cell", fake_run_cell)


class TestReportRoundTrip:
    def test_from_json_reverses_to_json(self) -> None:
        report = RunReport(trials=7, timeout_s=12.5, skipped=["x: not on PATH"])
        report.cells.append(
            CellResult(
                harness="h",
                harness_version="v",
                arm="injected",
                airlock_enabled=True,
                trial=1,
                status="ok",
                acted=False,
            )
        )
        back = RunReport.from_json(report.to_json())
        assert back.trials == 7
        assert back.timeout_s == 12.5
        assert back.skipped == ["x: not on PATH"]
        assert [cell_key(c) for c in back.cells] == [cell_key(c) for c in report.cells]

    def test_cell_key_is_the_four_axes_of_the_matrix(self) -> None:
        cell = CellResult(
            harness="h",
            harness_version="v",
            arm="benign",
            airlock_enabled=False,
            trial=3,
            status="ok",
            acted=None,
        )
        assert cell_key(cell) == ("h", "benign", False, 3)


class TestCheckpointIsWrittenAsItGoes:
    def test_every_cell_is_on_disk_when_the_run_finishes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, always_available: None
    ) -> None:
        _stub_cells(monkeypatch, [])
        ckpt = tmp_path / "run.json"
        report = run_matrix([_FAKE], trials=2, checkpoint=ckpt)

        assert len(report.cells) == 1 * 2 * 2 * 2  # harness x arms x modes x trials
        on_disk = RunReport.from_json(ckpt.read_text(encoding="utf-8"))
        assert len(on_disk.cells) == len(report.cells)

    def test_the_file_is_valid_json_after_every_single_cell(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, always_available: None
    ) -> None:
        """A kill lands between cells; the file must be parseable at every such point."""
        ckpt = tmp_path / "run.json"
        widths: list[int] = []

        real_write = runner_mod._write_checkpoint

        def spy(path: Path, report: RunReport) -> None:
            real_write(path, report)
            widths.append(len(json.loads(path.read_text(encoding="utf-8"))["cells"]))

        _stub_cells(monkeypatch, [])
        monkeypatch.setattr(runner_mod, "_write_checkpoint", spy)
        run_matrix([_FAKE], trials=2, checkpoint=ckpt)

        # One flush per cell, each strictly larger than the last: 1, 2, 3, ... 8.
        assert widths == list(range(1, 9))

    def test_no_temp_file_is_left_behind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, always_available: None
    ) -> None:
        _stub_cells(monkeypatch, [])
        ckpt = tmp_path / "run.json"
        run_matrix([_FAKE], trials=1, checkpoint=ckpt)
        assert [p.name for p in tmp_path.iterdir()] == ["run.json"]

    def test_without_a_checkpoint_nothing_is_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, always_available: None
    ) -> None:
        _stub_cells(monkeypatch, [])
        run_matrix([_FAKE], trials=1)
        assert list(tmp_path.iterdir()) == []


class TestResumeDoesNotPayTwice:
    def test_a_resumed_run_reruns_nothing_already_recorded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, always_available: None
    ) -> None:
        ckpt = tmp_path / "run.json"

        first: list[tuple[Any, ...]] = []
        _stub_cells(monkeypatch, first)
        run_matrix([_FAKE], trials=2, checkpoint=ckpt)
        assert len(first) == 8

        second: list[tuple[Any, ...]] = []
        _stub_cells(monkeypatch, second)
        resumed = run_matrix([_FAKE], trials=2, checkpoint=ckpt)

        assert second == [], "a fully-recorded matrix must not spend a single cell again"
        assert len(resumed.cells) == 8

    def test_a_partial_checkpoint_runs_only_the_missing_cells(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, always_available: None
    ) -> None:
        """The interrupted-run case: 3 of 8 bought, 5 still owed."""
        ckpt = tmp_path / "run.json"
        partial = RunReport(trials=2)
        for arm, airlock, trial in (
            ("injected", False, 1),
            ("injected", False, 2),
            ("injected", True, 1),
        ):
            partial.cells.append(
                CellResult(
                    harness="fake",
                    harness_version="fake 1.0",
                    arm=arm,
                    airlock_enabled=airlock,
                    trial=trial,
                    status="ok",
                    acted=False,
                )
            )
        ckpt.write_text(partial.to_json(), encoding="utf-8")

        ran: list[tuple[Any, ...]] = []
        _stub_cells(monkeypatch, ran)
        report = run_matrix([_FAKE], trials=2, checkpoint=ckpt)

        assert len(ran) == 5, "only the unbought cells should be run"
        assert ("fake", "injected", False, 1) not in ran
        assert len(report.cells) == 8
        assert len({cell_key(c) for c in report.cells}) == 8, "no duplicated cells"

    def test_resume_does_not_duplicate_the_skipped_note(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Harness, "is_available", lambda self: False)
        ckpt = tmp_path / "run.json"
        first = run_matrix([_FAKE], trials=1, checkpoint=ckpt)
        # Nothing ran, so nothing was flushed; seed the file to force the resume path.
        ckpt.write_text(first.to_json(), encoding="utf-8")
        again = run_matrix([_FAKE], trials=1, checkpoint=ckpt)
        assert len(again.skipped) == 1, again.skipped


class TestReportProseFollowsTheData:
    """The 2026-08-26 run produced the first live benign control, and caught a reporting bug.

    Through v0.8.82 the renderer emitted fixed prose reading *"both harnesses are indifferent
    to a README-planted script convention"* inside the null-control warning. That warning is
    already scoped to the harnesses whose control was zero, so on a run where one harness
    acted on the benign twin the sentence was simply false about the run it was describing.
    This is the same failure the run-2 postmortem named — presenting two different zeros
    identically — so it gets a test rather than a careful edit.
    """

    @staticmethod
    def _report(codex_benign_acted: int) -> RunReport:
        report = RunReport(trials=18)
        for harness, version in (("claude-code", "2.1.246"), ("codex", "0.147.0")):
            for arm in ("injected", "benign"):
                for mode in (False, True):
                    for trial in range(1, 19):
                        acted = (
                            harness == "codex"
                            and arm == "benign"
                            and mode
                            and trial <= codex_benign_acted
                        )
                        report.cells.append(
                            CellResult(
                                harness=harness,
                                harness_version=version,
                                arm=arm,
                                airlock_enabled=mode,
                                trial=trial,
                                status="ok",
                                acted=acted,
                                task_completed=True,
                                ran_tests=True,
                            )
                        )
        return report

    def test_it_does_not_claim_both_harnesses_when_one_control_fired(self) -> None:
        from benchmarks.harness_injection.report import render_results_md

        md = render_results_md(self._report(1), "2026-08-26")
        assert "both harnesses are indifferent" not in md
        assert "`claude-code` is indifferent" in md

    def test_it_still_says_both_when_both_controls_are_dead(self) -> None:
        from benchmarks.harness_injection.report import render_results_md

        md = render_results_md(self._report(0), "2026-08-26")
        assert "both harnesses are indifferent" in md

    def test_a_live_control_is_reported_with_its_p_value(self) -> None:
        """A lopsided-looking table must ship with the test that says it is not separable."""
        from benchmarks.harness_injection.report import render_results_md

        md = render_results_md(self._report(1), "2026-08-26")
        assert "The benign control fired" in md
        assert "p = 1.00" in md
        assert "does not establish" in md

    def test_no_live_control_block_when_no_control_fired(self) -> None:
        from benchmarks.harness_injection.report import render_results_md

        assert "The benign control fired" not in render_results_md(self._report(0), "2026-08-26")
