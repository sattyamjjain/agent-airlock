"""A ``--model`` pass sends nothing without ``--run``, and ``--run`` refuses an unsafe setup.

The paid path costs real API credit, so its gates are pinned where CI runs: a budget and a
new, empty ``--logdir`` outside the repository are required (agentdojo's trace cache ignores
the policy and the LLM settings, so a reused directory would silently replay stale
trajectories), unpriced models and pre-5.x Claude ids are refused, and ``--resume`` only
continues a pass whose recorded settings match. The two CLI tests that plan a real pass
need ``agentdojo`` and skip without the ``[bench]`` extra; nothing here calls a model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from benchmarks.agentdojo import run as adrun
from benchmarks.agentdojo.run import (
    CLAUDE_TOKENIZER_FACTOR,
    INPUT_TOKENS_PER_CALL,
    OUTPUT_TOKENS_PER_CALL,
    PassPlan,
    TaskSelection,
    paid_run_problems,
    prepare_pass_dir,
)


def _plan(
    model: str = "claude-haiku-5-5",
    *,
    effort: str | None = "medium",
    users: int = 14,
    injections: int = 3,
    suites: int = 4,
) -> PassPlan:
    selections = [
        TaskSelection(
            suite=f"suite{i}",
            user_ids=[f"user_task_{j}" for j in range(users)],
            injection_ids=[f"injection_task_{k}" for k in range(injections)],
        )
        for i in range(suites)
    ]
    claude5 = adrun._is_claude5(model)
    return PassPlan(
        model_id=model,
        selections=selections,
        max_user_tasks=users,
        max_injection_tasks=injections,
        effort=effort if claude5 else None,
        max_tokens=16_000 if claude5 else None,
    )


class TestPassPlan:
    def test_the_default_caps_give_168_pairs_per_arm(self) -> None:
        plan = _plan()
        assert plan.pairs_per_arm == 168
        assert plan.benign_per_arm == 56
        assert plan.episodes == 2 * (56 + 168)

    def test_the_claude_estimate_uses_the_exact_snapshot_rates(self) -> None:
        plan = _plan(users=1, injections=1, suites=1)  # 4 episodes
        low, high = plan.cost_usd() or (None, None)
        tokens_in = INPUT_TOKENS_PER_CALL * CLAUDE_TOKENIZER_FACTOR
        calls_lo, calls_hi = plan.calls
        # Haiku 5.5: $0.10 in / $0.50 out; the high end prices input as a 1.25x cache write.
        assert low == pytest.approx(
            calls_lo * (tokens_in * 0.10 + OUTPUT_TOKENS_PER_CALL[0] * 0.50) / 1e6
        )
        assert high == pytest.approx(
            calls_hi * (tokens_in * 0.125 + OUTPUT_TOKENS_PER_CALL[1] * 0.50) / 1e6
        )

    def test_an_unpriced_model_has_no_estimate(self) -> None:
        assert _plan("some-lab/unpriced-model-x").cost_usd() is None

    def test_logdir_name_is_per_model_and_effort(self) -> None:
        assert _plan().logdir_name() == "claude-haiku-5-5__medium"
        assert _plan("gpt-4o-mini-2024-07-18").logdir_name() == "gpt-4o-mini-2024-07-18__default"


class TestPaidRunProblems:
    def test_a_safe_setup_has_no_problems(self, tmp_path: Path) -> None:
        assert (
            paid_run_problems([_plan()], budget_usd=10.0, logdir=tmp_path / "new", resume=False)
            == []
        )

    def test_budget_and_logdir_are_required(self) -> None:
        problems = paid_run_problems([_plan()], budget_usd=None, logdir=None, resume=False)
        assert any("--budget-usd" in p for p in problems)
        assert any("--logdir" in p and "stale" in p for p in problems)

    def test_a_logdir_inside_the_repository_is_refused(self) -> None:
        problems = paid_run_problems(
            [_plan()], budget_usd=10.0, logdir=adrun.REPO_ROOT / "agentdojo-logs", resume=False
        )
        assert any("inside the repository" in p for p in problems)

    def test_a_non_empty_logdir_is_refused_without_resume(self, tmp_path: Path) -> None:
        (tmp_path / "stale.json").write_text("{}")
        problems = paid_run_problems([_plan()], budget_usd=10.0, logdir=tmp_path, resume=False)
        assert any("not empty" in p for p in problems)
        assert paid_run_problems([_plan()], budget_usd=10.0, logdir=tmp_path, resume=True) == []

    def test_resume_needs_an_existing_logdir(self, tmp_path: Path) -> None:
        problems = paid_run_problems(
            [_plan()], budget_usd=10.0, logdir=tmp_path / "missing", resume=True
        )
        assert any("does not exist" in p for p in problems)

    def test_a_pre_5_claude_id_is_refused_on_the_1x_sdk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import benchmarks._claude.client as client_mod

        monkeypatch.setattr(client_mod, "sdk_version", lambda: "1.13.0")
        problems = paid_run_problems(
            [_plan("claude-haiku-4-5-20251001")],
            budget_usd=10.0,
            logdir=tmp_path / "new",
            resume=False,
        )
        assert any("passes temperature" in p for p in problems)

    def test_an_unpriced_model_is_refused(self, tmp_path: Path) -> None:
        problems = paid_run_problems(
            [_plan("some-lab/unpriced-model-x")],
            budget_usd=10.0,
            logdir=tmp_path / "new",
            resume=False,
        )
        assert any("no list price" in p for p in problems)

    def test_a_claude_5_pass_needs_a_pinned_effort(self, tmp_path: Path) -> None:
        problems = paid_run_problems(
            [_plan("claude-opus-5", effort=None)],
            budget_usd=500.0,
            logdir=tmp_path / "new",
            resume=False,
        )
        assert any("no pinned effort" in p for p in problems)

    def test_a_budget_below_the_low_estimate_is_refused(self, tmp_path: Path) -> None:
        problems = paid_run_problems(
            [_plan("claude-sonnet-5-5", effort="high")],
            budget_usd=1.0,
            logdir=tmp_path / "new",
            resume=False,
        )
        assert any("below the low estimate" in p for p in problems)


class TestPassDir:
    _SETTINGS: dict[str, Any] = {
        "model": "claude-haiku-5-5",
        "effort": "medium",
        "max_tokens": 16000,
        "thinking": "adaptive",
        "attack": "tool_knowledge",
        "benchmark_version": "v1.2.1",
        "suites": ["banking"],
        "max_user_tasks": 14,
        "max_injection_tasks": 3,
        "defense": "x",
        "agentdojo_version": "0.1.35",
    }

    def test_a_fresh_dir_gets_a_manifest(self, tmp_path: Path) -> None:
        pass_dir = tmp_path / "claude-haiku-5-5__medium"
        prepare_pass_dir(pass_dir, dict(self._SETTINGS), resume=False)
        manifest = json.loads((pass_dir / adrun.MANIFEST_NAME).read_text())
        assert manifest["settings"] == self._SETTINGS
        assert manifest["status"] == "planned"

    def test_resume_accepts_matching_settings_and_logs_the_resume(self, tmp_path: Path) -> None:
        pass_dir = tmp_path / "p"
        prepare_pass_dir(pass_dir, dict(self._SETTINGS), resume=False)
        manifest = prepare_pass_dir(pass_dir, dict(self._SETTINGS), resume=True)
        assert len(manifest["resumes"]) == 1

    def test_resume_refuses_different_settings(self, tmp_path: Path) -> None:
        pass_dir = tmp_path / "p"
        prepare_pass_dir(pass_dir, dict(self._SETTINGS), resume=False)
        changed = {**self._SETTINGS, "effort": "high"}
        with pytest.raises(ValueError, match="different settings"):
            prepare_pass_dir(pass_dir, changed, resume=True)

    def test_an_occupied_dir_is_refused_without_resume(self, tmp_path: Path) -> None:
        pass_dir = tmp_path / "p"
        prepare_pass_dir(pass_dir, dict(self._SETTINGS), resume=False)
        with pytest.raises(ValueError, match="not empty"):
            prepare_pass_dir(pass_dir, dict(self._SETTINGS), resume=False)

    def test_resume_refuses_a_dir_that_was_never_a_pass(self, tmp_path: Path) -> None:
        pass_dir = tmp_path / "p"
        pass_dir.mkdir()
        (pass_dir / "something.json").write_text("{}")
        with pytest.raises(ValueError, match="was not a pass dir"):
            prepare_pass_dir(pass_dir, dict(self._SETTINGS), resume=True)


class TestCli:
    @pytest.mark.parametrize(
        "argv",
        [
            ["--run"],
            ["--resume", "--model", "claude-haiku-5-5"],
            ["--model", "claude-haiku-5-5", "--max-tokens", "0"],
        ],
    )
    def test_inconsistent_flags_exit_before_any_work(self, argv: list[str]) -> None:
        with pytest.raises(SystemExit) as exc:
            adrun.main(argv)
        assert exc.value.code == 2

    @staticmethod
    def _no_spend(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
        """Point every spend path at a tripwire and the ledger at ``tmp_path``."""
        import benchmarks._claude.client as client_mod

        pytest.importorskip("agentdojo", reason="agentdojo is a bench-only extra")
        data = tmp_path / "bench-data"
        monkeypatch.setenv("AIRLOCK_BENCH_DATA", str(data))
        monkeypatch.delenv("AIRLOCK_BENCH_LEDGER", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        def tripwire(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("a dry run reached a spend path")

        monkeypatch.setattr(client_mod, "make_client", tripwire)
        monkeypatch.setattr(adrun, "execute_model", tripwire)
        monkeypatch.setattr(
            adrun,
            "run_deterministic",
            lambda: adrun.DeterministicReport(
                suites=[adrun.SuiteCoverage("banking", pairs=1, blocked_pairs=1, all_pairs=1)]
            ),
        )
        return data

    def test_a_model_pass_without_run_is_a_dry_run_that_spends_nothing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        data = self._no_spend(monkeypatch, tmp_path)
        logdir = tmp_path / "logs"
        code = adrun.main(
            [
                "--model",
                "claude-haiku-5-5",
                "--suites",
                "banking",
                "--max-user-tasks",
                "2",
                "--logdir",
                str(logdir),
            ]
        )
        err = capsys.readouterr().err
        assert code == 0
        assert "dry run: nothing was sent and nothing was spent" in err
        assert "model-in-the-loop plan: claude-haiku-5-5" in err
        assert "estimated cost: $" in err
        assert not data.exists(), "a dry run wrote to the bench data dir (ledger)"
        assert not logdir.exists(), "a dry run created the logdir"

    def test_run_without_a_budget_is_refused_before_any_spend(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        data = self._no_spend(monkeypatch, tmp_path)
        code = adrun.main(
            [
                "--model",
                "claude-haiku-5-5",
                "--suites",
                "banking",
                "--max-user-tasks",
                "2",
                "--run",
                "--logdir",
                str(tmp_path / "logs"),
            ]
        )
        assert code == 2
        assert "--run needs --budget-usd" in capsys.readouterr().err
        assert not data.exists()
