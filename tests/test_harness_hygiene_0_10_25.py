"""0.10.25: a paid harness run cannot inherit the Claude Code session it was started from.

The harness runner copied ``os.environ`` into every CLI it drove. Started from inside a
Claude Code session, that handed each harness the session's ``ANTHROPIC_*`` and
``CLAUDECODE`` / ``CLAUDE_CODE_*`` variables: an ``ANTHROPIC_API_KEY`` bills the run to API
credit instead of the CLI's subscription login, and the session markers tell the child it
is nested. Nothing recorded how a cell was authenticated or which model actually ran, and
the published Reproduce line had no ``--run``, so it reproduced nothing.

These tests drive ``sh`` stubs, never a real harness.
"""

from __future__ import annotations

import dataclasses
import json
import re
import shlex
from pathlib import Path
from typing import Any

import pytest
from benchmarks.harness_injection import __main__ as cli
from benchmarks.harness_injection.fixture import ARMS
from benchmarks.harness_injection.harnesses import (
    HARNESSES,
    SESSION_ENV_KEEP,
    SESSION_ENV_REMOVE,
    Harness,
    harness_by_name,
    harness_env,
    removed_env_names,
)
from benchmarks.harness_injection.report import render_results_md, reproduce_command
from benchmarks.harness_injection.runner import (
    CellResult,
    RunReport,
    _observed,
    auth_matches,
    parse_auth,
    run_matrix,
)

ROOT = Path(__file__).resolve().parents[1]
ONE_ARM = (ARMS[0],)
SESSION_VARS = {
    "ANTHROPIC_API_KEY": "sk-ant-test-not-a-real-key",
    "ANTHROPIC_BASE_URL": "https://proxy.invalid",
    "CLAUDECODE": "1",
    "CLAUDE_CODE_ENTRYPOINT": "cli",
    "CLAUDE_EFFORT": "high",
    "CLAUDE_PID": "4242",
    "ENABLE_TOOL_SEARCH": "1",
    "ENABLE_LSP_TOOL": "1",
    "MAX_THINKING_TOKENS": "1000",
}
MAX_LOGIN = json.dumps(
    {
        "loggedIn": True,
        "authMethod": "claude.ai",
        "subscriptionType": "max",
        "email": "someone@example.com",
        "orgName": "Someone's Org",
        "orgId": "org-123",
    }
)


def _stub(name: str, script: str = "true", **fields: Any) -> Harness:
    return Harness(name=name, executable="sh", argv_template=("sh", "-c", script), **fields)


def _printer(text: str) -> tuple[str, ...]:
    return ("sh", "-c", f"printf '%s' {shlex.quote(text)}")


def _run(*harnesses: Harness, **kwargs: Any) -> RunReport:
    return run_matrix(
        list(harnesses), trials=1, timeout=60, airlock_modes=(False,), arms=ONE_ARM, **kwargs
    )


def _env_file_names(path: Path) -> set[str]:
    return {
        line.split("=", 1)[0]
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line
    }


@pytest.fixture
def session_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in SESSION_VARS.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-test-token")


class TestTheSessionEnvironmentIsRemoved:
    def test_the_removal_list(self) -> None:
        assert SESSION_ENV_REMOVE == (
            "ANTHROPIC_*",
            "CLAUDECODE",
            "CLAUDE_CODE_*",
            "CLAUDE_EFFORT",
            "CLAUDE_PID",
            "ENABLE_TOOL_SEARCH",
            "ENABLE_LSP_TOOL",
            "MAX_THINKING_TOKENS",
        )
        assert SESSION_ENV_KEEP == ("CLAUDE_CODE_OAUTH_TOKEN",)

    def test_every_harness_applies_it(self) -> None:
        assert all(harness.env_remove == SESSION_ENV_REMOVE for harness in HARNESSES)

    def test_harness_env(self) -> None:
        base = {**SESSION_VARS, "CLAUDE_CODE_OAUTH_TOKEN": "t", "PATH": "/bin", "HOME": "/h"}
        env = harness_env(_stub("s", env={"CLAUDE_CONFIG_DIR": "/cfg"}), base)
        assert env == {
            "CLAUDE_CODE_OAUTH_TOKEN": "t",
            "PATH": "/bin",
            "HOME": "/h",
            "CLAUDE_CONFIG_DIR": "/cfg",
        }

    def test_removed_names_are_names(self) -> None:
        names = removed_env_names(_stub("s"), {**SESSION_VARS, "PATH": "/bin"})
        assert names == sorted(SESSION_VARS)

    def test_a_cell_never_sees_them(self, session_env: None, tmp_path: Path) -> None:
        out = tmp_path / "cell.env"
        report = _run(_stub("dump", f"env > {shlex.quote(str(out))}"))
        assert report.cells and report.cells[0].status == "ok"
        names = _env_file_names(out)
        assert not names & set(SESSION_VARS)
        assert "CLAUDE_CODE_OAUTH_TOKEN" in names
        assert "AIRLOCK_ENABLED" in names

    def test_the_version_and_auth_commands_never_see_them(
        self, session_env: None, tmp_path: Path
    ) -> None:
        version_out, auth_out = tmp_path / "version.env", tmp_path / "auth.env"
        harness = _stub(
            "probe",
            version_argv=("sh", "-c", f"env > {shlex.quote(str(version_out))}; echo v1"),
            auth_argv=("sh", "-c", f"env > {shlex.quote(str(auth_out))}; printf '{{}}'"),
        )
        _run(harness)
        for path in (version_out, auth_out):
            assert not _env_file_names(path) & set(SESSION_VARS), path.name

    def test_the_report_lists_names_never_values(self, session_env: None) -> None:
        report = _run(_stub("plain"))
        assert "ANTHROPIC_API_KEY" in report.env_removed
        md = render_results_md(report, "2026-10-12")
        assert "`ANTHROPIC_API_KEY`" in md
        assert SESSION_VARS["ANTHROPIC_API_KEY"] not in md
        assert SESSION_VARS["ANTHROPIC_API_KEY"] not in report.to_json()


class TestAuthIsRecordedWithoutTheAccount:
    def test_method_and_plan_only(self) -> None:
        assert parse_auth(MAX_LOGIN) == "claude.ai/max"

    @pytest.mark.parametrize(
        ("document", "expected"),
        [
            ('{"authMethod": "claude.ai"}', "claude.ai"),
            ('{"loggedIn": true, "authMethod": "api_key", "apiProvider": "firstParty"}', "api_key"),
            ('{"loggedIn": false}', "logged-out"),
            ('{"authMethod": "someone@example.com"}', "unknown"),
            ('{"authMethod": "claude.ai", "subscriptionType": "a b"}', "claude.ai"),
            ('{"email": "someone@example.com"}', "unknown"),
            ("[1, 2]", "unknown"),
            ("not json", "unknown"),
            ("", "unknown"),
        ],
    )
    def test_anything_else(self, document: str, expected: str) -> None:
        assert parse_auth(document) == expected

    def test_an_api_key_beside_the_login_no_longer_matches(self) -> None:
        document = json.loads(MAX_LOGIN) | {"apiKeySource": "apiKeyHelper"}
        auth = parse_auth(json.dumps(document))
        assert auth == "claude.ai+apikey/max"
        assert not auth_matches(auth, "claude.ai")

    def test_auth_matches_the_method_whatever_the_plan(self) -> None:
        assert auth_matches("claude.ai/max", "claude.ai")
        assert auth_matches("claude.ai", "claude.ai")
        assert not auth_matches("api-key", "claude.ai")
        assert not auth_matches("claude.ai.evil/max", "claude.ai")
        assert not auth_matches("claude.ai/max", "")

    def test_every_cell_records_it_and_the_report_shows_it(self) -> None:
        report = _run(_stub("logged", auth_argv=_printer(MAX_LOGIN), expected_auth="claude.ai"))
        assert {cell.auth for cell in report.cells} == {"claude.ai/max"}
        md = render_results_md(report, "2026-10-12")
        assert "auth `claude.ai/max`" in md
        for private in ("someone@example.com", "Someone's Org", "org-123"):
            assert private not in md
            assert private not in report.to_json()

    def test_claude_code_asks_the_cli(self) -> None:
        claude = harness_by_name("claude-code")
        assert claude.auth_argv == ("claude", "auth", "status", "--json")
        assert claude.expected_auth == "claude.ai"
        assert claude.requires_model and claude.stdout_json


class TestTheAuthGateFailsClosed:
    def test_an_api_key_login_is_skipped(self) -> None:
        harness = _stub(
            "keyed", auth_argv=_printer('{"authMethod": "api-key"}'), expected_auth="claude.ai"
        )
        report = _run(harness)
        assert report.cells == []
        assert report.skipped and "--allow-any-auth" in report.skipped[0]
        assert "'api-key'" in report.skipped[0]

    def test_an_auth_command_that_fails_is_skipped(self) -> None:
        report = _run(_stub("broken", auth_argv=("sh", "-c", "exit 1"), expected_auth="claude.ai"))
        assert report.cells == []
        assert "'unknown'" in report.skipped[0]

    def test_the_override_runs_it(self) -> None:
        harness = _stub(
            "keyed", auth_argv=_printer('{"authMethod": "api-key"}'), expected_auth="claude.ai"
        )
        report = _run(harness, allow_any_auth=True)
        assert {cell.auth for cell in report.cells} == {"api-key"}

    def test_the_expected_login_runs(self) -> None:
        report = _run(_stub("logged", auth_argv=_printer(MAX_LOGIN), expected_auth="claude.ai"))
        assert report.cells and report.skipped == []


class TestResumeAndAuth:
    @staticmethod
    def _checkpoint(path: Path, harness: str, auth: str | None, arm: str = ARMS[0].name) -> None:
        cell = dataclasses.asdict(
            CellResult(
                harness=harness,
                harness_version="1",
                arm=arm,
                airlock_enabled=False,
                trial=1,
                status="ok",
                acted=False,
                auth=auth or "",
                detail="from the checkpoint",
            )
        )
        if auth is None:  # a checkpoint written before 0.10.25
            for key in ("auth", "models_observed", "cost_usd", "config_isolated"):
                del cell[key]
        path.write_text(json.dumps({"trials": 1, "cells": [cell]}), encoding="utf-8")

    def test_a_cell_under_another_auth_is_run_again(self, tmp_path: Path) -> None:
        ckpt = tmp_path / "ckpt.json"
        self._checkpoint(ckpt, "logged", "claude.ai/pro")
        report = _run(
            _stub("logged", auth_argv=_printer(MAX_LOGIN), expected_auth="claude.ai"),
            checkpoint=ckpt,
        )
        assert [(c.auth, c.detail) for c in report.cells] == [("claude.ai/max", "")]

    def test_a_cell_under_the_same_auth_is_kept(self, tmp_path: Path) -> None:
        ckpt = tmp_path / "ckpt.json"
        self._checkpoint(ckpt, "logged", "claude.ai/max")
        report = _run(
            _stub("logged", auth_argv=_printer(MAX_LOGIN), expected_auth="claude.ai"),
            checkpoint=ckpt,
        )
        assert [c.detail for c in report.cells] == ["from the checkpoint"]

    def test_an_old_checkpoint_still_loads(self, tmp_path: Path) -> None:
        ckpt = tmp_path / "ckpt.json"
        self._checkpoint(ckpt, "plain", None)
        loaded = RunReport.from_json(ckpt.read_text(encoding="utf-8"))
        assert loaded.cells[0].auth == "" and loaded.env_removed == []
        report = _run(_stub("plain"), checkpoint=ckpt)  # no auth command: auth "" matches
        assert [c.detail for c in report.cells] == ["from the checkpoint"]

    def test_a_skipped_harness_keeps_its_paid_cells(self, tmp_path: Path) -> None:
        ckpt = tmp_path / "ckpt.json"
        self._checkpoint(ckpt, "keyed", "claude.ai/max")
        harness = _stub(
            "keyed", auth_argv=_printer('{"authMethod": "api-key"}'), expected_auth="claude.ai"
        )
        report = _run(harness, _stub("other"), checkpoint=ckpt)
        assert [c.detail for c in report.cells if c.harness == "keyed"] == ["from the checkpoint"]
        on_disk = RunReport.from_json(ckpt.read_text(encoding="utf-8"))
        assert any(c.harness == "keyed" for c in on_disk.cells)


class TestTheJsonResult:
    def test_models_and_cost(self) -> None:
        stdout = json.dumps(
            {"type": "result", "total_cost_usd": 0.12, "modelUsage": {"m-b": {}, "m-a": {}}}
        )
        assert _observed(stdout) == ("m-a,m-b", 0.12)

    def test_noise_before_the_result(self) -> None:
        stdout = 'warming up\n{"partial": true\n' + json.dumps(
            {"total_cost_usd": 1, "modelUsage": {"m": {}}}
        )
        assert _observed(stdout) == ("m", 1.0)

    @pytest.mark.parametrize(
        "stdout", ["", "plain text", "[1]", '{"total_cost_usd": true}', '{"modelUsage": 3}']
    )
    def test_anything_else_records_nothing(self, stdout: str) -> None:
        models, cost = _observed(stdout)
        assert models == "" and cost is None

    def test_a_cell_records_them(self) -> None:
        result = json.dumps({"total_cost_usd": 0.5, "modelUsage": {"claude-haiku-5-5": {}}})
        report = _run(_stub("jsonish", f"printf '%s' {shlex.quote(result)}", stdout_json=True))
        cell = report.cells[0]
        assert (cell.models_observed, cell.cost_usd) == ("claude-haiku-5-5", 0.5)
        assert "ran `claude-haiku-5-5`" in render_results_md(report, "2026-10-12")

    def test_claude_code_asks_for_json_without_moving_the_model_flag(self) -> None:
        argv = harness_by_name("claude-code").argv("P", "m1")
        assert argv[:5] == ["claude", "-p", "--model", "m1", "P"]
        assert argv[-2:] == ["--output-format", "json"]


def _reproduce_args(line: str) -> list[str]:
    prefix = "python -m benchmarks.harness_injection "
    assert line.startswith(prefix), line
    return shlex.split(line[len(prefix) :].replace("<DIR>", "/tmp/claude-config"))


class TestTheReproduceLine:
    @staticmethod
    def _report(**cell_fields: Any) -> RunReport:
        report = RunReport(trials=18)
        report.cells.append(
            CellResult(
                harness="claude-code",
                harness_version="2",
                arm="injected",
                airlock_enabled=False,
                trial=1,
                status="ok",
                acted=False,
                **cell_fields,
            )
        )
        return report

    def test_it_runs_and_resumes(self) -> None:
        line = reproduce_command(self._report(model="claude-haiku-5-5"))
        assert line == (
            "python -m benchmarks.harness_injection --run --trials 18 --write "
            "--checkpoint ckpt.json --model claude-code=claude-haiku-5-5"
        )
        args = cli.build_parser().parse_args(_reproduce_args(line))
        assert args.run and args.write and args.trials == 18
        assert args.model == ["claude-code=claude-haiku-5-5"]

    def test_an_isolated_config_is_part_of_it(self) -> None:
        line = reproduce_command(self._report(model="m", config_isolated=True))
        assert line.endswith(" --claude-config-dir <DIR>")
        args = cli.build_parser().parse_args(_reproduce_args(line))
        assert args.claude_config_dir == Path("/tmp/claude-config")

    def test_the_rendered_file_carries_it(self) -> None:
        md = render_results_md(self._report(model="m"), "2026-10-12")
        assert reproduce_command(self._report(model="m")) in md

    def test_the_shipped_results_line(self) -> None:
        md = (ROOT / "benchmarks" / "harness_injection" / "RESULTS.md").read_text(encoding="utf-8")
        line = re.search(r"```bash\n(python -m benchmarks\.harness_injection [^\n]+)\n```", md)
        assert line, "no Reproduce line in RESULTS.md"
        assert " --run " in line.group(1)
        cli.build_parser().parse_args(_reproduce_args(line.group(1)))
        assert (
            "claude-code ran its CLI default; this run recorded neither its model nor its auth"
            in md
        )

    def test_the_docs_page_line(self) -> None:
        doc = (ROOT / "docs" / "benchmarks" / "injection-multi-harness.md").read_text(
            encoding="utf-8"
        )
        line = re.search(r"\*\*Reproduce:\*\* `([^`]+)`", doc)
        assert line, "no Reproduce line in injection-multi-harness.md"
        assert " --run " in line.group(1)
        cli.build_parser().parse_args(_reproduce_args(line.group(1)))


class TestTheCli:
    @pytest.fixture
    def all_available(self, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
        monkeypatch.setattr(Harness, "is_available", lambda self: True)
        calls: list[dict[str, Any]] = []

        def fake_run_matrix(harnesses: Any, **kwargs: Any) -> RunReport:
            calls.append({"harnesses": list(harnesses), **kwargs})
            return RunReport()

        monkeypatch.setattr(cli, "run_matrix", fake_run_matrix)
        return calls

    def test_run_refuses_an_unpinned_claude_code(self, all_available: list) -> None:
        with pytest.raises(SystemExit) as exc:
            cli.main(["--run", "--harness", "claude-code"])
        assert exc.value.code == 2
        assert all_available == []

    def test_run_refuses_when_claude_code_is_among_the_available(self, all_available: list) -> None:
        with pytest.raises(SystemExit):
            cli.main(["--run", "--model", "codex=gpt-6-astra"])
        assert all_available == []

    def test_a_pinned_run_goes_ahead(self, all_available: list) -> None:
        assert cli.main(["--run", "--harness", "claude-code", "--model", "claude-code=m"]) == 0
        assert all_available[0]["models"] == {"claude-code": "m"}
        assert all_available[0]["allow_any_auth"] is False

    def test_the_auth_override_reaches_the_runner(self, all_available: list) -> None:
        cli.main(["--run", "--harness", "codex", "--allow-any-auth"])
        assert all_available[0]["allow_any_auth"] is True

    def test_the_config_dir_reaches_claude_code_only(
        self, all_available: list, tmp_path: Path
    ) -> None:
        cli.main(
            [
                "--run",
                "--harness",
                "claude-code",
                "--harness",
                "codex",
                "--model",
                "claude-code=m",
                "--claude-config-dir",
                str(tmp_path),
            ]
        )
        envs = {h.name: h.env for h in all_available[0]["harnesses"]}
        assert envs["claude-code"] == {"CLAUDE_CONFIG_DIR": str(tmp_path)}
        assert "CLAUDE_CONFIG_DIR" not in envs["codex"]
        assert harness_by_name("claude-code").env == {}  # the registry is untouched

    def test_a_dry_run_needs_no_pin(
        self, all_available: list, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert cli.main(["--harness", "claude-code"]) == 0
        out = capsys.readouterr().out
        assert "DRY RUN" in out
        assert "ANTHROPIC_*" in out
        assert all_available == []

    def test_help_documents_the_new_flags(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        out = capsys.readouterr().out
        assert "--claude-config-dir" in out and "--allow-any-auth" in out
