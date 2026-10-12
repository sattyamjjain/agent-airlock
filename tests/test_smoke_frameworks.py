"""Unit tests for scripts/smoke_frameworks.py, the framework smoke matrix driver.

Nothing here touches the network or an agent SDK. The driver's pure helpers (verdicts,
result parsing, the child environment, budget and ledger pricing, the docs block) are
imported directly; the child harness (``CHILD_COMMON``, which runs inside each framework's
venv) is exec'd into a namespace so its scripted model and wire accounting are tested
without a framework.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from benchmarks._claude.budget import BudgetGuard
from benchmarks._claude.ledger import Ledger
from benchmarks._claude.pricing import price_usage, worst_case_usd

from scripts import smoke_frameworks as sf

_ROOT = Path(__file__).resolve().parents[1]


def _payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "constructed": True,
        "allowed_ran": True,
        "denied_ran": False,
        "denied_attempted": True,
        "denied_refused": True,
        "allowed_refused": False,
    }
    base.update(overrides)
    return base


class TestClassify:
    def _verdict(self, **overrides: bool) -> str:
        observed = {
            "allowed_ran": True,
            "denied_ran": False,
            "denied_attempted": True,
            "denied_refused": True,
            "allowed_refused": False,
            "run_error": False,
        }
        observed.update(overrides)
        return sf.classify(**observed)

    def test_allowed_ran_and_denied_refused_is_a_pass(self) -> None:
        assert self._verdict() == sf.PASS

    def test_a_denied_tool_that_ran_fails_even_with_a_refusal_on_record(self) -> None:
        assert self._verdict(denied_ran=True) == sf.FAIL

    def test_a_refused_allowed_call_fails(self) -> None:
        assert self._verdict(allowed_refused=True) == sf.FAIL

    def test_a_false_refusal_fails_even_when_the_denied_call_never_came(self) -> None:
        assert self._verdict(allowed_refused=True, denied_attempted=False) == sf.FAIL

    def test_a_model_that_never_tried_the_denied_call_is_inconclusive(self) -> None:
        verdict = self._verdict(denied_attempted=False, denied_refused=False)
        assert verdict == sf.INCONCLUSIVE

    def test_never_trying_it_because_the_exchange_broke_is_an_error(self) -> None:
        verdict = self._verdict(denied_attempted=False, denied_refused=False, run_error=True)
        assert verdict == sf.ERROR

    def test_an_attempt_neither_refused_nor_run_fails(self) -> None:
        assert self._verdict(denied_refused=False) == sf.FAIL

    def test_a_refusal_without_the_allowed_call_fails(self) -> None:
        assert self._verdict(allowed_ran=False) == sf.FAIL


class TestStatusFor:
    def test_no_result_line_is_an_error(self) -> None:
        assert sf.status_for(None, "mock") == sf.ERROR

    def test_an_import_failure_is_an_environment_problem(self) -> None:
        payload = {"constructed": False, "error_import": True, "error": "ImportError: x"}
        assert sf.status_for(payload, "mock") == sf.ENV

    def test_any_other_construct_failure_is_an_error(self) -> None:
        payload = {"constructed": False, "error_import": False, "error": "TypeError: x"}
        assert sf.status_for(payload, "run") == sf.ERROR

    def test_construct_mode_reports_ready(self) -> None:
        assert sf.status_for({"constructed": True}, "construct") == sf.READY

    def test_other_modes_judge_the_exchange(self) -> None:
        assert sf.status_for(_payload(), "mock") == sf.PASS
        assert sf.status_for(_payload(denied_ran=True), "run") == sf.FAIL


class TestParseChildOutput:
    def test_the_last_result_line_wins_over_framework_noise(self) -> None:
        stdout = "\n".join(
            [
                "Step 1 ━━━━",
                sf.RESULT_MARKER + json.dumps({"framework": "old"}),
                "Observations: Order A-1001 has shipped.",
                sf.RESULT_MARKER + json.dumps({"framework": "smolagents"}),
            ]
        )
        assert sf.parse_child_output(stdout) == {"framework": "smolagents"}

    def test_no_marker_is_none(self) -> None:
        assert sf.parse_child_output("Traceback (most recent call last):\n...") is None

    def test_a_torn_line_is_none(self) -> None:
        assert sf.parse_child_output(sf.RESULT_MARKER + '{"framework": ') is None

    def test_a_non_object_is_none(self) -> None:
        assert sf.parse_child_output(sf.RESULT_MARKER + "[1, 2]") is None


class TestChildEnv:
    PARENT = {
        "PATH": "/usr/bin",
        "LANG": "en_US.UTF-8",
        "HTTPS_PROXY": "http://proxy.example:3128",
        "ANTHROPIC_API_KEY": "sk-ant-parent-key-0123456789",
        "ANTHROPIC_BASE_URL": "https://elsewhere.example",
        "ANTHROPIC_AUTH_TOKEN": "token",
        "CLAUDECODE": "1",
        "CLAUDE_CODE_OAUTH_TOKEN": "oauth",
        "CLAUDE_CODE_ENTRYPOINT": "cli",
        "OPENAI_API_KEY": "sk-openai",
        "AWS_SECRET_ACCESS_KEY": "aws",
        "PYTHONPATH": "/repo/src",
    }

    def test_only_allowlisted_parent_variables_pass(self, tmp_path: Path) -> None:
        env = sf.build_child_env(self.PARENT, mode="mock", framework="crewai", workdir=tmp_path)
        assert env["PATH"] == "/usr/bin"
        assert env["HTTPS_PROXY"] == "http://proxy.example:3128"
        for name in (
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDECODE",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_ENTRYPOINT",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "PYTHONPATH",
        ):
            assert name not in env, name

    def test_the_parents_key_never_reaches_a_free_mode_child(self, tmp_path: Path) -> None:
        for mode in ("mock", "construct"):
            env = sf.build_child_env(self.PARENT, mode=mode, framework="x", workdir=tmp_path)
            assert env["ANTHROPIC_API_KEY"] == sf.MOCK_KEY
            assert "sk-ant-parent-key" not in json.dumps(env)

    def test_run_mode_passes_the_given_key_through_the_environment(self, tmp_path: Path) -> None:
        env = sf.build_child_env(
            {}, mode="run", framework="x", workdir=tmp_path, api_key="sk-ant-run-key-abcdefgh"
        )
        assert env["ANTHROPIC_API_KEY"] == "sk-ant-run-key-abcdefgh"
        assert env["SMOKE_MODE"] == "run"

    def test_a_key_outside_run_mode_or_run_mode_without_one_is_refused(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(ValueError):
            sf.build_child_env({}, mode="mock", framework="x", workdir=tmp_path, api_key="k" * 20)
        with pytest.raises(ValueError):
            sf.build_child_env({}, mode="run", framework="x", workdir=tmp_path)

    def test_home_and_the_audit_log_live_in_the_workdir(self, tmp_path: Path) -> None:
        env = sf.build_child_env({}, mode="mock", framework="x", workdir=tmp_path)
        assert env["HOME"] == str(tmp_path / "home")
        assert env["XDG_CONFIG_HOME"].startswith(str(tmp_path))
        assert env["AIRLOCK_AUDIT_LOG_PATH"] == str(tmp_path / "airlock_audit.jsonl")
        assert env["SMOKE_MODEL"] == sf.MODEL
        assert env["SMOKE_MAX_TOKENS"] == str(sf.MAX_TOKENS)

    def test_extra_settings_are_merged(self, tmp_path: Path) -> None:
        env = sf.build_child_env(
            {}, mode="mock", framework="x", workdir=tmp_path, extra={"SMOKE_MAX_CALLS": "4"}
        )
        assert env["SMOKE_MAX_CALLS"] == "4"


class TestScrubbedEnv:
    def test_build_and_install_commands_never_see_a_credential(self) -> None:
        env = sf.scrubbed_env(TestChildEnv.PARENT)
        assert env["PATH"] == "/usr/bin"
        assert not any(name.startswith("ANTHROPIC_") for name in env)
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in env


class TestRedact:
    def test_the_secret_value_is_replaced(self) -> None:
        text = sf.redact("auth failed for key abcdefgh12345678", ["abcdefgh12345678"])
        assert "abcdefgh12345678" not in text
        assert "[REDACTED]" in text

    def test_anything_shaped_like_an_anthropic_key_is_replaced(self) -> None:
        assert sf.redact("x sk-ant-api03-AbC_dEf-123456789 y") == "x sk-ant-[REDACTED] y"

    def test_short_values_are_not_used_as_secrets(self) -> None:
        assert sf.redact("order A-1001", ["A-1"]) == "order A-1001"


class TestRequirements:
    PYPROJECT = (
        "[project]\nname = 'demo'\n[project.optional-dependencies]\n"
        "claude-agent = ['claude-agent-sdk>=0.1.58,<0.3.0']\n"
        "pydantic-ai = ['pydantic-ai>=1.88.0,<3.0']\n"
    )

    def test_the_extras_range_carries_over(self) -> None:
        req = sf.extra_requirement(
            self.PYPROJECT, "claude-agent", "claude-agent-sdk", "claude-agent-sdk"
        )
        assert req == "claude-agent-sdk>=0.1.58,<0.3.0"

    def test_the_range_moves_to_another_distribution(self) -> None:
        req = sf.extra_requirement(
            self.PYPROJECT, "pydantic-ai", "pydantic-ai", "pydantic-ai-slim[anthropic]"
        )
        assert req == "pydantic-ai-slim[anthropic]>=1.88.0,<3.0"

    def test_a_missing_distribution_raises(self) -> None:
        with pytest.raises(KeyError):
            sf.extra_requirement(self.PYPROJECT, "claude-agent", "crewai", "crewai")

    def test_every_extra_the_matrix_names_exists_in_the_real_pyproject(self) -> None:
        text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        for fw in sf.FRAMEWORKS.values():
            if fw.extra is not None:
                req = sf.extra_requirement(text, *fw.extra)
                assert req.startswith(fw.extra[2]) and re.search(r"[<>=]", req), req

    def test_workaround_pins_apply_only_with_workarounds(self) -> None:
        autogen = sf.FRAMEWORKS["autogen"]
        assert "anthropic<1" in sf.requirements_for(autogen, self.PYPROJECT)
        assert "anthropic<1" not in sf.requirements_for(autogen, self.PYPROJECT, workarounds=False)


class TestBudget:
    def test_each_framework_reserves_max_calls_full_requests(self) -> None:
        crewai = sf.FRAMEWORKS["crewai"]
        plan = sf.budget_plan([crewai], budget_usd=1.0, max_calls=4)
        one = worst_case_usd(sf.MODEL, crewai.est_input_tokens, sf.MAX_TOKENS, batch=False)
        assert plan == {"crewai": pytest.approx(4 * one)}

    def test_a_budget_below_the_worst_case_is_refused(self) -> None:
        with pytest.raises(ValueError, match="worst case"):
            sf.budget_plan(list(sf.FRAMEWORKS.values()), budget_usd=0.01, max_calls=4)

    def test_the_whole_matrix_fits_well_under_a_dollar(self) -> None:
        plan = sf.budget_plan(list(sf.FRAMEWORKS.values()), budget_usd=1.0, max_calls=4)
        assert set(plan) == set(sf.FRAMEWORKS)
        assert sum(plan.values()) < 0.25

    def test_the_child_guard_gets_haiku_rates(self) -> None:
        rates = sf.child_rates()
        assert rates["input"] == pytest.approx(0.10)
        assert rates["output"] == pytest.approx(0.50)
        assert rates["long_prompt"] == [100_000, 5.0]


class TestLedgerEntries:
    FW = sf.FRAMEWORKS["anthropic"]

    def test_observed_usage_is_priced_by_exact_id(self) -> None:
        usage = {"input_tokens": 1200, "output_tokens": 300}
        payload = {"usage": [{"model": sf.MODEL, "usage": usage}], "unobserved_calls": 0}
        [(model, recorded, usd, how)] = sf.ledger_entries(self.FW, payload, 4)
        assert (model, recorded, how) == (sf.MODEL, usage, "observed")
        assert usd == pytest.approx(price_usage(sf.MODEL, usage, batch=False))

    def test_an_unlisted_model_is_priced_at_the_dearest_row(self) -> None:
        usage = {"input_tokens": 1000, "output_tokens": 1000}
        payload = {"usage": [{"model": "claude-imaginary-9", "usage": usage}]}
        [(_, _, usd, how)] = sf.ledger_entries(self.FW, payload, 4)
        assert how.startswith("unlisted")
        assert usd > price_usage(sf.MODEL, usage, batch=False)

    def test_unobserved_calls_are_recorded_at_the_worst_case(self) -> None:
        entries = sf.ledger_entries(self.FW, {"usage": [], "unobserved_calls": 2}, 4)
        worst = worst_case_usd(sf.MODEL, self.FW.est_input_tokens, sf.MAX_TOKENS, batch=False)
        assert [how for *_, how in entries] == ["unobserved", "unobserved"]
        assert sum(e[2] for e in entries) == pytest.approx(2 * worst)

    def test_a_child_with_no_result_is_recorded_at_every_call_worst_case(self) -> None:
        entries = sf.ledger_entries(self.FW, None, 3)
        assert len(entries) == 3
        assert all(how.startswith("no result") for *_, how in entries)


class TestRecordSpend:
    def test_usage_lands_in_the_ledger_and_the_reservation_is_freed(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        guard = BudgetGuard(1.0, ledger)
        fw = sf.FRAMEWORKS["langchain"]
        paid = sf.PaidRun("k" * 24, {fw.key: 0.05}, {}, ledger, guard, None, "smoke-test")
        guard.admit(f"smoke-frameworks-smoke-test-{fw.key}", 0.05)
        usage = {"input_tokens": 2000, "output_tokens": 500}
        outcome = sf.Outcome(
            sf.PASS, {"usage": [{"model": sf.MODEL, "usage": usage}], "unobserved_calls": 1}
        )

        sf.record_spend(paid, fw, outcome, 4)

        expected = price_usage(sf.MODEL, usage, batch=False) + worst_case_usd(
            sf.MODEL, fw.est_input_tokens, sf.MAX_TOKENS, batch=False
        )
        assert ledger.spent() == pytest.approx(expected, abs=1e-6)
        assert ledger.reserved() == 0
        assert outcome.usd == pytest.approx(expected, abs=1e-6)
        records = [r for r in ledger.records() if r["type"] == "usage"]
        assert [r["custom_id"] for r in records] == [
            "langchain-01-observed",
            "langchain-02-unobserved",
        ]
        assert "k" * 24 not in (tmp_path / "ledger.jsonl").read_text()


class TestFindings:
    def test_sampling_parameters_are_judged_against_haikus_rules(self) -> None:
        notes = sf.sampling_notes({"temperature": 0.1})
        assert notes == ["sends temperature=0.1 (Haiku 5.5 returns 400)"]
        assert sf.sampling_notes({"temperature": 1.0}) == [
            "sends temperature=1.0 (the one value Haiku 5.5 accepts)"
        ]
        both = sf.sampling_notes({"temperature": 1, "top_p": 0.99})
        assert both[-1] == "sends temperature and top_p together (Haiku 5.5 returns 400)"
        assert "Haiku 5.5 returns 400" in sf.sampling_notes({"top_k": 5})[0]

    def test_wire_and_behaviour_findings(self) -> None:
        payload = _payload(
            wire={
                "sampling": {},
                "max_tokens": [1024],
                "tool_choice": ['{"type": "any"}'],
                "prefill": True,
            },
            thinking="dropped",
            delivery="result",
            http_errors=["HTTP 400 invalid_request_error: temperature: ..."],
            budget_abort=True,
            error="APIConnectionError: boom",
            error_stage="run",
            notes=["child note"],
            warnings=["crewai 9 is outside SUPPORTED_CREWAI_VERSIONS"],
        )
        notes = sf.findings(payload)
        assert "max_tokens on the wire: 1024" in notes
        assert any(n.startswith("forces tool_choice") for n in notes)
        assert any("prefill" in n for n in notes)
        assert "thinking blocks dropped on the next request" in notes
        assert any("normal tool result" in n for n in notes)
        assert any(n.startswith("API error: HTTP 400") for n in notes)
        assert any("call cap or dollar share" in n for n in notes)
        assert "run error: APIConnectionError: boom" in notes
        assert notes[-2:] == ["child note", "crewai 9 is outside SUPPORTED_CREWAI_VERSIONS"]

    def test_truncation_refusal_and_a_different_served_model_are_named(self) -> None:
        payload = _payload(
            stop_reasons=["end_turn", "max_tokens", "refusal", "tool_use"],
            response_models=[sf.MODEL, "claude-haiku-9-9"],
        )
        notes = sf.findings(payload)
        assert "a response stopped with stop_reason max_tokens" in notes
        assert "a response stopped with stop_reason refusal" in notes
        assert f"served by claude-haiku-9-9, not {sf.MODEL}" in notes
        assert not any("end_turn" in n or "tool_use" in n for n in notes)

    def test_a_clean_exchange_has_nothing_to_say(self) -> None:
        payload = _payload(wire={"sampling": {}, "max_tokens": [sf.MAX_TOKENS]}, delivery="error")
        assert sf.findings(payload) == []


class TestExitCode:
    def test_a_fail_wins(self) -> None:
        assert sf.exit_code([sf.PASS, sf.ENV, sf.SKIPPED, sf.FAIL]) == 1

    def test_a_budget_refusal_is_three(self) -> None:
        assert sf.exit_code([sf.PASS, sf.SKIPPED, sf.ERROR]) == 3

    def test_an_environment_problem_is_two(self) -> None:
        assert sf.exit_code([sf.PASS, sf.ENV]) == 2
        assert sf.exit_code([sf.ERROR]) == 2

    def test_pass_inconclusive_and_ready_are_clean(self) -> None:
        assert sf.exit_code([sf.PASS, sf.INCONCLUSIVE, sf.READY]) == 0


class TestDocsBlock:
    def test_the_not_yet_run_block_lists_every_framework(self) -> None:
        block = sf.render_block(None)
        assert block.startswith(sf.BLOCK_BEGIN) and block.endswith(sf.BLOCK_END)
        assert "**Last run:** not yet run" in block
        rows = [line for line in block.splitlines() if line.startswith("| ")][1:]
        assert [row.split(" | ")[0].lstrip("| ") for row in rows] == [
            fw.title for fw in sf.FRAMEWORKS.values()
        ]
        assert all("Not yet run" in row for row in rows)
        for name in sf.EXCLUDED:
            assert f"**{name}**" in block

    def test_a_run_renders_a_dated_table(self) -> None:
        results = {
            "anthropic": sf.Outcome(
                sf.PASS,
                _payload(
                    versions={"anthropic": "1.13.0", "agent-airlock": "0.10.25"},
                    delivery="error",
                    model_calls=3,
                ),
                ["sends top_k=5 | pipe"],
                0.0012,
            )
        }
        meta = sf.doc_meta(results, max_calls=4, commit="abc1234567")
        block = sf.render_block({k: o.as_dict() for k, o in results.items()}, meta)
        assert re.search(r"\*\*Last run:\*\* \d{4}-\d{2}-\d{2} \(UTC\)", block)
        assert "agent-airlock 0.10.25 (`abc1234567`)" in block
        assert "ledger-priced spend $0.0012" in block
        row = next(line for line in block.splitlines() if line.startswith("| Anthropic"))
        assert "| PASS | yes | yes | yes | error | 3 |" in row
        assert "anthropic 1.13.0" in row
        assert "top_k=5 \\| pipe" in row
        assert "| LangChain | — |" in block

    def test_long_notes_are_truncated(self) -> None:
        result = {"status": sf.PASS, "payload": _payload(), "notes": ["x" * 900]}
        row = sf._row(sf.FRAMEWORKS["anthropic"], result)
        assert len(row) < 700 and row.rstrip(" |").endswith("...")

    def test_replace_block_touches_only_the_marked_region(self) -> None:
        text = f"before\n{sf.BLOCK_BEGIN}\nold\n{sf.BLOCK_END}\nafter\n"
        out = sf.replace_block(text, f"{sf.BLOCK_BEGIN}\nnew\n{sf.BLOCK_END}")
        assert out == f"before\n{sf.BLOCK_BEGIN}\nnew\n{sf.BLOCK_END}\nafter\n"

    @pytest.mark.parametrize(
        "text",
        [
            "no markers",
            f"{sf.BLOCK_BEGIN}\n{sf.BLOCK_BEGIN}\n{sf.BLOCK_END}",
            f"{sf.BLOCK_END}\n{sf.BLOCK_BEGIN}",
        ],
    )
    def test_replace_block_refuses_a_malformed_document(self, text: str) -> None:
        with pytest.raises(ValueError):
            sf.replace_block(text, "x")

    def test_write_doc_rewrites_the_block_in_place(self, tmp_path: Path) -> None:
        doc = tmp_path / "COMPATIBILITY.md"
        doc.write_text(f"# Title\n\n{sf.render_block(None)}\n\n## After\n", encoding="utf-8")
        results = {"anthropic": sf.Outcome(sf.FAIL, _payload(denied_ran=True), [], 0.0)}
        sf.write_doc(results, sf.doc_meta(results, max_calls=4, commit="c0ffee"), doc)
        text = doc.read_text(encoding="utf-8")
        assert text.startswith("# Title\n") and text.endswith("\n## After\n")
        assert "| FAIL |" in text and "not yet run" not in text

    def test_the_committed_docs_page_carries_one_block_with_every_framework(self) -> None:
        text = (_ROOT / "docs" / "COMPATIBILITY.md").read_text(encoding="utf-8")
        assert text.count(sf.BLOCK_BEGIN) == 1 and text.count(sf.BLOCK_END) == 1
        block = text[text.index(sf.BLOCK_BEGIN) : text.index(sf.BLOCK_END)]
        for fw in sf.FRAMEWORKS.values():
            assert f"| {fw.title} |" in block, fw.title


class TestArguments:
    @pytest.mark.parametrize(
        "argv",
        [
            ["--run"],
            ["--run", "--budget-usd", "0"],
            ["--budget-usd", "1"],
            ["--write"],
            ["--run", "--budget-usd", "1", "--write", "--only", "anthropic"],
            ["--run", "--budget-usd", "1", "--construct-only"],
            ["--only", "not-a-framework"],
            ["--max-calls", "20"],
        ],
    )
    def test_unsafe_or_meaningless_combinations_are_refused(self, argv: list[str]) -> None:
        with pytest.raises(SystemExit) as raised:
            sf.main(argv)
        assert raised.value.code == 2

    def test_list_prints_the_matrix_without_building_anything(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert sf.main(["--list"]) == 0
        out = capsys.readouterr().out
        for key in sf.FRAMEWORKS:
            assert key in out
        assert "(excluded)" in out


class TestChildScripts:
    @pytest.mark.parametrize("key", sorted(sf.FRAMEWORKS))
    def test_every_child_script_compiles(self, key: str) -> None:
        source = sf.child_source(key)
        compile(source, f"smoke_child_{key}.py", "exec")
        assert f"VERSIONS = {sf.FRAMEWORKS[key].versions!r}" in source

    def test_every_framework_has_a_body_and_no_body_is_orphaned(self) -> None:
        assert set(sf.CHILD_BODIES) == set(sf.FRAMEWORKS)


@pytest.fixture
def child(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """The child harness, exec'd as it runs in mock mode (no framework, no network)."""
    monkeypatch.setenv("SMOKE_MODE", "mock")
    monkeypatch.setenv("SMOKE_MAX_CALLS", "4")
    monkeypatch.setenv("SMOKE_WORKDIR", str(tmp_path))
    monkeypatch.setenv("AIRLOCK_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    namespace: dict[str, Any] = {"__name__": "smoke_child_under_test"}
    exec(compile(sf.CHILD_COMMON, "smoke_child_common", "exec"), namespace)  # noqa: S102
    return namespace


TOOLS = [
    {"name": "get_order_status", "input_schema": {"properties": {"order_id": {}}}},
    {"name": "delete_order", "input_schema": {"properties": {"order_id": {}}}},
]


def _assistant_tool_use(tool_id: str, name: str, signature: str | None = None) -> dict[str, Any]:
    content: list[dict[str, Any]] = []
    if signature:
        content.append({"type": "thinking", "thinking": "", "signature": signature})
    content.append({"type": "tool_use", "id": tool_id, "name": name, "input": {}})
    return {"role": "assistant", "content": content}


def _tool_result(tool_id: str, text: str, is_error: bool = False) -> dict[str, Any]:
    block = {"type": "tool_result", "tool_use_id": tool_id, "content": text, "is_error": is_error}
    return {"role": "user", "content": [block]}


class TestScriptedModel:
    def _next(self, child: dict[str, Any], messages: list[dict[str, Any]], tools=TOOLS) -> Any:
        blocks, stop = child["scripted_blocks"]({"tools": tools, "messages": messages})
        return blocks[0], stop

    def test_it_calls_the_allowed_tool_then_the_denied_one_then_stops(
        self, child: dict[str, Any]
    ) -> None:
        user = {"role": "user", "content": "go"}
        first, stop = self._next(child, [user])
        assert (first["name"], first["input"], stop) == (
            "get_order_status",
            {"order_id": "A-1001"},
            "tool_use",
        )
        second, _ = self._next(child, [user, _assistant_tool_use("t1", "get_order_status")])
        assert second["name"] == "delete_order"
        history = [
            user,
            _assistant_tool_use("t1", "get_order_status"),
            _tool_result("t1", "shipped"),
            _assistant_tool_use("t2", "delete_order"),
        ]
        last, stop = self._next(child, history)
        assert (last, stop) == ({"type": "text", "text": "DONE"}, "end_turn")

    def test_mcp_prefixed_names_and_a_final_answer_tool_are_handled(
        self, child: dict[str, Any]
    ) -> None:
        tools = [
            {"name": "mcp__orders__get_order_status", "input_schema": {}},
            {"name": "mcp__orders__delete_order", "input_schema": {}},
            {"name": "final_answer", "input_schema": {"properties": {"answer": {}}}},
        ]
        history = [
            _assistant_tool_use("t1", "mcp__orders__get_order_status"),
            _assistant_tool_use("t2", "mcp__orders__delete_order"),
        ]
        block, _ = self._next(child, history, tools)
        assert (block["name"], block["input"]) == ("final_answer", {"answer": "DONE"})

    def test_calls_replayed_as_text_count_as_made(self, child: dict[str, Any]) -> None:
        replay = (
            "Calling tools:\n[{'id': 'x', 'type': 'function', 'function': "
            "{'name': 'get_order_status', 'arguments': {}}}]"
        )
        error = "Error executing tool 'delete_order' with arguments {}: AIRLOCK_BLOCK"
        messages = [
            {"role": "assistant", "content": [{"type": "text", "text": replay}]},
            {"role": "user", "content": [{"type": "text", "text": error}]},
        ]
        assert child["called_tools"](messages) == {"get_order_status", "delete_order"}

    def test_a_react_prompt_gets_react_text(self, child: dict[str, Any]) -> None:
        body = {"system": "Use this format:\nAction: ...\nAction Input: ...", "messages": []}
        blocks, _ = child["scripted_blocks"](body)
        assert "Action: get_order_status" in blocks[0]["text"]
        body["messages"] = [{"role": "assistant", "content": blocks[0]["text"]}]
        assert "Action: delete_order" in child["scripted_blocks"](body)[0][0]["text"]

    def test_each_response_opens_with_a_thinking_block_like_haiku_5_5(
        self, child: dict[str, Any]
    ) -> None:
        message = child["scripted_message"]({"tools": TOOLS, "messages": [], "model": "m"})
        assert message["content"][0]["type"] == "thinking"
        assert message["content"][0]["thinking"] == ""
        assert message["content"][0]["signature"]
        assert message["model"] == "m"
        assert message["usage"] == child["MOCK_USAGE"]

    def test_the_stream_parses_back_to_the_same_message(self, child: dict[str, Any]) -> None:
        message = child["scripted_message"]({"tools": TOOLS, "messages": []})
        parsed = child["parse_sse"](child["sse_bytes"](message))
        assert parsed["model"] == message["model"]
        assert parsed["stop_reason"] == "tool_use"
        assert parsed["usage"]["input_tokens"] == 11
        assert parsed["usage"]["output_tokens"] == 7
        assert [b["type"] for b in parsed["content"]] == ["thinking", "tool_use"]
        assert parsed["content"][0]["signature"] == message["content"][0]["signature"]
        assert parsed["content"][1]["name"] == "get_order_status"


class TestRecorder:
    def _call(self, child: dict[str, Any], body: dict[str, Any]) -> dict[str, Any]:
        return child["RECORDER"].begin("test", json.dumps(body).encode())

    def test_the_call_cap_refuses_and_records_the_refusal(self, child: dict[str, Any]) -> None:
        for _ in range(4):
            self._call(child, {"model": "m", "messages": []})
        with pytest.raises(child["SmokeBudgetAbort"]):
            self._call(child, {"model": "m", "messages": []})
        assert child["RECORDER"].summary()["aborts"]

    def test_usage_comes_from_json_and_from_streams(self, child: dict[str, Any]) -> None:
        recorder = child["RECORDER"]
        message = child["scripted_message"]({"tools": TOOLS, "messages": []})
        call = self._call(child, {"model": "m", "messages": []})
        recorder.finish(call, 200, json.dumps(message).encode(), "application/json")
        call = self._call(child, {"model": "m", "messages": [], "stream": True})
        recorder.finish(call, 200, child["sse_bytes"](message), "text/event-stream")
        summary = recorder.summary()
        assert [u["usage"]["output_tokens"] for u in summary["usage"]] == [7, 7]
        assert summary["unobserved_calls"] == 0
        assert summary["tool_uses"] == ["get_order_status", "get_order_status"]

    def test_an_error_response_carries_no_usage(self, child: dict[str, Any]) -> None:
        recorder = child["RECORDER"]
        error = {"type": "error", "error": {"type": "invalid_request_error", "message": "temp"}}
        call = self._call(child, {"model": "m", "messages": []})
        recorder.finish(call, 400, json.dumps(error).encode(), "application/json")
        summary = recorder.summary()
        assert summary["usage"] == []
        assert summary["http_errors"] == ["HTTP 400 invalid_request_error: temp"]

    def test_unreadable_or_unread_responses_are_unobserved(self, child: dict[str, Any]) -> None:
        recorder = child["RECORDER"]
        call = self._call(child, {"model": "m", "messages": []})
        recorder.finish(call, 200, b"<html>gateway</html>", "text/html")
        self._call(child, {"model": "m", "messages": []})  # never finished
        assert recorder.summary()["unobserved_calls"] == 2

    def test_thinking_blocks_sent_back_are_kept_and_missing_ones_dropped(
        self, child: dict[str, Any]
    ) -> None:
        recorder = child["RECORDER"]
        message = child["scripted_message"]({"tools": TOOLS, "messages": []})
        signature = message["content"][0]["signature"]
        call = self._call(child, {"model": "m", "messages": []})
        recorder.finish(call, 200, json.dumps(message).encode(), "application/json")
        tool_id = message["content"][1]["id"]
        kept = [_assistant_tool_use(tool_id, "get_order_status", signature)]
        self._call(child, {"model": "m", "messages": kept})
        assert recorder.summary()["thinking"] == "kept"

    def test_a_follow_up_without_the_thinking_block_is_dropped(self, child: dict[str, Any]) -> None:
        recorder = child["RECORDER"]
        message = child["scripted_message"]({"tools": TOOLS, "messages": []})
        call = self._call(child, {"model": "m", "messages": []})
        recorder.finish(call, 200, json.dumps(message).encode(), "application/json")
        dropped = [_assistant_tool_use(message["content"][1]["id"], "get_order_status")]
        self._call(child, {"model": "m", "messages": dropped})
        assert recorder.summary()["thinking"] == "dropped"

    @pytest.mark.parametrize(("is_error", "delivery"), [(True, "error"), (False, "result")])
    def test_how_the_refusal_reached_the_model(
        self, child: dict[str, Any], is_error: bool, delivery: str
    ) -> None:
        messages = [
            _assistant_tool_use("t9", "delete_order"),
            _tool_result("t9", "AIRLOCK_BLOCK: not allowed", is_error),
        ]
        self._call(child, {"model": "m", "messages": messages})
        summary = child["RECORDER"].summary()
        assert summary["delivery"] == delivery
        assert summary["delivery_airlock_text"] is True

    def test_a_refusal_reported_as_text_is_seen(self, child: dict[str, Any]) -> None:
        text = "Error executing tool 'delete_order': SmolAgentsToolBlocked: AIRLOCK_BLOCK: no"
        self._call(child, {"model": "m", "messages": [{"role": "user", "content": text}]})
        assert child["RECORDER"].summary()["delivery"] == "text"

    def test_the_wire_summary_records_what_a_framework_sent(self, child: dict[str, Any]) -> None:
        body = {
            "model": "m",
            "max_tokens": 1024,
            "temperature": 0.1,
            "tool_choice": {"type": "any"},
            "messages": [{"role": "user", "content": "x"}, {"role": "assistant", "content": "y"}],
        }
        self._call(child, body)
        wire = child["RECORDER"].summary()["wire"]
        assert wire["sampling"] == {"temperature": 0.1}
        assert wire["max_tokens"] == [1024]
        assert wire["tool_choice"] == ['{"type": "any"}']
        assert wire["prefill"] is True


class TestChildVerdict:
    KEYS = ("allowed_ran", "denied_ran", "denied_attempted", "denied_refused", "allowed_refused")

    def test_the_childs_verdict_matches_the_drivers_on_every_combination(
        self, child: dict[str, Any]
    ) -> None:
        for bits in range(2 ** (len(self.KEYS) + 1)):
            observed = {key: bool(bits >> i & 1) for i, key in enumerate(self.KEYS)}
            run_error = bool(bits >> len(self.KEYS) & 1)
            payload = {"constructed": True, **observed, "error": "boom" if run_error else None}
            assert child["child_status"](payload) == sf.status_for(payload, "mock"), payload

    def test_construction_failures_agree_too(self, child: dict[str, Any]) -> None:
        for payload in ({"constructed": False, "error_import": True}, {"constructed": False}):
            assert child["child_status"](payload) == sf.status_for(payload, "mock")


class TestObservations:
    def _audit(self, tmp_path: Path, *records: dict[str, Any]) -> None:
        lines = ["# Agent-Airlock Audit Log", *(json.dumps(r) for r in records)]
        (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_canaries_and_the_audit_log_decide_the_observation(
        self, child: dict[str, Any], tmp_path: Path
    ) -> None:
        child["order_status_body"]("A-1001")
        self._audit(
            tmp_path,
            {"tool_name": "get_order_status", "blocked": False},
            {"tool_name": "delete_order", "blocked": True},
        )
        observed = child["observations"]()
        assert observed["allowed_ran"] is True
        assert observed["denied_ran"] is False
        assert observed["denied_refused"] is True
        assert observed["denied_attempted"] is True
        assert observed["allowed_refused"] is False
        assert child["NOTES"] == []

    def test_a_guard_refusal_counts_without_an_audit_log(self, child: dict[str, Any]) -> None:
        child["GUARD_REFUSALS"].append("delete_order")
        observed = child["observations"]()
        assert observed["denied_refused"] is True
        assert observed["audit_records"] == 0

    def test_an_allowed_call_audited_twice_is_called_out(
        self, child: dict[str, Any], tmp_path: Path
    ) -> None:
        child["order_status_body"]("A-1001")
        record = {"tool_name": "get_order_status", "blocked": False}
        self._audit(tmp_path, record, record)
        child["observations"]()
        assert any("wrapped by Airlock more than once" in n for n in child["NOTES"])


class TestChildRunModeGuard:
    @pytest.fixture
    def run_child(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
        monkeypatch.setenv("SMOKE_MODE", "run")
        monkeypatch.setenv("SMOKE_MAX_CALLS", "4")
        monkeypatch.setenv("SMOKE_WORKDIR", str(tmp_path))
        monkeypatch.setenv("SMOKE_BUDGET_USD", "0.004")
        monkeypatch.setenv("SMOKE_RATES", json.dumps(sf.child_rates()))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key-not-real-0000")
        namespace: dict[str, Any] = {"__name__": "smoke_child_under_test"}
        exec(compile(sf.CHILD_COMMON, "smoke_child_common", "exec"), namespace)  # noqa: S102
        return namespace

    def test_a_request_whose_worst_case_exceeds_the_share_is_not_sent(
        self, run_child: dict[str, Any]
    ) -> None:
        recorder = run_child["RECORDER"]
        small = json.dumps({"model": "m", "max_tokens": 4096, "messages": []}).encode()
        recorder.begin("hook:test", small)  # worst case ~$0.002: fits
        huge = json.dumps({"model": "m", "max_tokens": 4096, "pad": "x" * 90_000}).encode()
        with pytest.raises(run_child["SmokeBudgetAbort"], match="share"):
            recorder.begin("hook:test", huge)

    def test_tools_that_ran_without_a_hooked_model_call_are_booked_at_worst_case(
        self, run_child: dict[str, Any]
    ) -> None:
        run_child["order_status_body"]("A-1001")
        observed = run_child["observations"]()
        assert observed["unobserved_calls"] == run_child["TURNS"]
        assert any("no model call crossed the hooks" in n for n in run_child["NOTES"])

    def test_the_child_redacts_its_own_key(self, run_child: dict[str, Any]) -> None:
        text = run_child["redact"]("failed with sk-ant-test-key-not-real-0000")
        assert "not-real" not in text
