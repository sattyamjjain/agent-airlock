"""Tests for ``benchmarks/fix_hints``: corpus, arms, protocol, scoring, report and CLI.

No network and no SDK: the ``anthropic`` package is never imported (a paid path is driven
with a fake client, and the pilot with a stub module), and every refusal comes from the
checked-out airlock. Assertions are about the harness's invariants, not about the hint
text, so the hint fixes that land later do not have to touch this file.
"""

from __future__ import annotations

import json
import math
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlencode

import pytest
from benchmarks._claude.batch import CUSTOM_ID_RE, PlannedRequest
from benchmarks._claude.ledger import Ledger
from benchmarks._claude.models import DEFAULT_EFFORT, MODELS
from benchmarks._claude.store import RunStore
from benchmarks.fix_hints import __main__ as cli
from benchmarks.fix_hints import catalogue, payloads, protocol, report, score
from benchmarks.fix_hints.scenarios import (
    CATEGORIES,
    STRATA,
    Candidate,
    GenerationReport,
    Scenario,
    generate_with_report,
    self_check,
)

from agent_airlock.capabilities import Capability, get_required_capabilities
from agent_airlock.integrations._claude_sdk_tools import _sdk_error_result

TOOL_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


@pytest.fixture(scope="module")
def generated() -> tuple[list[Scenario], GenerationReport]:
    with cli.quiet_airlock_logs():
        return generate_with_report()


@pytest.fixture(scope="module")
def corpus(generated: tuple[list[Scenario], GenerationReport]) -> list[Scenario]:
    return generated[0]


@pytest.fixture(scope="module")
def by_category(corpus: list[Scenario]) -> dict[str, list[Scenario]]:
    out: dict[str, list[Scenario]] = {}
    for scenario in corpus:
        out.setdefault(scenario.category, []).append(scenario)
    return out


def first(by_category: dict[str, list[Scenario]], category: str, **match: Any) -> Scenario:
    return next(
        s
        for s in by_category[category]
        if all(getattr(s, key) == value for key, value in match.items())
    )


def canonical_arguments(scenario: Scenario) -> dict[str, Any]:
    """A call that does what the task asks, rebuilt from the scenario's oracle."""
    args: dict[str, Any] = {}
    for name, expected in scenario.expected.items():
        kind = scenario.compare[name]
        if kind == "path":
            args[name] = f"{scenario.config['filesystem_roots'][0]}/{expected}"
        elif kind == "url":
            query = f"?{urlencode(expected['query'])}" if expected["query"] else ""
            args[name] = f"https://{expected['host']}{expected['path']}{query}"
        elif kind == "number_any":
            args[name] = expected[0]
        else:
            args[name] = expected
    return args


def message(*blocks: dict[str, Any], stop: str = "tool_use", **extra: Any) -> dict[str, Any]:
    return {
        "model": "claude-haiku-5-5",
        "stop_reason": stop,
        "content": [{"type": "thinking", "thinking": "", "signature": "sig"}, *blocks],
        "usage": {"input_tokens": 900, "output_tokens": 300},
        **extra,
    }


def tool_use(name: str, arguments: Any) -> dict[str, Any]:
    return {"type": "tool_use", "id": "toolu_retry", "name": name, "input": arguments}


# --------------------------------------------------------------------------------------
# Corpus
# --------------------------------------------------------------------------------------


class TestCorpus:
    def test_generation_is_deterministic(self, generated: tuple[list[Scenario], Any]) -> None:
        corpus, report_ = generated
        with cli.quiet_airlock_logs():
            again, report_again = generate_with_report()
        assert [s.to_dict() for s in again] == [s.to_dict() for s in corpus]
        assert report_again.corpus_sha256 == report_.corpus_sha256

    def test_another_seed_draws_another_corpus(self, generated: tuple[list[Scenario], Any]) -> None:
        with cli.quiet_airlock_logs():
            _, other = generate_with_report(seed=7)
        assert other.corpus_sha256 != generated[1].corpus_sha256

    def test_category_counts_and_sids(self, generated: tuple[list[Scenario], Any]) -> None:
        corpus, report_ = generated
        assert report_.counts == dict(CATEGORIES)
        assert len(corpus) == sum(n for _, n in CATEGORIES) == 500
        assert len({s.sid for s in corpus}) == 500
        for scenario in corpus:
            assert scenario.sid.startswith(scenario.category.replace("_", "-") + "-")

    def test_control_strata_are_balanced(self, by_category: dict[str, list[Scenario]]) -> None:
        for category, strata in STRATA.items():
            counts: dict[str, int] = {}
            for scenario in by_category[category]:
                counts[scenario.variant] = counts.get(scenario.variant, 0) + 1
            assert counts == strata
        for scenario in by_category["control_policy"]:
            offered = scenario.variant.endswith("-alt")
            assert (scenario.alternative is not None) is offered
            assert scenario.tools_offered == (
                (scenario.tool, scenario.alternative) if offered else (scenario.tool,)
            )

    def test_path_and_endpoint_tasks_state_or_withhold_the_scope(
        self, by_category: dict[str, list[Scenario]]
    ) -> None:
        for scenario in by_category["path_stated"]:
            assert scenario.config["filesystem_roots"][0] in scenario.task
        for scenario in by_category["path_unstated"]:
            assert scenario.config["filesystem_roots"][0] not in scenario.task
        for scenario in by_category["endpoint_stated"]:
            assert scenario.expected["url"]["host"] in scenario.task
        for scenario in by_category["endpoint_unstated"]:
            assert scenario.expected["url"]["host"] not in scenario.task

    def test_every_malformed_call_draws_its_intended_refusal(self, corpus: list[Scenario]) -> None:
        with cli.quiet_airlock_logs():
            for scenario in corpus:
                result, calls = catalogue.invoke(scenario.tool, scenario.config, scenario.malformed)
                assert catalogue.is_refusal(result), scenario.sid
                assert calls == [], scenario.sid
                assert result["block_reason"] == scenario.expect_reason, scenario.sid
                assert catalogue.refusal_detail(result) == scenario.expect_detail, scenario.sid
                assert not catalogue.leaks_local_path(result), scenario.sid

    def test_only_admitted_integers_for_floats_are_rejected(
        self, generated: tuple[list[Scenario], GenerationReport]
    ) -> None:
        report_ = generated[1]
        rejecting = {category for category, reasons in report_.rejected.items() if reasons}
        assert rejecting == {"type_float"}
        reasons = report_.rejected["type_float"]
        assert sum(reasons.values()) == report_.total_rejected > 0
        assert all(reason.startswith("admitted") for reason in reasons)

    def test_self_check_rejects_bad_candidates(self, corpus: list[Scenario]) -> None:
        scenario = next(s for s in corpus if s.category == "type_int")
        good = canonical_arguments(scenario)

        def candidate(malformed: dict[str, Any], reason: str) -> Candidate:
            return Candidate(
                template="t",
                tool=scenario.tool,
                task=scenario.task,
                malformed=malformed,
                expected=scenario.expected,
                compare=scenario.compare,
                config={},
                expect_reason=reason,
                expect_detail=scenario.expect_detail,
                positive=(scenario.tool, good, {}),
            )

        with cli.quiet_airlock_logs():
            assert self_check(candidate(good, "validation_error")) == "admitted"
            assert (
                self_check(candidate(scenario.malformed, "ghost_arguments")) == "wrong block_reason"
            )
            assert self_check(candidate(scenario.malformed, "validation_error")) is None

    def test_a_relative_path_would_leak_the_working_directory(self) -> None:
        with cli.quiet_airlock_logs():
            result, _ = catalogue.invoke(
                "read_file",
                {"filesystem_roots": ["/airlock-bench/workspace"]},
                {"path": "reports/q3.txt"},
            )
        assert catalogue.is_refusal(result)
        assert catalogue.leaks_local_path(result)

    def test_scenario_round_trip(self, corpus: list[Scenario]) -> None:
        for scenario in corpus[::25]:
            clone = Scenario.from_dict(json.loads(json.dumps(scenario.to_dict())))
            assert clone == scenario
            assert clone.content_sha256() == scenario.content_sha256()


# --------------------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------------------


def _schema_titles(node: Any, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "properties" and isinstance(value, dict):
                for name, sub in value.items():
                    found += _schema_titles(sub, f"{path}.{name}")
            elif key == "title":
                found.append(path)
            else:
                found += _schema_titles(value, f"{path}.{key}")
    elif isinstance(node, list):
        for value in node:
            found += _schema_titles(value, path)
    return found


class TestCatalogue:
    def test_every_tool_has_a_clean_schema(self) -> None:
        for name in catalogue.TOOLS:
            schema = catalogue.tool_schema(name)
            assert set(schema) == {"name", "description", "input_schema"}, name
            assert "strict" not in schema
            body = schema["input_schema"]
            assert body["type"] == "object"
            assert sorted(body.get("required", [])) == sorted(catalogue.required_parameters(name))
            assert _schema_titles(body) == [], name

    def test_a_property_named_title_survives_title_stripping(self) -> None:
        body = catalogue.tool_schema("create_ticket")["input_schema"]
        assert body["properties"]["title"]["maxLength"] == 40

    def test_schemas_carry_constraints_and_literals(self) -> None:
        props = catalogue.tool_schema("set_volume")["input_schema"]["properties"]
        assert props["level"]["maximum"] == 1
        props = catalogue.tool_schema("set_priority")["input_schema"]["properties"]
        assert props["priority"]["enum"] == ["low", "normal", "high", "urgent"]

    def test_tool_schema_returns_a_copy(self) -> None:
        catalogue.tool_schema("get_forecast")["input_schema"]["properties"].clear()
        assert catalogue.tool_schema("get_forecast")["input_schema"]["properties"]

    def test_a_valid_call_returns_the_canary(self) -> None:
        with cli.quiet_airlock_logs():
            result, calls = catalogue.invoke("get_forecast", {}, {"city": "Oslo", "days": 3})
        assert result == catalogue.CANARY_PREFIX + "get_forecast"
        assert calls == [("get_forecast", {"city": "Oslo", "days": 3})]
        assert catalogue.ran("get_forecast", result, calls)

    def test_unknown_arguments_are_refused_not_stripped(self) -> None:
        with cli.quiet_airlock_logs():
            result, _ = catalogue.invoke(
                "get_forecast", {}, {"city": "Oslo", "days": 3, "units": "metric"}
            )
        assert result["block_reason"] == "ghost_arguments"

    def test_an_environment_override_of_unknown_args_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIRLOCK_UNKNOWN_ARGS", "strip_and_log")
        with pytest.raises(RuntimeError, match="AIRLOCK_UNKNOWN_ARGS"):
            catalogue.build_config({})

    def test_capability_tools_declare_their_capability(self) -> None:
        assert get_required_capabilities(catalogue.TOOLS["run_shell"]) == Capability.PROCESS_SHELL
        assert get_required_capabilities(catalogue.TOOLS["get_forecast"]) == Capability.NONE


# --------------------------------------------------------------------------------------
# Arms
# --------------------------------------------------------------------------------------

SYNTHETIC_REFUSAL: dict[str, Any] = {
    "success": False,
    "status": "blocked",
    "error": "AIRLOCK_BLOCK: Tool 't' validation failed. a: bad; b: worse",
    "block_reason": "validation_error",
    "fix_hints": ["fix a", "fix b"],
    "metadata": {
        "function": "t",
        "error_count": 2,
        "errors": [
            {"field": "a", "type": "int_type", "message": "bad", "fix_hint": "fix a"},
            {"field": "b", "type": "missing_argument", "message": "worse", "fix_hint": "fix b"},
        ],
    },
}


class TestArms:
    def test_n_strips_top_level_and_nested_hints_only(self) -> None:
        stripped = payloads.strip_hints(SYNTHETIC_REFUSAL)
        assert "fix_hints" not in stripped
        assert all("fix_hint" not in e for e in stripped["metadata"]["errors"])
        assert stripped["error"] == SYNTHETIC_REFUSAL["error"]
        assert stripped["metadata"]["errors"][1]["type"] == "missing_argument"
        assert SYNTHETIC_REFUSAL["fix_hints"] == ["fix a", "fix b"]  # input not mutated
        assert "fix_hint" in SYNTHETIC_REFUSAL["metadata"]["errors"][0]

    def test_h_is_the_json_of_the_refusal(self) -> None:
        assert json.loads(payloads.arm_content("h", SYNTHETIC_REFUSAL)) == SYNTHETIC_REFUSAL

    def test_g_is_constant(self) -> None:
        assert payloads.arm_content("g", SYNTHETIC_REFUSAL) == payloads.GENERIC_ERROR

    def test_unknown_arm(self) -> None:
        with pytest.raises(ValueError, match="unknown arm"):
            payloads.arm_content("x", SYNTHETIC_REFUSAL)

    def test_live_arms_on_one_scenario_per_category(
        self, by_category: dict[str, list[Scenario]]
    ) -> None:
        with cli.quiet_airlock_logs():
            for category, items in by_category.items():
                refusal = payloads.refusal(items[0])
                h = json.loads(payloads.arm_content("h", refusal))
                n = json.loads(payloads.arm_content("n", refusal))
                assert h == refusal, category
                assert "fix_hints" not in n, category
                for error in (n.get("metadata") or {}).get("errors") or []:
                    assert "fix_hint" not in error, category
                assert n == payloads.strip_hints(refusal), category
                s = payloads.arm_content("s", refusal)
                assert s == _sdk_error_result(refusal)["content"], category
                assert isinstance(s, list) and s[0]["type"] == "text", category

    def test_a_refusal_with_metadata_keeps_it_in_arm_n(
        self, by_category: dict[str, list[Scenario]]
    ) -> None:
        with cli.quiet_airlock_logs():
            refusal = payloads.refusal(by_category["path_unstated"][0])
        n = json.loads(payloads.arm_content("n", refusal))
        assert n["metadata"] == refusal["metadata"]

    def test_an_admitted_call_cannot_become_a_payload(self, corpus: list[Scenario]) -> None:
        scenario = next(s for s in corpus if s.category == "missing")
        fixed = Scenario.from_dict(
            {**scenario.to_dict(), "malformed": canonical_arguments(scenario)}
        )
        with cli.quiet_airlock_logs(), pytest.raises(payloads.PayloadError):
            payloads.refusal(fixed)


# --------------------------------------------------------------------------------------
# Protocol
# --------------------------------------------------------------------------------------


class TestProtocol:
    def test_request_params(self, by_category: dict[str, list[Scenario]]) -> None:
        scenario = by_category["type_int"][0]
        for alias, model_id in MODELS.items():
            if alias == "f51":
                continue
            params = protocol.build_params(scenario, model_id, "payload")
            assert set(params) == {
                "model",
                "max_tokens",
                "system",
                "tools",
                "messages",
                "thinking",
                "output_config",
            }
            assert params["max_tokens"] == 4096
            assert params["thinking"] == {"type": "adaptive"}
            assert params["output_config"] == {"effort": DEFAULT_EFFORT[model_id]}
            assert params["system"] == protocol.SYSTEM_PROMPT
            assert all("strict" not in tool for tool in params["tools"])

    def test_the_synthetic_turn_pairs_its_tool_ids(self, corpus: list[Scenario]) -> None:
        for scenario in corpus:
            messages = protocol.build_messages(scenario, "payload", "tool")
            assert [m["role"] for m in messages] == ["user", "assistant", "user"]
            call = messages[1]["content"][0]
            result = messages[2]["content"][0]
            assert call["type"] == "tool_use" and result["type"] == "tool_result"
            assert call["id"] == result["tool_use_id"] == protocol.tool_use_id(scenario.sid)
            assert TOOL_ID_RE.match(call["id"])
            assert call["name"] == scenario.tool
            assert call["input"] == scenario.malformed
            assert result["is_error"] is True
            assert messages[0]["content"] == scenario.task

    def test_s_content_goes_in_list_form(self, by_category: dict[str, list[Scenario]]) -> None:
        scenario = by_category["path_unstated"][0]
        with cli.quiet_airlock_logs():
            content = payloads.arm_content("s", payloads.refusal(scenario))
        result = protocol.build_messages(scenario, content, "tool")[2]["content"][0]
        assert isinstance(result["content"], list)
        assert result["content"][0]["type"] == "text"

    def test_text_protocol_is_one_user_turn(self, by_category: dict[str, list[Scenario]]) -> None:
        scenario = by_category["ghost"][0]
        content = [{"type": "text", "text": "AIRLOCK_BLOCK: nope"}]
        messages = protocol.build_messages(scenario, content, "text")
        assert len(messages) == 1 and messages[0]["role"] == "user"
        text = messages[0]["content"]
        assert scenario.task in text
        assert json.dumps(scenario.malformed) in text
        assert "AIRLOCK_BLOCK: nope" in text

    def test_unknown_protocol(self, corpus: list[Scenario]) -> None:
        with pytest.raises(ValueError, match="protocol"):
            protocol.build_messages(corpus[0], "x", "smoke-signals")

    def test_controls_offer_the_refused_tool_first(
        self, by_category: dict[str, list[Scenario]]
    ) -> None:
        scenario = first(by_category, "control_policy", variant="denylist-alt")
        names = [tool["name"] for tool in protocol.tools_for(scenario)]
        assert names == [scenario.tool, scenario.alternative]

    def test_every_custom_id_is_valid_and_unique(self, corpus: list[Scenario]) -> None:
        with cli.quiet_airlock_logs():
            table = payloads.build_payloads(corpus, payloads.ARMS)
        model_ids = [MODELS[a] for a in ("h55", "s55", "o55")]
        rows = protocol.plan_requests(corpus, table, model_ids, payloads.ARMS, "r1", "tool")
        assert len(rows) == len({row.custom_id for row in rows}) == 500 * 3 * 4
        for row in rows:
            assert CUSTOM_ID_RE.match(row.custom_id) and len(row.custom_id) <= 64
            assert protocol.parse_custom_id(row.custom_id) == ("r1", row.arm, row.model, row.sid)
            assert isinstance(row.planned(), PlannedRequest)
            assert row.est_input_tokens > protocol.TOOL_USE_OVERHEAD_TOKENS
        longest = max((s.sid for s in corpus), key=len)
        for round_ in (*protocol.ROUNDS, "pl", "pb"):
            value = protocol.custom_id(round_, "g", "f51", longest)
            assert CUSTOM_ID_RE.match(value) and len(value) <= 64

    def test_a_bad_custom_id_is_refused(self) -> None:
        with pytest.raises(ValueError):
            protocol.custom_id("r3", "h", "h55", "type-int-001")
        with pytest.raises(ValueError):
            protocol.parse_custom_id("mx-p0-h55-01001")

    def test_request_rows_round_trip(self, by_category: dict[str, list[Scenario]]) -> None:
        scenario = by_category["multi"][0]
        row = protocol.make_row(scenario, "h", MODELS["h55"], "payload", "r1", "tool")
        assert protocol.RequestRow.from_row(json.loads(json.dumps(row.to_row()))) == row
        assert row.payload_sha256 == payloads.content_sha256("payload")

    def test_pilot_plan(self, corpus: list[Scenario]) -> None:
        with cli.quiet_airlock_logs():
            pilot = protocol.pilot_requests(corpus, "tool")
        assert [(p.mode, p.row.model, p.row.arm) for p in pilot] == [
            ("sync", "h55", "h"),
            ("sync", "s55", "h"),
            ("sync", "o55", "h"),
            ("batch", "o55", "h"),
            ("sync", "s55", "s"),
        ]
        assert len({p.row.custom_id for p in pilot}) == 5
        last = pilot[-1].row
        assert last.sid.startswith("path-")
        content = last.params["messages"][2]["content"][0]["content"]
        assert isinstance(content, list)


# --------------------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------------------


class TestScore:
    def test_recovered_and_matching_the_task(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["type_int"][0]
        with cli.quiet_airlock_logs():
            outcome = score.score(
                scenario, message(tool_use(scenario.tool, canonical_arguments(scenario)))
            )
        assert outcome.outcome == "recovered"
        assert outcome.oracle_ok is True
        assert outcome.identical_retry is False
        assert outcome.success and outcome.semantic_success

    def test_recovered_but_not_what_the_task_asked(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["type_int"][0]
        wrong = {**canonical_arguments(scenario), "city": "Atlantis"}
        with cli.quiet_airlock_logs():
            outcome = score.score(scenario, message(tool_use(scenario.tool, wrong)))
        assert outcome.outcome == "recovered"
        assert outcome.oracle_ok is False
        assert outcome.success and not outcome.semantic_success

    def test_the_same_call_again(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["type_int"][0]
        with cli.quiet_airlock_logs():
            outcome = score.score(scenario, message(tool_use(scenario.tool, scenario.malformed)))
        assert outcome.outcome == "same_error"
        assert outcome.identical_retry is True
        assert outcome.retry_reason == "validation_error"

    def test_the_same_field_wrong_another_way_is_the_same_error(
        self, by_category: dict[str, Any]
    ) -> None:
        scenario = first(by_category, "constraint_numeric", tool="set_volume")
        retry = {**scenario.malformed, "level": str(scenario.expected["level"])}
        with cli.quiet_airlock_logs():
            outcome = score.score(scenario, message(tool_use(scenario.tool, retry)))
        assert outcome.outcome == "same_error"
        assert outcome.identical_retry is False

    def test_a_new_ghost_argument_is_a_different_error(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["type_int"][0]
        retry = {**canonical_arguments(scenario), "verbose": True}
        with cli.quiet_airlock_logs():
            outcome = score.score(scenario, message(tool_use(scenario.tool, retry)))
        assert outcome.outcome == "different_error"
        assert outcome.retry_reason == "ghost_arguments"
        assert outcome.retry_detail == ("verbose",)

    def test_input_that_is_not_an_object(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["missing"][0]
        outcome = score.score(scenario, message(tool_use(scenario.tool, ["not", "an", "object"])))
        assert outcome.outcome == "different_error"

    def test_no_tool_call(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["ghost"][0]
        outcome = score.score(
            scenario, message({"type": "text", "text": "Sorry."}, stop="end_turn")
        )
        assert outcome.outcome == "no_tool_call" and not outcome.success

    def test_another_tool(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["ghost"][0]
        outcome = score.score(scenario, message(tool_use("make_coffee", {})))
        assert outcome.outcome == "other_tool"
        assert outcome.tool_called == "make_coffee"

    def test_api_refusal_and_truncation(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["ghost"][0]
        refused = score.score(
            scenario, message(stop="refusal", stop_details={"type": "refusal", "category": "cyber"})
        )
        assert refused.outcome == "api_refusal"
        assert refused.refusal_category == "cyber"
        truncated = score.score(scenario, message(tool_use(scenario.tool, {}), stop="max_tokens"))
        assert truncated.outcome == "truncated"
        assert refused.counted and truncated.counted

    def test_only_the_first_tool_call_is_scored(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["type_int"][0]
        response = message(
            tool_use(scenario.tool, scenario.malformed),
            tool_use(scenario.tool, canonical_arguments(scenario)),
        )
        with cli.quiet_airlock_logs():
            outcome = score.score(scenario, response)
        assert outcome.outcome == "same_error"
        assert outcome.tool_calls == 2

    def test_a_batch_error_is_excluded(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["ghost"][0]
        outcome = score.score_result(
            scenario, {"custom_id": "x", "result": {"type": "errored", "error": {"type": "e"}}}
        )
        assert outcome.outcome == "errored" and not outcome.counted

    def test_a_stub_that_raises_is_a_harness_error(
        self, by_category: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scenario = by_category["type_int"][0]

        def boom(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("stub exploded")

        monkeypatch.setattr(score, "invoke", boom)
        outcome = score.score(scenario, message(tool_use(scenario.tool, scenario.malformed)))
        assert outcome.outcome == "harness_error" and not outcome.counted
        assert "stub exploded" in outcome.detail

    def test_control_outcomes(self, by_category: dict[str, Any]) -> None:
        scenario = first(by_category, "control_policy", variant="allowlist-alt")
        with cli.quiet_airlock_logs():
            retried = score.score(scenario, message(tool_use(scenario.tool, scenario.malformed)))
            switched = score.score(
                scenario, message(tool_use(scenario.alternative, scenario.malformed))
            )
            bad_switch = score.score(
                scenario, message(tool_use(scenario.alternative, {"nonsense": 1}))
            )
        stopped = score.score(scenario, message({"type": "text", "text": "No."}, stop="end_turn"))
        assert retried.outcome == "same_error" and not retried.success
        assert retried.retry_reason == "policy_violation"
        assert switched.outcome == "switched" and switched.success and switched.switch_ok
        assert bad_switch.outcome == "switched" and bad_switch.switch_ok is False
        assert stopped.outcome == "no_tool_call" and stopped.success

    def test_capability_control_retry(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["control_capability"][0]
        with cli.quiet_airlock_logs():
            outcome = score.score(scenario, message(tool_use(scenario.tool, scenario.malformed)))
        assert outcome.outcome == "same_error"
        assert outcome.retry_reason == "capability_denied"
        assert not outcome.success

    def test_outcomes_round_trip(self, by_category: dict[str, Any]) -> None:
        scenario = by_category["ghost"][0]
        outcome = score.with_meta(
            score.score(scenario, message(stop="max_tokens")),
            custom_id="fh-r1-h-h55-ghost-001",
            arm="h",
            model="h55",
            round="r1",
        )
        assert (outcome.sid, outcome.category, outcome.arm) == (scenario.sid, "ghost", "h")
        assert score.Outcome.from_dict(json.loads(json.dumps(outcome.to_dict()))) == outcome


# --------------------------------------------------------------------------------------
# Oracles
# --------------------------------------------------------------------------------------


class TestOracles:
    def test_the_task_answer_passes_airlock_and_the_oracle(self, corpus: list[Scenario]) -> None:
        with cli.quiet_airlock_logs():
            for scenario in corpus:
                if scenario.is_control:
                    continue
                args = canonical_arguments(scenario)
                result, calls = catalogue.invoke(scenario.tool, scenario.config, args)
                assert catalogue.ran(scenario.tool, result, calls), scenario.sid
                assert score.oracle_ok(scenario, args), scenario.sid

    def test_a_malformed_value_fails_the_oracle(self, corpus: list[Scenario]) -> None:
        """Where the defect changes a value (not only its JSON type), the oracle sees it.

        A type error can keep the value (``5.0`` for ``5``) and a ghost call carries every
        task value; airlock refuses those itself, and the oracle is only asked about calls
        airlock admitted, so it compares values and leaves types to airlock.
        """
        value_categories = {
            "missing",
            "constraint_numeric",
            "constraint_length",
            "constraint_literal",
            "path_stated",
            "path_unstated",
            "endpoint_stated",
            "endpoint_unstated",
            "multi",
        }
        for scenario in corpus:
            if scenario.category in value_categories:
                assert not score.oracle_ok(scenario, scenario.malformed), scenario.sid

    def test_the_oracle_compares_values_and_leaves_types_to_airlock(
        self, by_category: dict[str, Any]
    ) -> None:
        scenario = first(by_category, "type_int", template="get_forecast.days:float")
        assert score.oracle_ok(scenario, scenario.malformed)  # 5.0 == 5 as a value
        with cli.quiet_airlock_logs():
            outcome = score.score(scenario, message(tool_use(scenario.tool, scenario.malformed)))
        assert outcome.outcome == "same_error" and not outcome.semantic_success

    def test_path_oracle(self, by_category: dict[str, Any]) -> None:
        for scenario in by_category["path_unstated"]:
            root = scenario.config["filesystem_roots"][0]
            name = scenario.expected["path"]
            args = canonical_arguments(scenario)
            assert score.oracle_ok(scenario, {**args, "path": f"{root}/deeper/{name}"})
            assert score.oracle_ok(scenario, {**args, "path": f"{root}/{name}/"})
            assert not score.oracle_ok(scenario, {**args, "path": f"{root}/other-{name}"})
            assert not score.oracle_ok(scenario, {**args, "path": name})
            assert not score.oracle_ok(scenario, {**args, "path": f"{root}/../{name}"})
            assert not score.oracle_ok(scenario, {**args, "path": f"{root}-archive/{name}"})

    def test_url_oracle(self, by_category: dict[str, Any]) -> None:
        scenario = first(by_category, "endpoint_unstated", tool="fetch_url")
        host = scenario.expected["url"]["host"]
        good = canonical_arguments(scenario)["url"]
        base = good.split("?")[0]
        assert scenario.expected["url"]["query"]
        assert score.oracle_ok(scenario, {"url": good})
        assert score.oracle_ok(scenario, {"url": good.replace(host, host.upper())})
        assert score.oracle_ok(scenario, {"url": good + "&page=2"})
        assert not score.oracle_ok(scenario, {"url": base})
        assert not score.oracle_ok(scenario, {"url": good.replace(base, base + "/extra")})
        assert not score.oracle_ok(scenario, {"url": good.replace(host, "evil.example")})

    def test_comparators(self, corpus: list[Scenario]) -> None:
        dummy = corpus[0]
        cmp = score.COMPARATORS
        assert cmp["number"](3, 3.0, dummy) and not cmp["number"](3, "3", dummy)
        assert not cmp["number"](1, True, dummy)
        assert cmp["number_any"]([4096, 4000], 4000, dummy)
        assert cmp["exact"](True, True, dummy) and not cmp["exact"](True, 1, dummy)
        assert cmp["text"]("Lisbon", "  lisbon ", dummy)
        assert cmp["text_set"](["a", "B"], ["b", "A"], dummy)
        assert not cmp["text_set"](["a", "b"], ["a"], dummy)
        assert cmp["text_map"]({"Team": "Payments"}, {"team": "payments"}, dummy)
        assert not cmp["text_map"]({"team": "payments"}, {"team": 1}, dummy)
        assert cmp["present"]("x", "anything", dummy) and not cmp["present"]("x", " ", dummy)


# --------------------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------------------


def outcome(sid: str, category: str, arm: str, kind: str, **extra: Any) -> score.Outcome:
    return score.Outcome(
        outcome=kind,
        sid=sid,
        category=category,
        arm=arm,
        model=extra.pop("model", "h55"),
        round=extra.pop("round", "r1"),
        custom_id=f"fh-r1-{arm}-h55-{sid}",
        variant=extra.pop("variant", ""),
        oracle_ok=extra.pop("oracle_ok", None),
        usage={"input_tokens": 1000, "output_tokens": 100},
        served_model="claude-haiku-5-5",
        **extra,
    )


class TestReport:
    def test_cells_count_success_and_exclude_errors(self) -> None:
        rows = [
            outcome("type-int-001", "type_int", "h", "recovered", oracle_ok=True),
            outcome("type-int-002", "type_int", "h", "recovered", oracle_ok=False),
            outcome("type-int-003", "type_int", "h", "same_error", identical_retry=True),
            outcome("type-int-004", "type_int", "h", "errored"),
        ]
        cell = next(c for c in report.cells(rows) if c["category"] == "type_int")
        assert (cell["n"], cell["success"], cell["semantic"]) == (3, 2, 1)
        assert cell["identical_retries"] == 1
        assert cell["outcomes"]["errored"] == 1
        lo, hi = cell["rr_ci"]
        assert lo < 2 / 3 < hi

    def test_an_empty_cell_is_n_zero_not_zero_percent(self) -> None:
        assert report._rate(0, 0) == "n=0"
        assert report._rate(0, 5).startswith("0/5 0%")

    def test_mcnemar_pairs_and_identical_payload_exclusion(self) -> None:
        rows = [
            outcome("missing-001", "missing", "h", "recovered", oracle_ok=True),
            outcome("missing-001", "missing", "n", "same_error"),
            outcome("missing-002", "missing", "h", "same_error"),
            outcome("missing-002", "missing", "n", "recovered", oracle_ok=True),
            outcome("missing-003", "missing", "h", "recovered", oracle_ok=True),
            outcome("missing-003", "missing", "n", "same_error"),
        ]
        tests, noise = report.mcnemar_rows(rows, identical_hn={"missing-003"})
        missing = next(r for r in tests if r["scope"] == "missing" and r["comparison"] == "h_vs_n")
        assert (missing["pairs"], missing["b"], missing["c"]) == (2, 1, 1)
        assert missing["p"] == 1.0
        assert noise == [
            {
                "model": "h55",
                "comparison": "h_vs_n_identical_payload",
                "pairs": 1,
                "b": 1,
                "c": 0,
                "p": 1.0,
            }
        ]

    def test_controls_split_stopped_and_switched(self) -> None:
        rows = [
            outcome(
                "control-policy-001", "control_policy", "h", "no_tool_call", variant="allowlist-alt"
            ),
            outcome(
                "control-policy-002",
                "control_policy",
                "h",
                "switched",
                variant="denylist-alt",
                switch_ok=True,
            ),
            outcome(
                "control-policy-003", "control_policy", "h", "same_error", variant="allowlist-noalt"
            ),
        ]
        table = {r["scope"]: r for r in report.controls(rows)}
        offered = table["policy, alternative offered"]
        assert (offered["n"], offered["not_retried"], offered["stopped"], offered["switched"]) == (
            2,
            2,
            1,
            1,
        )
        assert table["policy, none offered"]["retried"] == 1

    def test_r2_scopes(self) -> None:
        r1 = [
            outcome(sid, "missing", arm, "same_error")
            for sid in ("missing-001", "missing-002", "missing-003")
            for arm in ("h", "n")
        ]
        r2 = [
            outcome(sid, "missing", arm, "recovered", oracle_ok=True, round="r2")
            for sid in ("missing-001", "missing-002", "missing-003")
            for arm in ("h", "n")
        ]
        rows = report.r2_vs_r1_rows(
            r2, r1, changed={"h": ["missing-001", "missing-002"], "n": []}, retest=["missing-003"]
        )
        table = {(r["arm"], r["scope"]): (r["pairs"], r["b"], r["c"]) for r in rows}
        assert table[("h", "changed")] == (2, 0, 2)
        assert table[("h", "retest")] == (1, 0, 1)
        assert table[("n", "unchanged, other arm changed")] == (2, 0, 2)

    def test_render_and_append(self, tmp_path: Path) -> None:
        rows = [
            outcome("type-int-001", "type_int", arm, "recovered", oracle_ok=True)
            for arm in ("h", "n", "s")
        ]
        meta = {
            "round": "r1",
            "date": "2026-10-14",
            "run_id": "fh-r1-20261014T000000Z",
            "models": {"h55": "claude-haiku-5-5"},
            "arms": ["h", "n", "s"],
            "request_template": {"max_tokens": 4096, "effort": {"h55": "medium"}},
        }
        summary = report.summarize_round(rows, meta, identical_hn=set(), planned=4)
        assert summary["requests"]["missing"] == 1
        block = report.render_block(summary)
        assert block.startswith("### Round R1 · 2026-10-14 · run `fh-r1-20261014T000000Z`")
        assert "1/1 100%" in block and "n=0" in block
        results = tmp_path / "RESULTS.md"
        base = cli.RESULTS_PATH.read_text(encoding="utf-8")
        base_r1 = base.count("### Round R1")  # real published rounds, if any
        results.write_text(base, encoding="utf-8")
        text = report.append_block(results, block)
        assert report.PLACEHOLDER_PREFIX not in text
        assert text.index(report.RESULTS_MARKER) < text.index("### Round R1")
        with pytest.raises(ValueError, match="already exists"):
            report.append_block(results, block)
        second = block.replace("fh-r1-20261014T000000Z", "fh-r1-20261015T000000Z")
        text = report.append_block(results, second)
        assert text.index("20261015") < text.index("20261014")  # newest first
        assert text.count("### Round R1") == base_r1 + 2

    def test_append_needs_the_marker(self, tmp_path: Path) -> None:
        results = tmp_path / "RESULTS.md"
        results.write_text("# no marker\n", encoding="utf-8")
        with pytest.raises(ValueError, match="marker"):
            report.append_block(results, "### Round R1 · x\n")

    def test_summary_json_merges_runs(self, tmp_path: Path) -> None:
        path = tmp_path / "summary.json"
        report.write_summary(path, {"round": "r1", "run_id": "a"})
        data = report.write_summary(path, {"round": "r2", "run_id": "b"})
        assert set(data["runs"]) == {"a", "b"}
        assert data["latest"] == {"r1": "a", "r2": "b"}

    def test_the_shipped_results_and_summary_agree(self) -> None:
        text = cli.RESULTS_PATH.read_text(encoding="utf-8")
        assert report.RESULTS_MARKER in text
        if "### Round" not in text:  # no round run yet: nothing may be claimed
            assert report.PLACEHOLDER_PREFIX in text
            assert not cli.SUMMARY_PATH.exists()
            return
        assert report.PLACEHOLDER_PREFIX not in text
        summary = json.loads(cli.SUMMARY_PATH.read_text(encoding="utf-8"))
        for run_id in summary["runs"]:
            assert f"run `{run_id}`" in text


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def _no_client() -> Any:
    raise AssertionError("a dry run must not build a client")


class TestCliDryRun:
    def test_dry_run_prints_counts_and_costs_without_the_sdk(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setitem(sys.modules, "anthropic", None)  # import anthropic -> ImportError
        monkeypatch.setattr(cli, "make_client", _no_client)
        assert cli.main([]) == 0
        out = capsys.readouterr().out
        assert "DRY RUN" in out
        assert "expected, 0 thinking" in out and "expected, 1,000 thinking" in out
        assert "worst case" in out
        for alias in ("h55", "s55", "o55"):
            assert re.search(rf"^{alias}\s+1,500\s", out, re.MULTILINE), alias
        assert re.search(r"^total\s+4,500\s", out, re.MULTILINE)
        assert "500 scenarios" in out

    def test_dry_run_costs_match_the_shared_planner(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        corpus: list[Scenario],
    ) -> None:
        monkeypatch.setattr(cli, "make_client", _no_client)
        assert cli.main(["--models", "h55", "--arms", "h,g"]) == 0
        out = capsys.readouterr().out
        with cli.quiet_airlock_logs():
            table = payloads.build_payloads(corpus, ["h", "g"])
        rows = protocol.plan_requests(corpus, table, [MODELS["h55"]], ["h", "g"], "r1", "tool")
        from benchmarks._claude.batch import plan_cost

        plan = plan_cost(
            [r.planned() for r in rows], batch=True, assumed_outputs=protocol.ASSUMED_OUTPUTS
        )
        line = next(line for line in out.splitlines() if line.startswith("h55"))
        assert "1,000" in line
        assert f"${plan.worst_case_usd:.2f}" in line or f"${plan.worst_case_usd:.4f}" in line

    def test_pilot_dry_run(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli, "make_client", _no_client)
        assert cli.main(["--pilot"]) == 0
        out = capsys.readouterr().out
        assert "fh-pb-h-o55-" in out and "fh-pl-s-s55-path-" in out

    def test_run_needs_a_positive_budget(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["--run"]) == 2
        assert cli.main(["--run", "--budget-usd", "0"]) == 2
        assert "budget" in capsys.readouterr().err

    def test_write_needs_a_run(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert cli.main(["--write"]) == 2

    def test_unknown_models_and_arms(self) -> None:
        assert cli.main(["--models", "gpt-4o"]) == 2
        assert cli.main(["--arms", "h,z"]) == 2

    def test_a_paid_run_refuses_a_dirty_tree(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(cli, "git_state", lambda _root: ("abc123", True))
        monkeypatch.setattr(cli, "make_client", _no_client)
        assert cli.main(["--models", "h55", "--arms", "h", "--run", "--budget-usd", "1"]) == 2
        assert "dirty tree" in capsys.readouterr().err


class _FakeBatches:
    def __init__(self) -> None:
        self.created: list[list[dict[str, Any]]] = []

    def create(self, requests: list[dict[str, Any]]) -> SimpleNamespace:
        self.created.append(requests)
        return SimpleNamespace(id=f"msgbatch_fake{len(self.created)}")

    def retrieve(self, _batch_id: str) -> SimpleNamespace:
        return SimpleNamespace(processing_status="ended")

    def results(self, batch_id: str) -> list[dict[str, Any]]:
        requests = self.created[int(batch_id.removeprefix("msgbatch_fake")) - 1]
        return [
            {
                "custom_id": r["custom_id"],
                "result": {
                    "type": "succeeded",
                    "message": {
                        "model": r["params"]["model"],
                        "stop_reason": "end_turn",
                        "content": [{"type": "text", "text": "I will not retry."}],
                        "usage": {"input_tokens": 800, "output_tokens": 50},
                    },
                },
            }
            for r in requests
        ]


@pytest.fixture
def bench_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AIRLOCK_BENCH_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("AIRLOCK_BENCH_LEDGER", str(tmp_path / "data" / "ledger.jsonl"))
    monkeypatch.delenv("AIRLOCK_BENCH_HARD_CAP_USD", raising=False)
    return tmp_path


@pytest.fixture
def fake_api(bench_data: Path, monkeypatch: pytest.MonkeyPatch) -> _FakeBatches:
    """A fake Batch API, a clean tree, and run ids that never collide within a second."""
    batches = _FakeBatches()
    client = SimpleNamespace(messages=SimpleNamespace(batches=batches))
    monkeypatch.setattr(cli, "make_client", lambda: client)
    monkeypatch.setattr(cli, "git_state", lambda _root: ("cafe" * 10, False))
    counter = iter(range(1, 100))
    monkeypatch.setattr(
        cli, "new_run_id", lambda prefix: f"{prefix}-20261014T0000{next(counter):02d}Z"
    )
    return batches


def _runs(bench_data: Path) -> list[str]:
    return sorted(path.name for path in (bench_data / "data" / "runs" / "fix_hints").iterdir())


class TestCliPaidPathsWithAFakeClient:
    def test_submit_collect_score_and_write(
        self,
        bench_data: Path,
        fake_api: _FakeBatches,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        batches = fake_api
        argv = ["--models", "h55", "--arms", "h", "--run", "--budget-usd", "5", "--no-wait"]
        assert cli.main(argv) == 0
        assert len(batches.created) == 1 and len(batches.created[0]) == 500
        sent = batches.created[0][0]["params"]
        assert "temperature" not in sent and "tool_choice" not in sent and "fallbacks" not in sent
        [run_id] = _runs(bench_data)
        assert run_id.startswith("fh-r1-")
        store = RunStore("fix_hints", run_id)
        manifest = store.read_manifest()
        assert manifest["git_sha"] == "cafe" * 10 and manifest["git_dirty"] is False
        assert set(manifest["source_sha256"]) == {
            "validator.py",
            "self_heal.py",
            "core.py",
            "_claude_sdk_tools.py",
        }
        assert manifest["protocol"] == "tool" and manifest["arms"] == ["h"]
        assert manifest["command"][-1] == "--no-wait"
        assert manifest["airlock_path"] == str(Path("src") / "agent_airlock")
        ledger = Ledger()
        assert ledger.reserved() > 0 and ledger.spent() == 0

        assert cli.main(["--collect", run_id]) == 0
        assert ledger.reserved() == 0
        assert ledger.spent() == pytest.approx(500 * (800 * 0.1 + 50 * 0.5) / 1e6 / 2)
        scores = (store.dir / "scores.jsonl").read_text().splitlines()
        assert len(scores) == 500
        out = capsys.readouterr().out
        assert "### Round R1" in out

        assert cli.main(["--collect", run_id]) == 0  # nothing collected twice
        assert ledger.spent() == pytest.approx(500 * (800 * 0.1 + 50 * 0.5) / 1e6 / 2)

        results = bench_data / "RESULTS.md"
        results.write_text(cli.RESULTS_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        summary = bench_data / "summary.json"
        write = ["--score", run_id, "--write", "--date", "2026-10-14"]
        write += ["--results", str(results), "--summary", str(summary)]
        assert cli.main(write) == 0
        text = results.read_text()
        assert f"### Round R1 · 2026-10-14 · run `{run_id}`" in text
        assert "msgbatch_fake1" in text
        assert json.loads(summary.read_text())["latest"] == {"r1": run_id}
        assert cli.main(write) == 2  # the same heading twice needs --force

    def test_r2_plans_changed_scenarios_plus_a_retest_sample(
        self, bench_data: Path, corpus: list[Scenario]
    ) -> None:
        with cli.quiet_airlock_logs():
            table = payloads.build_payloads(corpus, ["h", "n"])
        hashes = payloads.payload_hashes(table)
        store = RunStore("fix_hints", "fh-r1-20261014T000000Z")
        store.write_manifest({"round": "r1", "arms": ["h", "n"]})
        cli._write_scenarios(store, corpus)
        (store.dir / "payload_hashes.json").write_text(json.dumps(hashes))

        selected, plan = cli.plan_r2(corpus, hashes, store, ["h", "n"], 20261012)
        assert plan["changed"] == {"h": [], "n": []}
        assert len(plan["retest"]) == math.ceil(0.25 * 500) == len(selected)

        now = {sid: dict(arms) for sid, arms in hashes.items()}
        for sid in now:
            if sid.startswith("missing-"):
                now[sid]["h"] = "after-the-hint-fix"
        selected, plan = cli.plan_r2(corpus, now, store, ["h", "n"], 20261012)
        assert len(plan["changed"]["h"]) == 60 and plan["changed"]["n"] == []
        assert len(plan["retest"]) == math.ceil(0.25 * 440)
        assert not set(plan["retest"]) & set(plan["changed"]["h"])
        assert len(selected) == 60 + len(plan["retest"])
        again, plan_again = cli.plan_r2(corpus, now, store, ["h", "n"], 20261012)
        assert plan_again == plan and [s.sid for s in again] == [s.sid for s in selected]
        assert [s.run_id for s in cli.find_r1_runs(None)] == [store.run_id]
        assert plan["r1_run_ids"] == [store.run_id]

    def test_r2_refuses_a_corpus_that_moved(self, bench_data: Path, corpus: list[Scenario]) -> None:
        store = RunStore("fix_hints", "fh-r1-20261014T000000Z")
        store.write_manifest({"round": "r1", "arms": ["h"]})
        moved = [Scenario.from_dict({**corpus[0].to_dict(), "task": "changed"}), *corpus[1:]]
        cli._write_scenarios(store, moved)
        (store.dir / "payload_hashes.json").write_text("{}")
        with pytest.raises(cli.UsageError, match="corpus differs"):
            cli.plan_r2(corpus, {}, store, ["h"], 20261012)

    def test_r2_refuses_another_protocol(self, bench_data: Path, corpus: list[Scenario]) -> None:
        store = RunStore("fix_hints", "fh-r1-20261014T000000Z")
        store.write_manifest({"round": "r1", "arms": ["h"], "protocol": "text"})
        with pytest.raises(cli.UsageError, match="protocol"):
            cli.plan_r2(corpus, {}, store, ["h"], 20261012, "tool")

    def test_find_r1_runs_groups_runs_of_the_same_hint_code(self, bench_data: Path) -> None:
        for run_id, code in (
            ("fh-r1-20261013T000000Z", "old"),
            ("fh-r1-20261014T000000Z", "new"),
            ("fh-r1-20261014T000100Z", "new"),
        ):
            store = RunStore("fix_hints", run_id)
            store.write_manifest({"round": "r1", "source_sha256": {"core.py": code}})
            (store.dir / "payload_hashes.json").write_text("{}")
        found = [s.run_id for s in cli.find_r1_runs(None)]
        assert found == ["fh-r1-20261014T000000Z", "fh-r1-20261014T000100Z"]
        explicit = cli.find_r1_runs("fh-r1-20261013T000000Z")
        assert [s.run_id for s in explicit] == ["fh-r1-20261013T000000Z"]

    def test_a_paid_run_refuses_airlock_imported_from_another_checkout(
        self,
        bench_data: Path,
        fake_api: _FakeBatches,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(cli, "airlock_location", lambda: Path("/elsewhere/agent_airlock"))
        argv = ["--models", "h55", "--arms", "h", "--run", "--budget-usd", "5"]
        assert cli.main(argv) == 2
        assert fake_api.created == []
        assert "outside this checkout" in capsys.readouterr().err

    def test_a_round_that_does_not_fit_is_refused_before_any_submit(
        self, bench_data: Path, fake_api: _FakeBatches, capsys: pytest.CaptureFixture[str]
    ) -> None:
        argv = ["--models", "h55,o55", "--arms", "h", "--run", "--budget-usd", "2"]
        assert cli.main(argv) == 3
        assert fake_api.created == []
        assert not (bench_data / "data" / "runs").exists()
        assert "stage it with --models" in capsys.readouterr().err

    def test_a_round_staged_across_runs_is_scored_as_one(
        self, bench_data: Path, fake_api: _FakeBatches, capsys: pytest.CaptureFixture[str]
    ) -> None:
        base = ["--models", "h55", "--run", "--budget-usd", "5"]
        assert cli.main([*base, "--arms", "h"]) == 0
        assert cli.main([*base, "--arms", "n"]) == 0
        first_run, second_run = _runs(bench_data)
        results = bench_data / "RESULTS.md"
        results.write_text(cli.RESULTS_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        summary = bench_data / "summary.json"
        out_files = ["--results", str(results), "--summary", str(summary)]
        both = f"{first_run},{second_run}"
        capsys.readouterr()
        assert cli.main(["--score", both, "--write", "--date", "2026-10-14", *out_files]) == 0
        text = results.read_text()
        assert f"runs `{first_run}`, `{second_run}`" in text
        assert "| H vs N: pairs, b/c, p |" in text
        data = json.loads(summary.read_text())
        assert data["latest"]["r1"] == f"{first_run}+{second_run}"
        assert data["runs"][f"{first_run}+{second_run}"]["arms"] == ["h", "n"]

        assert cli.main(["--score", f"{first_run},{first_run}"]) == 2  # overlapping requests
        manifest = RunStore("fix_hints", second_run).read_manifest()
        manifest["source_sha256"] = {"core.py": "another hint code"}
        RunStore("fix_hints", second_run).write_manifest(manifest)
        assert cli.main(["--score", both]) == 2
        assert "hint code" in capsys.readouterr().err

    def test_pilot_records_acceptance_and_flags_a_thinking_rejection(
        self,
        bench_data: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        class FakeAPIError(Exception):
            def __init__(self, message: str, status_code: int) -> None:
                super().__init__(message)
                self.message = message
                self.status_code = status_code

        fake_sdk = types.ModuleType("anthropic")
        fake_sdk.APIError = FakeAPIError  # type: ignore[attr-defined]
        fake_sdk.__version__ = "0.0.0-test"  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "anthropic", fake_sdk)

        class Messages:
            def __init__(self) -> None:
                self.batches = _FakeBatches()
                self.calls: list[dict[str, Any]] = []

            def create(self, **params: Any) -> SimpleNamespace:
                self.calls.append(params)
                if params["model"] == MODELS["s55"] and len(self.calls) == 2:
                    raise FakeAPIError(
                        "messages.1: a final assistant message must start with a thinking block",
                        400,
                    )
                data = {
                    "model": params["model"],
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "ok"}],
                    "usage": {"input_tokens": 700, "output_tokens": 40},
                }
                return SimpleNamespace(to_dict=lambda: data)

        messages = Messages()
        monkeypatch.setattr(cli, "make_client", lambda: SimpleNamespace(messages=messages))
        monkeypatch.setattr(cli, "git_state", lambda _root: ("cafe" * 10, False))
        assert cli.main(["--pilot", "--run", "--budget-usd", "1"]) == 1
        out = capsys.readouterr().out
        assert "REJECTED 400" in out and "--protocol text" in out
        assert len(messages.calls) == 4
        assert len(messages.batches.created) == 1
        ledger = Ledger()
        assert ledger.reserved() == 0
        assert ledger.spent() > 0
