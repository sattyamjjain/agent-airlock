"""Tests for ``benchmarks._claude``: the plumbing that protects the API credit.

Every assertion here runs without the ``anthropic`` SDK and without network access: the
client checks the environment before importing the SDK, and batches are exercised
against a fake client.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from benchmarks._claude import batch as batch_mod
from benchmarks._claude.budget import BudgetExceededError, BudgetGuard, hard_cap_usd
from benchmarks._claude.client import ClientConfigError, check_environment
from benchmarks._claude.ledger import Ledger
from benchmarks._claude.models import DEFAULT_EFFORT, MODELS, model_alias, resolve_model
from benchmarks._claude.pricing import (
    UnpricedModelError,
    estimate_usd,
    price_usage,
    rates_for,
    worst_case_usd,
)
from benchmarks._claude.stats import (
    cluster_bootstrap_ci,
    format_rate,
    mcnemar_exact_p,
    newcombe_diff_ci,
)
from benchmarks._claude.store import RunStore


class TestPricing:
    def test_exact_ids_priced_at_list(self) -> None:
        assert rates_for("claude-opus-5-5").input == pytest.approx(4.0)
        assert rates_for("claude-opus-5-5").output == pytest.approx(20.0)
        assert rates_for("claude-sonnet-5-5").input == pytest.approx(2.0)
        assert rates_for("claude-haiku-5-5").output == pytest.approx(0.5)
        assert rates_for("claude-fable-5-1").output == pytest.approx(50.0)

    def test_opus_5_5_is_not_priced_as_opus_5(self) -> None:
        # The agentdojo prefix table metered claude-opus-5-5 at Opus 5's $5/$25.
        assert rates_for("claude-opus-5-5").input != rates_for("claude-opus-5").input

    def test_unknown_id_raises_never_zero(self) -> None:
        with pytest.raises(UnpricedModelError):
            rates_for("claude-imaginary-9")

    def test_cache_read_multipliers(self) -> None:
        assert rates_for("claude-fable-5-1").cache_read == pytest.approx(0.25)
        assert rates_for("claude-opus-5-5").cache_read == pytest.approx(0.20)
        assert rates_for("claude-sonnet-5-5").cache_read == pytest.approx(0.10)
        assert rates_for("claude-haiku-5-5").cache_read == pytest.approx(0.01)

    def test_haiku_long_prompt_tier(self) -> None:
        short = rates_for("claude-haiku-5-5", 100_000)
        long_ = rates_for("claude-haiku-5-5", 100_001)
        assert short.input == pytest.approx(0.10)
        assert long_.input == pytest.approx(0.50)
        assert long_.output == pytest.approx(2.50)

    def test_batch_halves(self) -> None:
        usage = {"input_tokens": 1_000_000, "output_tokens": 1_000_000}
        assert price_usage("claude-sonnet-5-5", usage, batch=False) == pytest.approx(12.0)
        assert price_usage("claude-sonnet-5-5", usage, batch=True) == pytest.approx(6.0)

    def test_cache_tokens_priced(self) -> None:
        usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 1_000_000,
            "cache_creation_input_tokens": 1_000_000,
        }
        # Opus 5.5: read 0.05x of $4 = $0.20, untyped write counted as 5-minute 1.25x = $5.
        assert price_usage("claude-opus-5-5", usage, batch=False) == pytest.approx(5.20)

    def test_one_hour_write_split(self) -> None:
        usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 1_000_000,
            "cache_creation": {
                "ephemeral_5m_input_tokens": 0,
                "ephemeral_1h_input_tokens": 1_000_000,
            },
        }
        assert price_usage("claude-opus-5-5", usage, batch=False) == pytest.approx(8.0)

    def test_sdk_usage_object(self) -> None:
        usage = SimpleNamespace(input_tokens=1000, output_tokens=100, cache_read_input_tokens=None)
        assert price_usage("claude-haiku-5-5", usage, batch=False) == pytest.approx(0.00015)

    def test_worst_case_and_estimate(self) -> None:
        assert worst_case_usd("claude-opus-5-5", 2000, 4096, batch=True) == pytest.approx(
            (2000 * 4 + 4096 * 20) / 1e6 / 2
        )
        assert estimate_usd("claude-haiku-5-5", 1800, 300, batch=True) == pytest.approx(
            (1800 * 0.1 + 300 * 0.5) / 1e6 / 2
        )


class TestModels:
    def test_aliases_round_trip(self) -> None:
        for alias, model in MODELS.items():
            assert resolve_model(alias) == model
            assert resolve_model(model) == model
            assert model_alias(model) == alias

    def test_effort_pinned_for_every_model(self) -> None:
        assert set(DEFAULT_EFFORT) == set(MODELS.values())
        assert DEFAULT_EFFORT["claude-opus-5-5"] == "medium"

    def test_unknown_model(self) -> None:
        with pytest.raises(ValueError, match="unknown model"):
            resolve_model("gpt-4o")


class TestLedgerAndBudget:
    def test_reserve_settle_spent(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        ledger.reserve("job-a", 5.0)
        assert ledger.reserved() == pytest.approx(5.0)
        ledger.record_usage(
            job="job-a",
            custom_id="x1",
            model="claude-haiku-5-5",
            batch=True,
            usage={"input_tokens": 10},
            usd=0.25,
        )
        ledger.settle("job-a")
        assert ledger.reserved() == 0
        assert ledger.spent() == pytest.approx(0.25)
        assert ledger.by_job() == {"job-a": pytest.approx(0.25)}

    def test_ledger_never_stores_text(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        ledger.record_usage(
            job="j",
            custom_id="c",
            model="claude-haiku-5-5",
            batch=False,
            usage={"input_tokens": 1, "output_tokens": 2},
            usd=0.0,
        )
        record = json.loads((tmp_path / "ledger.jsonl").read_text().strip())
        assert set(record) == {"ts", "type", "job", "custom_id", "model", "batch", "usage", "usd"}

    def test_torn_line_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        path.write_text('{"type": "usage", "job": "j", "usd": 1.0}\n{"type": "usa')
        assert Ledger(path).spent() == pytest.approx(1.0)

    def test_guard_admits_within_cap(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        guard = BudgetGuard(10.0, ledger)
        guard.admit("job", 9.0)
        assert ledger.reserved() == pytest.approx(9.0)

    def test_guard_refuses_over_command_cap(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        guard = BudgetGuard(10.0, ledger)
        guard.admit("first", 6.0)
        with pytest.raises(BudgetExceededError):
            guard.admit("second", 6.0)

    def test_guard_refuses_over_hard_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIRLOCK_BENCH_HARD_CAP_USD", "20")
        ledger = Ledger(tmp_path / "ledger.jsonl")
        ledger.record_usage(
            job="old", custom_id="c", model="claude-haiku-5-5", batch=True, usage={}, usd=15.0
        )
        guard = BudgetGuard(100.0, ledger)
        with pytest.raises(BudgetExceededError, match="hard cap"):
            guard.admit("new", 6.0)

    def test_default_hard_cap_keeps_reserve(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AIRLOCK_BENCH_HARD_CAP_USD", raising=False)
        assert hard_cap_usd() == 180.0

    def test_nonpositive_budget_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            BudgetGuard(0, Ledger(tmp_path / "l.jsonl"))


class TestClientEnvironment:
    def test_missing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(ClientConfigError, match="not set"):
            check_environment()

    def test_auth_token_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "tok")
        with pytest.raises(ClientConfigError, match="AUTH_TOKEN"):
            check_environment()

    def test_foreign_base_url_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
        monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://proxy.example.com")
        with pytest.raises(ClientConfigError, match="BASE_URL"):
            check_environment()

    def test_error_messages_never_contain_the_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = "sk-ant-api03-thisMustNeverAppear"
        monkeypatch.setenv("ANTHROPIC_API_KEY", secret)
        monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "x")
        with pytest.raises(ClientConfigError) as excinfo:
            check_environment()
        assert secret not in str(excinfo.value)

    def test_valid_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-real")
        monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/")
        assert check_environment() == "sk-test-not-real"


class _FakeBatches:
    def __init__(self, results: list[dict[str, Any]]) -> None:
        self.created: list[Any] = []
        self._results = results

    def create(self, requests: list[dict[str, Any]]) -> SimpleNamespace:
        self.created.append(requests)
        return SimpleNamespace(id="msgbatch_test1")

    def retrieve(self, batch_id: str) -> SimpleNamespace:
        return SimpleNamespace(processing_status="ended")

    def results(self, batch_id: str) -> list[dict[str, Any]]:
        return self._results


def _fake_client(results: list[dict[str, Any]]) -> SimpleNamespace:
    return SimpleNamespace(messages=SimpleNamespace(batches=_FakeBatches(results)))


class TestBatch:
    def _req(self, cid: str) -> batch_mod.PlannedRequest:
        return batch_mod.PlannedRequest(
            custom_id=cid,
            params={"model": "claude-haiku-5-5", "max_tokens": 1000, "messages": []},
            est_input_tokens=2000,
        )

    def test_custom_id_validated(self) -> None:
        with pytest.raises(ValueError, match="custom_id"):
            self._req("has space")
        with pytest.raises(ValueError, match="custom_id"):
            self._req("x" * 65)

    def test_plan_cost(self) -> None:
        plan = batch_mod.plan_cost([self._req("a"), self._req("b")], batch=True)
        assert plan.requests == 2
        assert plan.worst_case_usd == pytest.approx(
            2 * (2000 * 0.1 + 1000 * 0.5) / 1e6 / 2, abs=1e-4
        )

    def test_submit_collect_round_trip(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        store = RunStore("unit", "run1", root=tmp_path)
        store.write_manifest({"x": 1})
        results = [
            {
                "custom_id": "a",
                "result": {
                    "type": "succeeded",
                    "message": {
                        "model": "claude-haiku-5-5",
                        "usage": {"input_tokens": 2000, "output_tokens": 300},
                    },
                },
            },
            {"custom_id": "b", "result": {"type": "errored", "error": {"type": "invalid_request"}}},
        ]
        client = _fake_client(results)
        guard = BudgetGuard(5.0, ledger)
        batch_id = batch_mod.submit(
            client, [self._req("a"), self._req("b")], job="j1", guard=guard, store=store
        )
        assert batch_id == "msgbatch_test1"
        assert ledger.reserved() > 0
        outcome = batch_mod.collect(client, batch_id, job="j1", ledger=ledger, store=store)
        assert outcome == {"a": "succeeded", "b": "errored"}
        assert ledger.reserved() == 0
        assert ledger.spent() == pytest.approx((2000 * 0.1 + 300 * 0.5) / 1e6 / 2)
        assert len(list(store.iter_results())) == 2

    def test_dangling_intent_blocks_resubmit(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        store = RunStore("unit", "run2", root=tmp_path)
        store.record_intent("crashed", ["a"])
        with pytest.raises(RuntimeError, match="no batch id"):
            batch_mod.submit(
                _fake_client([]),
                [self._req("a")],
                job="j2",
                guard=BudgetGuard(5.0, ledger),
                store=store,
            )

    def test_failed_create_releases_reservation(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "ledger.jsonl")
        store = RunStore("unit", "run3", root=tmp_path)

        class Boom(_FakeBatches):
            def create(self, requests: list[dict[str, Any]]) -> SimpleNamespace:
                raise RuntimeError("network down")

        client = SimpleNamespace(messages=SimpleNamespace(batches=Boom([])))
        with pytest.raises(RuntimeError, match="network down"):
            batch_mod.submit(
                client, [self._req("a")], job="j3", guard=BudgetGuard(5.0, ledger), store=store
            )
        assert ledger.reserved() == 0

    def test_resubmission_never_retries_results(self) -> None:
        planned = ["ok", "refused", "err1", "err3", "new"]
        attempts = {
            "ok": ["succeeded"],
            "refused": ["succeeded"],
            "err1": ["errored"],
            "err3": ["errored", "expired", "errored"],
        }
        assert batch_mod.resubmission_set(planned, attempts) == ["err1", "new"]


class TestStats:
    def test_newcombe_matches_reference(self) -> None:
        # Newcombe (1998) worked example: 56/70 vs 48/80 -> 0.0524 to 0.3339.
        lo, hi = newcombe_diff_ci(56, 70, 48, 80)
        assert lo == pytest.approx(0.0524, abs=5e-4)
        assert hi == pytest.approx(0.3339, abs=5e-4)

    def test_mcnemar(self) -> None:
        assert mcnemar_exact_p(0, 0) == 1.0
        assert mcnemar_exact_p(0, 6) == pytest.approx(2 / 64)
        assert mcnemar_exact_p(5, 5) == 1.0

    def test_cluster_bootstrap_is_seeded(self) -> None:
        clusters = {"s1": [1, 1, 0], "s2": [0, 0], "s3": [1]}

        def rate(rows: list[int]) -> float:
            return sum(rows) / len(rows)

        first = cluster_bootstrap_ci(clusters, rate, iterations=200)
        second = cluster_bootstrap_ci(clusters, rate, iterations=200)
        assert first == second
        assert 0.0 <= first[0] <= first[1] <= 1.0

    def test_format_rate(self) -> None:
        assert format_rate(0, 0) == "n=0 (not measured)"
        assert format_rate(5, 10).startswith("5/10 (50.0%")
