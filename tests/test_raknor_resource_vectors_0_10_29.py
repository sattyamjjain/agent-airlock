"""Raknor SC-AG-05 resource-governance vectors (v1.1 draft, CC0) against ``CostTracker``.

The vectors come from raknor-ai/agent-governance-standard#4, at the commit named in
``tests/fixtures/third_party/raknor_v1_1_draft/README.md``. Each is a limit plus a timed
sequence of requests; a request is blocked or executed. The mapping to Airlock:

- the limit is ``BudgetConfig(max_tokens_per_session=limit)`` and a request's ``cost`` is
  its tokens (``TokenUsage(input_tokens=cost)``);
- a request is admitted by ``check_admission(estimate)`` with its cost as the estimate,
  then recorded with ``record()`` ("executed"), or refused by it ("blocked");
- ``reset`` is ``CostTracker.reset()``;
- the vector's ``t`` is the clock: ``time.time`` is replaced, so a record's timestamp is
  the vector's time. Nothing in the tracker expires on a timer, which ``p1`` checks past
  its ``counter_ttl_s``.

``z1``, ``z3`` and ``p1`` failed on 0.10.28 (a 0 limit was no limit; the crossing call was
dropped, so its total never reached the limit); ``z2`` and ``p2`` are the positive controls.
``f1`` (a declared model fallback) does not apply: Airlock never substitutes a model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import cost_tracking
from agent_airlock.cost_tracking import BudgetConfig, BudgetExceededError, CostTracker, TokenUsage

_VECTORS = Path(__file__).parent / "fixtures/third_party/raknor_v1_1_draft/resource-governance"


def _vectors() -> list[dict[str, Any]]:
    data = json.loads((_VECTORS / "vectors.json").read_text(encoding="utf-8"))
    assert data["license"] == "CC0-1.0"
    return list(data["vectors"])


def _params() -> list[Any]:
    params = []
    for vector in _vectors():
        if vector["fallback"] is not None:
            params.append(
                pytest.param(
                    vector,
                    id=f"{vector['id']}-not-applicable-airlock-never-substitutes-a-model",
                    marks=pytest.mark.skip(
                        reason="clause 3 declared fallback: Airlock never substitutes a model"
                    ),
                )
            )
        else:
            params.append(pytest.param(vector, id=vector["id"]))
    return params


def _run(vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Each request's outcome, in order: "executed" or "blocked"."""
    clock = {"t": 0.0}
    monkeypatch.setattr(cost_tracking.time, "time", lambda: clock["t"])
    tracker = CostTracker(budget=BudgetConfig(max_tokens_per_session=vector["limit"]))
    outcomes = []
    for step in vector["steps"]:
        clock["t"] = float(step["t"])
        if step.get("reset"):
            tracker.reset()
            continue
        usage = TokenUsage(input_tokens=step["cost"])
        try:
            tracker.check_admission(usage)
        except BudgetExceededError:
            outcomes.append("blocked")
            continue
        tracker.record("tool", usage)
        outcomes.append("executed")
    return outcomes


class TestRaknorResourceVectors:
    """Every applicable vector's expected outcomes, through Airlock's own API."""

    @pytest.mark.parametrize("vector", _params())
    def test_vector(self, vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
        expected = [step["expect"] for step in vector["steps"] if not step.get("reset")]
        assert _run(vector, monkeypatch) == expected

    def test_the_vendored_set_is_the_six_vectors(self) -> None:
        ids = [vector["id"] for vector in _vectors()]
        assert ids == [
            "z1-zero-limit-blocks",
            "z2-under-limit-runs",
            "z3-crossing-request-blocked",
            "p1-exceeded-persists-past-idle",
            "p2-explicit-reset-readmits",
            "f1-fallback-declared",
        ]
