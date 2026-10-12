"""Plan, price, submit, wait for and collect Message Batches, idempotently.

A request is a :class:`PlannedRequest` (custom id, Messages API params, estimated input
tokens). The flow for one job:

1. :func:`plan_cost` prices the job's worst case and expected cost;
2. :func:`submit` reserves the worst case in the ledger, writes the submit intent, creates
   the batch, then records the batch id. A crash between intent and creation leaves a
   dangling intent, and :func:`submit` refuses to resubmit over one without
   ``force_resubmit`` (it may have been created server-side; check the Console first);
3. :func:`wait` polls until the batch has ended;
4. :func:`collect` streams results to the run store, prices every succeeded result into
   the ledger at Batch rates, and settles the reservation.

Refusals and ``max_tokens`` stops are results, never retried. ``errored``, ``expired`` and
``canceled`` requests are returned by :func:`resubmission_set` for at most two retries.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .budget import BudgetGuard
from .ledger import Ledger
from .pricing import estimate_usd, price_usage, worst_case_usd
from .store import RunStore

CUSTOM_ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
RETRYABLE = frozenset({"errored", "expired", "canceled"})


@dataclass(frozen=True)
class PlannedRequest:
    """One Messages API request in a batch."""

    custom_id: str
    params: Mapping[str, Any]
    est_input_tokens: int

    def __post_init__(self) -> None:
        if not CUSTOM_ID_RE.match(self.custom_id):
            raise ValueError(f"invalid custom_id {self.custom_id!r} (want [a-zA-Z0-9_-]{{1,64}})")
        if "model" not in self.params or "max_tokens" not in self.params:
            raise ValueError(f"{self.custom_id}: params need model and max_tokens")


@dataclass
class CostPlan:
    """Priced plan for a set of requests."""

    requests: int
    input_tokens: int
    worst_case_usd: float
    expected_usd: dict[int, float] = field(default_factory=dict)
    """Expected cost keyed by assumed output tokens per request (visible + thinking)."""


def plan_cost(
    requests: Iterable[PlannedRequest],
    *,
    batch: bool,
    assumed_outputs: Iterable[int] = (300, 1300),
) -> CostPlan:
    """Price ``requests``: worst case (``max_tokens`` all spent) and expected at each assumption."""
    rows = list(requests)
    outputs = tuple(assumed_outputs)
    worst = 0.0
    expected = dict.fromkeys(outputs, 0.0)
    tokens = 0
    for req in rows:
        model = str(req.params["model"])
        tokens += req.est_input_tokens
        worst += worst_case_usd(
            model, req.est_input_tokens, int(req.params["max_tokens"]), batch=batch
        )
        for out in outputs:
            expected[out] += estimate_usd(model, req.est_input_tokens, out, batch=batch)
    return CostPlan(
        requests=len(rows),
        input_tokens=tokens,
        worst_case_usd=round(worst, 4),
        expected_usd={out: round(usd, 4) for out, usd in expected.items()},
    )


def submit(
    client: Any,
    requests: list[PlannedRequest],
    *,
    job: str,
    guard: BudgetGuard,
    store: RunStore,
    force_resubmit: bool = False,
) -> str:
    """Reserve, record intent, create the batch, record its id. Returns the batch id.

    Raises:
        BudgetExceededError: The job's worst case does not fit.
        RuntimeError: A dangling intent exists and ``force_resubmit`` is False.
    """
    if not requests:
        raise ValueError(f"job {job!r} has no requests")
    if store.dangling_intents() and not force_resubmit:
        raise RuntimeError(
            f"run {store.run_id} has a submit intent with no batch id (a crash mid-submit?). "
            "Check the Console's batch list before resubmitting with --force-resubmit."
        )
    plan = plan_cost(requests, batch=True)
    guard.admit(job, plan.worst_case_usd)
    store.record_intent(job, [r.custom_id for r in requests])
    try:
        batch = client.messages.batches.create(
            requests=[{"custom_id": r.custom_id, "params": dict(r.params)} for r in requests]
        )
    except Exception:
        guard.ledger.release(job, reason="batch create failed")
        raise
    store.record_batch_id(job, str(batch.id))
    return str(batch.id)


def wait(client: Any, batch_id: str, *, poll_s: float = 60.0, timeout_s: float = 26 * 3600) -> Any:
    """Poll until the batch has ended; return the final batch object.

    Raises:
        TimeoutError: The batch did not end within ``timeout_s``.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        batch = client.messages.batches.retrieve(batch_id)
        if batch.processing_status == "ended":
            return batch
        if time.monotonic() > deadline:
            raise TimeoutError(f"batch {batch_id} still {batch.processing_status}")
        time.sleep(poll_s)


def _result_dict(result: Any) -> dict[str, Any]:
    if isinstance(result, Mapping):
        return {str(k): v for k, v in result.items()}
    for name in ("to_dict", "model_dump"):
        method = getattr(result, name, None)
        if callable(method):
            data: Mapping[str, Any] = method()
            return {str(k): v for k, v in data.items()}
    raise TypeError(f"cannot serialise batch result of type {type(result).__name__}")


def collect(
    client: Any, batch_id: str, *, job: str, ledger: Ledger, store: RunStore
) -> dict[str, str]:
    """Store raw results, price succeeded ones into the ledger, settle the job.

    Returns:
        ``custom_id -> result type`` (``succeeded`` / ``errored`` / ``canceled`` / ``expired``).
    """
    outcome: dict[str, str] = {}
    for result in client.messages.batches.results(batch_id):
        row = _result_dict(result)
        store.append_result(batch_id, row)
        custom_id = str(row.get("custom_id"))
        res = row.get("result") or {}
        kind = str(res.get("type"))
        outcome[custom_id] = kind
        if kind == "succeeded":
            message = res.get("message") or {}
            model = str(message.get("model"))
            usage = message.get("usage") or {}
            ledger.record_usage(
                job=job,
                custom_id=custom_id,
                model=model,
                batch=True,
                usage=usage,
                usd=price_usage(model, usage, batch=True),
            )
    ledger.settle(job)
    return outcome


def resubmission_set(
    planned: Iterable[str], attempts: Mapping[str, list[str]], *, max_retries: int = 2
) -> list[str]:
    """Custom ids to resubmit: retryable outcomes with fewer than ``max_retries`` retries.

    Args:
        planned: Every custom id the run plans.
        attempts: ``custom_id -> [result type per attempt, oldest first]``.
    """
    out = []
    for cid in planned:
        history = attempts.get(cid, [])
        if not history or history[-1] in RETRYABLE and len(history) <= max_retries:
            out.append(cid)
    return out


def record_sync_message(
    message: Any, *, job: str, custom_id: str, ledger: Ledger, store: RunStore | None = None
) -> float:
    """Price a synchronous response into the ledger (and the store). Returns its USD cost."""
    data = message if isinstance(message, Mapping) else message.to_dict()
    model = str(data.get("model"))
    usage = data.get("usage") or {}
    usd = price_usage(model, usage, batch=False)
    ledger.record_usage(
        job=job, custom_id=custom_id, model=model, batch=False, usage=usage, usd=usd
    )
    if store is not None:
        store.append_sync(
            {"custom_id": custom_id, "result": {"type": "succeeded", "message": data}}
        )
    return usd
