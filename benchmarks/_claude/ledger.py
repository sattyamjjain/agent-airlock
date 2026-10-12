"""Append-only spend ledger shared by every credit-funded benchmark.

One JSON object per line, written under an exclusive ``fcntl`` lock so two runs on the
same machine cannot interleave a record. Records:

* ``reserve`` - a job's worst-case cost, held while it runs;
* ``usage`` - one response's priced usage (the raw usage dict is kept beside the price);
* ``settle`` / ``release`` - the job finished (or was abandoned); its reservation is freed.

:meth:`Ledger.spent` sums ``usage`` records; :meth:`Ledger.reserved` sums open
reservations. The ledger never stores prompts, outputs or credentials.

Location: ``$AIRLOCK_BENCH_LEDGER``, else ``$AIRLOCK_BENCH_DATA/ledger.jsonl``, else
``~/.cache/agent-airlock-bench/ledger.jsonl``. Use one ledger per credit cycle.
"""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def default_data_dir() -> Path:
    """Directory for downloaded datasets, raw run outputs and the ledger (never in git)."""
    configured = os.environ.get("AIRLOCK_BENCH_DATA")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".cache" / "agent-airlock-bench"


def default_ledger_path() -> Path:
    """The ledger file for this credit cycle."""
    configured = os.environ.get("AIRLOCK_BENCH_LEDGER")
    if configured:
        return Path(configured).expanduser()
    return default_data_dir() / "ledger.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Ledger:
    """Append-only JSONL spend ledger.

    Args:
        path: Ledger file. Created (with parents) on first write.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else default_ledger_path()

    def _append(self, record: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": _now(), **record}, sort_keys=True, default=str)
        with self.path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def records(self) -> Iterator[dict[str, Any]]:
        """Yield every record, oldest first. A torn final line is skipped."""
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_SH)
            try:
                lines = handle.readlines()
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

    def reserve(self, job: str, usd: float) -> None:
        """Hold ``usd`` for ``job`` until it is settled or released."""
        self._append({"type": "reserve", "job": job, "usd": round(float(usd), 6)})

    def record_usage(
        self,
        *,
        job: str,
        custom_id: str,
        model: str,
        batch: bool,
        usage: Mapping[str, Any],
        usd: float,
    ) -> None:
        """Record one response's priced usage."""
        self._append(
            {
                "type": "usage",
                "job": job,
                "custom_id": custom_id,
                "model": model,
                "batch": batch,
                "usage": dict(usage),
                "usd": round(float(usd), 8),
            }
        )

    def settle(self, job: str) -> None:
        """Free ``job``'s reservation; its real spend is the sum of its usage records."""
        self._append({"type": "settle", "job": job})

    def release(self, job: str, reason: str = "") -> None:
        """Free ``job``'s reservation without it having run (or after a failure)."""
        self._append({"type": "release", "job": job, "reason": reason})

    def spent(self, job: str | None = None) -> float:
        """Total priced usage, for one job or overall."""
        return round(
            sum(
                float(r.get("usd", 0.0))
                for r in self.records()
                if r.get("type") == "usage" and (job is None or r.get("job") == job)
            ),
            6,
        )

    def reserved(self) -> float:
        """Sum of reservations whose job has not been settled or released."""
        open_jobs: dict[str, float] = {}
        for r in self.records():
            kind = r.get("type")
            job = str(r.get("job"))
            if kind == "reserve":
                open_jobs[job] = open_jobs.get(job, 0.0) + float(r.get("usd", 0.0))
            elif kind in {"settle", "release"}:
                open_jobs.pop(job, None)
        return round(sum(open_jobs.values()), 6)

    def by_job(self) -> dict[str, float]:
        """Spend per job, for the ledger report."""
        out: dict[str, float] = {}
        for r in self.records():
            if r.get("type") == "usage":
                job = str(r.get("job"))
                out[job] = out.get(job, 0.0) + float(r.get("usd", 0.0))
        return {job: round(usd, 6) for job, usd in sorted(out.items())}
