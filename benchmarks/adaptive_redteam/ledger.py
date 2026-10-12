"""The resumable, append-only per-(guard, seed) ledger.

One JSON file per seed at ``ledger/<guard>/<guard>.seed<NN>[.nohints].json``. It
carries a header (schema 1) and the list of classified attempts. A resumed run
loads the file, learns which ``candidate_id``s already ran, and skips them, so a
5-hour or weekly limit that pauses a wave never loses or repeats work.

Schema 1 header fields: ``schema``, ``guard``, ``adapter_mode``, ``preset``,
``seed``, ``fix_hints`` (the hints-on/off arm), ``airlock_version``, ``git_sha``,
``status``, ``budget``. The body carries ``attempts[]`` and the derived
``refusals[]`` / ``bypasses[]`` / ``plateau``.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .oracle import Attempt, CallSpec, Candidate, Outcome
from .stats import queries_to_plateau

SCHEMA = 1


def ledger_path(root: Path, guard: str, seed: int, *, nohints: bool) -> Path:
    """The canonical ledger path for one (guard, seed[, nohints]) run."""
    suffix = ".nohints" if nohints else ""
    return root / guard / f"{guard}.seed{seed:02d}{suffix}.json"


@dataclass
class Ledger:
    """Append-only ledger for one (guard, seed) campaign arm."""

    path: Path
    guard: str
    seed: int
    adapter_mode: str = "C"
    preset: str | None = None
    nohints: bool = False
    airlock_version: str = ""
    git_sha: str = ""
    budget: int = 100
    status: str = "open"
    attempts: list[Attempt] = field(default_factory=list)

    @classmethod
    def open(
        cls,
        root: Path,
        guard: str,
        seed: int,
        *,
        nohints: bool = False,
        adapter_mode: str = "C",
        preset: str | None = None,
        airlock_version: str = "",
        git_sha: str = "",
        budget: int = 100,
    ) -> Ledger:
        """Open (or resume) a ledger file, loading any attempts already recorded."""
        path = ledger_path(root, guard, seed, nohints=nohints)
        if path.exists():
            return cls._load(path, guard, seed, nohints)
        return cls(
            path=path,
            guard=guard,
            seed=seed,
            adapter_mode=adapter_mode,
            preset=preset,
            nohints=nohints,
            airlock_version=airlock_version,
            git_sha=git_sha,
            budget=budget,
        )

    @classmethod
    def _load(cls, path: Path, guard: str, seed: int, nohints: bool) -> Ledger:
        data = json.loads(path.read_text(encoding="utf-8"))
        ledger = cls(
            path=path,
            guard=data.get("guard", guard),
            seed=int(data.get("seed", seed)),
            adapter_mode=data.get("adapter_mode", "C"),
            preset=data.get("preset"),
            nohints=bool(data.get("fix_hints") is False) if "fix_hints" in data else nohints,
            airlock_version=data.get("airlock_version", ""),
            git_sha=data.get("git_sha", ""),
            budget=int(data.get("budget", 100)),
            status=data.get("status", "open"),
        )
        for rec in data.get("attempts", []):
            ledger.attempts.append(_attempt_from_json(rec, guard, seed))
        return ledger

    # -- resume ------------------------------------------------------------

    def completed_ids(self) -> set[str]:
        """Candidate ids already recorded (a resumed run skips these)."""
        return {a.candidate.candidate_id for a in self.attempts}

    def is_done(self, candidate_id: str) -> bool:
        return candidate_id in self.completed_ids()

    # -- append ------------------------------------------------------------

    def record(self, attempt: Attempt) -> None:
        """Append one classified attempt and persist atomically."""
        if self.is_done(attempt.candidate.candidate_id):
            return
        self.attempts.append(attempt)
        self.flush()

    def mark_plateaued(self) -> None:
        self.status = "plateaued"
        self.flush()

    def mark_complete(self) -> None:
        self.status = "complete"
        self.flush()

    # -- derived -----------------------------------------------------------

    def bypasses(self) -> list[Attempt]:
        return [a for a in self.attempts if a.outcome is Outcome.BYPASS]

    def refusals(self) -> list[Attempt]:
        return [a for a in self.attempts if a.outcome is Outcome.HARD_BLOCK]

    def plateau(self) -> int | None:
        return queries_to_plateau(self.attempts)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "guard": self.guard,
            "adapter_mode": self.adapter_mode,
            "preset": self.preset,
            "seed": self.seed,
            # ``fix_hints`` records the arm: True = hints shown, False = ablation.
            "fix_hints": not self.nohints,
            "airlock_version": self.airlock_version,
            "git_sha": self.git_sha,
            "status": self.status,
            "budget": self.budget,
            "attempts": [a.to_json() for a in self.attempts],
            "refusals": [a.candidate.candidate_id for a in self.refusals()],
            "bypasses": [a.candidate.candidate_id for a in self.bypasses()],
            "plateau": self.plateau(),
        }

    def flush(self) -> None:
        """Write the ledger atomically (temp file + rename)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.to_json(), indent=2, sort_keys=False)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def _attempt_from_json(rec: dict[str, Any], guard: str, seed: int) -> Attempt:
    from .oracle import Intent

    candidate = Candidate(
        guard=guard,
        seed=seed,
        candidate_id=str(rec["candidate_id"]),
        call=CallSpec.from_json(rec.get("call", {})),
        intent=Intent(rec.get("intent", "attack")),
    )
    return Attempt(
        candidate=candidate,
        outcome=Outcome(rec["outcome"]),
        block_reason=rec.get("block_reason"),
        fix_hints=list(rec.get("fix_hints", [])),
        sink_hits=list(rec.get("sink_hits", [])),
        novel=bool(rec.get("novel", True)),
    )
