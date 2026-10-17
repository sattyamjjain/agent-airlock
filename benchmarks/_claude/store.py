"""On-disk run store: manifest, planned requests, batch ids and raw results, outside git.

Layout under ``<data dir>/runs/<bench>/<run_id>/``::

    manifest.json        git SHA + dirty flag, airlock and SDK versions, pricing snapshot,
                         request template, seeds, case lists, the operator's command
    requests.jsonl       every planned request (custom_id, params, estimated input tokens)
    batches.json         submit intents and created batch ids, in order
    results/<id>.jsonl   raw batch results, one ``result.to_dict()`` per line
    sync.jsonl           raw responses of synchronous calls (pilots), one per line

Raw outputs stay here and never enter the repository; a benchmark commits only its
aggregates. Re-scoring a stored run costs nothing.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ledger import default_data_dir


def git_state(repo: Path | None = None) -> tuple[str, bool]:
    """Return ``(HEAD sha, dirty)`` for the checkout, or ``("unknown", True)``."""
    cwd = str(repo) if repo is not None else None
    try:
        sha = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True, check=True
        ).stdout.strip()
        status = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown", True
    return sha, bool(status)


def new_run_id(prefix: str) -> str:
    """A sortable run id, e.g. ``fresh-20261013T091500Z``."""
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"


class RunStore:
    """Files for one run of one benchmark.

    Args:
        bench: Benchmark package name, e.g. ``mcptox``.
        run_id: Run identifier (:func:`new_run_id`).
        root: Data directory; defaults to :func:`~.ledger.default_data_dir`.
    """

    def __init__(self, bench: str, run_id: str, root: Path | None = None) -> None:
        base = root if root is not None else default_data_dir()
        self.dir = base / "runs" / bench / run_id
        self.bench = bench
        self.run_id = run_id

    @property
    def manifest_path(self) -> Path:
        return self.dir / "manifest.json"

    def exists(self) -> bool:
        return self.manifest_path.exists()

    def write_manifest(self, manifest: Mapping[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.manifest_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(dict(manifest), indent=2, sort_keys=True, default=str))
        tmp.replace(self.manifest_path)

    def read_manifest(self) -> dict[str, Any]:
        return dict(json.loads(self.manifest_path.read_text()))

    def write_requests(self, rows: Iterable[Mapping[str, Any]]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.dir / "requests.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(dict(row), sort_keys=True, default=str) + "\n")

    def read_requests(self) -> list[dict[str, Any]]:
        path = self.dir / "requests.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    # -- batch bookkeeping -------------------------------------------------------------

    def _batches_path(self) -> Path:
        return self.dir / "batches.json"

    def batches(self) -> list[dict[str, Any]]:
        path = self._batches_path()
        if not path.exists():
            return []
        return list(json.loads(path.read_text()))

    def _write_batches(self, entries: list[dict[str, Any]]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self._batches_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(entries, indent=2, sort_keys=True))
        tmp.replace(self._batches_path())

    def record_intent(self, job: str, custom_ids: list[str]) -> None:
        """Write the submit intent before the batch is created (crash safety)."""
        entries = self.batches()
        entries.append({"job": job, "custom_ids": custom_ids, "batch_id": None})
        self._write_batches(entries)

    def record_batch_id(self, job: str, batch_id: str) -> None:
        entries = self.batches()
        for entry in reversed(entries):
            if entry["job"] == job and entry["batch_id"] is None:
                entry["batch_id"] = batch_id
                break
        else:
            raise KeyError(f"no open intent for job {job!r}")
        self._write_batches(entries)

    def dangling_intents(self) -> list[dict[str, Any]]:
        """Intents with no batch id: a submit crashed between intent and creation."""
        return [entry for entry in self.batches() if entry["batch_id"] is None]

    # -- results -----------------------------------------------------------------------

    def results_path(self, batch_id: str) -> Path:
        return self.dir / "results" / f"{batch_id}.jsonl"

    def append_result(self, batch_id: str, row: Mapping[str, Any]) -> None:
        path = self.results_path(batch_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(row), sort_keys=True, default=str) + "\n")

    def iter_results(self) -> Iterator[dict[str, Any]]:
        """Every stored batch result and synchronous response, in file order."""
        results_dir = self.dir / "results"
        if results_dir.exists():
            for path in sorted(results_dir.glob("*.jsonl")):
                for line in path.read_text().splitlines():
                    if line.strip():
                        yield json.loads(line)
        sync = self.dir / "sync.jsonl"
        if sync.exists():
            for line in sync.read_text().splitlines():
                if line.strip():
                    yield json.loads(line)

    def append_sync(self, row: Mapping[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        with (self.dir / "sync.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(row), sort_keys=True, default=str) + "\n")
