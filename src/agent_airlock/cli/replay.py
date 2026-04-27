"""``airlock replay`` — corpus regression bench (v0.5.8+).

Pipes each payload in a versioned corpus through the installed
guard chain (or a caller-specified subset) and emits a pass/fail
matrix in TAP, JSON, or table form.

Exit codes:
    0 — every payload met its ``expected_verdict``
    1 — at least one mismatch (the JSON form names them)
    2 — corpus parse / hash error

Usage::

    airlock replay --corpus wild-2026-04
    airlock replay --corpus wild-2026-04 --format json
    airlock replay --corpus wild-2026-04 --guards pr_metadata
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import Literal

from ..corpus import Corpus, CorpusEntry, CorpusError, load_corpus


@dataclass(frozen=True)
class ReplayResult:
    """One payload's per-guard verdict."""

    entry_id: str
    expected_verdict: str
    actual_verdict: Literal["block", "warn", "allow"]
    matched: bool
    guard: str
    detail: str = ""


def _run_pr_metadata_guard(entry: CorpusEntry) -> ReplayResult:
    """Default guard runner: PR-metadata guard from v0.5.8."""
    from ..mcp_spec.pr_metadata_guard import PRMetadataGuard

    guard = PRMetadataGuard(reject_threshold=0.9)
    sanitized = guard.sanitize(entry.payload, source="pr_body")
    if sanitized.risk_score >= 0.9:
        actual = "block"
    elif sanitized.risk_score > 0.0:
        actual = "warn"
    else:
        actual = "allow"
    return ReplayResult(
        entry_id=entry.id,
        expected_verdict=entry.expected_verdict,
        actual_verdict=actual,
        matched=(actual == entry.expected_verdict),
        guard="pr_metadata",
        detail=f"risk_score={sanitized.risk_score:.2f}, matches={len(sanitized.matches)}",
    )


_GUARD_RUNNERS = {
    "pr_metadata": _run_pr_metadata_guard,
}

DEFAULT_GUARDS = ("pr_metadata",)


def replay_corpus(
    corpus: Corpus,
    *,
    guards: tuple[str, ...] = DEFAULT_GUARDS,
) -> list[ReplayResult]:
    """Run every entry through every requested guard."""
    out: list[ReplayResult] = []
    for entry in corpus.entries:
        for g in guards:
            runner = _GUARD_RUNNERS.get(g)
            if runner is None:
                out.append(
                    ReplayResult(
                        entry_id=entry.id,
                        expected_verdict=entry.expected_verdict,
                        actual_verdict="allow",
                        matched=False,
                        guard=g,
                        detail=f"unknown guard {g!r}",
                    )
                )
                continue
            out.append(runner(entry))
    return out


def _emit_tap(results: list[ReplayResult]) -> str:
    lines = [f"1..{len(results)}"]
    for i, r in enumerate(results, 1):
        ok = "ok" if r.matched else "not ok"
        lines.append(
            f"{ok} {i} - {r.entry_id} guard={r.guard} "
            f"expected={r.expected_verdict} actual={r.actual_verdict} "
            f"({r.detail})"
        )
    return "\n".join(lines)


def _emit_json(results: list[ReplayResult], corpus_name: str) -> str:
    return json.dumps(
        {
            "corpus": corpus_name,
            "total": len(results),
            "matched": sum(1 for r in results if r.matched),
            "mismatched": sum(1 for r in results if not r.matched),
            "results": [asdict(r) for r in results],
        },
        indent=2,
    )


def _emit_table(results: list[ReplayResult]) -> str:
    rows = ["| Entry | Guard | Expected | Actual | OK |", "|---|---|---|---|---|"]
    for r in results:
        rows.append(
            f"| {r.entry_id} | {r.guard} | {r.expected_verdict} | "
            f"{r.actual_verdict} | {'✓' if r.matched else '✗'} |"
        )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--corpus", required=True, help="Corpus name, e.g. 'wild-2026-04'")
    parser.add_argument(
        "--guards",
        default=",".join(DEFAULT_GUARDS),
        help="Comma-separated guard names. Default: pr_metadata",
    )
    parser.add_argument(
        "--format",
        choices=["tap", "json", "table"],
        default="tap",
    )
    args = parser.parse_args(argv)

    try:
        corpus = load_corpus(args.corpus)
    except CorpusError as exc:
        print(f"corpus load failed: {exc}", file=sys.stderr)
        return 2

    guards = tuple(g.strip() for g in args.guards.split(",") if g.strip())
    results = replay_corpus(corpus, guards=guards)

    if args.format == "tap":
        print(_emit_tap(results))
    elif args.format == "json":
        print(_emit_json(results, corpus.name))
    else:
        print(_emit_table(results))

    return 0 if all(r.matched for r in results) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["DEFAULT_GUARDS", "ReplayResult", "main", "replay_corpus"]
