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
    actual: Literal["block", "warn", "allow"]
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


def _run_transcript_ingest_guard(entry: CorpusEntry) -> ReplayResult:
    """Guard runner for the short-form-video transcript ingestion path."""
    from ..mcp_spec.transcript_ingest_guard import (
        SourceKind,
        TranscriptIngestGuard,
    )

    guard = TranscriptIngestGuard(reject_threshold=0.9)
    inspection = guard.inspect(entry.payload, source_kind=SourceKind.TRANSCRIPT)
    actual: Literal["block", "warn", "allow"] = inspection.verdict
    return ReplayResult(
        entry_id=entry.id,
        expected_verdict=entry.expected_verdict,
        actual_verdict=actual,
        matched=(actual == entry.expected_verdict),
        guard="transcript_ingest",
        detail=f"risk_score={inspection.risk_score:.2f}",
    )


_GUARD_RUNNERS = {
    "pr_metadata": _run_pr_metadata_guard,
    "transcript_ingest": _run_transcript_ingest_guard,
}

DEFAULT_GUARDS = ("pr_metadata",)

# Per-namespace default guards: replaying ``--namespace short_form_video``
# without an explicit ``--guards`` switches the runner to the
# transcript-ingest guard so the user gets the right semantics for free.
_NAMESPACE_DEFAULT_GUARDS: dict[str, tuple[str, ...]] = {
    "short_form_video": ("transcript_ingest",),
}


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
        default=None,
        help=(
            "Comma-separated guard names. Default depends on --namespace: "
            "'pr_metadata' for the corpus root, 'transcript_ingest' for "
            "'short_form_video', etc."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["tap", "json", "table"],
        default="tap",
    )
    parser.add_argument(
        "--namespace",
        default=None,
        help=(
            "Filter the corpus to one namespace (e.g. 'short_form_video'). "
            "When omitted, all entries are replayed."
        ),
    )
    parser.add_argument(
        "--bundle-lock",
        default=None,
        help=(
            "Path to a policy_bundle.lock file (Feature B / v0.6.0). When "
            "supplied alongside --bundle-manifest, the run refuses if any "
            "preset content hash drifted from the lock."
        ),
    )
    parser.add_argument(
        "--bundle-manifest",
        default=None,
        help="Path to a pack manifest YAML used in tandem with --bundle-lock.",
    )
    args = parser.parse_args(argv)

    if (args.bundle_lock and not args.bundle_manifest) or (
        args.bundle_manifest and not args.bundle_lock
    ):
        print(
            "--bundle-lock and --bundle-manifest must be used together",
            file=sys.stderr,
        )
        return 3

    if args.bundle_lock and args.bundle_manifest:
        from pathlib import Path as _Path

        from ..pack import (
            LockfileDriftError,
            LockfileFormatError,
            PackInstaller,
            load_manifest,
            read_lock,
            verify_lock,
        )

        try:
            manifest = load_manifest(_Path(args.bundle_manifest))
            installed = PackInstaller().install(manifest)
            preset_data = {pid: dict(data) for pid, data in installed.composed.items()}
            lock = read_lock(_Path(args.bundle_lock))
            verify_lock(lock, preset_data)
        except (LockfileDriftError, LockfileFormatError) as exc:
            print(f"bundle-lock check failed: {exc}", file=sys.stderr)
            return 2

    try:
        corpus = load_corpus(args.corpus, namespace=args.namespace)
    except CorpusError as exc:
        print(f"corpus load failed: {exc}", file=sys.stderr)
        return 2

    if args.guards:
        guards = tuple(g.strip() for g in args.guards.split(",") if g.strip())
    elif args.namespace and args.namespace in _NAMESPACE_DEFAULT_GUARDS:
        guards = _NAMESPACE_DEFAULT_GUARDS[args.namespace]
    else:
        guards = DEFAULT_GUARDS
    results = replay_corpus(corpus, guards=guards)

    if args.format == "tap":
        print(_emit_tap(results))
    elif args.format == "json":
        print(_emit_json(results, corpus.name))
    else:
        print(_emit_table(results))

    if any(not r.matched for r in results):
        return 2  # Issue #2: block / mismatch -> exit 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["DEFAULT_GUARDS", "ReplayResult", "main", "replay_corpus"]
