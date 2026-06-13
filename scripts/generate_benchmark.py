#!/usr/bin/env python3
"""Generate BENCHMARK.md from the public guard-suite corpus.

Runs agent-airlock's *comprehensive* guard suite (every guard enabled,
block-iff-any-refuses) over a deterministic exploit-shape corpus and
reports two numbers that matter together:

- **detection rate** — fraction of malicious entries the suite blocks
  (true positives / all ``expected_block=true`` entries);
- **false-positive rate** — fraction of benign entries the suite
  wrongly blocks (false positives / all ``expected_block=false``
  entries).

Honest scope
------------
This is a SELF-corpus: it grades agent-airlock against its own CVE
fixtures. ``expected_block`` is an independent judgement of whether a
payload is malicious; the benchmark measures whether the guard suite
agrees. It is NOT a competitive benchmark and NOT an adaptive-attacker
ASR measurement. A high detection rate on one's own corpus is
expected — the value is the *reproducible, per-class, false-positive-
aware* breakdown, not a headline percentage.

Run::

    python3 scripts/generate_benchmark.py            # writes BENCHMARK.md
    python3 scripts/generate_benchmark.py --check     # CI: fail if stale
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

# Make ``src/`` importable when run from the repo root without an install.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from agent_airlock import (  # noqa: E402
    CodegenDelimiterInjectionGuard,
    EvalRCEGuard,
    FilterEvalRCEGuard,
    MCPServerEnvInterpolationGuard,
    McpSubprocessArgInjectionGuard,
    StdioCommandInjectionGuard,
    UnsafeDeserializationGuard,
)
from agent_airlock.regression_corpus import (  # noqa: E402
    CorpusEntry,
    MetisInspiredCorpusBlockRateGuard,
)

_DEFAULT_CORPUS = _REPO_ROOT / "tests/cves/corpora/airlock_guard_benchmark_2026_06_13.json"
_DEFAULT_OUT = _REPO_ROOT / "BENCHMARK.md"

# A realistic "all guards enabled" deployment. The subprocess guard is
# deny-by-default, so it gets an allowlist of the common static MCP
# launchers; everything else uses shipped defaults.
_ALLOWED_LAUNCHERS = ("uvx", "npx", "node", "python", "python3", "deno")
_SPAWN_KEYS = ("command", "cmd", "args", "argv", "env")


def _comprehensive_chain() -> Any:
    """Return a guard chain: blocks iff ANY guard in the suite refuses.

    Each guard is constructed once. A guard that raises on an unexpected
    payload shape is treated as "did not block" for that guard (the next
    guard still runs) — never as a crash, never as a silent global skip.
    """
    eval_guard = EvalRCEGuard()
    filter_eval_guard = FilterEvalRCEGuard()
    codegen_guard = CodegenDelimiterInjectionGuard()
    deser_guard = UnsafeDeserializationGuard()
    env_guard = MCPServerEnvInterpolationGuard()
    subproc_guard = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED_LAUNCHERS)
    stdio_guard = StdioCommandInjectionGuard()

    def _refuses(guard: Any, payload: Mapping[str, Any]) -> bool:
        try:
            return not guard.evaluate(payload).allowed
        except Exception:  # noqa: BLE001 - a wrong-shape payload is not a block
            return False

    def chain(entry: CorpusEntry) -> bool:
        args = entry.args
        # Generic value-scanning guards run on every entry.
        if _refuses(eval_guard, args):
            return True
        if _refuses(filter_eval_guard, args):
            return True
        if _refuses(codegen_guard, args):
            return True
        if _refuses(deser_guard, args):
            return True
        if _refuses(env_guard, args):
            return True
        # Spawn-shaped guards run only on entries that carry spawn fields,
        # matching how an operator wires them (no coercion of arbitrary
        # strings into a fake argv — that would manufacture false positives).
        if any(k in args for k in _SPAWN_KEYS):
            if _refuses(subproc_guard, args):
                return True
            if _refuses(stdio_guard, args):
                return True
        return False

    return chain


def _load_raw(corpus_path: Path) -> dict[str, Any]:
    return json.loads(corpus_path.read_text(encoding="utf-8"))


def _run(corpus_path: Path) -> dict[str, Any]:
    raw = _load_raw(corpus_path)
    meta = {k: v for k, v in raw.items() if k != "entries"}
    raw_entries = raw["entries"]
    by_id = {e["prompt_id"]: e for e in raw_entries}

    entries = [
        CorpusEntry(
            prompt_id=e["prompt_id"],
            tool_name=e["tool_name"],
            args=e["args"],
            anchor=e["anchor"],
            expected_block=e["expected_block"],
            violation_category=e.get("violation_category"),
        )
        for e in raw_entries
    ]

    # Use the shipped harness so the artifact is genuinely produced by
    # agent-airlock's own code path. baseline/threshold are irrelevant
    # here (we read per-prompt outcomes, not the regression-gate verdict).
    guard = MetisInspiredCorpusBlockRateGuard(
        corpus=entries,
        baseline_block_rate=0.0,
        drift_threshold=1.0,
        guard_chain=_comprehensive_chain(),
    )
    decision = guard.evaluate()

    rows: list[dict[str, Any]] = []
    for o in decision.outcomes:
        src = by_id[o.prompt_id]
        rows.append(
            {
                "prompt_id": o.prompt_id,
                "attack_class": src.get("attack_class", "uncategorized"),
                "cwe": src.get("cwe", "—"),
                "owasp": src.get("owasp", "—"),
                "anchor": o.anchor,
                "expected_block": o.expected_block,
                "blocked": o.blocked,
            }
        )
    return {"meta": meta, "rows": rows}


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n_exploit = sum(1 for r in rows if r["expected_block"])
    n_benign = sum(1 for r in rows if not r["expected_block"])
    tp = sum(1 for r in rows if r["expected_block"] and r["blocked"])
    fn = sum(1 for r in rows if r["expected_block"] and not r["blocked"])
    fp = sum(1 for r in rows if not r["expected_block"] and r["blocked"])
    tn = sum(1 for r in rows if not r["expected_block"] and not r["blocked"])

    per_class: dict[str, dict[str, int]] = defaultdict(
        lambda: {"exploit": 0, "tp": 0, "benign": 0, "fp": 0}
    )
    for r in rows:
        c = per_class[r["attack_class"]]
        if r["expected_block"]:
            c["exploit"] += 1
            c["tp"] += int(r["blocked"])
        else:
            c["benign"] += 1
            c["fp"] += int(r["blocked"])

    return {
        "total": len(rows),
        "n_exploit": n_exploit,
        "n_benign": n_benign,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "detection_rate": (tp / n_exploit) if n_exploit else 0.0,
        "fp_rate": (fp / n_benign) if n_benign else 0.0,
        "accuracy": ((tp + tn) / len(rows)) if rows else 0.0,
        "per_class": dict(sorted(per_class.items())),
    }


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _render(result: dict[str, Any], corpus_path: Path) -> str:
    rows = result["rows"]
    m = _metrics(rows)
    meta = result["meta"]
    today = datetime.date.today().isoformat()
    rel_corpus = corpus_path.relative_to(_REPO_ROOT)
    owasp_codes = sorted({r["owasp"] for r in rows if r["owasp"] != "—"})

    out: list[str] = []
    out.append("# agent-airlock — guard-suite benchmark")
    out.append("")
    out.append(
        "> **What this measures:** whether agent-airlock's full guard suite blocks "
        "malicious tool-call arguments (**detection rate**) without blocking benign "
        "ones (**false-positive rate**), on a deterministic, reproducible corpus."
    )
    out.append("")
    out.append("> **Honest scope:** this is a **self-corpus** — it grades agent-airlock")
    out.append("> against its own CVE fixtures. Every `expected_block` is an *independent*")
    out.append("> judgement of whether the payload is malicious; the suite's job is to")
    out.append("> agree. It is **not** a competitive benchmark and **not** an")
    out.append("> adaptive-attacker / ASR measurement. The value is the reproducible,")
    out.append("> per-class, false-positive-aware breakdown — not the headline number.")
    out.append("")
    out.append("## Headline")
    out.append("")
    out.append("| metric | value |")
    out.append("|---|---|")
    out.append(
        f"| **Detection rate** (malicious blocked) | **{_pct(m['detection_rate'])}** "
        f"({m['tp']}/{m['n_exploit']}) |"
    )
    out.append(
        f"| **False-positive rate** (benign blocked) | **{_pct(m['fp_rate'])}** "
        f"({m['fp']}/{m['n_benign']}) |"
    )
    out.append(f"| Overall accuracy | {_pct(m['accuracy'])} ({m['tp'] + m['tn']}/{m['total']}) |")
    out.append(f"| Corpus size | {m['total']} entries ({m['n_exploit']} malicious, {m['n_benign']} benign) |")
    out.append(f"| Missed attacks (false negatives) | {m['fn']} |")
    out.append("")
    out.append("## By attack class")
    out.append("")
    out.append("| attack class | CWE | OWASP (indicative) | detection | false positives |")
    out.append("|---|---|---|---|---|")
    cwe_by_class: dict[str, str] = {}
    owasp_by_class: dict[str, str] = {}
    for r in rows:
        cwe_by_class.setdefault(r["attack_class"], r["cwe"])
        owasp_by_class.setdefault(r["attack_class"], r["owasp"])
    for cls, c in m["per_class"].items():
        det = f"{c['tp']}/{c['exploit']}" if c["exploit"] else "—"
        fpr = f"{c['fp']}/{c['benign']}" if c["benign"] else "—"
        out.append(
            f"| `{cls}` | {cwe_by_class.get(cls, '—')} | "
            f"{owasp_by_class.get(cls, '—')} | {det} | {fpr} |"
        )
    out.append("")
    out.append("## Every entry")
    out.append("")
    out.append("| prompt | class | expected | suite verdict | anchor |")
    out.append("|---|---|---|---|---|")
    for r in rows:
        expected = "malicious" if r["expected_block"] else "benign"
        if r["expected_block"]:
            verdict = "✅ blocked" if r["blocked"] else "❌ MISSED"
        else:
            verdict = "⚠️ false-positive" if r["blocked"] else "✅ allowed"
        out.append(
            f"| `{r['prompt_id']}` | `{r['attack_class']}` | {expected} | "
            f"{verdict} | `{r['anchor']}` |"
        )
    out.append("")
    out.append("## Methodology")
    out.append("")
    out.append(f"- **Guard suite:** {meta.get('guard_chain', 'comprehensive')}")
    out.append("- **Decision rule:** an entry is *blocked* iff **any** guard in the suite refuses it.")
    out.append(
        "- **`expected_block`:** an independent malicious/benign label per entry. "
        "Detection counts agreements on malicious entries; false positives count "
        "disagreements on benign entries."
    )
    if owasp_codes:
        out.append(
            f"- **OWASP mapping:** indicative alignment with the OWASP Agentic / MCP "
            f"Top-10 ({', '.join(owasp_codes)}), using the codes agent-airlock already "
            f"applies in its presets. The rigorous axis is `attack_class` + CWE."
        )
    out.append(f"- **Corpus:** [`{rel_corpus}`]({rel_corpus}) — deterministic, version-controlled.")
    out.append("")
    out.append("### Known limitations (read before trusting the headline)")
    out.append("")
    out.append(
        "- **Maximal-coverage config, not a tuned deployment.** Every guard runs on every "
        "argument value. This *maximises detection* — overlapping guards catch obfuscations "
        "(e.g. the codegen guard's quote/breakout check catches `eval` indirection the eval "
        "guard alone misses) — but it also **over-blocks benign code-like strings** "
        "(dict access such as `data['key']`, embedded JSON). The false-positive rate above "
        "reflects that. In production, scope guards to their intended fields "
        "(`CodegenDelimiterInjectionGuard(allowed_literal_fields=...)`, "
        "`MCPServerEnvInterpolationGuard(scanned_keys=...)`) to cut false positives."
    )
    out.append(
        "- **Signature/syntax-based, not semantic.** Individual guards match known sink/token "
        "shapes; in isolation several are evadable (e.g. aliasing `eval`). Detection here is a "
        "property of the *suite* (defense-in-depth), not of any single guard."
    )
    out.append(
        "- **Self-corpus.** Payloads derive from agent-airlock's own CVE fixtures, so a high "
        "detection number is expected and is **not** evidence of robustness against novel or "
        "adaptive attackers. Treat this as a coverage / regression baseline, not an ASR result."
    )
    out.append("")
    out.append("### Reproduce")
    out.append("")
    out.append("```bash")
    out.append("make benchmark        # regenerates this file")
    out.append("# or:")
    out.append("python3 scripts/generate_benchmark.py")
    out.append("```")
    out.append("")
    out.append(
        f"_Generated {today} by `scripts/generate_benchmark.py` from "
        f"`{meta.get('corpus_id', rel_corpus.name)}`. Re-run after any guard change to "
        f"refresh the numbers._"
    )
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate BENCHMARK.md from the guard corpus.")
    parser.add_argument("--corpus", type=Path, default=_DEFAULT_CORPUS)
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if the on-disk BENCHMARK.md differs from a fresh render (CI drift gate).",
    )
    args = parser.parse_args(argv)

    if not args.corpus.exists():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        return 1

    result = _run(args.corpus)
    rendered = _render(result, args.corpus)

    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current.strip() != rendered.strip():
            print(f"{args.out.name} is stale — run `make benchmark`.", file=sys.stderr)
            return 1
        print(f"{args.out.name} is up to date.")
        return 0

    args.out.write_text(rendered, encoding="utf-8")
    m = _metrics(result["rows"])
    print(
        f"wrote {args.out.relative_to(_REPO_ROOT)} — "
        f"detection {_pct(m['detection_rate'])} ({m['tp']}/{m['n_exploit']}), "
        f"false-positives {_pct(m['fp_rate'])} ({m['fp']}/{m['n_benign']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
