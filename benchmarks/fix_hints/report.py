"""Aggregate scored outcomes into a round's summary, and render it for ``RESULTS.md``.

Statistics, all descriptive (no multiplicity correction; the p-values are not a
significance claim across the table):

* **RR** (recovery rate) and **SR** (semantic recovery) per model x arm x category, each
  with a 95% Wilson interval (:func:`benchmarks._claude.stats.wilson_interval`);
* **controls**: not retried, split stopped / switched / other tool, against retried;
* **McNemar exact** (:func:`benchmarks._claude.stats.mcnemar_exact_p`) for H vs N and S
  vs H on the same scenarios, and for R2 vs R1 per arm. H vs N leaves out scenarios
  whose H and N payloads are byte-identical (nothing to remove); their discordance is
  reported as noise.

Denominators exclude ``errored`` and ``harness_error`` outcomes, which are counted
beside them. A cell with no outcomes is ``n=0``, never ``0%``.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from benchmarks._claude.pricing import UnpricedModelError, price_usage
from benchmarks._claude.stats import mcnemar_exact_p, wilson_interval

from .payloads import ARMS
from .scenarios import CATEGORIES, CATEGORY_GROUP, CONTROL_CATEGORIES
from .score import EXCLUDED, OUTCOMES, Outcome

RESULTS_MARKER = "<!-- FIX-HINTS-ROUNDS: append newest below; never edit dated blocks -->"
PLACEHOLDER_PREFIX = "_Not yet measured._"
REPO_BLOB = "https://github.com/sattyamjjain/agent-airlock/blob/main"

REPAIR_CATEGORIES: tuple[str, ...] = tuple(
    name for name, _ in CATEGORIES if name not in CONTROL_CATEGORIES
)
SCOPES: tuple[str, ...] = (
    "type",
    "missing",
    "ghost",
    "constraint",
    "path_stated",
    "path_unstated",
    "endpoint_stated",
    "endpoint_unstated",
    "multi",
    "all_repair",
    "control_policy",
    "control_capability",
)
"""The rows of the paired-test tables."""


def _scope_of(category: str) -> str:
    group = CATEGORY_GROUP[category]
    return group if group in {"type", "constraint"} else category


def _in_scope(category: str, scope: str) -> bool:
    if scope == "all_repair":
        return category not in CONTROL_CATEGORIES
    return _scope_of(category) == scope


# --------------------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------------------


def _cell(outcomes: list[Outcome]) -> dict[str, Any]:
    counted = [o for o in outcomes if o.counted]
    n = len(counted)
    success = sum(o.success for o in counted)
    semantic = sum(o.semantic_success for o in counted)
    rr_lo, rr_hi = wilson_interval(success, n) if n else (0.0, 0.0)
    sr_lo, sr_hi = wilson_interval(semantic, n) if n else (0.0, 0.0)
    return {
        "n": n,
        "success": success,
        "semantic": semantic,
        "rr": success / n if n else None,
        "rr_ci": [rr_lo, rr_hi] if n else None,
        "sr": semantic / n if n else None,
        "sr_ci": [sr_lo, sr_hi] if n else None,
        "identical_retries": sum(1 for o in counted if o.identical_retry),
        "outcomes": dict(Counter(o.outcome for o in outcomes)),
    }


def cells(outcomes: Iterable[Outcome]) -> list[dict[str, Any]]:
    """One cell per model x arm x category, plus an ``all_repair`` cell per model x arm."""
    grouped: dict[tuple[str, str, str], list[Outcome]] = defaultdict(list)
    for outcome in outcomes:
        grouped[(outcome.model, outcome.arm, outcome.category)].append(outcome)
        if outcome.category not in CONTROL_CATEGORIES:
            grouped[(outcome.model, outcome.arm, "all_repair")].append(outcome)
    return [
        {"model": model, "arm": arm, "category": category, **_cell(items)}
        for (model, arm, category), items in sorted(grouped.items())
    ]


def controls(outcomes: Iterable[Outcome]) -> list[dict[str, Any]]:
    """Control rows: policy split by whether an alternative was offered, and capability."""
    grouped: dict[tuple[str, str, str], list[Outcome]] = defaultdict(list)
    for outcome in outcomes:
        if outcome.category == "control_policy":
            offered = "alternative offered" if outcome.variant.endswith("-alt") else "none offered"
            grouped[(outcome.model, f"policy, {offered}", outcome.arm)].append(outcome)
        elif outcome.category == "control_capability":
            grouped[(outcome.model, "capability", outcome.arm)].append(outcome)
    rows = []
    for (model, scope, arm), items in sorted(grouped.items()):
        counted = [o for o in items if o.counted]
        tally = Counter(o.outcome for o in counted)
        retried = tally["recovered"] + tally["same_error"] + tally["different_error"]
        rows.append(
            {
                "model": model,
                "scope": scope,
                "arm": arm,
                "n": len(counted),
                "not_retried": sum(o.success for o in counted),
                "stopped": tally["no_tool_call"],
                "switched": tally["switched"],
                "switched_admitted": sum(1 for o in counted if o.switch_ok),
                "other_tool": tally["other_tool"],
                "retried": retried,
                "api_refusal": tally["api_refusal"],
                "truncated": tally["truncated"],
                "excluded": sum(1 for o in items if not o.counted),
            }
        )
    return rows


def _paired(
    first: Mapping[str, Outcome], second: Mapping[str, Outcome], keys: Iterable[str]
) -> dict[str, Any]:
    b = c = pairs = 0
    for key in keys:
        a, z = first.get(key), second.get(key)
        if a is None or z is None or not a.counted or not z.counted:
            continue
        pairs += 1
        if a.success and not z.success:
            b += 1
        elif z.success and not a.success:
            c += 1
    return {"pairs": pairs, "b": b, "c": c, "p": mcnemar_exact_p(b, c)}


def _index(outcomes: Iterable[Outcome]) -> dict[tuple[str, str], dict[str, Outcome]]:
    """``(model, arm) -> sid -> outcome``."""
    out: dict[tuple[str, str], dict[str, Outcome]] = defaultdict(dict)
    for outcome in outcomes:
        out[(outcome.model, outcome.arm)][outcome.sid] = outcome
    return out


def mcnemar_rows(
    outcomes: list[Outcome], identical_hn: set[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """H vs N and S vs H per model x scope, and the H vs N noise on identical payloads."""
    index = _index(outcomes)
    category_of = {o.sid: o.category for o in outcomes}
    models = sorted({o.model for o in outcomes})
    rows: list[dict[str, Any]] = []
    noise: list[dict[str, Any]] = []
    for model in models:
        h, n, s = (
            index.get((model, "h"), {}),
            index.get((model, "n"), {}),
            index.get((model, "s"), {}),
        )
        for scope in SCOPES:
            sids = sorted(sid for sid, cat in category_of.items() if _in_scope(cat, scope))
            if h and n:
                hn = [sid for sid in sids if sid not in identical_hn]
                rows.append(
                    {"model": model, "scope": scope, "comparison": "h_vs_n", **_paired(h, n, hn)}
                )
            if s and h:
                rows.append(
                    {"model": model, "scope": scope, "comparison": "s_vs_h", **_paired(s, h, sids)}
                )
        if h and n and identical_hn:
            noise.append(
                {
                    "model": model,
                    "comparison": "h_vs_n_identical_payload",
                    **_paired(h, n, sorted(identical_hn)),
                }
            )
    return rows, noise


def r2_vs_r1_rows(
    r2: list[Outcome],
    r1: list[Outcome],
    changed: Mapping[str, Iterable[str]],
    retest: Iterable[str],
) -> list[dict[str, Any]]:
    """R1 vs R2 per model x arm, on changed payloads and on the unchanged retest control.

    Args:
        changed: ``arm -> sids`` whose payload for that arm differs from R1's.
        retest: The sids drawn as the unchanged test-retest control.
    """
    first, second = _index(r1), _index(r2)
    retest_set = set(retest)
    rows = []
    for model, arm in sorted(second):
        changed_set = set(changed.get(arm, ()))
        ran = set(second[(model, arm)])
        scopes = (
            ("changed", sorted(ran & changed_set)),
            ("retest", sorted((ran & retest_set) - changed_set)),
            # Unchanged for this arm, re-run only because another arm's payload changed:
            # also a retest, but of the changed categories rather than a random draw.
            ("unchanged, other arm changed", sorted(ran - changed_set - retest_set)),
        )
        for scope, sids in scopes:
            paired = _paired(first.get((model, arm), {}), second[(model, arm)], sids)
            rows.append({"model": model, "arm": arm, "scope": scope, **paired})
    return rows


def spend(outcomes: Iterable[Outcome], model_ids: Mapping[str, str]) -> dict[str, Any]:
    """Batch-rate cost and token totals of the scored results, per model alias."""
    per_model: dict[str, dict[str, float]] = defaultdict(
        lambda: {"usd": 0.0, "input_tokens": 0, "output_tokens": 0, "unpriced": 0}
    )
    for outcome in outcomes:
        if not outcome.usage:
            continue
        model_id = outcome.served_model or model_ids.get(outcome.model, outcome.model)
        entry = per_model[outcome.model]
        try:
            entry["usd"] += price_usage(model_id, outcome.usage, batch=True)
        except UnpricedModelError:
            entry["unpriced"] += 1
        entry["input_tokens"] += int(outcome.usage.get("input_tokens") or 0)
        entry["output_tokens"] += int(outcome.usage.get("output_tokens") or 0)
    total = round(sum(entry["usd"] for entry in per_model.values()), 4)
    return {"usd": total, "per_model": {k: dict(v) for k, v in sorted(per_model.items())}}


def summarize_round(
    outcomes: list[Outcome],
    meta: Mapping[str, Any],
    *,
    identical_hn: set[str],
    planned: int,
    r1_outcomes: list[Outcome] | None = None,
) -> dict[str, Any]:
    """Everything the round block and ``summary.json`` report, from scored outcomes.

    Args:
        outcomes: Every scored outcome of the round.
        meta: The run manifest (plus ``date``), see ``__main__``.
        identical_hn: sids whose H and N payloads are byte-identical.
        planned: Requests the run planned (so uncollected ones are reported).
        r1_outcomes: R1's outcomes, for an R2 round's paired comparison.
    """
    models = dict(meta.get("models") or {})
    served: dict[str, set[str]] = defaultdict(set)
    for outcome in outcomes:
        if outcome.served_model:
            served[outcome.model].add(outcome.served_model)
    tally = Counter(o.outcome for o in outcomes)
    rows, noise = mcnemar_rows(outcomes, identical_hn)
    summary: dict[str, Any] = {
        "round": meta.get("round"),
        "date": meta.get("date"),
        "run_id": meta.get("run_id"),
        "run_ids": list(meta.get("run_ids") or [meta.get("run_id")]),
        "git": {"sha": meta.get("git_sha"), "dirty": meta.get("git_dirty")},
        "source_sha256": meta.get("source_sha256", {}),
        "protocol": meta.get("protocol"),
        "request_template": meta.get("request_template", {}),
        "models": models,
        "arms": list(meta.get("arms") or []),
        "batches": meta.get("batches", {}),
        "sdk": meta.get("sdk_version"),
        "pricing_snapshot": meta.get("pricing_snapshot"),
        "corpus": meta.get("corpus", {}),
        "requests": {
            "planned": planned,
            "scored": len(outcomes),
            "counted": sum(1 for o in outcomes if o.counted),
            "errored": tally["errored"],
            "harness_error": tally["harness_error"],
            "missing": max(planned - len(outcomes), 0),
        },
        "served_models": {k: sorted(v) for k, v in sorted(served.items())},
        "spend": spend(outcomes, models),
        "cells": cells(outcomes),
        "controls": controls(outcomes),
        "mcnemar": rows,
        "noise": noise,
    }
    if r1_outcomes is not None:
        r2_plan = meta.get("r2", {})
        summary["r1_run_id"] = r2_plan.get("r1_run_id")
        summary["r1_run_ids"] = list(r2_plan.get("r1_run_ids") or [r2_plan.get("r1_run_id")])
        summary["r2_plan"] = {
            "changed": {arm: len(sids) for arm, sids in (r2_plan.get("changed") or {}).items()},
            "retest": len(r2_plan.get("retest") or []),
        }
        summary["r2_vs_r1"] = r2_vs_r1_rows(
            outcomes, r1_outcomes, r2_plan.get("changed") or {}, r2_plan.get("retest") or []
        )
    return summary


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------


def _pct(value: float) -> str:
    return f"{100 * value:.0f}"


def _rate(k: int, n: int) -> str:
    if n == 0:
        return "n=0"
    lo, hi = wilson_interval(k, n)
    return f"{k}/{n} {_pct(k / n)}% ({_pct(lo)}-{_pct(hi)})"


def _p(value: float) -> str:
    return "<0.001" if value < 0.001 else f"{value:.3f}"


def _short(sha: Any) -> str:
    return str(sha)[:12] if sha else "unknown"


def _arms_of(summary: Mapping[str, Any]) -> list[str]:
    present = {cell["arm"] for cell in summary["cells"]}
    return [arm for arm in ARMS if arm in present]


def _provenance(summary: Mapping[str, Any]) -> list[str]:
    git = summary.get("git") or {}
    tree = "dirty tree" if git.get("dirty") else "clean tree"
    hashes = ", ".join(
        f"`{name}` `{_short(sha)}`"
        for name, sha in sorted((summary.get("source_sha256") or {}).items())
    )
    batches = ", ".join(
        f"{alias} `{batch}`" for alias, batch in sorted((summary.get("batches") or {}).items())
    )
    template = summary.get("request_template") or {}
    effort = ", ".join(f"{k} {v}" for k, v in sorted((template.get("effort") or {}).items()))
    lines = [
        f"- **Commit** `{_short(git.get('sha'))}` ({tree}). Hint code sha256: {hashes or 'not recorded'}.",
        f"- **Protocol** `{summary.get('protocol')}`; max_tokens {template.get('max_tokens')}, "
        f"adaptive thinking, effort per model ({effort or 'not recorded'}), no temperature, "
        "no tool_choice, no fallbacks.",
        f"- **Batches** {batches or 'none recorded'}; `anthropic` {summary.get('sdk')}; "
        f"pricing `{summary.get('pricing_snapshot')}`.",
    ]
    requests = summary["requests"]
    served = summary.get("served_models") or {}
    models = summary.get("models") or {}
    mismatched = {alias: ids for alias, ids in served.items() if ids != [models.get(alias)]}
    served_line = (
        "every result reported the requested model id"
        if not mismatched
        else "model ids served other than requested: "
        + "; ".join(f"{alias}: {', '.join(ids)}" for alias, ids in mismatched.items())
    )
    cost = summary.get("spend") or {}
    lines.append(
        f"- **Requests** {requests['planned']:,} planned, {requests['scored']:,} scored, "
        f"{requests['counted']:,} counted; {requests['errored']} errored and "
        f"{requests['harness_error']} harness errors left out of every denominator; "
        f"{requests['missing']} not collected. {served_line[0].upper() + served_line[1:]}. "
        f"Cost of the scored results at Batch rates: ${cost.get('usd', 0.0):.2f}."
    )
    corpus = summary.get("corpus") or {}
    rejected = corpus.get("rejected") or {}
    rejected_text = "; ".join(
        f"{category}: {count} {reason}"
        for category, reasons in rejected.items()
        for reason, count in reasons.items()
    )
    total_rejected = sum(sum(r.values()) for r in rejected.values())
    lines.append(
        f"- **Corpus** seed {corpus.get('seed')}, {corpus.get('scenarios')} scenarios, "
        f"sha256 `{_short(corpus.get('sha256'))}`. Candidates rejected by the self-check: "
        f"{total_rejected}{f' ({rejected_text})' if rejected_text else ''}; "
        f"duplicate draws redrawn: {corpus.get('duplicates', 0)}."
    )
    return lines


def _recovery_tables(summary: Mapping[str, Any]) -> list[str]:
    arms = _arms_of(summary)
    by_key = {(c["model"], c["arm"], c["category"]): c for c in summary["cells"]}
    models = summary.get("models") or {}
    effort = (summary.get("request_template") or {}).get("effort") or {}
    out: list[str] = []
    for alias in sorted({c["model"] for c in summary["cells"]}):
        out.append(
            f"#### Recovery by category: `{models.get(alias, alias)}` ({alias}, effort {effort.get(alias, '?')})"
        )
        out.append("")
        header = (
            ["Category"] + [f"{a.upper()} RR" for a in arms] + [f"{a.upper()} SR" for a in arms]
        )
        out.append("| " + " | ".join(header) + " |")
        out.append("|" + "---|" * len(header))
        for category in (*REPAIR_CATEGORIES, "all_repair"):
            label = "**All repair categories**" if category == "all_repair" else f"`{category}`"
            row = [label]
            for metric in ("success", "semantic"):
                for arm in arms:
                    cell = by_key.get((alias, arm, category))
                    row.append(_rate(cell[metric], cell["n"]) if cell else "n=0")
            out.append("| " + " | ".join(row) + " |")
        out.append("")
    return out


def _control_table(summary: Mapping[str, Any]) -> list[str]:
    rows = summary["controls"]
    if not rows:
        return []
    out = [
        "#### Controls: the refused tool must not be called again",
        "",
        "Not retried = stopped (no tool call) + switched (the permitted alternative) + other "
        "tool. Switched (admitted) counts switches whose call itself passed its stub.",
        "",
        "| Model | Control | Arm | Not retried | Stopped | Switched (admitted) | Other tool | Retried | API refusal | Truncated |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        out.append(
            f"| {r['model']} | {r['scope']} | {r['arm'].upper()} | {_rate(r['not_retried'], r['n'])} "
            f"| {r['stopped']} | {r['switched']} ({r['switched_admitted']}) | {r['other_tool']} "
            f"| {r['retried']} | {r['api_refusal']} | {r['truncated']} |"
        )
    out.append("")
    return out


def _paired_tables(summary: Mapping[str, Any]) -> list[str]:
    rows = summary["mcnemar"]
    if not rows:
        return []
    out = [
        "#### Paired tests",
        "",
        "McNemar exact, two-sided, on success (recovered; for a control, not retried). "
        "b = only the first arm succeeded, c = only the second. Descriptive: no "
        "multiplicity correction. H vs N leaves out scenarios whose H and N payloads are "
        "byte-identical (no hints to remove).",
        "",
        "| Model | Scope | H vs N: pairs, b/c, p | S vs H: pairs, b/c, p |",
        "|---|---|---|---|",
    ]
    by_key = {(r["model"], r["scope"], r["comparison"]): r for r in rows}
    for model in sorted({r["model"] for r in rows}):
        for scope in SCOPES:
            cols = []
            for comparison in ("h_vs_n", "s_vs_h"):
                r = by_key.get((model, scope, comparison))
                cols.append(
                    f"{r['pairs']}, {r['b']}/{r['c']}, {_p(r['p'])}" if r and r["pairs"] else "n=0"
                )
            label = "all repair categories" if scope == "all_repair" else scope
            out.append(f"| {model} | {label} | {cols[0]} | {cols[1]} |")
    out.append("")
    for r in summary.get("noise") or []:
        out.append(
            f"Noise, {r['model']}: H vs N on {r['pairs']} byte-identical payload pairs "
            f"disagreed {r['b'] + r['c']} times (b/c {r['b']}/{r['c']})."
        )
    if summary.get("noise"):
        out.append("")
    return out


def _outcome_table(summary: Mapping[str, Any]) -> list[str]:
    columns = [o for o in OUTCOMES if o not in EXCLUDED]
    out = [
        "#### Outcomes",
        "",
        "| Model | Arm | " + " | ".join(columns) + " | identical retries | excluded |",
        "|---|---|" + "---|" * (len(columns) + 2),
    ]
    for cell in summary["cells"]:
        if cell["category"] != "all_repair":
            continue
        tally = cell["outcomes"]
        excluded = sum(tally.get(o, 0) for o in EXCLUDED)
        values = " | ".join(str(tally.get(o, 0)) for o in columns)
        out.append(
            f"| {cell['model']} | {cell['arm'].upper()} | {values} | "
            f"{cell['identical_retries']} | {excluded} |"
        )
    out.append("")
    out.append("Repair categories only; the controls are tabled above.")
    out.append("")
    return out


def _r2_table(summary: Mapping[str, Any]) -> list[str]:
    rows = summary.get("r2_vs_r1")
    if rows is None:
        return []
    plan = summary.get("r2_plan") or {}
    changed = ", ".join(
        f"{arm.upper()} {count}" for arm, count in sorted((plan.get("changed") or {}).items())
    )
    r1_ids = summary.get("r1_run_ids") or [summary.get("r1_run_id")]
    out = [
        f"#### R2 against R1 ({_ids(r1_ids)})",
        "",
        "Paired by scenario, arm and model. Changed = the arm's payload differs from R1's "
        f"(scenarios per arm: {changed or 'none'}); retest = unchanged, a seeded 25% "
        f"control ({plan.get('retest', 0)} scenarios) that measures run-to-run noise; "
        "unchanged, other arm changed = this arm's payload is R1's, re-run because another "
        "arm's payload for the scenario changed.",
        "",
        "| Model | Arm | Scope | Pairs | R1 only | R2 only | p |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        p = _p(r["p"]) if r["pairs"] else "n=0"
        out.append(
            f"| {r['model']} | {r['arm'].upper()} | {r['scope']} | {r['pairs']} | {r['b']} "
            f"| {r['c']} | {p} |"
        )
    out.append("")
    return out


def _ids(run_ids: list[Any]) -> str:
    return ", ".join(f"`{run_id}`" for run_id in run_ids)


def render_block(summary: Mapping[str, Any]) -> str:
    """The dated markdown block for one round (staged across one or more runs)."""
    run_ids = summary.get("run_ids") or [summary.get("run_id")]
    label = "run" if len(run_ids) == 1 else "runs"
    heading = (
        f"### Round {str(summary.get('round')).upper()} · {summary.get('date')} · "
        f"{label} {_ids(run_ids)}"
    )
    lines = [heading, "", *_provenance(summary), ""]
    lines += _recovery_tables(summary)
    lines += _control_table(summary)
    lines += _paired_tables(summary)
    lines += _r2_table(summary)
    lines += _outcome_table(summary)
    return "\n".join(lines).rstrip() + "\n"


def append_block(results_path: Path, block: str, *, force: bool = False) -> str:
    """Insert ``block`` newest-first under :data:`RESULTS_MARKER`; return the new text.

    The "not yet measured" placeholder below the marker is dropped with the first block.
    Earlier blocks are never edited.

    Raises:
        ValueError: The marker is missing, or the block's heading already exists and
            ``force`` is False.
    """
    text = results_path.read_text(encoding="utf-8")
    if RESULTS_MARKER not in text:
        raise ValueError(f"{results_path} has no append marker {RESULTS_MARKER!r}")
    heading = block.strip().splitlines()[0].strip()
    if heading in text and not force:
        raise ValueError(f"a block headed {heading!r} already exists; pass --force to add another")
    head, _, tail = text.partition(RESULTS_MARKER)
    paragraphs = tail.lstrip("\n").split("\n\n")
    if paragraphs and paragraphs[0].startswith(PLACEHOLDER_PREFIX):
        paragraphs = paragraphs[1:]
    rest = "\n\n".join(paragraphs).strip("\n")
    new = f"{head}{RESULTS_MARKER}\n\n{block.strip()}\n" + (f"\n{rest}\n" if rest else "")
    results_path.write_text(new, encoding="utf-8")
    return new


def write_summary(path: Path, summary: Mapping[str, Any]) -> dict[str, Any]:
    """Merge one round's summary into ``summary.json`` (keyed by run id); return the data."""
    data: dict[str, Any] = {}
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("benchmark", "fix_hints")
    data.setdefault("results", f"{REPO_BLOB}/benchmarks/fix_hints/RESULTS.md")
    data.setdefault("runs", {})
    data.setdefault("latest", {})
    run_id = str(summary.get("run_id"))
    data["runs"][run_id] = dict(summary)
    data["latest"][str(summary.get("round"))] = run_id
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data
