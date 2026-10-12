"""Render the MCPTox summaries into ``RESULTS.md`` blocks and a console report.

``RESULTS.md`` is also included verbatim in the docs site, so every link to a repository
file is an absolute GitHub blob URL, and nothing here quotes MCPTox text: the tables are
counts, rates and intervals only.

* The replay block sits between :data:`REPLAY_BEGIN` and :data:`REPLAY_END` and is
  rewritten whole by ``replay --write``.
* Fresh-run blocks are appended below :data:`FRESH_MARKER`, newest last; a dated block is
  never edited, and a repeated heading needs ``--force``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

REPLAY_BEGIN = "<!-- MCPTOX-REPLAY:BEGIN -->"
REPLAY_END = "<!-- MCPTOX-REPLAY:END -->"
FRESH_MARKER = "<!-- MCPTOX-FRESH-RUNS: append newest below; never edit dated blocks -->"
NOT_MEASURED = "_Not yet measured._"
BLOB = "https://github.com/sattyamjjain/agent-airlock/blob/main"
TIER_LABELS = {
    "G0": "G0 (contract only)",
    "G": "G (+ tool allowlist)",
    "LP": "LP (+ path / endpoint scopes)",
}


def pct(rate: Mapping[str, Any] | None, *, boot: bool = False) -> str:
    """``k/n (p%, 95% CI a-b%)`` or ``n=0 (not measured)``."""
    if not rate or not rate.get("n"):
        return "n=0 (not measured)"
    k, n = rate["k"], rate["n"]
    lo, hi = rate["wilson"]
    text = f"{k}/{n} ({100 * k / n:.1f}%, CI {100 * lo:.1f}-{100 * hi:.1f}%"
    if boot and rate.get("bootstrap"):
        blo, bhi = rate["bootstrap"]
        text += f"; server bootstrap {100 * blo:.1f}-{100 * bhi:.1f}%"
    return text + ")"


def short(rate: Mapping[str, Any] | None) -> str:
    """``p% (k/n)`` for dense tables."""
    if not rate or not rate.get("n"):
        return "n=0"
    return f"{100 * rate['k'] / rate['n']:.1f}% ({rate['k']}/{rate['n']})"


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return lines


def _headline(pop: Mapping[str, Any], *, boot: bool) -> list[str]:
    rows = []
    for tier, label in TIER_LABELS.items():
        m = pop["tiers"][tier]
        rows.append(
            [
                label,
                pct(m["attack_refusal_lower"], boot=boot),
                pct(m["attack_refusal_upper"]),
                pct(m["direct_execution_refusal_all"]),
                pct(m["benign_false_refusal"], boot=boot),
                f"{short(m['benign_false_refusal_policy'])} / "
                f"{short(m['benign_false_refusal_contract_only'])}",
                pct(m["uptake_call_refusal"]),
            ]
        )
    return _table(
        [
            "Tier",
            "Attack refusal, lower bound (every real call refused)",
            "Upper bound (any real call refused)",
            "Direct Execution refused",
            "Benign-proxy false refusal",
            "of which policy / contract-only",
            "Poison-literal calls refused",
        ],
        rows,
    )


def _compact_rows(groups: Mapping[str, Any]) -> list[list[str]]:
    rows = []
    for name, g in groups.items():
        rows.append(
            [
                f"`{name}`",
                str(g["S"]),
                short(g["G0"]["attack_refusal_lower"]),
                short(g["G"]["attack_refusal_lower"]),
                short(g["LP"]["attack_refusal_lower"]),
                short(g["LP"]["attack_refusal_upper"]),
                str(g["B"]),
                short(g["G"]["benign_false_refusal"]),
                short(g["LP"]["benign_false_refusal"]),
            ]
        )
    return rows


_COMPACT_HEADER = [
    "Group",
    "S",
    "G0 lower",
    "G lower",
    "LP lower",
    "LP upper",
    "B",
    "G false refusal",
    "LP false refusal",
]


def render_replay_block(summary: Mapping[str, Any]) -> str:
    """The replay block's body (without the markers)."""
    prov = summary["provenance"]
    host = prov["host"]
    labels = prov["labels"]
    online, local = summary["online"], summary["local"]
    acct = summary["accounting"]
    cover = summary["policy_coverage"]
    canonical = "canonical Linux host" if host["canonical"] else "NON-CANONICAL host"
    lines = [
        f"### Replay, measured {prov['date']} (UTC)",
        "",
        f"- Host: {host['system']} {host['release']} ({canonical}), Python {host['python']}; "
        f"agent-airlock {prov['agent_airlock_version']} at `{prov['git_sha'][:12]}`"
        f"{' (dirty tree)' if prov['git_dirty'] else ''}.",
        f"- Filesystem gate checks `~` paths in their expanded form: "
        f"{'yes' if prov['tilde_expanded'] else 'no'}.",
        f"- Data: MCPTox `{prov['data']['file']}` at `{prov['data']['commit'][:12]}`, sha256 "
        f"`{prov['data']['sha256'][:16]}...`, verified before scoring.",
        f"- LP labels: blind commit `{labels['blind_commit'][:12]}`; `lp_labels.py` sha256 "
        f"`{labels['sha256_at_run'][:16]}...` "
        f"({'matches' if labels['matches_blind'] else 'DIFFERS FROM'} the blind commit's).",
        f"- Bootstrap: {prov['bootstrap']['iterations']} resamples of whole servers, seed "
        f"{prov['bootstrap']['seed']}.",
        f"- Reproduce: `{prov['command']}`",
        "",
        f"Denominators: {acct['by_source']['online']} API-model responses and "
        f"{acct['by_source']['local']} local-model responses. API models: S = {online['S']} "
        f"Success responses with a real-tool call, DE = {online['DE']} Direct Execution "
        f"responses with a poisoned-tool call, B = {online['B']} Failure-Ignored responses "
        "with a real-tool call.",
        "",
        "#### API models (primary)",
        "",
        *_headline(online, boot=True),
        "",
        "Direct Execution under G is refused by construction: the allowlist is the clean "
        "prompt's tools, and the poisoned tool is not one of them. G0 shows what the call "
        "contract alone does to the same calls.",
        "",
        "#### Local models (secondary)",
        "",
        *_headline(local, boot=False),
        "",
        "#### Claude 3.7 Sonnet (MCPTox's recorded outputs)",
        "",
        *_table(
            _COMPACT_HEADER,
            _compact_rows(
                {
                    "both keys": summary["claude_3_7"]["combined"],
                    **{k: v for k, v in summary["claude_3_7"].items() if k != "combined"},
                }
            ),
        ),
        "",
        "#### By paradigm (API models)",
        "",
        *_table(_COMPACT_HEADER, _compact_rows(summary["by_paradigm_online"])),
        "",
        "#### By risk category (API models)",
        "",
        *_table(_COMPACT_HEADER, _compact_rows(summary["by_risk_online"])),
        "",
        "#### By model family (API models)",
        "",
        *_table(_COMPACT_HEADER, _compact_rows(summary["by_family_online"])),
        "",
        "#### By model",
        "",
        *_table(_COMPACT_HEADER, _compact_rows(summary["by_model"])),
        "",
        "#### Why real calls in S were refused (API models)",
        "",
        *_table(
            ["Tier", "Block reasons (refused real calls)"],
            [
                [tier, ", ".join(f"`{k}` {v}" for k, v in reasons.items()) or "none"]
                for tier, reasons in summary["block_reasons_online"].items()
            ],
        ),
        "",
        "#### wrong_data = 0 subset (API models)",
        "",
        *_headline(summary["online_wrong_data_0"], boot=False),
        "",
        "#### Poison-literal uptake against MCPTox's labels",
        "",
        *_table(
            ["Source", "Precision (uptake -> Success)", "Recall (Success -> uptake)"],
            [
                [src, pct(v["precision"]), pct(v["recall"])]
                for src, v in summary["uptake_vs_labels"].items()
            ],
        ),
        "",
        "#### MCPTox's own attack success rate, from its labels (reproduction anchor)",
        "",
        *_table(
            ["API model", "Success / labelled (None excluded)"],
            [[f"`{m}`", pct(r)] for m, r in summary["label_asr_online"].items()],
        ),
        "",
        "#### Accounting (nothing dropped)",
        "",
        *_accounting(acct),
        "",
        f"LP coverage: {cover['servers_effective_lp']} servers at LP, "
        f"{cover['servers_lp_fallback_to_g']} without clean queries at G; "
        f"{cover['fs_scoped_tools']} tools filesystem-scoped, "
        f"{cover['allowlist_scoped_tools']} on an endpoint allowlist, "
        f"{cover['open_web_scoped_tools']} open-web with the SSRF pre-check; "
        f"{cover['labelled_scope_fallbacks']} labelled scopes could not be derived and fell "
        "back to G.",
    ]
    return "\n".join(lines)


def _accounting(acct: Mapping[str, Any]) -> list[str]:
    rows = []
    for source, labels in acct["label_by_status"].items():
        for label, cells in labels.items():
            rows.append(
                [
                    source,
                    f"`{label}`",
                    *(str(cells.get(s, 0)) for s in ("calls", "no_call", "malformed", "empty")),
                ]
            )
    lines = _table(["Source", "Label", "calls", "no_call", "malformed", "empty"], rows)
    lines += [
        "",
        "Parse repairs: " + ", ".join(f"`{k}` {v}" for k, v in acct["parse_notes"].items()) + ".",
        "",
        "Calls: "
        + ", ".join(f"{k} {v}" for k, v in acct["call_classes"].items())
        + " (other = neither a clean-prompt tool nor the poisoned tool: not replayable).",
        "",
        "Real or poisoned calls that could not be replayed: "
        + (
            ", ".join(f"`{k}` {v}" for k, v in acct["unreplayable_real_or_poisoned"].items())
            or "none"
        )
        + ".",
    ]
    return lines


def replace_block(text: str, body: str, *, begin: str = REPLAY_BEGIN, end: str = REPLAY_END) -> str:
    """Replace everything between ``begin`` and ``end`` with ``body``.

    Raises:
        ValueError: A marker is missing or out of order.
    """
    start = text.find(begin)
    stop = text.find(end)
    if start == -1 or stop == -1 or stop < start:
        raise ValueError(f"RESULTS.md lacks the {begin} / {end} markers")
    return text[: start + len(begin)] + "\n" + body.rstrip() + "\n" + text[stop:]


def append_fresh_block(text: str, block: str, *, heading: str, force: bool = False) -> str:
    """Append a dated fresh-run block below the marker (never editing earlier blocks).

    Raises:
        ValueError: The marker is missing, or ``heading`` already exists and not ``force``.
    """
    if FRESH_MARKER not in text:
        raise ValueError("RESULTS.md lacks the fresh-run marker")
    if heading in text and not force:
        raise ValueError(f"{heading!r} already in RESULTS.md; pass --force to add another")
    head, tail = text.split(FRESH_MARKER, 1)
    tail = tail.replace("\n" + NOT_MEASURED + "\n", "\n", 1)
    # The section runs to the next level-2 heading; the new block goes at its end.
    cut = tail.find("\n## ")
    section, rest = (tail, "") if cut == -1 else (tail[:cut], tail[cut:])
    return head + FRESH_MARKER + section.rstrip() + "\n\n" + block.rstrip() + "\n" + rest


def format_console(summary: Mapping[str, Any]) -> str:
    """A short plain-text report for the terminal."""
    lines = []
    for source in ("online", "local"):
        pop = summary[source]
        lines.append(
            f"{source}: responses {pop['responses']}, S {pop['S']}, DE {pop['DE']}, B {pop['B']}"
        )
        for tier in TIER_LABELS:
            m = pop["tiers"][tier]
            lines.append(
                f"  {tier:<3} attack lower {short(m['attack_refusal_lower']):<22} "
                f"upper {short(m['attack_refusal_upper']):<22} "
                f"DE {short(m['direct_execution_refusal_all']):<20} "
                f"benign FR {short(m['benign_false_refusal'])}"
            )
    return "\n".join(lines)
