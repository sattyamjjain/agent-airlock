"""``scan-tools`` over MCPTox's real tool descriptions, not the 23 hand-written stand-ins.

The released ``response_all.json`` (fetched and verified by :mod:`benchmarks.mcptox.data`,
never committed) carries every poisoned tool block and every server's clean tool blocks.
This module runs the same static check the fixture bench runs (``scan_tool`` under the
permissive policy, so only the SCAN002 trust-boundary check can bite) over:

* every **unique poisoned description** (normalised: literal ``\\n`` separators turned into
  newlines, then the block's ``Description:`` text), plus a per-case weighted rate over all
  1,348 cases, broken down by paradigm, by risk category and by whether the description
  carries an ``<IMPORTANT>`` tag;
* every **clean tool block** of the 45 servers (362 blocks; 353 of them are in the
  released ``tool_names``), whose flags are false positives.

The numbers are deterministic and offline. They are a property of the static checker on
real attack text, still not MCPTox's model-in-the-loop attack success rate. Nothing here
quotes MCPTox text; the report is counts, rates and Wilson intervals only.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_airlock.scan import resolve_policy, scan_tool
from benchmarks._claude.stats import wilson_interval
from benchmarks.mcptox.clean import ToolSpec, clean_servers, parse_tool_blocks
from benchmarks.mcptox.data import iter_cases
from benchmarks.mcptox.stubs import quiet_airlock_logs

TRUST_CODE = "SCAN002"
IMPORTANT_TAG = "<important>"


def tool_def(spec: ToolSpec) -> dict[str, Any]:
    """An MCP tool definition for a parsed block (closed, string-typed schema)."""
    return {
        "name": spec.name,
        "description": spec.description,
        "inputSchema": {
            "type": "object",
            "properties": {p.name: {"type": "string", "maxLength": 256} for p in spec.params},
            "required": [p.name for p in spec.params if p.required],
            "additionalProperties": False,
        },
    }


def flagged(spec: ToolSpec) -> bool:
    """True iff ``scan-tools`` raises the trust-boundary violation for this block."""
    result = scan_tool(tool_def(spec), resolve_policy("permissive"))
    return any(v.code == TRUST_CODE for v in result.violations)


@dataclass
class Tally:
    """``k`` flagged of ``n``."""

    k: int = 0
    n: int = 0

    def add(self, hit: bool) -> None:
        self.n += 1
        self.k += int(hit)

    def as_dict(self) -> dict[str, Any]:
        if not self.n:
            return {"k": 0, "n": 0, "rate": None, "wilson": None}
        lo, hi = wilson_interval(self.k, self.n)
        return {
            "k": self.k,
            "n": self.n,
            "rate": round(self.k / self.n, 4),
            "wilson": [round(lo, 4), round(hi, 4)],
        }


@dataclass
class RealCorpusReport:
    """Detection on real poisoned descriptions and false positives on real clean ones."""

    unique: Tally = field(default_factory=Tally)
    per_case: Tally = field(default_factory=Tally)
    by_paradigm: dict[str, Tally] = field(default_factory=lambda: defaultdict(Tally))
    by_risk: dict[str, Tally] = field(default_factory=lambda: defaultdict(Tally))
    by_tag: dict[str, Tally] = field(default_factory=lambda: defaultdict(Tally))
    clean_blocks: Tally = field(default_factory=Tally)
    clean_listed: Tally = field(default_factory=Tally)
    unparsed_poisoned: int = 0

    def to_dict(self) -> dict[str, Any]:
        def table(groups: Mapping[str, Tally]) -> dict[str, Any]:
            return {k: v.as_dict() for k, v in sorted(groups.items())}

        return {
            "poisoned_unique": self.unique.as_dict(),
            "poisoned_per_case": self.per_case.as_dict(),
            "by_paradigm": table(self.by_paradigm),
            "by_risk": table(self.by_risk),
            "by_important_tag": table(self.by_tag),
            "clean_false_positive_blocks": self.clean_blocks.as_dict(),
            "clean_false_positive_listed": self.clean_listed.as_dict(),
            "unparsed_poisoned_blocks": self.unparsed_poisoned,
        }


def run_real_corpus(doc: Mapping[str, Any]) -> RealCorpusReport:
    """Score every poisoned and clean block in a verified MCPTox document."""
    with quiet_airlock_logs():  # the trust guard logs every flag it raises
        return _run(doc)


def _run(doc: Mapping[str, Any]) -> RealCorpusReport:
    report = RealCorpusReport()
    verdicts: dict[str, bool] = {}
    for case in iter_cases(doc):
        blocks = parse_tool_blocks(case.poisoned_tool)
        if not blocks:
            report.unparsed_poisoned += 1
            continue
        spec = blocks[0]
        key = spec.description.strip()
        if key not in verdicts:
            verdicts[key] = flagged(spec)
            report.unique.add(verdicts[key])
        hit = verdicts[key]
        report.per_case.add(hit)
        report.by_paradigm[case.paradigm].add(hit)
        report.by_risk[case.risk].add(hit)
        tagged = "tagged" if IMPORTANT_TAG in key.lower() else "untagged"
        report.by_tag[tagged].add(hit)
    for server in clean_servers(doc):
        listed = set(server.listed_tool_names)
        for spec in server.tools:
            hit = flagged(spec)
            report.clean_blocks.add(hit)
            if spec.name in listed:
                report.clean_listed.add(hit)
    return report


def _cell(t: Mapping[str, Any]) -> str:
    if not t["n"]:
        return "n=0 (not measured)"
    lo, hi = t["wilson"]
    return f"{t['k']}/{t['n']} ({100 * t['rate']:.1f}%, 95% CI {100 * lo:.1f}-{100 * hi:.1f}%)"


def _rows(groups: Mapping[str, Mapping[str, Any]]) -> list[str]:
    return [f"| {name} | {_cell(t)} |" for name, t in groups.items()]


def render_real_section(data: Mapping[str, Any], *, date: str, command: str) -> list[str]:
    """The dated 'Real MCPTox corpus' section for ``RESULTS.md`` (counts only)."""
    lines: Sequence[str] = [
        f"## Real MCPTox corpus (measured {date}, UTC)",
        "",
        f"Reproduce: `{command}`. It fetches and verifies MCPTox's",
        "`response_all.json` at commit `f85189f9ad12` (never committed) and runs the same",
        "check as the fixtures: `scan_tool` under the permissive policy, where a SCAN002",
        "trust-boundary violation counts as detected.",
        "",
        "| Population | Flagged (SCAN002) |",
        "| --- | --- |",
        f"| Unique poisoned descriptions | {_cell(data['poisoned_unique'])} |",
        f"| All cases, weighted by case | {_cell(data['poisoned_per_case'])} |",
        f"| Clean tool blocks (false positives) | {_cell(data['clean_false_positive_blocks'])} |",
        "| Clean blocks named in `tool_names` (false positives) | "
        f"{_cell(data['clean_false_positive_listed'])} |",
        "",
        "Per case, by paradigm:",
        "",
        "| Paradigm | Flagged |",
        "| --- | --- |",
        *_rows(data["by_paradigm"]),
        "",
        "Per case, by whether the description carries an `<IMPORTANT>` tag:",
        "",
        "| Tag | Flagged |",
        "| --- | --- |",
        *_rows(data["by_important_tag"]),
        "",
        "Per case, by risk category:",
        "",
        "| Risk category | Flagged |",
        "| --- | --- |",
        *_rows(data["by_risk"]),
        "",
        f"Poisoned blocks that did not parse: {data['unparsed_poisoned_blocks']}.",
    ]
    return list(lines)
