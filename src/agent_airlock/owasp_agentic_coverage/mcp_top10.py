"""OWASP MCP Top 10 coverage matrix: loader and Markdown renderer.

The README's "MCP-specific mapping" table gives each MCP01-MCP10 risk a list of controls
and a ``Full`` / ``Partial`` label. ``mcp_top10_coverage.yaml`` is the evidence behind that
table: for each control the README names, the module(s) that implement it, the preset(s)
that configure it, the test file(s) that exercise it and where it runs (an ``@Airlock``
step, or a helper the host calls itself); for each risk, one line on why its label holds.

The matrix renders to ``docs/owasp-mcp-top-10-coverage.md``;
``tests/owasp_agentic_coverage/test_mcp_top10_coverage.py`` byte-diffs that page and checks
the evidence against the code and the README row.

It is a separate file from the Agentic matrix (``agentic_coverage.yaml``) because its shape
differs: one Agentic row names one guard module, while one MCP row names several controls,
each with its own evidence. The restricted YAML parser is shared (:mod:`.render`), so the
core stays Pydantic-only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from .render import _parse_yaml

MCP_COVERAGE_PATH: Path = Path(__file__).resolve().parent / "mcp_top10_coverage.yaml"

#: Prepended to the rendered table; the docs page is exactly this plus :func:`render_markdown`.
GENERATED_HEADER = (
    "<!-- @generated from "
    "src/agent_airlock/owasp_agentic_coverage/mcp_top10_coverage.yaml — do not edit by "
    "hand; regenerated and byte-diffed in "
    "tests/owasp_agentic_coverage/test_mcp_top10_coverage.py -->\n\n"
)

COVERAGE_LABELS: frozenset[str] = frozenset({"Full", "Partial", "Monitor-only"})

#: Where a control runs. ``step N`` names an ``# Step N`` comment in ``core.py``; ``execute``,
#: ``post-execution`` and ``wrapper`` are the rest of the ``@Airlock`` call path; ``own
#: decorator`` is a decorator other than ``@Airlock``; ``host-called`` is a helper the host
#: calls itself, which the ``@Airlock`` wrapper never does.
RUNS_PATTERN = re.compile(
    r"^(?:step \d+(?:\.\d+)?|execute|post-execution|wrapper|own decorator|host-called)$"
)
CALL_PATH_PATTERN = re.compile(r"^(?:step \d+(?:\.\d+)?|execute|post-execution|wrapper)$")

_RISK_KEYS = (
    "risk_id",
    "risk_name",
    "coverage",
    "justification",
    "last_verified",
    "measured_block_rate",
)
_CONTROL_KEYS = ("risk_id", "control", "runs", "how", "modules", "tests")


@dataclass(frozen=True)
class McpRisk:
    """One MCP01-MCP10 row: its README title, label and the reason for the label."""

    risk_id: str
    risk_name: str
    coverage: str
    justification: str
    last_verified: str
    measured_block_rate: str
    readme_note: str = ""
    """Text in the README controls cell that is a caveat, not a control (MCP07's)."""


@dataclass(frozen=True)
class McpControl:
    """One control a README row names, and the code that backs it."""

    risk_id: str
    control: str
    """The README's own wording; it appears verbatim in that row's controls cell."""
    runs: str
    how: str
    modules: tuple[str, ...]
    presets: tuple[str, ...]
    tests: tuple[str, ...]

    @property
    def on_call_path(self) -> bool:
        """True when the ``@Airlock`` wrapper runs this control itself."""
        return bool(CALL_PATH_PATTERN.match(self.runs))


@dataclass(frozen=True)
class McpCoverage:
    """The whole MCP Top 10 matrix."""

    spec_version: str
    spec_url: str
    last_verified_global: str
    risks: tuple[McpRisk, ...] = field(default_factory=tuple)
    controls: tuple[McpControl, ...] = field(default_factory=tuple)

    def controls_for(self, risk_id: str) -> tuple[McpControl, ...]:
        """The controls recorded for ``risk_id``, in README order."""
        return tuple(c for c in self.controls if c.risk_id == risk_id)


def _split(value: Any) -> tuple[str, ...]:
    """A comma-separated scalar as a tuple of its non-empty, stripped items."""
    return tuple(item.strip() for item in str(value or "").split(",") if item.strip())


def _mappings(raw: dict[str, Any], key: str, target: Path) -> list[dict[str, Any]]:
    """The list block ``key``, every item a mapping."""
    items = raw.get(key) or []
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        raise ValueError(f"{target}: {key!r} must be a list of mappings")
    return items


def _require(item: dict[str, Any], keys: tuple[str, ...], where: str) -> None:
    for key in keys:
        if not item.get(key):
            raise ValueError(f"{where} missing required key {key!r}")


def _risk(item: dict[str, Any], where: str) -> McpRisk:
    _require(item, _RISK_KEYS, where)
    if item["coverage"] not in COVERAGE_LABELS:
        raise ValueError(f"{where} coverage {item['coverage']!r} is not one of {COVERAGE_LABELS}")
    return McpRisk(
        risk_id=str(item["risk_id"]),
        risk_name=str(item["risk_name"]),
        coverage=str(item["coverage"]),
        justification=str(item["justification"]),
        last_verified=str(item["last_verified"]),
        measured_block_rate=str(item["measured_block_rate"]),
        readme_note=str(item.get("readme_note") or ""),
    )


def _control(item: dict[str, Any], where: str) -> McpControl:
    _require(item, _CONTROL_KEYS, where)
    if not RUNS_PATTERN.match(str(item["runs"])):
        raise ValueError(f"{where} runs {item['runs']!r} is not a known place a control runs")
    return McpControl(
        risk_id=str(item["risk_id"]),
        control=str(item["control"]),
        runs=str(item["runs"]),
        how=str(item["how"]),
        modules=_split(item["modules"]),
        presets=_split(item.get("presets")),
        tests=_split(item["tests"]),
    )


def load_mcp_coverage(path: Path | None = None) -> McpCoverage:
    """Load and validate the MCP Top 10 matrix.

    Risks are sorted by ``risk_id``; each risk's controls keep their YAML (README) order.

    Raises:
        ValueError: a required key is missing or empty, a label or ``runs`` value is not
            one this module knows, a control names an unknown risk, a risk has no control,
            or a value holds ``|`` (it would split a Markdown table cell).
    """
    target = path or MCP_COVERAGE_PATH
    raw = _parse_yaml(target.read_text(encoding="utf-8"))
    for key in ("spec_version", "spec_url", "last_verified_global"):
        if not raw.get(key):
            raise ValueError(f"{target}: missing required key {key!r}")

    risks = sorted(
        (_risk(r, f"{target}: risks[{i}]") for i, r in enumerate(_mappings(raw, "risks", target))),
        key=lambda r: r.risk_id,
    )
    controls = [
        _control(c, f"{target}: controls[{i}]")
        for i, c in enumerate(_mappings(raw, "controls", target))
    ]
    known = {r.risk_id for r in risks}
    for c in controls:
        if c.risk_id not in known:
            raise ValueError(f"{target}: control {c.control!r} names unknown risk {c.risk_id}")
    for r in risks:
        if not any(c.risk_id == r.risk_id for c in controls):
            raise ValueError(f"{target}: {r.risk_id} has no controls")
    for value in _cells(raw, risks, controls):
        if "|" in value:
            raise ValueError(f"{target}: a value holds '|', which splits a table cell: {value!r}")

    return McpCoverage(
        spec_version=str(raw["spec_version"]),
        spec_url=str(raw["spec_url"]),
        last_verified_global=str(raw["last_verified_global"]),
        risks=tuple(risks),
        controls=tuple(sorted(controls, key=lambda c: c.risk_id)),
    )


def _cells(raw: dict[str, Any], risks: list[McpRisk], controls: list[McpControl]) -> list[str]:
    """Every string the renderer writes into the page."""
    out = [str(v) for v in raw.values() if not isinstance(v, list)]
    for r in risks:
        out += [r.risk_id, r.risk_name, r.justification, r.last_verified, r.measured_block_rate]
    for c in controls:
        out += [c.control, c.how, *c.modules, *c.presets, *c.tests]
    return out


def _code(items: tuple[str, ...]) -> str:
    return ", ".join(f"`{item}`" for item in items) or "—"


def _runs(control: McpControl) -> str:
    where = f"`@Airlock` {control.runs}" if control.on_call_path else control.runs
    return f"{where}: {control.how}"


_PREAMBLE = (
    "The evidence behind the README's MCP Top-10 table. **Full**: the controls that run on "
    "the `@Airlock` call path cover the risk where it reaches a tool call, and nothing the "
    "risk names is out of scope. **Partial**: part of the risk is out of scope, or the "
    "control that covers it runs only where the host calls it. No benchmark in this "
    "repository maps its corpus to MCP01-MCP10, so no row has a measured block-rate.",
    "Each control is named as the README names it. Runs: an `@Airlock` step (the "
    "`# Step N` comments in `core.py`), `@Airlock` execute, post-execution or wrapper (the "
    "decision record, written around the steps), a decorator of its own, or host-called: "
    "a helper the host calls itself, which the `@Airlock` wrapper never calls.",
)


def render_markdown(coverage: McpCoverage) -> str:
    """Render the matrix as deterministic Markdown: a risk table, then a control table."""
    lines = [
        "# OWASP MCP Top 10 coverage",
        "",
        f"Spec: {coverage.spec_url} ({coverage.spec_version})",
        f"Last verified (global): {coverage.last_verified_global}",
        "",
        _PREAMBLE[0],
        "",
        "## Risks",
        "",
        "| Risk ID | Risk | Coverage | Why | Last verified | Measured block-rate |",
        "|---------|------|----------|-----|---------------|---------------------|",
    ]
    for r in coverage.risks:
        lines.append(
            f"| {r.risk_id} | {r.risk_name} | {r.coverage} | {r.justification} | "
            f"{r.last_verified} | {r.measured_block_rate} |"
        )
    lines += [
        "",
        "## Controls",
        "",
        _PREAMBLE[1],
        "",
        "| Risk ID | Control | Runs | Module | Preset | Test |",
        "|---------|---------|------|--------|--------|------|",
    ]
    for c in coverage.controls:
        lines.append(
            f"| {c.risk_id} | {c.control} | {_runs(c)} | {_code(c.modules)} | "
            f"{_code(c.presets)} | {_code(c.tests)} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_page(coverage: McpCoverage) -> str:
    """The full docs page: :data:`GENERATED_HEADER` plus :func:`render_markdown`."""
    return GENERATED_HEADER + render_markdown(coverage)


def stale_risks(coverage: McpCoverage, max_age_days: int = 30) -> list[McpRisk]:
    """Risks whose ``last_verified`` is older than ``max_age_days`` (UTC)."""
    today = datetime.now(tz=timezone.utc).date()
    out: list[McpRisk] = []
    for r in coverage.risks:
        try:
            verified = date.fromisoformat(r.last_verified)
        except ValueError as exc:
            raise ValueError(f"{r.risk_id}: invalid last_verified={r.last_verified!r}") from exc
        if (today - verified).days > max_age_days:
            out.append(r)
    return out


__all__ = [
    "GENERATED_HEADER",
    "MCP_COVERAGE_PATH",
    "McpControl",
    "McpCoverage",
    "McpRisk",
    "load_mcp_coverage",
    "render_markdown",
    "render_page",
    "stale_risks",
]
