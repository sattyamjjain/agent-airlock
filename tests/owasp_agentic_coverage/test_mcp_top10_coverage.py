"""The OWASP MCP Top 10 matrix: generated page, code evidence, and README agreement.

Until this file the README's "MCP-specific mapping" table had nothing behind it but a test
pinning its ten titles: the controls each row named and its Full / Partial label were prose.
Checked against the code on 2026-11-10, five of its six Full labels did not hold. MCP02,
MCP03, MCP04, MCP08 and MCP10 each leaned on controls the ``@Airlock`` wrapper never calls
(credential scopes, the capability-union grant, the description-manifest check, the stdio
launch screen, OpenTelemetry export, the workspace PII config) or named a risk leg that is
out of scope, and MCP05 named "sandbox for DANGEROUS", which nothing on the call path
enforces (``CapabilityPolicy.require_sandbox_for`` is read only by ``airlock scan-tools``).

``mcp_top10_coverage.yaml`` now records, per control the README names, its module(s),
preset(s), test file(s) and where it runs, and per risk the reason for its label. This file
holds it to the code (modules import, presets are registered, test files exist, a named
``# Step`` is in ``core.py``, a named callable or class exists, a named config switch is a
real field), to the generated page (byte-diff), and to the README row (title, label and
every control the row names).
"""

from __future__ import annotations

import dataclasses
import importlib
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import agent_airlock
from agent_airlock import policy_presets
from agent_airlock.config import AirlockConfig
from agent_airlock.owasp_agentic_coverage.mcp_top10 import (
    MCP_COVERAGE_PATH,
    McpControl,
    McpCoverage,
    load_mcp_coverage,
    render_markdown,
    render_page,
    stale_risks,
)
from agent_airlock.policy import SecurityPolicy

from .test_coverage_completeness import MCP_TOP_10_2026, _mcp_mapping_table
from .test_readme_docs_parity import normalise

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "docs" / "owasp-mcp-top-10-coverage.md"
CORE = REPO_ROOT / "src" / "agent_airlock" / "core.py"
EXPECTED_IDS = [f"MCP{i:02d}" for i in range(1, 11)]

#: ``| **MCP04 Software Supply …** | controls | Partial |``: id, title, controls, label.
_README_ROW = re.compile(
    r"^\|\s*\*\*(MCP\d{2})\s+([^*]+?)\*\*\s*\|(.*)\|\s*\*{0,2}([A-Za-z-]+)\*{0,2}\s*\|\s*$",
    re.M,
)
#: ``| MCP04 | Software Supply … | Partial | why | …``: the generated page's risk table only
#: (a control-table row's third cell is never a bare label).
_DOCS_ROW = re.compile(
    r"^\|\s*(MCP\d{2})\s*\|\s*([^|]+?)\s*\|\s*(Full|Partial|Monitor-only)\s*\|", re.M
)


@pytest.fixture(scope="module")
def mcp() -> McpCoverage:
    return load_mcp_coverage()


def parse_readme(table: str) -> dict[str, tuple[tuple[str, ...], str, str]]:
    """Risk id -> (normalised title, controls cell, label) from the README MCP table."""
    return {
        m.group(1): (normalise(m.group(2)), m.group(3).strip(), m.group(4))
        for m in _README_ROW.finditer(table)
    }


def parse_docs(text: str) -> dict[str, tuple[tuple[str, ...], str]]:
    """Risk id -> (normalised title, label) from the generated page's risk table."""
    return {m.group(1): (normalise(m.group(2)), m.group(3)) for m in _DOCS_ROW.finditer(text)}


def disagreements(readme_table: str, docs_text: str) -> list[str]:
    """Every way the README table and the generated page disagree on titles and labels."""
    r, d = parse_readme(readme_table), parse_docs(docs_text)
    out = [f"{i}: in the docs page, absent from the README" for i in sorted(set(d) - set(r))]
    out += [f"{i}: in the README, absent from the docs page" for i in sorted(set(r) - set(d))]
    for risk_id in sorted(set(r) & set(d)):
        (r_name, _, r_label), (d_name, d_label) = r[risk_id], d[risk_id]
        if r_label != d_label:
            out.append(f"{risk_id}: coverage README={r_label!r} docs={d_label!r}")
        if r_name != d_name:
            out.append(f"{risk_id}: name README={' '.join(r_name)!r} docs={' '.join(d_name)!r}")
    return out


def unexplained(cell: str, phrases: list[str]) -> str:
    """What is left of a README controls cell once every recorded phrase is taken out.

    Longest phrase first, so a phrase inside a longer one cannot eat part of it. What may
    remain is separators and ``and``; anything else is a control with no evidence.
    """
    rest = cell
    for phrase in sorted(phrases, key=len, reverse=True):
        rest = rest.replace(phrase, " ; ", 1)
    rest = re.sub(r"\band\b", " ", rest)
    return re.sub(r"[\s,;.]+", " ", rest).strip()


class TestMatrixShape:
    def test_ten_risks_in_order_with_the_pinned_titles(self, mcp: McpCoverage) -> None:
        assert [r.risk_id for r in mcp.risks] == EXPECTED_IDS
        assert {r.risk_id: r.risk_name for r in mcp.risks} == MCP_TOP_10_2026

    def test_spec_pinned(self, mcp: McpCoverage) -> None:
        # A spec bump is an explicit PR.
        assert mcp.spec_url == "https://owasp.org/www-project-mcp-top-10/"
        assert mcp.spec_version == "beta"

    def test_every_risk_has_a_control(self, mcp: McpCoverage) -> None:
        assert all(mcp.controls_for(i) for i in EXPECTED_IDS)

    def test_not_stale_on_ship_day(self, mcp: McpCoverage) -> None:
        assert stale_risks(mcp, max_age_days=30) == []


class TestGeneratedPage:
    def test_doc_byte_matches_render(self, mcp: McpCoverage) -> None:
        """Regenerate with ``render_mcp_page(load_mcp_coverage())`` into the page."""
        assert DOC.read_text(encoding="utf-8") == render_page(mcp), (
            "docs/owasp-mcp-top-10-coverage.md is stale. Regenerate it: python -c "
            '"from agent_airlock.owasp_agentic_coverage import load_mcp_coverage, '
            "render_mcp_page; import pathlib; pathlib.Path('docs/owasp-mcp-top-10-coverage.md')"
            '.write_text(render_mcp_page(load_mcp_coverage()))"'
        )

    def test_render_is_byte_stable(self, mcp: McpCoverage) -> None:
        assert render_markdown(mcp) == render_markdown(load_mcp_coverage())

    def test_header_names_its_source_and_this_test(self) -> None:
        header = DOC.read_text(encoding="utf-8").splitlines()[0]
        assert MCP_COVERAGE_PATH.relative_to(REPO_ROOT).as_posix() in header
        assert Path(__file__).relative_to(REPO_ROOT).as_posix() in header

    def test_no_measured_rate_is_invented(self, mcp: McpCoverage) -> None:
        """No benchmark here maps its corpus to MCP01-MCP10 (``benchmarks/blockrate`` maps to
        ASI slots only). A measured value needs a live-run join test in the same PR, like
        ``TestMeasuredBlockRate.test_published_rates_match_a_live_benchmark_run``."""
        assert {r.measured_block_rate for r in mcp.risks} == {"not measured"}


def _namespaces(modules: tuple[str, ...]) -> list[ModuleType]:
    return [*(importlib.import_module(m) for m in modules), agent_airlock, policy_presets]


def _resolve(dotted: str, namespaces: list[ModuleType]) -> bool:
    """Whether ``a.b.c`` names something in one of ``namespaces``.

    The first part may also be a namespace's own short name (``observability.configure``).
    """
    first, *rest = dotted.split(".")
    for ns in namespaces:
        obj: Any = ns if ns.__name__.rsplit(".", 1)[-1] == first else getattr(ns, first, None)
        for part in rest:
            obj = getattr(obj, part, None)
        if obj is not None:
            return True
    return False


#: Backticked ``name()`` / ``Class.method()`` (no arguments) and backticked CamelCase names.
_NAMED = re.compile(r"`@?([A-Za-z_][\w.]*)\(\)`|`([A-Z][\w]*(?:\.[A-Za-z_]\w*)*)`")


def _named(text: str) -> list[str]:
    return [m.group(1) or m.group(2) for m in _NAMED.finditer(text)]


class TestEvidenceExists:
    """Each module, preset, test, step, callable and switch the matrix names is real."""

    def test_modules_import(self, mcp: McpCoverage) -> None:
        for c in mcp.controls:
            for module in c.modules:
                importlib.import_module(module)  # raises if the module is gone

    def test_presets_are_live_registry_factories(self, mcp: McpCoverage) -> None:
        factories = {m.factory_name for m in policy_presets.list_active()}
        missing = [(c.risk_id, p) for c in mcp.controls for p in c.presets if p not in factories]
        assert not missing, f"presets not in policy_presets.list_active(): {missing}"

    def test_test_paths_exist(self, mcp: McpCoverage) -> None:
        missing = [
            (c.risk_id, t) for c in mcp.controls for t in c.tests if not (REPO_ROOT / t).is_file()
        ]
        assert not missing, f"test files that do not exist: {missing}"

    def test_named_steps_are_core_step_comments(self, mcp: McpCoverage) -> None:
        core = CORE.read_text(encoding="utf-8")
        for c in mcp.controls:
            if c.runs.startswith("step "):
                number = c.runs.removeprefix("step ")
                assert re.search(rf"# Step {re.escape(number)}(?![\d.])", core), (
                    f"{c.risk_id} {c.control!r}: core.py has no '# Step {number}' comment"
                )

    def test_named_callables_and_classes_exist(self, mcp: McpCoverage) -> None:
        missing: list[str] = []
        for r in mcp.risks:
            controls = mcp.controls_for(r.risk_id)
            every_module = tuple(m for c in controls for m in c.modules)
            for name in _named(r.justification):
                if not _resolve(name, _namespaces(every_module)):
                    missing.append(f"{r.risk_id} justification: {name}")
            for c in controls:
                for name in _named(f"{c.control} {c.how}"):
                    if not _resolve(name, _namespaces(c.modules)):
                        missing.append(f"{c.risk_id} {c.control!r}: {name}")
        assert not missing, f"names that resolve to nothing: {missing}"

    def test_named_config_switches_are_real_fields(self, mcp: McpCoverage) -> None:
        """``when the policy sets `x``` and ``AirlockConfig(x=...)`` name real fields, and
        a switch said to be on by default is on in a default ``AirlockConfig``."""
        policy_fields = {f.name for f in dataclasses.fields(SecurityPolicy)}
        config_fields = {f.name for f in dataclasses.fields(AirlockConfig)}
        default = AirlockConfig()
        for c in mcp.controls:
            for name in re.findall(r"the policy sets `(\w+)`", c.how):
                assert name in policy_fields, f"{c.control!r}: SecurityPolicy has no {name}"
            for name in re.findall(r"`AirlockConfig\((\w+)=", c.how):
                assert name in config_fields, f"{c.control!r}: AirlockConfig has no {name}"
            if "on by default" in c.how:
                switches = re.findall(r"`(\w+)`", c.how.split("on by default")[0])
                assert switches, c.control
                for name in switches:
                    assert getattr(default, name) is True, f"{c.control!r}: {name} is off"


class TestLabels:
    def test_a_full_label_rests_on_a_call_path_control(self, mcp: McpCoverage) -> None:
        """A Full row whose every control is a helper the host must remember to call is the
        shape five of the six Full rows had before 2026-11-10."""
        offenders = [
            r.risk_id
            for r in mcp.risks
            if r.coverage == "Full" and not any(c.on_call_path for c in mcp.controls_for(r.risk_id))
        ]
        assert not offenders, f"Full with no control on the @Airlock call path: {offenders}"

    def test_every_label_has_a_reason(self, mcp: McpCoverage) -> None:
        assert all(len(r.justification.split()) >= 10 for r in mcp.risks)


class TestReadmeAgreement:
    def test_both_surfaces_parse_ten_rows(self) -> None:
        """A parser that matches nothing would make every comparison below pass."""
        assert sorted(parse_readme(_mcp_mapping_table())) == EXPECTED_IDS
        assert sorted(parse_docs(DOC.read_text(encoding="utf-8"))) == EXPECTED_IDS

    def test_titles_and_labels_agree(self) -> None:
        found = disagreements(_mcp_mapping_table(), DOC.read_text(encoding="utf-8"))
        assert found == [], (
            "README.md and docs/owasp-mcp-top-10-coverage.md disagree:\n  - "
            + "\n  - ".join(found)
            + "\nThe page is generated from mcp_top10_coverage.yaml; fix the wrong surface."
        )

    def test_every_control_the_readme_names_has_evidence(self, mcp: McpCoverage) -> None:
        rows = parse_readme(_mcp_mapping_table())
        problems: list[str] = []
        for r in mcp.risks:
            cell = rows[r.risk_id][1]
            phrases = [c.control for c in mcp.controls_for(r.risk_id)]
            phrases += [r.readme_note] if r.readme_note else []
            problems += [
                f"{r.risk_id}: not in the README row: {p!r}" for p in phrases if p not in cell
            ]
            rest = unexplained(cell, phrases)
            if rest:
                problems.append(f"{r.risk_id}: README names controls with no evidence: {rest!r}")
        assert not problems, "\n".join(problems)


class TestTheGatesFire:
    """Seeded mismatches: without these the checks above could pass for the wrong reason."""

    _README = "| **MCP04 Software Supply Chain Attacks & Dependency Tampering** | a, b | Partial |"
    _DOCS = (
        "| MCP04 | Software Supply Chain Attacks & Dependency Tampering | Partial | why | d | n |"
    )

    def test_identical_rows_agree(self) -> None:
        assert disagreements(self._README, self._DOCS) == []

    def test_a_label_mismatch_is_caught(self) -> None:
        found = disagreements(self._README.replace("| Partial |", "| Full |"), self._DOCS)
        assert found and "coverage" in found[0]

    def test_a_renamed_risk_is_caught(self) -> None:
        found = disagreements(self._README.replace("Software Supply", "Supply"), self._DOCS)
        assert found and "name" in found[0]

    def test_a_missing_row_is_caught(self) -> None:
        assert disagreements("", self._DOCS) == ["MCP04: in the docs page, absent from the README"]

    def test_a_control_row_is_not_read_as_a_risk_row(self) -> None:
        assert parse_docs("| MCP04 | `x` deny | `@Airlock` step 2: y | `m` | — | `t` |") == {}

    def test_an_unrecorded_control_is_caught(self) -> None:
        assert unexplained("a, b and c", ["a", "b"]) == "c"
        assert unexplained("a, b and c", ["a", "b", "c"]) == ""

    def test_a_call_path_check_tells_helpers_apart(self) -> None:
        def control(runs: str) -> McpControl:
            return McpControl("MCP01", "c", runs, "h", ("m",), (), ("t",))

        assert control("step 2.76").on_call_path and control("post-execution").on_call_path
        assert not control("host-called").on_call_path
        assert not control("own decorator").on_call_path


_RISK = (
    '  - risk_id: "MCP01"\n'
    '    risk_name: "Token Mismanagement & Secret Exposure"\n'
    '    coverage: "{coverage}"\n'
    '    justification: "{why}"\n'
    '    last_verified: "2026-11-10"\n'
    '    measured_block_rate: "not measured"\n'
)
_CONTROL = (
    '  - risk_id: "{risk}"\n'
    '    control: "c"\n'
    '    runs: "{runs}"\n'
    '    how: "h"\n'
    '    modules: "agent_airlock.policy"\n'
    '    presets: ""\n'
    '    tests: "tests/test_policy.py"\n'
)


def _yaml(
    tmp_path: Path,
    *,
    coverage: str = "Partial",
    why: str = "w",
    runs: str = "step 2",
    risk: str = "MCP01",
    controls: bool = True,
) -> Path:
    path = tmp_path / "mcp.yaml"
    body = (
        'spec_version: "beta"\nspec_url: "https://example.com"\n'
        'last_verified_global: "2026-11-10"\nrisks:\n'
        + _RISK.format(coverage=coverage, why=why)
        + ("controls:\n" + _CONTROL.format(risk=risk, runs=runs) if controls else "")
    )
    path.write_text(body, encoding="utf-8")
    return path


class TestLoaderRejects:
    def test_a_minimal_matrix_loads(self, tmp_path: Path) -> None:
        cov = load_mcp_coverage(_yaml(tmp_path))
        assert [c.modules for c in cov.controls] == [("agent_airlock.policy",)]
        assert cov.controls[0].presets == ()

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"coverage": "Mostly"}, "coverage"),
            ({"runs": "sometimes"}, "runs"),
            ({"why": "a | b"}, "splits a table cell"),
            ({"risk": "MCP11"}, "unknown risk"),
            ({"controls": False}, "has no controls"),
            ({"why": ""}, "missing required key 'justification'"),
        ],
    )
    def test_a_bad_matrix_is_refused(
        self, tmp_path: Path, kwargs: dict[str, Any], message: str
    ) -> None:
        with pytest.raises(ValueError, match=message):
            load_mcp_coverage(_yaml(tmp_path, **kwargs))
