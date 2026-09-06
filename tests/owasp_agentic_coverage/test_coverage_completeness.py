"""Tests for ``owasp_agentic_coverage`` matrix loader / renderer / gates.

Covers BOTH published matrices: the OWASP LLM Top-10 (``coverage.yaml``) and the
OWASP Agentic Top-10 (``agentic_coverage.yaml``). The cross-file checks — every
``guard_module`` imports, every ``test_path`` exists — are what make each matrix
*evidence* rather than prose.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

from agent_airlock import policy_presets
from agent_airlock.owasp_agentic_coverage import (
    load_coverage,
    render_json,
    render_markdown,
)
from agent_airlock.owasp_agentic_coverage.render import (
    COVERAGE_PATH,
    stale_entries,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTIC_PATH = COVERAGE_PATH.parent / "agentic_coverage.yaml"
AGENTIC_DOC = REPO_ROOT / "docs" / "owasp-agentic-2026-coverage.md"
# MUST byte-match the header used to generate AGENTIC_DOC.
AGENTIC_DOC_HEADER = (
    "<!-- @generated from "
    "src/agent_airlock/owasp_agentic_coverage/agentic_coverage.yaml — do not edit by "
    "hand; regenerated and byte-diffed in "
    "tests/owasp_agentic_coverage/test_coverage_completeness.py -->\n\n"
)


@pytest.fixture
def coverage() -> object:
    return load_coverage()


@pytest.fixture
def agentic() -> object:
    return load_coverage(AGENTIC_PATH)


class TestCoverageCompleteness:
    def test_all_ten_owasp_risks_mapped(self, coverage) -> None:
        assert len(coverage.entries) == 10
        ids = {e.risk_id for e in coverage.entries}
        assert ids == {f"LLM{i:02d}" for i in range(1, 11)}

    def test_every_entry_has_non_empty_guard(self, coverage) -> None:
        for e in coverage.entries:
            assert e.guard_module, f"{e.risk_id}: empty guard_module"
            assert e.preset, f"{e.risk_id}: empty preset"
            assert e.test_path, f"{e.risk_id}: empty test_path"

    def test_spec_version_pinned(self, coverage) -> None:
        # Spec bump must be an explicit PR; the literal value is asserted.
        assert coverage.spec_version == "2026-Q1"


class TestDeterministicRender:
    def test_markdown_byte_stable(self, coverage) -> None:
        a = render_markdown(coverage)
        b = render_markdown(coverage)
        assert a == b

    def test_json_byte_stable(self, coverage) -> None:
        a = render_json(coverage)
        b = render_json(coverage)
        assert a == b

    def test_entries_sorted_by_risk_id(self, coverage) -> None:
        ids = [e.risk_id for e in coverage.entries]
        assert ids == sorted(ids)


class TestCIGate:
    """Synthetic missing-mapping fixture must trip the gate."""

    def test_missing_guard_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "coverage.yaml"
        bad.write_text(
            'spec_version: "2026-Q1"\n'
            'spec_url: "https://example.com"\n'
            'last_verified_global: "2026-04-28"\n'
            "entries:\n"
            '  - risk_id: "LLM01"\n'
            '    risk_name: "Prompt Injection"\n'
            '    guard_module: ""\n'
            '    preset: "p"\n'
            '    test_path: "t"\n'
            '    last_verified: "2026-04-28"\n'
            '    advisory_url: "https://example.com"\n',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="missing required key 'guard_module'"):
            load_coverage(path=bad)

    def test_stale_entry_detected(self, tmp_path: Path) -> None:
        bad = tmp_path / "coverage.yaml"
        bad.write_text(
            'spec_version: "2026-Q1"\n'
            'spec_url: "https://example.com"\n'
            'last_verified_global: "2026-01-01"\n'
            "entries:\n"
            '  - risk_id: "LLM01"\n'
            '    risk_name: "Prompt Injection"\n'
            '    guard_module: "x"\n'
            '    preset: "p"\n'
            '    test_path: "t"\n'
            '    last_verified: "2025-01-01"\n'
            '    advisory_url: "https://example.com"\n',
            encoding="utf-8",
        )
        c = load_coverage(path=bad)
        assert len(stale_entries(c, max_age_days=30)) == 1


class TestPath:
    def test_default_path_exists(self) -> None:
        assert COVERAGE_PATH.exists()


class TestAgenticMatrix:
    """The OWASP Agentic Top-10 matrix (``agentic_coverage.yaml``)."""

    def test_ten_asi_risks_sorted(self, agentic) -> None:
        assert len(agentic.entries) == 10
        ids = [e.risk_id for e in agentic.entries]
        assert ids == sorted(ids)
        assert set(ids) == {f"ASI{i:02d}" for i in range(1, 11)}

    def test_spec_version_pinned(self, agentic) -> None:
        # The real OWASP Agentic list version; a bump must be an explicit PR.
        assert agentic.spec_version == "v2.01"

    def test_presets_are_live_registry_factories(self, agentic) -> None:
        """Every Agentic ``preset`` must be a real ``list_active()`` factory — the
        registry API, not a regex, so the mapping cannot name a preset that no longer
        ships."""
        factories = {m.factory_name for m in policy_presets.list_active()}
        for e in agentic.entries:
            assert e.preset in factories, (
                f"{e.risk_id}: preset {e.preset!r} is not in policy_presets.list_active()"
            )

    def test_not_stale_on_ship_day(self, agentic) -> None:
        assert stale_entries(agentic, max_age_days=30) == []

    def test_doc_byte_matches_render(self, agentic) -> None:
        """docs/owasp-agentic-2026-coverage.md is regenerate-and-diff gated (same
        discipline as the CVE catalog): it must byte-match the rendered matrix."""
        expected = AGENTIC_DOC_HEADER + render_markdown(agentic)
        assert AGENTIC_DOC.read_text(encoding="utf-8") == expected, (
            "docs/owasp-agentic-2026-coverage.md is stale — regenerate it from "
            "agentic_coverage.yaml via render_markdown()."
        )


class TestMatrixEvidence:
    """Cross-file: every mapping in BOTH matrices points at a real module + test."""

    @pytest.mark.parametrize("path", [COVERAGE_PATH, AGENTIC_PATH])
    def test_guard_modules_import_and_test_paths_exist(self, path: Path) -> None:
        cov = load_coverage(path)
        for e in cov.entries:
            importlib.import_module(e.guard_module)  # raises if the module is gone
            test_file = REPO_ROOT / e.test_path
            assert test_file.is_file(), (
                f"{e.risk_id} ({path.name}): test_path {e.test_path!r} does not exist"
            )


# The OWASP MCP Top 10 (2026 beta), pinned to the authoritative titles at
# https://owasp.org/www-project-mcp-top-10/ (retrieved 2026-07-29). The README
# claimed the OWASP MCP Top 10 was "covered end-to-end by the
# OWASP_MCP_TOP_10_2026 policy preset" while the mapping table listed only 7 of
# 10 and the preset docstring marked MCP06/MCP08 "(reserved)". This constant is
# the single source both surfaces are bound to below, so neither can drift back
# to a stale taxonomy or drop a category.
MCP_TOP_10_2026 = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}
README = REPO_ROOT / "README.md"


def _mcp_mapping_table() -> str:
    """The README 'MCP-specific mapping' table, from its heading to the next one."""
    body = README.read_text(encoding="utf-8")
    start = body.index("### MCP-specific mapping")
    end = body.index("Use it directly", start)
    return body[start:end]


class TestMcpTopTenMapping:
    """Bind the README MCP Top-10 mapping table AND the OWASP_MCP_TOP_10_2026
    preset docstring to the authoritative taxonomy, so the 'covered end-to-end'
    honesty bug (7/10 rows, MCP06/08 'reserved') cannot silently return."""

    def test_readme_table_lists_all_ten_with_authoritative_titles(self) -> None:
        table = _mcp_mapping_table()
        missing = [
            f"{rid} {title}"
            for rid, title in MCP_TOP_10_2026.items()
            if f"**{rid} {title}**" not in table
        ]
        assert not missing, (
            "README MCP Top-10 mapping table is missing rows or uses non-authoritative "
            f"titles for: {missing}"
        )

    def test_readme_table_makes_no_end_to_end_single_preset_claim(self) -> None:
        # The specific false claim that shipped: one preset covering all ten.
        table = _mcp_mapping_table()
        assert "covered end-to-end by the `OWASP_MCP_TOP_10_2026` policy preset" not in table, (
            "README revived the 'covered end-to-end by the OWASP_MCP_TOP_10_2026 policy "
            "preset' claim — the single preset covers only the policy-layer subset."
        )

    def test_preset_docstring_enumerates_the_same_ten(self) -> None:
        doc = policy_presets.owasp_mcp_top_10_2026_policy.__doc__ or ""
        missing = [
            f"{rid} {title}"
            for rid, title in MCP_TOP_10_2026.items()
            if f"{rid} {title}" not in doc
        ]
        assert not missing, (
            "owasp_mcp_top_10_2026_policy docstring drifted from the authoritative OWASP "
            f"MCP Top-10 taxonomy for: {missing}"
        )
        assert "(reserved)" not in doc, (
            "preset docstring still marks an MCP category '(reserved)' — MCP06/MCP08 are "
            "named categories (Intent Flow Subversion / Lack of Audit and Telemetry)."
        )


# ---------------------------------------------------------------------------
# measured_block_rate
# ---------------------------------------------------------------------------

_MEASURED_RE = re.compile(r"^\d+\.\d% \(n=\d+\)$")
_UNMEASURED_RE = re.compile(r"^not measured \(n=0\)$")


def has_evidence(measured_block_rate: str) -> bool:
    """True iff the value is a measurement or an explicit unmeasured marker.

    Anything else — empty, prose, a bare percentage with no sample size — is
    treated as absent. A rate without its ``n`` is not evidence: 100% of two
    items and 100% of two hundred are not the same claim.
    """
    value = (measured_block_rate or "").strip()
    return bool(_MEASURED_RE.match(value) or _UNMEASURED_RE.match(value))


class TestMeasuredBlockRate:
    """A coverage label must be backed by a number or an explicit 'no number'.

    Before this field the matrix asserted "Full", "Partial" and "Monitor-only"
    in a ``risk_name`` string, evidenced by a test path and never by a rate,
    while ``benchmarks/blockrate`` published 100% over 106 malicious items with
    no OWASP dimension at all. The two artifacts described the same ten risks
    and never met.

    The case this class exists to stop is a ``(Full)`` with neither a measured
    rate nor an admission that nothing was measured. ASI08 is exactly that
    shape today: labelled ``(Full)`` on the strength of CircuitBreaker /
    RetryPolicy / rate-limit code, with a block-rate corpus that contains zero
    cascading-failure items. It now says so out loud.
    """

    def test_every_agentic_entry_carries_evidence(self, agentic) -> None:
        missing = [e.risk_id for e in agentic.entries if not has_evidence(e.measured_block_rate)]
        assert not missing, (
            f"entries with no measured rate and no explicit unmeasured marker: {missing}. "
            'Add `measured_block_rate: "NN.N% (n=NN)"` or '
            '`measured_block_rate: "not measured (n=0)"`.'
        )

    def test_full_coverage_claims_are_backed(self, agentic) -> None:
        """The load-bearing one: '(Full)' with no evidence at all."""
        offenders = [
            e.risk_id
            for e in agentic.entries
            if "(Full)" in e.risk_name and not has_evidence(e.measured_block_rate)
        ]
        assert not offenders, (
            f"{offenders} claim (Full) coverage without a measured block-rate or an "
            "explicit 'not measured (n=0)' marker. A full-coverage claim with neither "
            "is the assertion this field exists to prevent."
        )

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("100.0% (n=22)", True),
            ("84.4% (n=45)", True),
            ("not measured (n=0)", True),
            ("", False),
            ("   ", False),
            ("100%", False),  # no sample size
            ("100.0%", False),  # no sample size
            ("high", False),
            ("not measured", False),  # no explicit n
            ("Full", False),
        ],
    )
    def test_evidence_predicate(self, value: str, expected: bool) -> None:
        assert has_evidence(value) is expected

    def test_a_full_claim_with_no_evidence_is_caught(self, tmp_path: Path) -> None:
        """Negative control: the gate must actually fail on the shape it targets."""
        bad = tmp_path / "agentic.yaml"
        bad.write_text(
            'spec_version: "v2.01"\n'
            'spec_url: "https://example.com"\n'
            'last_verified_global: "2026-09-06"\n'
            "entries:\n"
            '  - risk_id: "ASI08"\n'
            '    risk_name: "Cascading Failures (Full)"\n'
            '    guard_module: "agent_airlock.circuit_breaker"\n'
            '    preset: "owasp_mcp_top_10_2026_policy"\n'
            '    test_path: "tests/test_new_features.py"\n'
            '    last_verified: "2026-09-06"\n'
            '    advisory_url: "https://example.com"\n',
            encoding="utf-8",
        )
        loaded = load_coverage(bad)
        offenders = [
            e.risk_id
            for e in loaded.entries
            if "(Full)" in e.risk_name and not has_evidence(e.measured_block_rate)
        ]
        assert offenders == ["ASI08"]

    def test_published_rates_match_a_live_benchmark_run(self, agentic) -> None:
        """The published number must equal what the benchmark produces now.

        This is the join the work item is about: re-run the corpus, aggregate per
        OWASP slot, and compare against what the shipped matrix claims. A corpus
        edit that changes a slot's population fails here until the yaml is
        regenerated, so the two artifacts cannot drift apart again.
        """
        from benchmarks.blockrate.report import asi_breakdown
        from benchmarks.blockrate.runner import run_blockrate

        stats = asi_breakdown(run_blockrate(measure_latency=False))
        for e in agentic.entries:
            s = stats[e.risk_id]
            expected = (
                f"not measured (n={s.malicious_total})"
                if s.malicious_total == 0
                else f"{s.block_rate * 100:.1f}% (n={s.malicious_total})"
            )
            assert e.measured_block_rate == expected, (
                f"{e.risk_id}: matrix says {e.measured_block_rate!r}, a live run says "
                f"{expected!r}. Regenerate agentic_coverage.yaml and the docs page."
            )
