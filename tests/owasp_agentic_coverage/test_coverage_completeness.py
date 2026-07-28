"""Tests for ``owasp_agentic_coverage`` matrix loader / renderer / gates.

Covers BOTH published matrices: the OWASP LLM Top-10 (``coverage.yaml``) and the
OWASP Agentic Top-10 (``agentic_coverage.yaml``). The cross-file checks — every
``guard_module`` imports, every ``test_path`` exists — are what make each matrix
*evidence* rather than prose.
"""

from __future__ import annotations

import importlib
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
