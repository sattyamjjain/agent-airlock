"""Tests for ``owasp_agentic_coverage`` matrix loader / renderer / gates."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_airlock.owasp_agentic_coverage import (
    load_coverage,
    render_json,
    render_markdown,
)
from agent_airlock.owasp_agentic_coverage.render import (
    COVERAGE_PATH,
    stale_entries,
)


@pytest.fixture
def coverage() -> object:
    return load_coverage()


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
