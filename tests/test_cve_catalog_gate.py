"""The CVE catalog must publish every CVE-numbered regression, and say so accurately.

Through v0.8.79 the generator skipped any module whose docstring header it could not parse,
printed a warning, and **exited 0**. Nineteen of thirty-one CVE-numbered modules were being
dropped — while `marketplace.json` told readers to "see the generated catalog at
docs/cves/index.md" to substantiate a count of 38. The link did not support the claim, and
no gate noticed, because the gate only compared the file against the generator's own
(already truncated) output.

Two things are asserted here, and they are different:

1. **Completeness** — every `test_cve_*.py` module reaches the catalog. This is the bug.
2. **Honesty of the split** — 38 regression modules exist, 31 are CVE-numbered, and the
   published wording says both rather than implying the catalog holds all 38. The other
   seven are advisory regressions with no CVE id, plus umbrellas whose CVEs already appear.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from scripts.gen_cve_catalog import (
    UnparseableCVEModule,
    _catalog_modules,
    _match_header,
    collect,
)

_ROOT = Path(__file__).resolve().parents[1]
_CATALOG = _ROOT / "docs" / "cves" / "index.md"
_CVE_DIR = _ROOT / "tests" / "cves"


class TestEveryCveNumberedModuleReachesTheCatalog:
    """The regression. If this fails the catalog is under-reporting again."""

    def test_no_module_is_silently_skipped(self) -> None:
        entries = collect(strict=True)
        assert len(entries) == len(_catalog_modules())

    def test_every_module_filename_is_represented(self) -> None:
        published = {e.file.name for e in collect()}
        expected = {p.name for p in _catalog_modules()}
        missing = sorted(expected - published)
        assert not missing, f"absent from the catalog: {missing}"

    def test_the_count_is_what_the_suite_actually_holds(self) -> None:
        rows = len(re.findall(r"^\| \[CVE-", _CATALOG.read_text(encoding="utf-8"), re.M))
        assert rows == len(list(_CVE_DIR.glob("test_cve_*.py")))

    def test_the_catalog_is_not_trivially_small(self) -> None:
        """A glob bug that matched nothing would make every other assertion vacuous."""
        assert len(collect()) >= 31


class TestItFailsClosedOnAnUnreadableModule:
    """A gate that warns is not a gate — that is how 19 modules went missing."""

    def test_strict_collect_raises_on_an_unparseable_module(self, tmp_path, monkeypatch) -> None:
        import scripts.gen_cve_catalog as mod

        (tmp_path / "test_cve_2026_00002_probe.py").write_text(
            '"""No CVE id on the first line."""\n', encoding="utf-8"
        )
        monkeypatch.setattr(mod, "TESTS_DIR", tmp_path)
        with pytest.raises(UnparseableCVEModule):
            mod.collect(strict=True)

    def test_non_strict_collect_still_only_warns(self, tmp_path, monkeypatch) -> None:
        """`--write` stays lenient so an author mid-edit can regenerate and see the warning."""
        import scripts.gen_cve_catalog as mod

        (tmp_path / "test_cve_2026_00002_probe.py").write_text(
            '"""No CVE id on the first line."""\n', encoding="utf-8"
        )
        monkeypatch.setattr(mod, "TESTS_DIR", tmp_path)
        assert mod.collect(strict=False) == []

    def test_the_error_names_the_offending_file(self, tmp_path, monkeypatch) -> None:
        import scripts.gen_cve_catalog as mod

        (tmp_path / "test_cve_2026_00002_probe.py").write_text('"""nope."""\n', encoding="utf-8")
        monkeypatch.setattr(mod, "TESTS_DIR", tmp_path)
        with pytest.raises(UnparseableCVEModule, match="test_cve_2026_00002_probe"):
            mod.collect(strict=True)


class TestTheHeaderShapesTheRepoActuallyUses:
    """All four are in the tree today; a parser that only knew one caused the outage."""

    @pytest.mark.parametrize(
        ("header", "cve", "title"),
        [
            (
                "CVE-2026-75130 — Upstash Context7 ContextCrush MCP instruction injection.",
                "CVE-2026-75130",
                "Upstash Context7 ContextCrush MCP instruction injection",
            ),
            (
                "CVE-2026-11393 (AgentCore CLI triple-quote codegen RCE) regression.",
                "CVE-2026-11393",
                "AgentCore CLI triple-quote codegen RCE",
            ),
            (
                "Tests for CVE-2026-23744 MCPJam Inspector unauthenticated public bind (v0.5.6+).",
                "CVE-2026-23744",
                "MCPJam Inspector unauthenticated public bind",
            ),
            (
                'CVE-2026-33032 "MCPwn" — nginx-ui missing /mcp_message auth middleware.',
                "CVE-2026-33032",
                '"MCPwn" — nginx-ui missing /mcp_message auth middleware',
            ),
        ],
    )
    def test_each_shape_parses(self, header: str, cve: str, title: str) -> None:
        matched = _match_header(header)
        assert matched is not None, header
        assert matched[0] == cve
        assert matched[1] == title

    def test_a_line_with_no_cve_id_does_not_parse(self) -> None:
        assert _match_header("Tests for the archived-MCP-server advisory gate (v0.5.6+).") is None

    def test_a_trailing_version_marker_is_not_part_of_the_title(self) -> None:
        matched = _match_header(
            "Tests for CVE-2026-6980 GitPilot-MCP repo_path injection (v0.5.7+)."
        )
        assert matched is not None
        assert "v0.5.7" not in matched[1]


class TestNothingIsInvented:
    """A harvested field must come from the docstring, never from a default."""

    def test_no_entry_carries_a_cvss_absent_from_its_source(self) -> None:
        for entry in collect():
            if entry.cvss:
                doc = entry.file.read_text(encoding="utf-8")
                score = re.search(r"(\d\.\d)", entry.cvss)
                assert score and score.group(1) in doc, f"{entry.cve_id}: CVSS not in source"

    def test_no_entry_carries_a_url_absent_from_its_source(self) -> None:
        for entry in collect():
            doc = entry.file.read_text(encoding="utf-8")
            for url in (entry.nvd, entry.advisory, entry.writeup):
                if url:
                    assert url in doc, f"{entry.cve_id}: {url} not in source"

    def test_a_module_with_no_cvss_renders_an_em_dash_rather_than_a_guess(self) -> None:
        from scripts.gen_cve_catalog import render

        rendered = render([e for e in collect() if e.cvss is None][:1])
        assert "—" in rendered or not [e for e in collect() if e.cvss is None]


class TestThePublishedSplitIsAccurate:
    """38 modules, 31 CVE-numbered. Both numbers must appear, and both must be true."""

    @staticmethod
    def _module_counts() -> tuple[int, int]:
        from tests.test_marketplace_metadata import _cve_regression_module_count

        return _cve_regression_module_count(), len(list(_CVE_DIR.glob("test_cve_*.py")))

    def test_the_two_counts_are_what_the_tree_holds(self) -> None:
        total, cve_numbered = self._module_counts()
        assert total == 38
        assert cve_numbered == 31

    def test_the_marketplace_states_both_numbers(self) -> None:
        text = (_ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        total, cve_numbered = self._module_counts()
        assert f"{total} CVE / advisory regression tests" in text
        assert f"{cve_numbered} are CVE-numbered" in text

    def test_the_readme_points_at_the_catalog_with_the_number_it_shows(self) -> None:
        text = (_ROOT / "README.md").read_text(encoding="utf-8")
        _total, cve_numbered = self._module_counts()
        assert f"{cve_numbered} CVE-numbered ones are published" in text

    def test_the_catalog_row_count_equals_the_cve_numbered_count(self) -> None:
        rows = len(re.findall(r"^\| \[CVE-", _CATALOG.read_text(encoding="utf-8"), re.M))
        assert rows == self._module_counts()[1]


class TestTheCatalogsOwnCIClaim:
    """The catalog tells readers CI checks it. That has to be true.

    From the day it was written, ``docs/cves/index.md`` said "CI runs
    ``python3 scripts/gen_cve_catalog.py --check`` on every PR, so the catalog
    and the tests stay in lockstep." Nothing ran it — the script appeared in no
    workflow and no Makefile target. The row count was gated (see
    ``test_the_catalog_row_count_equals_the_cve_numbered_count``), but a drifted
    title, CVSS or advisory URL inside a ``tests/cves/`` docstring would have
    shipped with the catalog silently out of date.

    This is the same class of defect the repo already gates elsewhere: a
    documented gate that does not exist is worse than no documented gate,
    because it stops anyone from looking.
    """

    _WORKFLOWS = _ROOT / ".github" / "workflows"

    def _claims_ci_checks_it(self) -> bool:
        text = _CATALOG.read_text(encoding="utf-8")
        return "gen_cve_catalog.py --check" in text and "CI runs" in text

    @staticmethod
    def _uncommented(text: str) -> str:
        """Drop YAML comment lines.

        Without this the assertion below matches the *comment* that explains the
        step rather than the step itself, and would keep passing after someone
        deleted the `run:` line — a gate that cannot fail, which is the exact
        defect this class exists to prevent. Caught by negative control.
        """
        return "\n".join(
            line for line in text.splitlines() if not line.lstrip().startswith("#")
        )

    def test_the_claim_is_backed_by_a_workflow(self) -> None:
        if not self._claims_ci_checks_it():
            pytest.skip("catalog no longer claims CI checks it")
        hits = [
            p.name
            for p in sorted(self._WORKFLOWS.glob("*.yml"))
            if "gen_cve_catalog.py --check"
            in self._uncommented(p.read_text(encoding="utf-8"))
        ]
        assert hits, (
            "docs/cves/index.md says CI runs `gen_cve_catalog.py --check` on every "
            "PR, but no workflow under .github/workflows/ invokes it. Either wire "
            "the gate up or stop claiming it."
        )

    def test_the_makefile_exposes_the_same_gate(self) -> None:
        makefile = (_ROOT / "Makefile").read_text(encoding="utf-8")
        assert "check-cve-catalog:" in makefile, (
            "every other claim gate has a make target; this one should too"
        )

    def test_the_committed_catalog_is_actually_in_sync(self) -> None:
        """What `--check` asserts, asserted here too so it fails in the suite."""
        from scripts.gen_cve_catalog import collect, render

        assert render(collect()).strip() in _CATALOG.read_text(encoding="utf-8").strip()
