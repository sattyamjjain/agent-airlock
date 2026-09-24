"""The CVE catalog must publish every CVE-numbered regression, and say so accurately.

Through v0.8.79 the generator skipped any module whose docstring header it could not parse,
printed a warning, and **exited 0**. Nineteen of thirty-one CVE-numbered modules were being
dropped — while `marketplace.json` told readers to "see the generated catalog at
docs/cves/index.md" to substantiate a count of 38. The link did not support the claim, and
no gate noticed, because the gate only compared the file against the generator's own
(already truncated) output.

Two things are asserted here, and they are different:

1. **Completeness** — every `test_cve_*.py` module reaches the catalog. This is the bug.
2. **Honesty of the split** — the module count, the CVE-numbered module count and the
   catalog's row count are three different numbers, and the published wording has to say
   which it means. ``TestThePublishedSplitIsAccurate`` pins all three.
3. **One row per CVE** — the catalog is keyed by CVE id, so a CVE covered by two modules
   gets one row listing both. ``TestOneRowPerCve`` pins that, and is the gate ``--check``
   structurally could not provide.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from scripts.gen_cve_catalog import (
    CVEEntry,
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
        # A row is one CVE and a CVE may be covered by several modules, so the
        # completeness invariant is over *files*, not over rows.
        entries = collect(strict=True)
        published_files = [f for e in entries for f in e.files]
        assert len(published_files) == len(_catalog_modules())

    def test_every_module_filename_is_represented(self) -> None:
        published = {f.name for e in collect() for f in e.files}
        expected = {p.name for p in _catalog_modules()}
        missing = sorted(expected - published)
        assert not missing, f"absent from the catalog: {missing}"

    def test_the_count_is_what_the_suite_actually_holds(self) -> None:
        # Rows are distinct CVEs. Two CVEs here carry two modules each, so this
        # is deliberately NOT a module count -- see TestOneRowPerCve.
        rows = len(re.findall(r"^\| \[CVE-", _CATALOG.read_text(encoding="utf-8"), re.M))
        assert rows == len({e.cve_id for e in collect()})

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
                doc = "\n".join(f.read_text(encoding="utf-8") for f in entry.files)
                score = re.search(r"(\d\.\d)", entry.cvss)
                assert score and score.group(1) in doc, f"{entry.cve_id}: CVSS not in source"

    def test_no_entry_carries_a_url_absent_from_its_source(self) -> None:
        for entry in collect():
            doc = "\n".join(f.read_text(encoding="utf-8") for f in entry.files)
            for url in (entry.nvd, entry.advisory, entry.writeup):
                if url:
                    assert url in doc, f"{entry.cve_id}: {url} not in source"

    def test_a_module_with_no_cvss_renders_an_em_dash_rather_than_a_guess(self) -> None:
        from scripts.gen_cve_catalog import render

        rendered = render([e for e in collect() if e.cvss is None][:1])
        assert "—" in rendered or not [e for e in collect() if e.cvss is None]


class TestThePublishedSplitIsAccurate:
    """Three different numbers live here. Conflating any two is how this drifts.

    - **total regression modules** under ``tests/cves/`` (marketplace proof point)
    - **CVE-numbered modules**, i.e. ``test_cve_*.py`` (marketplace proof point)
    - **distinct CVEs**, which is what the catalog publishes as rows (README)

    They are not interchangeable: two CVEs are covered by two modules each, so
    the CVE-numbered module count runs ahead of the row count. Before v0.10.5
    the README quoted the module count while pointing at the catalog, which
    published rows -- the two happened to be equal only because the catalog was
    double-counting. Fixing the catalog made them differ, which is correct.

    The literals below are deliberate canaries: a change to any of them should
    be a decision someone made, not drift someone missed.
    """

    @staticmethod
    def _module_counts() -> tuple[int, int]:
        from tests.test_marketplace_metadata import _cve_regression_module_count

        return _cve_regression_module_count(), len(list(_CVE_DIR.glob("test_cve_*.py")))

    @staticmethod
    def _distinct_cve_count() -> int:
        return len({e.cve_id for e in collect()})

    def test_the_module_counts_are_what_the_tree_holds(self) -> None:
        total, cve_numbered = self._module_counts()
        assert total == 47
        assert cve_numbered == 40

    def test_the_distinct_cve_count_is_what_the_catalog_publishes(self) -> None:
        assert self._distinct_cve_count() == 38

    def test_the_cve_numbered_modules_exceed_the_distinct_cves(self) -> None:
        """The whole reason the two numbers must not be conflated again."""
        _total, cve_numbered = self._module_counts()
        assert cve_numbered > self._distinct_cve_count(), (
            "if these are equal, either the duplicate-covering modules were removed "
            "or the catalog is double-counting again"
        )

    def test_the_marketplace_states_both_module_numbers(self) -> None:
        text = (_ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8")
        total, cve_numbered = self._module_counts()
        assert f"{total} CVE / advisory regression tests" in text
        assert f"{cve_numbered} are CVE-numbered" in text

    def test_the_readme_points_at_the_catalog_with_the_row_count(self) -> None:
        """The README's number must be the catalog's row count, not the module count."""
        text = (_ROOT / "README.md").read_text(encoding="utf-8")
        total, _cve_numbered = self._module_counts()
        assert f"{total} CVE/advisory regression tests" in text
        assert f"{self._distinct_cve_count()} distinct CVEs" in text

    def test_the_catalog_row_count_equals_the_distinct_cve_count(self) -> None:
        rows = len(re.findall(r"^\| \[CVE-", _CATALOG.read_text(encoding="utf-8"), re.M))
        assert rows == self._distinct_cve_count()


class TestOneRowPerCve:
    """The duplicate-row defect, and the gate that can now see it.

    ``docs/cves/index.md`` carried **36 rows for 34 distinct CVEs**: CVE-2026-30615
    and CVE-2026-42271 each appeared twice, once per covering module, under two
    different titles. Because the anchor is derived from the CVE id, both rows of a
    pair linked to the same ``#cve-...`` target and the detail section emitted that
    id twice, so one summary link in each pair necessarily resolved to the wrong
    section and the duplicated HTML ``id`` was invalid.

    ``--check`` could not see it. It compares generated output to committed output,
    and the generator wrote the duplicate into both sides, so the comparison was
    green while the artefact was wrong. That is the class of drift this adds.
    """

    def test_no_cve_id_is_published_twice(self) -> None:
        from scripts.gen_cve_catalog import assert_unique_cve_rows

        assert_unique_cve_rows(collect())

    def test_the_committed_catalog_has_no_repeated_row(self) -> None:
        ids = re.findall(r"^\| \[(CVE-[\d-]+)\]", _CATALOG.read_text(encoding="utf-8"), re.M)
        assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})

    def test_every_anchor_is_emitted_once(self) -> None:
        anchors = re.findall(r'<a id="(cve-[\d-]+)"></a>', _CATALOG.read_text(encoding="utf-8"))
        assert len(anchors) == len(set(anchors))

    def test_every_summary_link_resolves_to_an_anchor(self) -> None:
        text = _CATALOG.read_text(encoding="utf-8")
        targets = set(re.findall(r'<a id="(cve-[\d-]+)"></a>', text))
        links = set(re.findall(r"^\| \[CVE-[\d-]+\]\(#(cve-[\d-]+)\)", text, re.M))
        assert links <= targets, sorted(links - targets)

    def test_a_merged_row_lists_every_module_behind_it(self) -> None:
        merged = [e for e in collect() if len(e.files) > 1]
        assert merged, "expected at least one CVE covered by two modules"
        text = _CATALOG.read_text(encoding="utf-8")
        for entry in merged:
            for path in entry.files:
                assert path.name in text, f"{entry.cve_id}: {path.name} not published"

    def test_the_gate_can_actually_fail(self) -> None:
        """A gate that cannot fail is the defect this repo keeps finding."""
        from scripts.gen_cve_catalog import DuplicateCVERows, assert_unique_cve_rows

        entries = collect()[:1]
        with pytest.raises(DuplicateCVERows, match=entries[0].cve_id):
            assert_unique_cve_rows(entries + entries)

    def test_merging_is_what_removes_the_duplicate(self) -> None:
        from scripts.gen_cve_catalog import DuplicateCVERows, assert_unique_cve_rows
        from scripts.gen_cve_catalog import merge_duplicate_cves as merge

        one = collect()[0]
        twin = CVEEntry(cve_id=one.cve_id, title="second module", files=[Path("b.py")])
        pair = [one, twin]
        with pytest.raises(DuplicateCVERows):
            assert_unique_cve_rows(pair)
        folded = merge(pair)
        assert len(folded) == 1
        assert len(folded[0].files) == len(one.files) + 1
        assert_unique_cve_rows(folded)


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
        return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    def test_the_claim_is_backed_by_a_workflow(self) -> None:
        if not self._claims_ci_checks_it():
            pytest.skip("catalog no longer claims CI checks it")
        hits = [
            p.name
            for p in sorted(self._WORKFLOWS.glob("*.yml"))
            if "gen_cve_catalog.py --check" in self._uncommented(p.read_text(encoding="utf-8"))
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
