"""CI guard: numeric claims about our own surface must not drift.

v0.8.68 machine-checked the zero-dependency claim, the changelog and the pins. This closes
the remaining numeric claims, which fall into two treatments:

**Rendered from source** (nothing to assert here — the generator *is* the check):

* every number in ``BENCHMARK.md`` — rendered by ``scripts/generate_benchmark.py`` and
  drift-gated in CI by ``generate_benchmark.py --check``;
* the README ``TEST-BADGE`` block — rendered by ``scripts/update_test_badge.py``.

**Asserted by a test that fails when the underlying number moves** (this module, plus the
pre-existing guards it deliberately does not duplicate):

* the badge's *version* vs the package version — ``tests/test_badge_version.py``;
* the badge's internal reconciliation — ``tests/test_badge_test_count_honesty.py``;
* framework-integration counts — ``tests/test_readme_framework_claims.py``;
* preset registry / docs parity — ``tests/presets/test_registry_parity.py``;
* **the hand-written copies of the test count in ``docs/distribution/``** — here;
* **the egress-bench payload/category/slip counts** — here.

The distribution copies are the sharp edge. Five submission drafts under
``docs/distribution/`` repeat the badge's test count in prose (thirteen occurrences at the
time of writing) and even carry a note telling a human to "refresh the test count at
submission time". A human instruction is exactly the thing that rots: the badge is
regenerated every release and the copies are not. This asserts the *relative* invariant —
copies equal the badge — which never flaps on a normal commit and fails precisely when a
release moves the badge and leaves the drafts behind.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_README = _ROOT / "README.md"
_DISTRIBUTION = _ROOT / "docs" / "distribution"

_BADGE_BLOCK_RE = re.compile(
    r"<!-- TEST-BADGE-START -->(?P<body>.*?)<!-- TEST-BADGE-END -->", re.DOTALL
)
_BADGE_COUNT_RE = re.compile(r"\*\*Test suite:\*\*\s*([\d,]+)\s*tests")
_BADGE_VERSION_RE = re.compile(r"\*\*v(\d+\.\d+\.\d+[^\s*]*)\*\*")

#: Shapes in which the distribution drafts restate the badge's test count.
_TEST_COUNT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"([\d][\d,]{2,6})\s+tests\b"),
    re.compile(r"\bit is\s+\*\*([\d][\d,]{2,6})\*\*"),
    re.compile(r"\bv\d+\.\d+\.\d+\s*=\s*([\d][\d,]{2,6})\b"),
)

#: ``(version, count)`` pairs, e.g. "(v0.8.70 = 3,749)".
_VERSION_PAIR_RE = re.compile(r"\bv(\d+\.\d+\.\d+)\s*=\s*([\d][\d,]{2,6})\b")


def _as_int(raw: str) -> int:
    return int(raw.replace(",", ""))


def _badge_body() -> str:
    block = _BADGE_BLOCK_RE.search(_README.read_text(encoding="utf-8"))
    assert block, "README is missing the TEST-BADGE block"
    return block.group("body")


def _badge_test_count() -> int:
    match = _BADGE_COUNT_RE.search(_badge_body())
    assert match, "could not read the test count from the TEST-BADGE block"
    return _as_int(match.group(1))


def _badge_version() -> str:
    match = _BADGE_VERSION_RE.search(_badge_body())
    assert match, "could not read the version from the TEST-BADGE block"
    return match.group(1)


def _distribution_files() -> list[Path]:
    return sorted(_DISTRIBUTION.glob("*.md")) if _DISTRIBUTION.is_dir() else []


class TestDistributionTestCountParity:
    """Every hand-written copy of the test count must equal the generated badge."""

    def test_distribution_drafts_exist(self) -> None:
        """Without this, every parametrised check below would pass vacuously."""
        assert _distribution_files(), "expected submission drafts under docs/distribution/"

    def test_at_least_one_copy_is_found(self) -> None:
        """If the prose is reworded so the patterns stop matching, fail loudly."""
        total = sum(
            len(pattern.findall(path.read_text(encoding="utf-8")))
            for path in _distribution_files()
            for pattern in _TEST_COUNT_PATTERNS
        )
        assert total > 0, (
            "no test-count mentions matched in docs/distribution/ — the wording changed and "
            "this guard has gone blind; update _TEST_COUNT_PATTERNS"
        )

    @pytest.mark.parametrize("path", _distribution_files(), ids=lambda p: p.name)
    def test_every_test_count_matches_the_badge(self, path: Path) -> None:
        badge = _badge_test_count()
        text = path.read_text(encoding="utf-8")
        offenders: list[tuple[int, str]] = []
        for line_no, line in enumerate(text.splitlines(), 1):
            for pattern in _TEST_COUNT_PATTERNS:
                for match in pattern.finditer(line):
                    if _as_int(match.group(1)) != badge:
                        offenders.append((line_no, line.strip()))
        assert not offenders, (
            f"{path.relative_to(_ROOT)} states a test count that is not the README badge "
            f"({badge:,}):\n"
            + "\n".join(f"  line {n}: {text_}" for n, text_ in offenders)
            + "\nRun `make test-badge`, then update these drafts to match."
        )

    @pytest.mark.parametrize("path", _distribution_files(), ids=lambda p: p.name)
    def test_version_count_pairs_match_the_badge(self, path: Path) -> None:
        badge_version = _badge_version()
        badge_count = _badge_test_count()
        offenders: list[str] = []
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for version, count in _VERSION_PAIR_RE.findall(line):
                if version != badge_version or _as_int(count) != badge_count:
                    offenders.append(
                        f"  line {line_no}: v{version} = {count} "
                        f"(badge says v{badge_version} = {badge_count:,})"
                    )
        assert not offenders, (
            f"{path.relative_to(_ROOT)} pairs a version with a test count that does not match "
            "the README badge:\n" + "\n".join(offenders)
        )


class TestToolPrivBenchScenarioCount:
    """The README's ToolPrivBench scenario count is re-derived from the loaded corpus."""

    _CLAIM = re.compile(r"ToolPrivBench,\s*([\d,]+)\s+scenarios")

    def test_readme_scenario_count_matches_the_corpus(self) -> None:
        claimed = self._CLAIM.search(_README.read_text(encoding="utf-8"))
        assert claimed, "README no longer states a ToolPrivBench scenario count"
        from benchmarks.toolprivbench.scenarios import load_scenarios

        scenarios, _source = load_scenarios()
        assert _as_int(claimed.group(1)) == len(scenarios), (
            f"README claims {claimed.group(1)} ToolPrivBench scenarios; the loaded corpus has "
            f"{len(scenarios)}"
        )


class TestEgressBenchDocClaims:
    """``docs/security/egress-bench.md`` states three numbers; all three are re-derived."""

    DOC = _ROOT / "docs" / "security" / "egress-bench.md"

    @staticmethod
    def _rows() -> list[object]:
        sys.path.insert(0, str(_ROOT / "scripts"))
        try:
            import egress_bench
        finally:
            sys.path.pop(0)
        return list(egress_bench.walk(egress_bench.FIXTURE_DIR))

    def _graded(self) -> list[object]:
        return [row for row in self._rows() if getattr(row, "status", "") != "skip"]

    def test_doc_exists(self) -> None:
        assert self.DOC.is_file()

    def test_payload_count_claim_matches_live_run(self) -> None:
        claimed = re.search(r"(\d+)\s+payloads", self.DOC.read_text(encoding="utf-8"))
        assert claimed, "egress-bench doc no longer states a payload count"
        actual = sum(int(getattr(row, "payload_count", 0)) for row in self._graded())
        assert int(claimed.group(1)) == actual, (
            f"egress-bench doc claims {claimed.group(1)} payloads; a live walk of "
            f"tests/cves/fixtures/ grades {actual}"
        )

    def test_category_count_claim_matches_live_run(self) -> None:
        text = self.DOC.read_text(encoding="utf-8")
        words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6}
        # An optional adjective may sit between the count and the noun
        # ("three *graded* fixture categories"), so allow one filler word.
        claimed = re.search(
            r"\b(one|two|three|four|five|six|\d+)\s+(?:\w+\s+)?fixture categories\b", text, re.I
        )
        assert claimed, "egress-bench doc no longer states a fixture-category count"
        token = claimed.group(1).lower()
        expected = words.get(token, int(token) if token.isdigit() else None)
        assert expected is not None, f"unparsable category count {claimed.group(1)!r}"
        assert expected == len(self._graded()), (
            f"egress-bench doc claims {expected} graded fixture categories; a live walk "
            f"grades {len(self._graded())}"
        )

    def test_zero_slips_claim_holds(self) -> None:
        text = self.DOC.read_text(encoding="utf-8")
        if "zero slips" not in text.lower():
            pytest.skip("doc no longer claims zero slips")
        unblocked = sum(int(getattr(row, "unblocked", 0)) for row in self._graded())
        assert unblocked == 0, (
            f"egress-bench doc claims zero slips but a live walk leaves {unblocked} payload(s) "
            "unblocked"
        )
