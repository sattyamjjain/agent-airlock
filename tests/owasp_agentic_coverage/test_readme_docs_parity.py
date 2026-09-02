"""The OWASP matrix is published twice. The two copies must agree.

`README.md` carries a hand-written matrix with prose evidence per row.
`docs/owasp-agentic-2026-coverage.md` is generated from
`src/agent_airlock/owasp_agentic_coverage/agentic_coverage.yaml` and byte-diffed by
`test_coverage_completeness.py`. That byte-diff protects the generated copy from drifting
away from its own source. Nothing protected the two *surfaces* from drifting away from each
other, and a reader who lands on one of them has no way to know the other says something
different.

This repository has already shipped that defect class more than once. v0.8.x reconciled
three surfaces that disagreed on the CVE-regression count, and the registry-parity gate
landed after four internal surfaces agreed with each other and all disagreed with PyPI. The
coverage matrix is the highest-stakes place for it to happen again: a row saying **Full** in
one file and **Partial** in another is a security claim with two answers.

What is compared, and what deliberately is not
----------------------------------------------
* **Risk ID set** and **coverage label** per ID — the security claim. Exact match required.
* **Risk name** per ID, after normalisation. ``Memory & Context Poisoning`` and
  ``Memory and Context Poisoning`` are the same row; a rename to something else is not.
  Normalising here rather than forcing byte-equality keeps the gate pointed at meaning.
* **Module lists are NOT compared.** The README cites every module that contributes to a
  row; the YAML schema holds exactly one canonical ``guard_module`` per risk. They differ by
  design and always will, so comparing them would produce a permanently red gate, which is a
  gate that gets deleted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
DOCS_MATRIX = ROOT / "docs" / "owasp-agentic-2026-coverage.md"

#: ``| **ASI04 Agentic Supply Chain Vulnerabilities** | … | … | Partial |``
_README_ROW = re.compile(
    r"^\|\s*\*\*(ASI\d{2})\s+([^*]+?)\*\*\s*\|.*\|\s*\*{0,2}([A-Za-z-]+)\*{0,2}\s*\|\s*$",
    re.M,
)
#: ``| ASI04 | Agentic Supply Chain Vulnerabilities (Partial) | … |``
_DOCS_ROW = re.compile(
    r"^\|\s*(ASI\d{2})\s*\|\s*(.+?)\s*\((Full|Partial|Monitor-only)\)\s*\|",
    re.M,
)

EXPECTED_IDS = frozenset(f"ASI{i:02d}" for i in range(1, 11))


def normalise(name: str) -> tuple[str, ...]:
    """Reduce a risk name to comparable tokens.

    ``&``/``and`` and the ``(RCE)`` vs ``/ RCE`` spellings are presentation, not meaning.
    A genuine rename survives this and fails the comparison.
    """
    text = name.lower().replace("&", " and ")
    text = re.sub(r"[()/,]", " ", text)
    return tuple(text.split())


def parse_readme(text: str) -> dict[str, tuple[tuple[str, ...], str]]:
    """Map risk id -> (normalised name, coverage label) from the README matrix."""
    return {m.group(1): (normalise(m.group(2)), m.group(3)) for m in _README_ROW.finditer(text)}


def parse_docs(text: str) -> dict[str, tuple[tuple[str, ...], str]]:
    """Map risk id -> (normalised name, coverage label) from the generated matrix."""
    return {m.group(1): (normalise(m.group(2)), m.group(3)) for m in _DOCS_ROW.finditer(text)}


def disagreements(readme_text: str, docs_text: str) -> list[str]:
    """Return every way the two matrices disagree. Empty means they agree."""
    r, d = parse_readme(readme_text), parse_docs(docs_text)
    out: list[str] = []
    for missing in sorted(set(d) - set(r)):
        out.append(f"{missing}: in docs matrix, absent from README matrix")
    for missing in sorted(set(r) - set(d)):
        out.append(f"{missing}: in README matrix, absent from docs matrix")
    for risk_id in sorted(set(r) & set(d)):
        (r_name, r_cov), (d_name, d_cov) = r[risk_id], d[risk_id]
        if r_cov != d_cov:
            out.append(f"{risk_id}: coverage README={r_cov!r} docs={d_cov!r}")
        if r_name != d_name:
            out.append(f"{risk_id}: name README={' '.join(r_name)!r} docs={' '.join(d_name)!r}")
    return out


class TestTheTwoPublishedMatricesAgree:
    def test_both_surfaces_parse_ten_rows(self) -> None:
        """A parser that silently matches nothing is a gate that cannot fail.

        Asserted before the comparison, so a future edit that reshapes either table breaks
        this loudly instead of turning the comparison into a no-op over two empty dicts.
        """
        r = parse_readme(README.read_text(encoding="utf-8"))
        d = parse_docs(DOCS_MATRIX.read_text(encoding="utf-8"))
        assert set(r) == EXPECTED_IDS, f"README matrix parsed {sorted(r)}"
        assert set(d) == EXPECTED_IDS, f"docs matrix parsed {sorted(d)}"

    def test_readme_and_docs_matrices_do_not_disagree(self) -> None:
        found = disagreements(
            README.read_text(encoding="utf-8"), DOCS_MATRIX.read_text(encoding="utf-8")
        )
        assert found == [], (
            "README.md and docs/owasp-agentic-2026-coverage.md disagree about the OWASP "
            "coverage matrix:\n  - " + "\n  - ".join(found) + "\nThe docs matrix is generated "
            "from agentic_coverage.yaml; fix whichever surface is wrong, then regenerate."
        )


class TestTheGateActuallyFires:
    """Seeded mismatches. Without these the test above passes for the wrong reason."""

    _README_STUB = "| **ASI04 Agentic Supply Chain Vulnerabilities** | ev | mod | Partial |"
    _DOCS_STUB = "| ASI04 | Agentic Supply Chain Vulnerabilities (Partial) | m | p | t | d | a |"

    def test_identical_rows_agree(self) -> None:
        assert disagreements(self._README_STUB, self._DOCS_STUB) == []

    def test_a_coverage_label_mismatch_is_caught(self) -> None:
        found = disagreements(
            self._README_STUB.replace("| Partial |", "| **Full** |"), self._DOCS_STUB
        )
        assert found and "coverage" in found[0]

    def test_a_renamed_risk_is_caught(self) -> None:
        found = disagreements(
            self._README_STUB.replace("Agentic Supply Chain Vulnerabilities", "Supply Chain"),
            self._DOCS_STUB,
        )
        assert found and "name" in found[0]

    def test_a_row_missing_from_one_surface_is_caught(self) -> None:
        assert disagreements("", self._DOCS_STUB) == [
            "ASI04: in docs matrix, absent from README matrix"
        ]
        assert disagreements(self._README_STUB, "") == [
            "ASI04: in README matrix, absent from docs matrix"
        ]

    @pytest.mark.parametrize(
        ("readme_name", "docs_name"),
        [
            ("Memory & Context Poisoning", "Memory and Context Poisoning"),
            ("Unexpected Code Execution (RCE)", "Unexpected Code Execution / RCE"),
        ],
    )
    def test_presentation_differences_are_not_disagreements(
        self, readme_name: str, docs_name: str
    ) -> None:
        """These two pairs are live in the repo today and must not fail the build."""
        assert normalise(readme_name) == normalise(docs_name)
