"""CI guard: the prior-art record must keep quoting the paper accurately.

``PRIOR_ART.md`` credits arXiv:2608.18351 by reproducing figures and two sentences
*verbatim*. Verbatim quotes of someone else's work are exactly the claim class this repo
already machine-checks elsewhere — ``tests/test_numeric_claim_parity.py`` says it plainly:
*"A human instruction is exactly the thing that rots."* A reflow that drops a digit, or an
edit that trims the quoted conclusion down to the convenient half, would be a
misattribution rather than a typo, and nothing else in the suite would notice.

Two asymmetric things are gated here on purpose:

* the **figures and the conclusion**, because misquoting another author's result is the
  worst failure this file can have; and
* the **counter-quote** — the abstract's opening claim that permission gating alone is
  insufficient — because that is the half that does *not* flatter this library, and it is
  therefore the half most likely to be quietly lost in a later edit.

The no-head-to-head sentence is gated for the same reason: it is the sentence a future
edit would be tempted to soften.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_PRIOR_ART = _ROOT / "PRIOR_ART.md"
_README = _ROOT / "README.md"
_BENCHMARK = _ROOT / "BENCHMARK.md"
_GENERATOR = _ROOT / "scripts" / "generate_benchmark.py"


def _flat(path: Path) -> str:
    """Collapse markdown wrapping so a quote spanning several lines still matches."""
    text = path.read_text(encoding="utf-8")
    return re.sub(r"\s+", " ", text.replace("\n> ", " ").replace(">", " "))


@pytest.fixture(scope="module")
def prior_art() -> str:
    return _flat(_PRIOR_ART)


class TestPriorArtRecordExists:
    def test_file_is_at_repo_root(self) -> None:
        assert _PRIOR_ART.is_file(), "PRIOR_ART.md must live at the repo root"

    def test_paper_is_identified_by_id_and_link(self, prior_art: str) -> None:
        assert "arXiv:2608.18351" in prior_art
        assert "https://arxiv.org/abs/2608.18351" in prior_art

    def test_authors_and_submission_date_are_attributed(self, prior_art: str) -> None:
        assert "Alexander Tu, Michael Tu" in prior_art
        assert "18 August 2026" in prior_art


class TestQuotedFiguresAreVerbatim:
    #: Every figure the record reproduces from the abstract.
    FIGURES = (
        "Qwen3.5-4B",
        "1,500 tasks",
        "98.48% safe success",
        "2,896 evaluation episodes",
        "500 held-out tasks",
        "64.36% for the base policy",
        "from 4.56% to 0.79%",
    )

    @pytest.mark.parametrize("figure", FIGURES)
    def test_figure_survives_verbatim(self, prior_art: str, figure: str) -> None:
        assert figure in prior_art, f"figure no longer quoted verbatim: {figure!r}"

    def test_the_full_quoted_sentence_is_intact(self, prior_art: str) -> None:
        quoted = (
            "after training using this framework on Qwen3.5-4B over 1,500 tasks, the "
            "selected seed reaches 98.48% safe success across 2,896 evaluation episodes "
            "spanning all 500 held-out tasks, compared with 64.36% for the base policy, "
            "and reduces excess-authority error events from 4.56% to 0.79%"
        )
        assert quoted in prior_art


class TestBothHalvesOfTheAbstractAreRecorded:
    def test_the_authors_conclusion_is_quoted_in_full(self, prior_art: str) -> None:
        """Including the scope clause — trimming it would overstate their conclusion."""
        conclusion = (
            "We conclude learned restraint through least-privilege aware post-training is "
            "therefore useful as an additional control layer for tool-using agents in "
            "executable terminal and MCP environments, but it does not replace permission "
            "gates and sandboxing."
        )
        assert conclusion in prior_art

    def test_the_unflattering_half_is_not_dropped(self, prior_art: str) -> None:
        """The abstract's opening claim is about the category this library is in."""
        counter = (
            "Traditional permission gating systems alone for validating agent environments "
            "are insufficient"
        )
        assert counter in prior_art


class TestTheNullIsStatedPlainly:
    def test_absence_of_a_head_to_head_is_stated_not_softened(self, prior_art: str) -> None:
        assert "There is no head-to-head." in prior_art
        assert "the honest claim is complementarity and not superiority" in prior_art, (
            "the no-superiority sentence must not be softened away"
        )


class TestTheRecordIsReachable:
    def test_readme_links_to_it(self) -> None:
        assert "(./PRIOR_ART.md)" in _README.read_text(encoding="utf-8")

    def test_benchmark_links_to_it(self) -> None:
        assert "PRIOR_ART.md" in _BENCHMARK.read_text(encoding="utf-8")

    def test_benchmark_link_comes_from_the_generator(self) -> None:
        """BENCHMARK.md is generated; a hand-edit would be erased by ``make benchmark``."""
        assert "PRIOR_ART.md" in _GENERATOR.read_text(encoding="utf-8")
