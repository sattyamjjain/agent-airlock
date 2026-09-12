"""The README must stay short enough to be read.

Until v0.10.4 this file was **1,822 lines / 18,206 words / 156 KB**. Measured against
comparable projects on the day it was cut, that was an outlier by an order of magnitude:

===============================  ======  =======
project                          words   stars
===============================  ======  =======
pydantic/pydantic                   267   28,759
openai/openai-agents-python          803   29,385
modelcontextprotocol/python-sdk      600   24,273
pydantic/pydantic-ai               1,762   19,877
e2b-dev/E2B                          390   13,762
guardrails-ai/guardrails           1,010    7,398
protectai/llm-guard                  502    3,205
**agent-airlock (before)**       **18,206**   --
===============================  ======  =======

The most-starred projects had the *shortest* READMEs. Ours was 10x the longest comparable.

Length was the symptom; ordering was the disease. The first thing a visitor read — before
any badge — was a bold paragraph about a head-to-head study that had **not been run**,
followed by a table of a null result. `pip install` appeared at line 166, the first code at
line 196, and a table of contents at line 316. The rigour is real and is the project's best
asset, but leading with it meant the reader's first impression was of caveats, and most
never reached the part where airlock blocks 12/12 payloads a production gateway forwards.

This gate exists because that regression is *easy* and *gradual*. Every individual addition
is defensible — one more feature, one more caveat, one more benchmark row — and the file was
never rewritten in one sitting. Nothing was watching the total. Now something is.

**If this test fails, the fix is usually to put the content in `docs/` and link it**, not to
raise the ceiling. The ceiling has headroom on purpose; spending it should be a decision.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

#: Roughly 40% above the 2026-09-12 rewrite (285 lines / 2,050 words). Headroom for real
#: growth, nowhere near enough to drift back to a feature catalogue.
MAX_LINES = 400
MAX_WORDS = 3_000

#: A visitor who cannot see code in the first screenful cannot tell what this is.
MAX_LINE_OF_FIRST_CODE_BLOCK = 50


def _text() -> str:
    return README.read_text(encoding="utf-8")


class TestTheReadmeStaysReadable:
    def test_line_count(self) -> None:
        lines = len(_text().splitlines())
        assert lines <= MAX_LINES, (
            f"README is {lines} lines, over the {MAX_LINES} ceiling. Move the new material "
            "into docs/ and link it — see this module's docstring before raising the limit."
        )

    def test_word_count(self) -> None:
        words = len(_text().split())
        assert words <= MAX_WORDS, (
            f"README is {words} words, over the {MAX_WORDS} ceiling. The median comparable "
            "project ships ~600. Link, do not inline."
        )

    def test_code_appears_in_the_first_screenful(self) -> None:
        """What it is, shown not described, before the reader has to scroll twice."""
        for number, line in enumerate(_text().splitlines(), start=1):
            if line.startswith("```"):
                assert number <= MAX_LINE_OF_FIRST_CODE_BLOCK, (
                    f"first code block is at line {number}; it must appear within the first "
                    f"{MAX_LINE_OF_FIRST_CODE_BLOCK} lines. Before the 2026-09-12 rewrite it "
                    "was at line 196, behind a wall of caveats."
                )
                return
        raise AssertionError("README has no code block at all")

    def test_no_table_of_contents(self) -> None:
        """Needing one is the diagnosis, not the cure.

        The old README had a table of contents at line 316 — i.e. after more preamble than
        most projects' entire README.
        """
        assert not re.search(r"^#+\s*.*table of contents", _text(), re.I | re.M), (
            "README grew a table of contents. That means it is too long to scan; shorten it "
            "rather than adding navigation to the length."
        )


class TestInPageLinksResolve:
    """`scripts/check_links.py` deliberately skips `#anchor` targets, so nothing checked these.

    Its `_LINK_RE` excludes any target starting with `#`, which is correct for its job —
    validating that files exist — but leaves the README's own navigation unchecked. Rename a
    heading and the nav strip at the top silently points at nothing, with no CI signal.

    Scoped to the README rather than added to `check_links.py`, because the repo has 122
    markdown files and turning this on everywhere at once is a remediation project, not a
    gate. Here it costs nothing and guards the surface people actually land on.
    """

    @staticmethod
    def _slug(heading: str) -> str:
        """GitHub's anchor slug: lowercase, drop punctuation, spaces to hyphens."""
        text = heading.strip().lower()
        text = re.sub(r"[^\w\s-]", "", text)
        return re.sub(r"\s+", "-", text).strip("-")

    def test_every_in_page_anchor_has_a_heading(self) -> None:
        text = _text()
        headings = {self._slug(h) for h in re.findall(r"^#{1,6}\s+(.+)$", text, re.M)}
        anchors = set(re.findall(r"\]\(#([^)]+)\)", text))
        dead = sorted(a for a in anchors if a not in headings)
        assert not dead, (
            f"README links to anchors with no matching heading: {dead}. "
            "Renaming a heading breaks its nav link and nothing else catches it."
        )

    def test_there_is_navigation_to_check(self) -> None:
        """A guard that passes because the thing it guards was deleted is not a guard."""
        assert re.findall(r"\]\(#([^)]+)\)", _text()), (
            "README has no in-page navigation links at all"
        )


class TestTheOpeningLeadsWithTheProduct:
    """Ordering, which is what actually broke — not just size."""

    def test_install_command_is_early(self) -> None:
        text = _text()
        index = text.find("pip install")
        assert index != -1, "README no longer tells anyone how to install it"
        line = text[:index].count("\n") + 1
        assert line <= 60, (
            f"`pip install` is at line {line}. It was at 166 before the rewrite, behind the "
            "caveats; keep it near the top."
        )

    def test_the_first_heading_after_the_hero_is_not_a_disclaimer(self) -> None:
        """The rigour belongs in the README — just not as the opening act.

        The honesty section is still here and still load-bearing; it simply comes after the
        reader knows what the library does.
        """
        headings = re.findall(r"^##\s+(.+)$", _text(), re.M)
        assert headings, "README has no H2 sections"
        first = headings[0].lower()
        assert "null" not in first and "not been run" not in first, (
            f"first section is {headings[0]!r} — lead with what this does, then qualify it"
        )

    def test_the_honesty_section_survives(self) -> None:
        """Shortening must not become laundering.

        Cutting 90% of a README is exactly when the inconvenient parts get lost. These are
        the claims that make the benchmark numbers worth believing, so they are pinned.
        """
        text = _text()
        assert "How numbers are reported here" in text
        assert "Null results are published" in text
        assert "never fabricated" in text
        assert "(./PRIOR_ART.md)" in text
