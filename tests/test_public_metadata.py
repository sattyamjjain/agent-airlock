"""Regression tests for public-facing metadata drift (v0.5.4+).

These tests guard against the exact bugs fixed in v0.5.4:

1. ``pyproject.toml [project.urls]`` carried a single-``j`` ``sattyamjain``
   slug on Homepage / Documentation / Repository / Issues. The real GitHub
   org is ``sattyamjjain`` (double-j), so every PyPI landing-page link was
   404'd. Asserting the canonical slug in every URL prevents the typo
   from sneaking back in.
2. The ``README.md`` ``Performance`` table claimed ``1,157 passing``
   while the auto-generated ``TEST-BADGE`` block directly above it
   already read ``1,540 tests``. Two sources of truth disagreed with
   each other. The fix removes the hand-maintained row; this test keeps
   the stale number from re-appearing.

Both assertions are cheap and pure-Python; no pytest fixtures.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# tomllib is stdlib on 3.11+; fall back to the tomli extra for 3.10
# (already a declared dependency via pyproject.toml:43).
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
README = PROJECT_ROOT / "README.md"

CANONICAL_GITHUB_SLUG = "sattyamjjain"  # double-j — the real org
STALE_TEST_COUNT = "1,157 passing"


def _load_pyproject() -> dict:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)


# PEP 508: a distribution name is the leading run before any version specifier,
# extra bracket, or environment marker.
_DIST_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def _dist_name(requirement: str) -> str:
    base = requirement.split(";", 1)[0].strip()
    match = _DIST_NAME.match(base)
    assert match, f"cannot parse a distribution name from requirement {requirement!r}"
    return match.group(1).lower()


def _unmarked_core_distributions() -> set[str]:
    """Core runtime distributions with no environment marker.

    A marker-gated entry (``tomli>=2.0;python_version<'3.11'``) is a stdlib
    backport, not a third-party runtime dependency on any supported modern
    Python (``tomllib`` is stdlib on 3.11+), so it is excluded here.
    """
    deps = _load_pyproject()["project"]["dependencies"]
    return {_dist_name(req) for req in deps if ";" not in req}


# A registry summary (PyPI ``info.summary`` == pyproject ``description``) is shown
# with no room for a footnote, so a bare "zero-dep" there reads as an unqualified
# claim over two real installs. The defensible standalone claim is "Pydantic-only";
# the qualifier must travel with the word if "zero-dep" is ever used at all.
_ZERO_DEP_VARIANTS = ("zero-dep", "zero dep", "zerodep", "zero-dependency", "zero dependencies")


def _project_description() -> str:
    return str(_load_pyproject()["project"]["description"])


def test_summary_makes_no_unqualified_zero_dep_claim() -> None:
    """The PyPI one-line summary must not carry a bare 'zero-dep' claim.

    The registry page renders this string with no footnote (unlike README.md, where
    ``[^deps]`` qualifies the table row), so if 'zero-dep' appears at all, 'Pydantic'
    must qualify it in the same string. In the spirit of test_no_placeholder_cves.py:
    a claim that needed a footnote once will need it again.
    """
    desc = _project_description()
    low = desc.lower()
    for variant in _ZERO_DEP_VARIANTS:
        if variant in low:
            assert "pydantic" in low, (
                f"pyproject description carries an unqualified {variant!r} claim; the "
                "registry page has no footnote — convey 'Pydantic-only' instead "
                f"(description: {desc!r})"
            )


def test_summary_conveys_pydantic_only() -> None:
    """The summary should name Pydantic — the defensible standalone dependency claim."""
    assert "pydantic" in _project_description().lower(), (
        "the PyPI one-line summary should convey 'Pydantic-only' (the standalone-true "
        "dependency claim) rather than an unqualified 'zero-dep'"
    )


def test_zero_dep_guard_would_catch_an_unqualified_claim() -> None:
    """The detector fires on a synthetic unqualified summary — proving it is live,
    not silently passing (mirrors test_no_placeholder_cves's guard-would-catch)."""
    synthetic = "A contract layer for tool calls — in-process, zero-dep. Strict validation."
    low = synthetic.lower()
    caught = any(v in low for v in _ZERO_DEP_VARIANTS) and "pydantic" not in low
    assert caught, "guard failed to flag an unqualified zero-dep summary"


def test_project_urls_point_to_canonical_repo() -> None:
    """Every [project.urls] entry must contain the canonical ``sattyamjjain`` slug."""
    data = _load_pyproject()
    urls = data["project"]["urls"]
    assert urls, "pyproject.toml [project.urls] is empty — PyPI landing page will have no links"
    for name, url in urls.items():
        assert CANONICAL_GITHUB_SLUG in url, (
            f"[project.urls].{name} = {url!r} does not contain "
            f"canonical slug {CANONICAL_GITHUB_SLUG!r} — likely the single-``j`` "
            "typo from v0.5.3 has crept back in"
        )


def test_readme_no_contradicting_test_count() -> None:
    """README must not hand-maintain a test count — TEST-BADGE block is authoritative."""
    text = README.read_text(encoding="utf-8")
    assert STALE_TEST_COUNT not in text, (
        f"README.md still contains the stale {STALE_TEST_COUNT!r} row. "
        "The TEST-BADGE block (regenerated by scripts/update_test_badge.py) is "
        "the only sanctioned source of test-count truth."
    )


def test_readme_integration_count_matches_examples() -> None:
    """README Performance table's 'Framework integrations' must equal the row count in 'Complete Examples'.

    Honesty bug from v0.5.5: Performance row hardcoded 9 while the
    Complete Examples table at line ~538 listed 10 frameworks
    (Claude Agent SDK was added in v0.5.1 but the metric never
    caught up). This test scrapes the example table and asserts the
    Performance row tracks it, so neither side can drift again.
    """
    text = README.read_text(encoding="utf-8")
    # Find the Complete Examples section and count its data rows.
    marker = "### Complete Examples"
    idx = text.find(marker)
    assert idx >= 0, "README is missing the '### Complete Examples' section"
    # Stop at the next ## or ### heading.
    rest = text[idx + len(marker) :]
    next_section = re.search(r"\n#+ ", rest)
    block = rest if next_section is None else rest[: next_section.start()]
    # Count rows that look like a Markdown data row beginning with "| Something | ..."
    # but skip the header and separator rows.
    data_rows = [
        line
        for line in block.splitlines()
        if line.startswith("|")
        and not line.startswith("| Framework |")
        and not line.startswith("|---")
    ]
    actual_count = len(data_rows)
    # Performance table row.
    perf_match = re.search(r"\|\s*\*\*Framework integrations\*\*\s*\|\s*(\d+)\s*\|", text)
    assert perf_match, "README Performance table is missing the 'Framework integrations' row"
    claimed = int(perf_match.group(1))
    assert claimed == actual_count, (
        f"README claims {claimed} framework integrations but Complete Examples "
        f"table has {actual_count} rows. Fix one or the other."
    )


def test_readme_does_not_hand_maintain_loc_count() -> None:
    """README must not re-introduce a hand-maintained ``Lines of Code`` row.

    Honesty bug from v0.5.4–v0.5.7: the row claimed ``~27,400`` while
    the actual ``src/`` Python LoC was 22,670 — a ~20% drift carried
    across four releases without anyone noticing. v0.5.7.1 dropped
    the row from the Performance table because LoC is the only row
    that drifts naturally and isn't useful to package consumers
    anyway. This test keeps it from sneaking back in.
    """
    text = README.read_text(encoding="utf-8")
    assert "Lines of Code" not in text, (
        "README.md re-introduced the hand-maintained 'Lines of Code' row. "
        "Don't — it drifts and the TEST-BADGE block + Complete Examples "
        "table are the only sources of truth this README hand-maintains."
    )


def test_core_dependencies_are_pydantic_only() -> None:
    """The airlock core must stay Pydantic-only (v0.8.59+).

    Honesty bug fixed in v0.8.59: ``structlog`` was an unconditional
    ``[project].dependencies`` entry for 24 releases while every public surface
    — the README subtitle, the Performance table's ``Core dependencies: 0``
    row, and the PyPI ``description`` — advertised a zero-dependency,
    Pydantic-only core. It now lives in the ``[logging]`` extra (the core imports
    it through ``agent_airlock._log``, which falls back to a stdlib shim). This
    guard is why the claim can never quietly drift again: any new unconditional
    core dependency trips it.
    """
    unmarked = _unmarked_core_distributions()
    extra = sorted(unmarked - {"pydantic"})
    assert unmarked == {"pydantic"}, (
        "The airlock core must stay Pydantic-only — the README's "
        "'Core dependencies: 0 (Pydantic only)' pitch depends on it. Unexpected "
        f"unconditional core dependenc(ies): {extra}. Gate a new dependency behind "
        "an optional extra (as structlog is, via [logging]), or add it here "
        "deliberately with the README row updated to match."
    )


def test_readme_core_dependency_count_matches_pyproject() -> None:
    """The README 'Core dependencies' number must equal pyproject's reality.

    The row reads ``| **Core dependencies** | 0 (Pydantic only) |``. The integer
    counts third-party runtime dependencies *beyond* the Pydantic foundation —
    which is exactly ``len(unmarked core distributions) - {"pydantic"}``. Binding
    the two means the table can never restate a stale number: add a core dep and
    both this guard and :func:`test_core_dependencies_are_pydantic_only` fail.
    """
    text = README.read_text(encoding="utf-8")
    match = re.search(r"\|\s*\*\*Core dependencies\*\*\s*\|\s*(\d+)\b[^|]*\|", text)
    assert match, "README Performance table is missing the '| **Core dependencies** |' row"
    claimed = int(match.group(1))
    beyond_pydantic = _unmarked_core_distributions() - {"pydantic"}
    assert claimed == len(beyond_pydantic), (
        f"README 'Core dependencies' row says {claimed} but pyproject declares "
        f"{len(beyond_pydantic)} unconditional runtime dependenc(ies) beyond Pydantic: "
        f"{sorted(beyond_pydantic)}. The number means 'third-party runtime deps beyond "
        "the Pydantic foundation' — keep it and pyproject in lockstep."
    )


def test_python_version_matches_pyproject() -> None:
    """Sanity-check: the Python interpreter running the test suite meets the floor."""
    data = _load_pyproject()
    requires = data["project"]["requires-python"]
    # "requires-python = ">=3.10"" → we only assert the pin is parseable and real.
    assert requires.startswith(">="), f"requires-python {requires!r} must start with '>='"
    min_version = requires.removeprefix(">=").strip()
    major, minor = (int(x) for x in min_version.split(".", 1))
    # Running interpreter must satisfy the declared floor — defensive guard for
    # contributors on very old stacks.
    assert sys.version_info >= (major, minor), (
        f"Python {sys.version_info.major}.{sys.version_info.minor} is below the "
        f"declared floor {min_version}"
    )
