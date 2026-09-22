"""Single-source-of-truth guard for the package version.

The 0.8.26 release bumped ``pyproject.toml`` but not
``agent_airlock.__version__``, so the published 0.8.26 wheel self-reported
``__version__ == "0.8.25"``. This regression pins the two together: a future
release that bumps one and forgets the other fails CI here instead of shipping
a wheel that lies about its own version.

Two more surfaces state the version, and both had gone stale by 2026-09-22:

* ``SECURITY.md`` said security fixes land only on the ``0.8.x`` line while the
  package shipped ``0.10.8`` — two minor lines behind. A reporter on a supported
  version read that table and concluded they were unsupported, which is the exact
  inverse of what a security policy is for. The same file, four screens down,
  described behaviour that shipped in ``v0.10.6``, so the document contradicted
  itself.
* ``CITATION.cff`` said ``0.10.4`` / ``2026-09-12``, four patch releases behind,
  and nothing anywhere in ``tests/``, ``scripts/`` or ``.github/`` referenced that
  file at all.

The ``SECURITY.md`` half is a *repeat*. Through v0.8.57 that file advertised
``sattyamjain@example.com`` as the vulnerability contact **and** pinned its
supported-versions table to ``0.1.x`` while the package shipped ``0.8.x``. The
fix had two halves; only the contact half got a guard
(``test_security_docs_publish_no_example_com_contact`` in
``tests/test_marketplace_metadata.py``, whose body searches for the literal
string ``example.com`` and says nothing about versions). The unguarded half went
stale again by the same two-minor margin. That is why these checks exist and why
deleting them as redundant would be wrong: the sibling guard covers a different
failure and always did.

The checks are written as module-level functions over text rather than inline
assertions so the negative tests below can drive them with a deliberately stale
document. A guard nobody has watched fail is a guard nobody can trust.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import agent_airlock

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_SECURITY = _ROOT / "SECURITY.md"
_CITATION = _ROOT / "CITATION.cff"
_CHANGELOG = _ROOT / "CHANGELOG.md"

#: A "supported line" string: ``0.10.x``. Deliberately only the ``.x`` form, so the
#: historical "Fixed in v0.8.74 (affects v0.5.7-v0.8.73)" row keeps working — those
#: are concrete patch versions recording what happened, not claims about what is
#: supported today, and rewriting them would be falsifying history.
_MINOR_LINE_RE = re.compile(r"\b(\d+)\.(\d+)\.x\b")

#: ``## [0.10.8] - 2026-09-21``
_RELEASE_HEADING_RE = re.compile(r"^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})", re.M)


def _pyproject_version() -> str:
    with _PYPROJECT.open("rb") as fh:
        return str(tomllib.load(fh)["project"]["version"])


def _minor_line(version: str) -> tuple[int, int]:
    major, minor, *_ = version.split(".")
    return int(major), int(minor)


def _cff_field(text: str, field: str) -> str | None:
    """Read one top-level scalar out of a CITATION.cff without a YAML dependency.

    The core is Pydantic-only and ``tests`` should not be the place a YAML parser
    sneaks in, so this reads the two flat fields it needs by line prefix.
    """
    for line in text.splitlines():
        if line.startswith(f"{field}:"):
            return line.split(":", 1)[1].strip().strip('"').strip("'")
    return None


def security_supported_line_problems(security_text: str, version: str) -> list[str]:
    """Every way ``SECURITY.md`` can disagree with the shipped version.

    Checks the whole file rather than just the Supported Versions section, on
    purpose: a stale ``N.M.x`` anywhere in a security policy is a claim about what
    receives fixes, and the reader does not know which paragraph is authoritative.
    """
    current = _minor_line(version)
    found = {(int(a), int(b)) for a, b in _MINOR_LINE_RE.findall(security_text)}
    problems: list[str] = []

    if current not in found:
        problems.append(
            f"SECURITY.md never names the shipped minor line "
            f"'{current[0]}.{current[1]}.x' (pyproject version {version})"
        )
    for other in sorted(found - {current}):
        relation = "below" if other < current else "above"
        problems.append(
            f"SECURITY.md names supported line '{other[0]}.{other[1]}.x', "
            f"which is {relation} the shipped line '{current[0]}.{current[1]}.x'"
        )
    return problems


def citation_problems(citation_text: str, version: str, changelog_text: str) -> list[str]:
    """``CITATION.cff`` must cite the shipped version, on the date that release is dated."""
    problems: list[str] = []

    cited = _cff_field(citation_text, "version")
    if cited != version:
        problems.append(f"CITATION.cff version is {cited!r}, pyproject is {version!r}")

    released = _cff_field(citation_text, "date-released")
    dates = dict(_RELEASE_HEADING_RE.findall(changelog_text))
    expected = dates.get(version)
    if expected is None:
        problems.append(
            f"CHANGELOG.md has no dated '## [{version}] - YYYY-MM-DD' heading to date "
            f"CITATION.cff against"
        )
    elif released != expected:
        problems.append(
            f"CITATION.cff date-released is {released!r}, but CHANGELOG.md dates "
            f"{version} as {expected!r}"
        )
    return problems


class TestVersionConsistency:
    def test_dunder_version_matches_pyproject(self) -> None:
        assert agent_airlock.__version__ == _pyproject_version(), (
            "agent_airlock.__version__ and pyproject.toml [project].version have "
            "drifted — bump both in lockstep on every release."
        )

    def test_security_policy_names_the_shipped_minor_line(self) -> None:
        problems = security_supported_line_problems(
            _SECURITY.read_text(encoding="utf-8"), _pyproject_version()
        )
        assert not problems, (
            "SECURITY.md's supported-versions claim has drifted from the shipped "
            "version. A reporter reads this table to decide whether their version "
            "still receives fixes:\n  " + "\n  ".join(problems)
        )

    def test_citation_cites_the_shipped_version(self) -> None:
        problems = citation_problems(
            _CITATION.read_text(encoding="utf-8"),
            _pyproject_version(),
            _CHANGELOG.read_text(encoding="utf-8"),
        )
        assert not problems, "CITATION.cff has drifted:\n  " + "\n  ".join(problems)


class TestTheseGuardsActuallyFail:
    """Drive each check with a deliberately stale document.

    Without these, a refactor that made the checks vacuous would look identical to
    a repository that is simply correct. That is the failure mode the sibling
    ``example.com`` guard has never been protected against.
    """

    _STALE_SECURITY = (
        "# Security Policy\n\n## Supported Versions\n\n"
        "Security fixes land only on the current `0.8.x` line.\n\n"
        "| Version | Supported |\n| --- | --- |\n"
        "| 0.8.x | yes |\n"
    )

    def test_a_security_doc_two_minors_behind_fails(self) -> None:
        problems = security_supported_line_problems(self._STALE_SECURITY, "0.10.8")
        assert problems
        assert any("0.8.x" in p and "below" in p for p in problems)
        assert any("never names" in p for p in problems)

    def test_a_security_doc_naming_no_line_at_all_fails(self) -> None:
        problems = security_supported_line_problems("# Security Policy\n", "0.10.8")
        assert any("never names" in p for p in problems)

    def test_the_shipped_security_doc_passes(self) -> None:
        assert (
            security_supported_line_problems(
                _SECURITY.read_text(encoding="utf-8"), _pyproject_version()
            )
            == []
        )

    def test_historical_patch_versions_are_not_flagged(self) -> None:
        """The 'Fixed in v0.8.74 (affects v0.5.7-v0.8.73)' row must survive.

        Those record what happened and are still true. Only the ``N.M.x`` form is a
        claim about what is supported now.
        """
        text = (
            "Security fixes land on the current `0.10.x` line.\n"
            "| v0.8.74 | fixed a thing (affects v0.5.7-v0.8.73) |\n"
            "That holds under `sandbox=True` as well (since v0.10.6).\n"
        )
        assert security_supported_line_problems(text, "0.10.8") == []

    def test_a_citation_one_patch_behind_fails(self) -> None:
        stale = 'version: 0.10.7\ndate-released: "2026-09-21"\n'
        changelog = "## [0.10.8] - 2026-09-21\n"
        problems = citation_problems(stale, "0.10.8", changelog)
        assert any("0.10.7" in p and "version" in p for p in problems)

    def test_a_citation_with_the_wrong_release_date_fails(self) -> None:
        stale = 'version: 0.10.8\ndate-released: "2026-09-12"\n'
        changelog = "## [0.10.8] - 2026-09-21\n"
        problems = citation_problems(stale, "0.10.8", changelog)
        assert any("date-released" in p for p in problems)

    def test_the_shipped_citation_passes(self) -> None:
        assert (
            citation_problems(
                _CITATION.read_text(encoding="utf-8"),
                _pyproject_version(),
                _CHANGELOG.read_text(encoding="utf-8"),
            )
            == []
        )
