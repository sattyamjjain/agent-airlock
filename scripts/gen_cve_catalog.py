#!/usr/bin/env python3
"""Generate `docs/cves/index.md` from the regression test headers in `tests/cves/`.

Each CVE regression test module starts with a structured docstring:

    \"\"\"CVE-YYYY-NNNNN — <component> <short title>.

    Vulnerability (from the ...):
        <paragraph>

    Advisory: <url>
    NVD:      <url>
    CVSS:     <n.n> (<severity>)

    Airlock fit: <strong|strongest|partial|out-of-scope>.
        <paragraph>
    \"\"\"

This script parses those headers and emits a single markdown page with a
summary table plus per-CVE detail sections. The output is checked into the
repo so reviewers can diff it on PRs; this script's own `--check` mode, run by
CI's `docs` job, verifies the checked-in file matches what the generator would
produce. (This line used to name `scripts/check_cve_catalog.py`, which has never
existed — the gate is `gen_cve_catalog.py --check`.)

Usage:
    python3 scripts/gen_cve_catalog.py > docs/cves/index.md
    # or, for in-place update:
    python3 scripts/gen_cve_catalog.py --write
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests" / "cves"
OUTPUT = ROOT / "docs" / "cves" / "index.md"

# The canonical header: ``CVE-YYYY-NNNN — Title.``
CVE_HEADER_RE = re.compile(r"^(CVE-\d{4}-\d+)\s+—\s+(.+?)\.?\s*$")

# Two older shapes that predate the canonical one. Through v0.8.79 the generator
# silently skipped them, so **19 of 31 regression modules never reached the published
# catalog** — while `marketplace.json` pointed readers at that catalog to substantiate a
# count of 38. The link did not support the claim. Rather than rewrite 19 docstrings by
# hand (and risk transcribing a CVSS wrong), the parser now reads what is already there:
#
#   ``CVE-YYYY-NNNN (Title) regression.``       -> _CVE_PAREN_RE
#   ``Tests for CVE-YYYY-NNNN Title (v0.5.6+).`` -> _CVE_PREFIX_RE
_CVE_PAREN_RE = re.compile(r"^(CVE-\d{4}-\d+)\s*\((.+?)\)\s*(?:preset\s+)?regression.*$", re.I)
_CVE_PREFIX_RE = re.compile(r"^Tests?\s+for\s+(CVE-\d{4}-\d+)\s+(.+?)\.?\s*$", re.I)

#: Trailing version parentheticals like ``(v0.5.6+)`` are noise in a title.
_TITLE_VERSION_SUFFIX_RE = re.compile(r"\s*\(v\d+\.\d+\.\d+\+?\)\s*$")

#: Bare URLs anywhere in the docstring, used only when the labelled field is absent.
_BARE_URL_RE = re.compile(r"https?://[^\s`)>\]]+")

#: A CVSS score stated in prose, e.g. "CVSS 9.8" or "CVSS v3.1 9.0".
_BARE_CVSS_RE = re.compile(r"CVSS\s*(?:v[34](?:\.\d)?\s*)?(\d\.\d)", re.I)


#: Last-resort: the line simply *starts* with a CVE id. Covers the remaining hand-written
#: shapes (``CVE-x (Alias) — title.``, ``CVE-x "Nickname" — title.``, ``CVE-x (title).``)
#: without one special case per author. Anything left over after the id becomes the title.
_CVE_LEADING_RE = re.compile(r"^(CVE-\d{4}-\d+)\s*[—–\-:]?\s*(.+?)\.?\s*$")

#: Separator debris left at the head of a title once the id is removed.
_TITLE_LEAD_SEP_RE = re.compile(r"^[\s—–\-:]+")


def _clean_title(raw: str) -> str:
    title = _TITLE_LEAD_SEP_RE.sub("", raw.strip())
    title = _TITLE_VERSION_SUFFIX_RE.sub("", title)
    return title.rstrip(". ").strip()


def _match_header(header: str) -> tuple[str, str] | None:
    """Return ``(cve_id, title)`` for any accepted header shape.

    Ordered most-specific first so the canonical form keeps its exact title, and the
    permissive fallback only sees lines the structured patterns did not claim.
    """
    for pattern in (CVE_HEADER_RE, _CVE_PAREN_RE, _CVE_PREFIX_RE, _CVE_LEADING_RE):
        m = pattern.match(header)
        if m:
            title = _clean_title(m.group(2))
            if title:
                return m.group(1), title
    return None


ADVISORY_RE = re.compile(r"^Advisory:\s*(.+?)\s*$", re.MULTILINE)
WRITEUP_RE = re.compile(r"^Write-?up:\s*(.+?)\s*$", re.MULTILINE)
NVD_RE = re.compile(r"^NVD:\s*(.+?)\s*$", re.MULTILINE)
CVSS_RE = re.compile(r"^CVSS:\s*(.+?)\s*$", re.MULTILINE)
# Match only the first word on the "Airlock fit:" line so trailing commentary
# (some headers say "strong — this is what v0.4.1 was built for.") doesn't
# end up as a badge label.
AIRLOCK_FIT_LABEL_RE = re.compile(r"^Airlock fit:\s*([A-Za-z-]+)", re.MULTILINE)


@dataclass
class CVEEntry:
    """Parsed metadata for one CVE, backed by one or more regression tests.

    ``files`` is a list because **a row is one CVE, not one test module**. Two
    CVEs in this suite are covered by two modules each (CVE-2026-30615 and
    CVE-2026-42271), and until v0.10.5 each of those emitted its own row: the
    summary table carried 36 rows for 34 distinct CVEs, and because the anchor
    is derived from the CVE id, both rows of a pair linked to the same
    ``#cve-...`` target while the detail section emitted that id twice. One of
    the two links necessarily landed on the wrong section, and the duplicated
    HTML ``id`` was invalid besides.

    The gate could not see it: ``--check`` compares generated output to
    committed output, and both were wrong in the same way. See
    :func:`assert_unique_cve_rows`.
    """

    cve_id: str
    title: str
    files: list[Path]
    advisory: str | None = None
    writeup: str | None = None
    nvd: str | None = None
    cvss: str | None = None
    airlock_fit: str | None = None
    description: str = ""
    mitigation: str = ""

    @property
    def fit_badge(self) -> str:
        """Short label for the summary table."""
        fit = (self.airlock_fit or "").lower()
        if not fit:
            return "—"
        return fit.capitalize()

    @property
    def sort_key(self) -> tuple[str, str]:
        year = self.cve_id.split("-")[1] if "-" in self.cve_id else "0"
        return (year, self.cve_id)


def _extract_docstring(path: Path) -> str | None:
    try:
        module = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return None
    return ast.get_docstring(module, clean=False)


def _parse_entry(path: Path, doc: str) -> CVEEntry | None:
    lines = doc.splitlines()
    if not lines:
        return None

    header = lines[0].strip()
    matched = _match_header(header)
    if matched is None:
        return None
    cve_id, title = matched

    entry = CVEEntry(cve_id=cve_id, title=title, files=[path])

    if m := ADVISORY_RE.search(doc):
        entry.advisory = m.group(1).strip()
    if m := WRITEUP_RE.search(doc):
        entry.writeup = m.group(1).strip()
    if m := NVD_RE.search(doc):
        entry.nvd = m.group(1).strip()
    if m := CVSS_RE.search(doc):
        entry.cvss = m.group(1).strip()
    if m := AIRLOCK_FIT_LABEL_RE.search(doc):
        entry.airlock_fit = m.group(1).strip()

    description_block: list[str] = []
    mitigation_block: list[str] = []
    mode: str | None = None
    # In "fit" mode, a non-blank zero-indent line signals a new section
    # (e.g. a concluding note like "This file tests ..."). Stop capturing.
    just_saw_blank = False

    for raw in lines[1:]:
        stripped = raw.strip()
        if stripped.startswith("Vulnerability"):
            mode = "vuln"
            just_saw_blank = False
            continue
        if stripped.startswith("Airlock fit:"):
            mode = "fit"
            just_saw_blank = False
            continue
        if stripped.startswith(("Advisory:", "Write-up:", "Writeup:", "NVD:", "CVSS:")):
            mode = None
            just_saw_blank = False
            continue
        if mode == "fit" and just_saw_blank and stripped and raw[:1] != " ":
            mode = None
            continue
        if mode == "vuln":
            description_block.append(raw)
        elif mode == "fit":
            mitigation_block.append(raw)
        just_saw_blank = not stripped

    entry.description = _dedent_block(description_block).strip()
    entry.mitigation = _dedent_block(mitigation_block).strip()

    # Fallback harvest for the older headers, which carry the same facts as prose rather
    # than as labelled fields. Only fills what is ABSENT — a labelled field always wins,
    # and nothing is invented: a module with no CVSS anywhere renders "—" in the table.
    if entry.cvss is None:
        if m := _BARE_CVSS_RE.search(doc):
            entry.cvss = m.group(1)
    if entry.nvd is None or entry.advisory is None:
        urls = list(dict.fromkeys(_BARE_URL_RE.findall(doc)))
        nvd_urls = [u for u in urls if "nvd.nist.gov" in u]
        other = [u for u in urls if "nvd.nist.gov" not in u and "cwe.mitre.org" not in u]
        if entry.nvd is None and nvd_urls:
            entry.nvd = nvd_urls[0]
        if entry.advisory is None and other:
            entry.advisory = other[0]

    # An older module with no prose "Vulnerability:" block still has a docstring worth
    # showing; use its opening paragraph rather than publishing an empty entry.
    if not entry.description:
        body = [ln for ln in lines[1:] if ln.strip()]
        entry.description = _dedent_block(body[:6]).strip()

    return entry


def _dedent_block(block: list[str]) -> str:
    if not block:
        return ""
    non_empty = [ln for ln in block if ln.strip()]
    if not non_empty:
        return ""
    indent = min(len(ln) - len(ln.lstrip(" ")) for ln in non_empty)
    return "\n".join(ln[indent:] if len(ln) >= indent else ln for ln in block)


def _catalog_modules() -> list[Path]:
    """The CVE-numbered regression modules this catalog publishes.

    Deliberately ``test_cve_*.py`` and not every module under ``tests/cves/``. The wider
    set that ``tests/test_marketplace_metadata.py`` counts (38) also contains advisory
    regressions with **no CVE id of their own** — an archived-server gate, the Unit 42
    sampling preset, the Vercel/Context.ai OAuth breach — plus two umbrella modules whose
    constituent CVEs already have their own rows here. Forcing those into a table keyed by
    CVE id would either invent ids or leave blank keys.

    So the split is real and the published wording has to match it: **40 regression
    modules, of which 33 are CVE-numbered and appear below.** That sentence is asserted by
    ``tests/test_cve_catalog_gate.py`` against both numbers, so neither can drift.
    """
    return sorted(TESTS_DIR.glob("test_cve_*.py"))


class UnparseableCVEModule(RuntimeError):
    """A ``test_cve_*.py`` module the catalog generator could not read.

    Why this is fatal rather than a warning: through v0.8.79 an unparseable module was
    skipped with a warning and exit 0, so **19 of 31 regression modules never reached the
    published catalog** — while ``marketplace.json`` told readers to "see the generated
    catalog at docs/cves/index.md" to substantiate a count of 38. The link did not support
    the claim, and nothing failed. A gate that warns is not a gate.
    """

    def __init__(self, paths: list[Path]) -> None:
        self.paths = paths

        # Relative where possible for a readable CI log, absolute otherwise: a caller
        # pointing TESTS_DIR outside the repo must still get the message rather than a
        # ValueError from relative_to().
        def _label(path: Path) -> str:
            try:
                return str(path.relative_to(ROOT))
            except ValueError:
                return str(path)

        listing = "\n".join(f"  - {_label(p)}" for p in paths)
        super().__init__(
            f"{len(paths)} CVE regression module(s) could not be parsed into the "
            f"catalog, so they would be published as absent:\n{listing}\n\n"
            "Give the module docstring a first line starting with its CVE id, e.g.\n"
            "    CVE-2026-75130 — Component and short title.\n"
            "Optional labelled fields (Advisory:/NVD:/CVSS:/Airlock fit:) render when "
            "present; bare URLs and a prose CVSS in the docstring are harvested as a "
            "fallback. Nothing is invented — a module with no CVSS renders an em dash."
        )


def collect(*, strict: bool = False) -> list[CVEEntry]:
    """Parse every ``test_cve_*.py`` module into a catalog entry.

    Args:
        strict: Raise :class:`UnparseableCVEModule` instead of warning when a module
            cannot be parsed. This is the difference between the catalog quietly
            under-reporting and the build stopping — see the class docstring.

    Raises:
        UnparseableCVEModule: With ``strict=True``, when any module is skipped.
    """
    entries: list[CVEEntry] = []
    skipped: list[Path] = []
    for path in _catalog_modules():
        doc = _extract_docstring(path)
        entry = _parse_entry(path, doc) if doc else None
        if entry is None:
            skipped.append(path)
            print(f"warning: could not parse {path}", file=sys.stderr)
            continue
        entries.append(entry)

    if skipped and strict:
        raise UnparseableCVEModule(skipped)

    entries.sort(key=lambda e: e.sort_key)
    return merge_duplicate_cves(entries)


def _metadata_score(entry: CVEEntry) -> int:
    """How many labelled fields this parse actually recovered."""
    return sum(
        field is not None
        for field in (entry.advisory, entry.writeup, entry.nvd, entry.cvss, entry.airlock_fit)
    )


def merge_duplicate_cves(entries: list[CVEEntry]) -> list[CVEEntry]:
    """Fold entries that share a CVE id into one row per CVE.

    A row is one CVE, not one test module. Two CVEs here are covered by two
    modules each, and emitting a row per module produced a table whose ``CVE``
    column repeated an id while both of its links pointed at a single anchor.

    Which parse supplies the prose, when a group has more than one:

    1. the entry that recovered the most labelled fields (``Advisory:``,
       ``NVD:``, ``CVSS:``, ``Airlock fit:``, ``Write-up:``), since the older
       docstring shapes in this suite recover fewer;
    2. then the longer ``Vulnerability`` + ``Airlock fit`` prose;
    3. then the filename, so the result is stable across machines.

    Individual metadata fields are coalesced across the whole group rather than
    taken from the winner alone, so a CVSS that only the loser carried is still
    published. Every module in the group is listed under ``files`` and rendered,
    so nothing becomes unreachable; the losing module's full prose remains one
    click away in its own source file.

    Order is preserved: groups appear at the position of their first entry, so a
    pre-sorted input stays sorted.
    """
    grouped: dict[str, list[CVEEntry]] = {}
    for entry in entries:
        grouped.setdefault(entry.cve_id, []).append(entry)

    merged: list[CVEEntry] = []
    for group in grouped.values():
        if len(group) == 1:
            merged.append(group[0])
            continue

        primary = max(
            group,
            key=lambda e: (
                _metadata_score(e),
                len(e.description) + len(e.mitigation),
                e.files[0].name,
            ),
        )

        def _first(field: str, _group: list[CVEEntry] = group) -> str | None:
            for candidate in _group:
                value = getattr(candidate, field)
                if value is not None:
                    return str(value)
            return None

        merged.append(
            CVEEntry(
                cve_id=primary.cve_id,
                title=primary.title,
                files=sorted((f for e in group for f in e.files), key=lambda p: p.name),
                advisory=_first("advisory"),
                writeup=_first("writeup"),
                nvd=_first("nvd"),
                cvss=_first("cvss"),
                airlock_fit=_first("airlock_fit"),
                description=primary.description,
                mitigation=primary.mitigation,
            )
        )
    return merged


class DuplicateCVERows(RuntimeError):
    """The catalog would publish two rows for one CVE id.

    Why this is its own gate rather than a comment: ``--check`` compares the
    generated output to the committed output, so a generator that emitted a
    duplicate row wrote it into both sides and the comparison stayed green. The
    catalog carried 36 rows for 34 distinct CVEs for as long as that was true.

    Duplicate rows are not merely untidy. The anchor is derived from the CVE id,
    so a repeated id emits the same ``<a id="cve-...">`` twice: the HTML is
    invalid, and one of the two summary links necessarily resolves to the other
    row's section.
    """

    def __init__(self, duplicates: dict[str, int]) -> None:
        self.duplicates = duplicates
        listing = "\n".join(f"  - {cve}: {count} rows" for cve, count in sorted(duplicates.items()))
        super().__init__(
            f"{len(duplicates)} CVE id(s) would be published more than once:\n{listing}\n\n"
            "A row is one CVE, not one test module. merge_duplicate_cves() folds "
            "modules that share an id; if you see this, that fold was bypassed."
        )


def assert_unique_cve_rows(entries: list[CVEEntry]) -> None:
    """Raise :class:`DuplicateCVERows` if any CVE id appears in more than one entry."""
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.cve_id] = counts.get(entry.cve_id, 0) + 1
    duplicates = {cve: n for cve, n in counts.items() if n > 1}
    if duplicates:
        raise DuplicateCVERows(duplicates)


HEADER = """# CVE catalog

This page is auto-generated from the regression tests in
[`tests/cves/`](https://github.com/sattyamjjain/agent-airlock/tree/main/tests/cves).

Every CVE listed here has a corresponding test that reproduces the
vulnerable tool-call pattern and asserts an agent-airlock primitive blocks
it. The suite is a **second defence** — upstream vendors have shipped fixes
for every CVE below. Agent-airlock's job is to catch the same class of bug
when a vulnerable server is still running, or when a new tool ships with the
same shape.

See [`tests/cves/README.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/README.md)
for the classification rules and a list of CVEs we deliberately chose NOT
to cover (transport-layer and web-framework bugs that sit outside the
airlock execution seam).

To regenerate this page:

```bash
python3 scripts/gen_cve_catalog.py --write
```

CI runs `python3 scripts/gen_cve_catalog.py --check` on every PR, so the
catalog and the tests stay in lockstep.
"""


def render(entries: list[CVEEntry]) -> str:
    out: list[str] = [HEADER, "", "## Summary", ""]
    out.append("| CVE | Component / title | CVSS | Airlock fit |")
    out.append("| --- | --- | --- | --- |")
    for e in entries:
        anchor = e.cve_id.lower()
        out.append(f"| [{e.cve_id}](#{anchor}) | {e.title} | {e.cvss or '—'} | {e.fit_badge} |")
    out.append("")
    out.append("## Details")
    out.append("")

    for e in entries:
        anchor = e.cve_id.lower()
        out.append(f"### {e.cve_id}")
        out.append("")
        out.append(f"**{e.title}**")
        out.append("")
        if e.cvss:
            out.append(f"- **CVSS:** {e.cvss}")
        if e.airlock_fit:
            out.append(f"- **Airlock fit:** {e.airlock_fit}")
        if e.nvd:
            out.append(f"- **NVD:** [{e.nvd}]({e.nvd})")
        if e.advisory:
            out.append(f"- **Advisory:** [{e.advisory}]({e.advisory})")
        if e.writeup:
            out.append(f"- **Write-up:** [{e.writeup}]({e.writeup})")
        rels = [f.relative_to(ROOT).as_posix() for f in e.files]
        links = ", ".join(
            f"[`{rel}`](https://github.com/sattyamjjain/agent-airlock/blob/main/{rel})"
            for rel in rels
        )
        label = "Regression test" if len(rels) == 1 else "Regression tests"
        out.append(f"- **{label}:** {links}")
        out.append("")
        if e.description:
            out.append("**Vulnerability**")
            out.append("")
            out.append(e.description)
            out.append("")
        if e.mitigation:
            out.append("**Airlock mitigation**")
            out.append("")
            out.append(e.mitigation)
            out.append("")
        out.append(f'<a id="{anchor}"></a>')
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help=f"write output to {OUTPUT.relative_to(ROOT)} instead of stdout",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=f"exit non-zero if {OUTPUT.relative_to(ROOT)} differs from generator output",
    )
    args = parser.parse_args()

    # `--check` is the CI gate, so it is the mode that must refuse a module it cannot
    # read. `--write` stays lenient on purpose: an author mid-edit should be able to
    # regenerate and see the warning, then have CI stop them if they ship it anyway.
    try:
        entries = collect(strict=args.check)
    except UnparseableCVEModule as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    # Uniqueness is checked in every mode, not just `--check`. The duplicate-row
    # defect survived for so long precisely because `--check` only compares two
    # artefacts that were wrong together; a mode that can still *write* a
    # duplicate would leave that hole open from the other side.
    try:
        assert_unique_cve_rows(entries)
    except DuplicateCVERows as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    content = render(entries)

    if args.check:
        if not OUTPUT.exists():
            print(f"FAIL: {OUTPUT.relative_to(ROOT)} is missing.", file=sys.stderr)
            return 1
        existing = OUTPUT.read_text(encoding="utf-8")
        if existing != content:
            print(
                f"FAIL: {OUTPUT.relative_to(ROOT)} is out of date. "
                f"Run `python3 scripts/gen_cve_catalog.py --write`.",
                file=sys.stderr,
            )
            return 1
        return 0

    if args.write:
        OUTPUT.write_text(content, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(entries)} CVEs)", file=sys.stderr)
        return 0

    sys.stdout.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
