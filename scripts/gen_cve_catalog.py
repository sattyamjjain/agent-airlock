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
repo so reviewers can diff it on PRs; `scripts/check_cve_catalog.py` in CI
verifies the checked-in file matches what the generator would produce.

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

CVE_HEADER_RE = re.compile(r"^(CVE-\d{4}-\d+)\s+—\s+(.+?)\.?\s*$")
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
    """Parsed metadata for a single CVE regression test."""

    cve_id: str
    title: str
    file: Path
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
    match = CVE_HEADER_RE.match(header)
    if not match:
        return None

    entry = CVEEntry(cve_id=match.group(1), title=match.group(2).strip(), file=path)

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
    return entry


def _dedent_block(block: list[str]) -> str:
    if not block:
        return ""
    non_empty = [ln for ln in block if ln.strip()]
    if not non_empty:
        return ""
    indent = min(len(ln) - len(ln.lstrip(" ")) for ln in non_empty)
    return "\n".join(ln[indent:] if len(ln) >= indent else ln for ln in block)


def collect() -> list[CVEEntry]:
    entries: list[CVEEntry] = []
    for path in sorted(TESTS_DIR.glob("test_cve_*.py")):
        doc = _extract_docstring(path)
        if not doc:
            continue
        entry = _parse_entry(path, doc)
        if entry is None:
            print(f"warning: could not parse {path}", file=sys.stderr)
            continue
        entries.append(entry)
    entries.sort(key=lambda e: e.sort_key)
    return entries


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
        rel = e.file.relative_to(ROOT).as_posix()
        out.append(
            f"- **Regression test:** [`{rel}`](https://github.com/sattyamjjain/agent-airlock/blob/main/{rel})"
        )
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

    entries = collect()
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
