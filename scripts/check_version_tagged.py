#!/usr/bin/env python3
"""CI guard: a declared version must not sit on main untagged.

The failure this exists for: ``pyproject.toml`` was bumped to ``0.8.56`` on 2026-07-24
(the commit that shipped the AgentDojo defense numbers) and then sat on ``main`` for two
days with **no ``v0.8.56`` git tag** — so the best benchmark the repo had was declared but
unreleased, and no one could ``pip install`` it. This guard turns that state red.

Rule: if ``pyproject.toml``'s version has **no matching ``vX.Y.Z`` tag**, and the commit
that introduced that version is more than ``GRACE_COMMITS`` commits behind ``HEAD``, fail.
One grace commit lets a release-prep commit (docs/CHANGELOG) land between the bump and the
tag; a version that lingers longer than that is drift.

Lenient by construction: if git, history, or tags are unavailable (e.g. a shallow CI
checkout), it prints a note and passes rather than false-failing. Run it in CI with a full
checkout (``fetch-depth: 0``) and tags fetched so the check is real.

Exit codes: 0 = ok (tagged, within grace, or indeterminate) · 1 = untagged drift · 2 = usage.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

GRACE_COMMITS = 1
ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"


def _git(*args: str) -> str | None:
    """Run a git command; return stripped stdout, or None if git/command fails."""
    try:
        result = subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _declared_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.M)
    if not match:
        print("check_version_tagged: no version in pyproject.toml", file=sys.stderr)
        raise SystemExit(2)
    return match.group(1)


def main() -> int:
    version = _declared_version()
    tag = f"v{version}"

    tags = _git("tag", "--list")
    if tags is None:
        print("check_version_tagged: git unavailable — skipping (not a hard fail).")
        return 0
    if tag in set(tags.splitlines()):
        print(f"check_version_tagged: OK — {tag} exists.")
        return 0

    # No matching tag. Find the commit that introduced the current version string.
    intro = _git("log", "-1", "--format=%H", "-S", f'version = "{version}"', "--", "pyproject.toml")
    if not intro:
        print(
            f"check_version_tagged: cannot locate the {version} bump commit "
            "(shallow clone?) — skipping.",
        )
        return 0

    since = _git("rev-list", "--count", f"{intro}..HEAD")
    commits_after_bump = int(since) if since and since.isdigit() else 0

    if commits_after_bump > GRACE_COMMITS:
        print(
            f"check_version_tagged: FAIL — pyproject declares {version} but tag {tag} is "
            f"missing, and the bump is {commits_after_bump} commits behind HEAD "
            f"(> {GRACE_COMMITS} grace). Cut the release:\n"
            f"  git tag -a {tag} -m {tag} && git push origin {tag}",
            file=sys.stderr,
        )
        return 1

    print(
        f"check_version_tagged: OK — {version} is untagged but only {commits_after_bump} "
        f"commit(s) past the bump (grace {GRACE_COMMITS})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
