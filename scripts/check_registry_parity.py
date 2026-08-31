#!/usr/bin/env python3
"""Registry-parity gate: the declared version must not outrun PyPI.

Why this exists
---------------
On 2026-08-31 the repo declared ``0.8.83`` in ``pyproject.toml``, in
``agent_airlock.__version__``, in the README badge and in a written ``## [0.8.83]``
CHANGELOG section — and PyPI served ``0.8.82``. Nothing was red. Every version check the
repo owned compared one *repo-internal* surface to another:

* ``check_version_tagged.py`` — ``pyproject.toml`` against the git tags.
* ``check_changelog_heading.py`` — ``pyproject.toml`` against the CHANGELOG heading.
* the ``__init__``/``pyproject`` parity test — the package constant against the build
  metadata (added in 0.8.26, after a wheel shipped reporting the wrong version).

Each of those is real, and all of them agreed, because the repo was internally consistent.
It was consistent about a version nobody could install. The one comparison nobody made was
against the **external registry**, which is the only surface a user actually receives.

What it checks
--------------
Two failure conditions, both only meaningful while the repo is *ahead* of the registry:

1. **Distance.** More than one release ahead of PyPI means an earlier version was declared
   and never published — the drift already happened and went unnoticed. A single patch
   ahead (``0.8.83`` over ``0.8.82``), or a clean minor/major rollover (``0.9.0``,
   ``1.0.0``), is the normal state between the bump and the release, and passes.
2. **Age.** One release ahead is normal for hours and suspicious for days. Past
   :data:`MAX_UNPUBLISHED_DAYS`, the bump commit's own date says the release was forgotten
   rather than in flight.

Two modes
---------
**Default.** Both checks. Wired into ``ci.yml``'s ``version-tag-guard`` job, beside
``check_version_tagged.py`` — the same job, for the same class of failure, one seam
further out. Main-pushes only, where the drift lives.

**``--distance-only``.** Drops the age check. This is what ``publish.yml`` runs, and the
reason the split exists: at publish time the repo is *always* ahead of the registry —
that is what publishing means — so an age check there would fail the very release that
resolves it. A gate that blocks its own remedy is a deadlock, not a gate. The distance
check has no such problem and is worth running at publish, where it catches a release that
silently skips a version.

Lenient by construction, like ``check_version_tagged.py``: if PyPI is unreachable, returns
something unparseable, or git history is missing (a shallow checkout), this prints a note
and passes. A registry outage must not turn the repo red — that is how a gate gets
switched off.

Exit codes: ``0`` pass or indeterminate · ``1`` drift · ``2`` usage.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"

#: PyPI JSON endpoint for the published project.
PYPI_URL = "https://pypi.org/pypi/agent-airlock/json"

#: Seconds to wait on PyPI before giving up and passing.
HTTP_TIMEOUT = 10

#: Being this far ahead of the registry means an earlier version was never published.
MAX_RELEASES_AHEAD = 1

#: A version may sit unpublished this long before the bump reads as forgotten.
MAX_UNPUBLISHED_DAYS = 3

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")

Version = tuple[int, int, int]


def parse_version(text: str) -> Version:
    """Parse a leading ``major.minor.patch`` out of ``text``.

    Args:
        text: A version string, e.g. ``"0.8.83"``.

    Returns:
        The ``(major, minor, patch)`` triple.

    Raises:
        ValueError: If no ``N.N.N`` prefix is present.
    """
    match = _VERSION_RE.match(text.strip())
    if not match:
        raise ValueError(f"unparseable version {text!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def releases_ahead(repo: Version, registry: Version) -> int | None:
    """How many releases ``repo`` is ahead of ``registry``.

    Counts a clean rollover as one release: ``0.9.0`` is one ahead of ``0.8.83``, and
    ``1.0.0`` is one ahead of ``0.9.4``. A version bump does not have to be a patch bump
    to be a single release, and failing a legitimate minor would make this gate wrong in
    the direction that gets it deleted.

    Args:
        repo: The version declared in the repository.
        registry: The version PyPI serves.

    Returns:
        ``0`` when equal, a positive count when ahead, ``-1`` when the repo is *behind*
        the registry, and ``None`` for a jump this function will not vouch for (several
        minors, or a major skipping ahead) — the caller treats ``None`` as too far.
    """
    if repo == registry:
        return 0
    if repo < registry:
        return -1
    if repo[:2] == registry[:2]:
        return repo[2] - registry[2]
    # Ahead on a different line. A single clean rollover counts as one release.
    if repo[0] == registry[0] and repo[1] == registry[1] + 1 and repo[2] == 0:
        return 1
    if repo[0] == registry[0] + 1 and repo[1] == 0 and repo[2] == 0:
        return 1
    return None


def evaluate(
    repo_text: str,
    registry_text: str,
    unpublished_days: int | None,
    *,
    check_age: bool = True,
) -> list[str]:
    """Compare the declared version to the registry and return failure messages.

    Pure: no network, no git, no clock. Everything calendar- or network-derived arrives as
    an argument so the gate's own behaviour is testable without either.

    Args:
        repo_text: Version declared in ``pyproject.toml``.
        registry_text: Version PyPI currently serves.
        unpublished_days: Age in days of the commit that declared ``repo_text``, or
            ``None`` when it could not be determined (shallow clone).
        check_age: When False, skip the age condition (``--distance-only``).

    Returns:
        A list of human-readable failures; empty means the gate passes.
    """
    repo = parse_version(repo_text)
    registry = parse_version(registry_text)
    ahead = releases_ahead(repo, registry)

    if ahead == 0:
        return []

    if ahead == -1:
        return [
            f"PyPI serves {registry_text} but this repo declares {repo_text} — the "
            f"registry is AHEAD of the repo. Something was published that main does not "
            f"contain; reconcile before shipping anything else."
        ]

    if ahead is None or ahead > MAX_RELEASES_AHEAD:
        gap = "several releases" if ahead is None else f"{ahead} releases"
        return [
            f"this repo declares {repo_text} but PyPI serves {registry_text} — {gap} "
            f"ahead (max {MAX_RELEASES_AHEAD}). At least one declared version was never "
            f"published. Cut the missing release(s) before bumping again."
        ]

    # Exactly one release ahead: normal between the bump and the release, and only a
    # problem once it has been that way for a while.
    if not check_age:
        return []
    if unpublished_days is None:
        return []
    if unpublished_days > MAX_UNPUBLISHED_DAYS:
        return [
            f"this repo declared {repo_text} {unpublished_days} days ago and PyPI still "
            f"serves {registry_text} (max {MAX_UNPUBLISHED_DAYS}d unpublished). The "
            f"release was not cut. Publish it:\n"
            f"      git tag v{repo_text} && git push origin v{repo_text}\n"
            f"      gh release create v{repo_text} --notes-file <the CHANGELOG section>\n"
            f"    or, if {repo_text} is not meant to ship, roll the declared version back."
        ]
    return []


def declared_version() -> str:
    """Read ``[project].version`` out of ``pyproject.toml``."""
    match = re.search(r'^version\s*=\s*"([^"]+)"', _PYPROJECT.read_text(encoding="utf-8"), re.M)
    if not match:
        print("check_registry_parity: no version in pyproject.toml", file=sys.stderr)
        raise SystemExit(2)
    return match.group(1)


def registry_version(url: str = PYPI_URL) -> str | None:
    """Fetch the version PyPI serves, or None if the registry cannot be reached."""
    request = urllib.request.Request(url, headers={"User-Agent": "agent-airlock-parity-gate"})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None
    version = payload.get("info", {}).get("version")
    return version if isinstance(version, str) else None


def bump_age_days(version: str) -> int | None:
    """Days since the commit that introduced ``version`` into ``pyproject.toml``.

    Uses the same ``git log -S`` pickaxe as ``check_version_tagged.py`` so the two agree
    on which commit counts as "the bump". Returns None when git or history is unavailable.
    """
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                "-1",
                "--format=%cI",
                "-S",
                f'version = "{version}"',
                "--",
                "pyproject.toml",
            ],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        when = _dt.datetime.fromisoformat(result.stdout.strip())
    except ValueError:
        return None
    now = _dt.datetime.now(_dt.timezone.utc)
    return (now - when.astimezone(_dt.timezone.utc)).days


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--distance-only",
        action="store_true",
        help=(
            "skip the unpublished-age check; for publish.yml, where the repo is always "
            "ahead of the registry and an age check would block its own remedy"
        ),
    )
    args = parser.parse_args(argv)

    repo = declared_version()
    registry = registry_version()
    if registry is None:
        print(
            "check_registry_parity: PyPI unreachable or unparseable — skipping "
            "(not a hard fail)."
        )
        return 0

    try:
        failures = evaluate(
            repo,
            registry,
            bump_age_days(repo),
            check_age=not args.distance_only,
        )
    except ValueError as exc:
        print(f"check_registry_parity: {exc} — skipping (not a hard fail).")
        return 0

    if failures:
        print("\ncheck_registry_parity: FAIL", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1

    scope = "distance only" if args.distance_only else "distance and age"
    print(f"check_registry_parity: OK — repo {repo}, PyPI {registry} ({scope}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
