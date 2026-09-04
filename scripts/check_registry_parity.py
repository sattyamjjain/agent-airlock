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
Three failure conditions. The first two are only meaningful while the repo is *ahead* of
the registry:

1. **Distance.** More than one release ahead of PyPI means an earlier version was declared
   and never published — the drift already happened and went unnoticed. A single patch
   ahead (``0.8.83`` over ``0.8.82``), or a clean minor/major rollover (``0.9.0``,
   ``1.0.0``), is the normal state between the bump and the release, and passes.
2. **Age.** One release ahead is normal for hours and suspicious for days. Past
   :data:`MAX_UNPUBLISHED_DAYS`, the bump commit's own date says the release was forgotten
   rather than in flight.
3. **Documented-but-never-tagged.** *Every* dated ``## [x.y.z] - YYYY-MM-DD`` heading in
   ``CHANGELOG.md`` must have a matching ``vX.Y.Z`` git tag, and ``pyproject.toml`` may run
   ahead of the newest tag only while its own section is still ``## [Unreleased]``.

Why the third condition exists, and why its threshold is zero
------------------------------------------------------------
Conditions 1 and 2 were added on 2026-08-31 and check exactly one direction of drift: the
declared version running ahead of the registry. On 2026-09-02 the repo declared ``0.8.84``,
wrote and dated a full ``## [0.8.84] - 2026-09-02`` CHANGELOG section, and never tagged it.
Nothing was red, because every existing check was satisfied: ``check_version_tagged.py``
grants a one-commit grace and the bump commit *was* ``HEAD``; ``check_changelog_heading.py``
found its heading and stopped there; and this gate's own distance check saw exactly one
release of separation, which reads as the normal state between a bump and a release.

The lesson is the general one, not the specific one: **a guard that only checks one
direction of drift is a guard against one kind of mistake.** The same two surfaces can
disagree in more than one way, and covering the direction that burned you last time says
nothing about the others.

Condition 3 shipped on 2026-09-03 with ``MAX_DOCUMENTED_AHEAD = 1``, on the argument that
one dated section ahead of the newest tag is the ordinary state for the minutes between
writing the release commit and pushing the tag — so a stricter threshold would fire on
every release and be switched off within a week.

**That argument was wrong, and it was falsified the next morning.** The same commit that
added this condition also bumped ``pyproject.toml`` to ``0.8.85`` and wrote a dated
``## [0.8.85] - 2026-09-03`` section without tagging it, reproducing one cycle later the
exact state the condition was written to catch — and passing it. Two consecutive days in
that state is not a minutes-long window.

The threshold was measuring the wrong thing. **A dated heading is a claim that a version
shipped, and the check on a claim is whether the artifact backing it exists — not how far
away it is.** Distance cannot separate a thirty-second publishing window from a release
nobody cut, because both are exactly one ahead. Existence can. So the allowance moved to
where the in-flight state actually lives: ``## [Unreleased]``, which carries no date and
makes no claim, and under which ``pyproject.toml`` may sit :data:`MAX_UNRELEASED_AHEAD`
release past the newest tag.

How to release without tripping this
------------------------------------
The dated heading and the tag must reach ``main`` together, because ``version-tag-guard``
runs on main pushes and this condition has no grace::

    # release commit: bump pyproject, promote [Unreleased] -> ## [X.Y.Z] - <date>
    git tag -a vX.Y.Z -m vX.Y.Z
    git push --atomic origin main vX.Y.Z
    gh release create vX.Y.Z --notes-file <the CHANGELOG section>

Feature work does not bump the version and does not date a section: its entries go under
``## [Unreleased]``, and both this condition and ``check_changelog_heading.py`` stay green.
That split is what makes the two gates satisfiable at once. Before it, the only way to
satisfy ``check_changelog_heading.py`` on a bumped ``main`` was to write a dated heading —
which is precisely the state this condition now fails. Two gates that cannot both be
green is how the state kept recurring.

Three historical versions predate that discipline and are grandfathered by name in
:data:`GRANDFATHERED_UNTAGGED`. Nothing may be added to that set: an untagged dated section
*is* the failure, and a grandfather list that grows is a gate being switched off one entry
at a time.

Deliberately *not* covered here: a tag ahead of the CHANGELOG. That is a real drift too, but
it is ``check_changelog_heading.py``'s seam — it already requires the declared version to
have a conformant heading — and duplicating it here would give two gates one owner.

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
from collections.abc import Sequence
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _ROOT / "pyproject.toml"
_CHANGELOG = _ROOT / "CHANGELOG.md"

#: PyPI JSON endpoint for the published project.
PYPI_URL = "https://pypi.org/pypi/agent-airlock/json"

#: Seconds to wait on PyPI before giving up and passing.
HTTP_TIMEOUT = 10

#: Being this far ahead of the registry means an earlier version was never published.
MAX_RELEASES_AHEAD = 1

#: A version may sit unpublished this long before the bump reads as forgotten.
MAX_UNPUBLISHED_DAYS = 3

#: How far a dated CHANGELOG heading may run ahead of the newest git tag. Zero is not a
#: tuning choice, it is the invariant: a dated heading claims a version shipped, so the tag
#: backing it must exist. Was 1 for one day; see the module docstring for why that failed.
MAX_DOCUMENTED_AHEAD = 0

#: How far ``pyproject.toml`` may run past the newest tag *while its section is still
#: ``[Unreleased]``* — one release in flight. A dated section gets no such allowance.
MAX_UNRELEASED_AHEAD = 1

#: Dated headings from before this repo tagged consistently (2026-01-31 / 2026-02-01).
#: Frozen by construction: ``test_grandfather_list_is_closed`` fails if it grows.
GRANDFATHERED_UNTAGGED = frozenset({"0.1.0", "0.1.1", "0.3.0"})

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")

#: ``## [x.y.z] - YYYY-MM-DD``, optionally followed by a title. Three or four components:
#: 0.5.7.1 and 0.5.6.1 shipped as historical hotfixes. Same shape as the regex in
#: ``check_changelog_heading.py``; the two must agree on what a release heading looks like.
_CHANGELOG_HEADING = re.compile(r"^## \[(\d+(?:\.\d+){2,3})\] - (\d{4}-\d{2}-\d{2})( .*)?$")

#: ``v1.2.3`` / ``v0.5.7.1``. Anything else in ``git tag --list`` is not a release tag.
_TAG_RE = re.compile(r"^v(\d+(?:\.\d+){2,3})$")

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


def _order_key(version: str) -> tuple[int, int, int, int]:
    """Sort key that keeps a four-component hotfix above its three-component base.

    ``parse_version`` deliberately truncates to a triple, which would tie ``0.5.7.1`` with
    ``0.5.7`` and make "newest" ambiguous for the two historical hotfix releases. Ordering
    uses the fourth component; the ahead-count still uses the triple.
    """
    parts = [int(x) for x in version.split(".")]
    parts += [0] * (4 - len(parts))
    return parts[0], parts[1], parts[2], parts[3]


def documented_versions(changelog_text: str) -> list[str]:
    """Every *dated* release heading in a CHANGELOG, newest first.

    ``## [Unreleased]`` is skipped on purpose: it carries no date and makes no claim to
    have shipped, which is exactly the state this check wants people in before a tag exists.

    Args:
        changelog_text: Full contents of ``CHANGELOG.md``.

    Returns:
        Version strings of every dated heading, ordered newest first.
    """
    found = [
        match.group(1)
        for line in changelog_text.splitlines()
        if (match := _CHANGELOG_HEADING.match(line))
    ]
    return sorted(found, key=_order_key, reverse=True)


def tagged_versions(tag_output: str) -> set[str]:
    """Every release version in ``git tag --list`` output.

    Args:
        tag_output: Raw newline-separated stdout of ``git tag --list``.

    Returns:
        Version strings of every ``vX.Y.Z`` tag. Anything else is not a release tag.
    """
    return {
        match.group(1) for line in tag_output.splitlines() if (match := _TAG_RE.match(line.strip()))
    }


def newest_documented_version(changelog_text: str) -> str | None:
    """The newest dated release heading in a CHANGELOG, or None if there are none."""
    found = documented_versions(changelog_text)
    return found[0] if found else None


def newest_tagged_version(tag_output: str) -> str | None:
    """The newest release version in ``git tag --list`` output, or None if there are none."""
    found = tagged_versions(tag_output)
    return max(found, key=_order_key) if found else None


def has_dated_heading(changelog_text: str, version: str) -> bool:
    """Whether ``version`` carries a dated heading, rather than sitting in ``[Unreleased]``."""
    return version in set(documented_versions(changelog_text))


def evaluate_documented_vs_tagged(documented: Sequence[str], tagged: set[str]) -> list[str]:
    """Fail for every dated CHANGELOG heading that has no matching git tag.

    An existence check, not a distance check. A dated heading asserts that a version
    shipped, and the tag is the artifact backing that assertion; see the module docstring
    for why the distance framing this replaced could not see the failure it was built for.

    Pure: no filesystem, no git, no clock. Both surfaces arrive as already-extracted values
    so the condition is testable without a repository.

    Lenient in every indeterminate direction, matching the rest of this gate: no dated
    headings, or no release tags at all, returns no failures. A gate that reddens a shallow
    clone is a gate that gets switched off.

    Args:
        documented: Dated CHANGELOG versions.
        tagged: Versions that have a release tag.

    Returns:
        A list of human-readable failures; empty means this condition passes.
    """
    if not documented or not tagged:
        return []

    missing = [
        version
        for version in documented
        if version not in tagged and version not in GRANDFATHERED_UNTAGGED
    ]
    if not missing:
        return []

    newest = max(tagged, key=_order_key)
    first = missing[0]
    subject = (
        f"{len(missing)} dated sections describe versions"
        if len(missing) > 1
        else "that dated section describes a version"
    )
    return [
        f"CHANGELOG.md dates {', '.join(missing)} with no matching git tag (newest tag is "
        f"v{newest}). A dated heading says the version shipped, so {subject} nobody can "
        f"install. Tag it:\n"
        f"      git tag -a v{first} -m v{first}\n"
        f"      git push --atomic origin main v{first}\n"
        f"      gh release create v{first} --notes-file <the CHANGELOG section>\n"
        f"    or, if it is not meant to ship, move that section back under [Unreleased]."
    ]


def evaluate_declared_vs_tagged(
    declared: str,
    tagged: set[str],
    *,
    declared_is_dated: bool,
) -> list[str]:
    """Fail when ``pyproject.toml`` runs too far past the newest tag while unreleased.

    The allowance is conditional on the declared version still being *in flight*: a version
    whose entries sit under ``[Unreleased]`` may run :data:`MAX_UNRELEASED_AHEAD` release
    past the newest tag. A version carrying a dated section is claiming to have shipped,
    and :func:`evaluate_documented_vs_tagged` owns that case with no allowance at all.

    Args:
        declared: Version declared in ``pyproject.toml``.
        tagged: Versions that have a release tag.
        declared_is_dated: Whether ``declared`` carries a dated CHANGELOG heading.

    Returns:
        A list of human-readable failures; empty means this condition passes.
    """
    if not tagged or declared_is_dated:
        return []

    newest = max(tagged, key=_order_key)
    try:
        ahead = releases_ahead(parse_version(declared), parse_version(newest))
    except ValueError:
        return []

    if ahead is not None and ahead <= MAX_UNRELEASED_AHEAD:
        return []

    gap = "several releases" if ahead is None else f"{ahead} releases"
    return [
        f"pyproject.toml declares {declared} with its entries still under [Unreleased], but "
        f"the newest git tag is v{newest} — {gap} ahead (max {MAX_UNRELEASED_AHEAD} while "
        f"unreleased). A version in between was never cut; tag it before bumping again."
    ]


def repo_documented_versions() -> list[str]:
    """Dated CHANGELOG versions, or empty when CHANGELOG.md is absent or unreadable."""
    try:
        return documented_versions(_CHANGELOG.read_text(encoding="utf-8"))
    except OSError:
        return []


def repo_tagged_versions() -> set[str]:
    """Release tags, or empty when git is unavailable or the clone carries no tags.

    ``publish.yml`` checks out without ``fetch-tags``, so this is routinely empty there and
    both tag-facing conditions simply do not apply.
    """
    try:
        result = subprocess.run(
            ["git", "tag", "--list"],
            cwd=_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return set()
    if result.returncode != 0:
        return set()
    return tagged_versions(result.stdout)


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

    # Run in both modes: neither has an age component, so neither can deadlock a publish
    # the way the unpublished-age check would.
    documented = repo_documented_versions()
    tagged = repo_tagged_versions()
    failures += evaluate_documented_vs_tagged(documented, tagged)
    failures += evaluate_declared_vs_tagged(
        repo, tagged, declared_is_dated=repo in set(documented)
    )

    if failures:
        print("\ncheck_registry_parity: FAIL", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1

    scope = "distance only" if args.distance_only else "distance and age"
    changelog_scope = (
        f", {len(documented)} dated CHANGELOG sections all tagged through "
        f"v{max(tagged, key=_order_key)}"
        if documented and tagged
        else ", CHANGELOG/tag comparison skipped"
    )
    print(
        f"check_registry_parity: OK — repo {repo}, PyPI {registry} "
        f"({scope}{changelog_scope})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
