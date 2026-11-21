"""OIDC publish-window guard (v0.7.6+, TanStack postmortem 2026-05-11).

The TanStack 2026-05-11 postmortem disclosed that an attacker
extracted the runner's OIDC token directly from ``/proc/<pid>/maps``
and ``/proc/<pid>/mem`` of the Runner.Worker process and used it to
republish 42 packages × 84 versions outside the workflow's own
publish step. The npm trusted-publisher binding has no per-publish
review — once configured, any code path in the workflow can mint a
publish-capable token.

Airlock's runtime surface for this exploitation class is "agent that
fetches / runs just-mutated package versions should reject blast-list
pairs". This guard fails-closed on:

1. A ``package`` + ``version`` argument pair appearing in the
   operator-supplied blast list, OR
2. A registry tarball URL (``https://registry.npmjs.org/<pkg>/-/...-<ver>.tgz``)
   targeting any pair in the blast list.

The guard ships with the incident's blast list as a dated snapshot
(``data/oidc_publish_blast_2026_10_28.json``: the 84 versions
GHSA-g7cv-rxg3-hmpx lists, 42 npm packages at two exact versions each)
loadable via :func:`load_blast_list_from_2026_05_11`, which is named for the
incident, not the snapshot. Operators regenerate when new entries are
confirmed (see ``docs/policies/npm-oidc-publish-window-guard.md``).

A second source (v0.10.32): GitHub's and OSV's malware advisories, read offline by
:mod:`agent_airlock.mcp_spec.malware_advisory_feed` from a dated snapshot
(``data/malware_blast_<YYYY_MM_DD>.json``, refreshed by
``scripts/refresh_malware_blast.py``). An advisory that names exact versions adds pairs; one
that calls every version malicious adds a whole package, passed as ``blocked_packages``, and
a package argument or tarball URL naming it is refused whatever the version, or with none.
The preset unions both sources; a guard built directly gets only what it is given.

Why structural (no SDK import)
------------------------------
Pure-data preset: the blast list is a frozenset of
``(ecosystem, name, version)`` tuples, the URL detector is a
compiled regex. No ``npm`` / ``pypi`` package metadata client is
loaded.

Matching (v0.10.28)
-------------------
A pair matches in any spelling a package manager accepts for the same
release: versions are compared the way npm's ``semver.clean`` and PEP 440
compare them (surrounding whitespace, a leading ``v`` / ``=`` and ``+build``
metadata dropped, case folded, ``2.6.2.0`` == ``2.6.2``); ``package`` may
carry the version itself (``name@1.2.3``, ``@scope/name@1.2.3``,
``alias@npm:name@1.2.3``, ``name==1.2.3``, ``name[extra]==1.2.3``); PyPI
names compare by PEP 503; ``package`` / ``version`` / ``url`` may each be a
string, UTF-8 ``bytes`` or a list of them. A tarball URL matches on an exact
``-<version>.tgz`` boundary, with its query, fragment, port, userinfo and
percent-escapes (``@scope%2fname``) set aside, on ``registry.npmjs.org`` and
its Yarn alias, read as Node's ``new URL()`` reads it (a backslash is a path
separator; ``.`` / ``..`` segments, ``%2e`` spellings included, are resolved).
A ``package`` that is a tarball URL, or ``name@<url>``, is read as that URL, and
a ``version`` written ``npm:1.2.3`` or ``npm:@scope/real@1.2.3`` (Yarn, pnpm) as
the release it installs. Arguments that are not a mapping, and a field of any
other shape, are refused (``DENY_UNINSPECTABLE``). Until v0.10.28 the guard
compared exact strings only, so each of those spellings walked past it, and
a top-level list raised ``AttributeError``.

Honest scope
------------
- The guard is a **known-bad blast-list** denier, NOT a generic OIDC
  anomaly detector. The architectural fix is in npm's per-publish-
  review feature request (see postmortem "Remediation Guidance").
- It matches exact releases only. A range (``^1.146.0``, ``>=2.6.2``)
  that could resolve to a listed release is not resolved here, and a git
  spec (``github:TanStack/router#v1.161.9``) or a tarball on any host but the
  two registries is not read.
- The fixture is a point-in-time snapshot. Operators must regenerate
  on new confirmed blast-list extensions; Sunday review surfaces
  this as a checklist item.
- Until 0.10.28 the shipped snapshot was
  ``data/oidc_publish_blast_2026_05_11.json`` (kept, superseded). It spelled
  90 of its 93 versions with a ``-compromised-2026-05-11`` suffix no
  registry publishes, so those rows never matched a real install; it named
  ``@tanstack/react-query``, which the postmortem lists as clean; and its
  three PyPI rows appear in neither source it cited. The current snapshot
  is copied from the GitHub advisory's affected-version table.
- The wider Mini Shai-Hulud wave (Mistral, UiPath and other npm scopes,
  per Aikido) is not in the incident list; the malware advisory snapshot carries what
  GitHub flagged as malware up to its date, and nothing published after it.
- A whole-package entry has no version to narrow it, so it is matched in one ecosystem: the
  one the argument's syntax names (a pip specifier such as ``==``, ``>=`` or ``[extra]`` is
  PyPI; ``@scope/name``, ``name@version``, an ``npm:`` alias or a tarball URL is npm), else
  the one ``installs_from`` names. npm malware squats real PyPI names (``pydantic``,
  ``typing-extensions``, ``uvicorn`` and hundreds more), so a guard that read a bare name in
  both would refuse them for a pip tool; ``installs_from`` is therefore required with
  ``blocked_packages``. Pairs still match in either ecosystem, as they always have.
- A rescoped name (v0.10.36, ``rescoped_names``) is refused on its basename alone: a
  legitimate ``@yourco/md-doc-mcp`` is refused too until it is put on ``rescope_allow``.
  Only scoped npm names whose basename names MCP and is not generic are indexed
  (:func:`~agent_airlock.mcp_spec.malware_advisory_feed.rescoped_name_index`); an unscoped
  copy, or a new basename, still passes until an advisory names it.

Primary sources
---------------
- GHSA-g7cv-rxg3-hmpx (CVE-2026-45321), the affected-version table:
  https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- TanStack postmortem (2026-05-11):
  https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Aikido — Mini Shai-Hulud Is Back (2026-05-11, cross-ecosystem):
  https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- GHSA-m5xq-h2p4-962g (2026-11-19), ``@fdcasj_dfew/md-doc-mcp`` 1.0.0 and 1.0.1, the
  ``@ifasn`` MCP malware republished under a new scope (the rescoped-name check):
  https://github.com/advisories/GHSA-m5xq-h2p4-962g
- GHSA-h82f-cjm4-g22r (2026-11-20), ``@guicai777/mcp-doctor`` 1.0.1, installable for four
  days before any advisory (the release-age check):
  https://github.com/advisories/GHSA-h82f-cjm4-g22r
"""

from __future__ import annotations

import enum
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from typing import Any, Literal
from urllib.parse import unquote, urlsplit

from .._log import structlog
from .._url_paths import normalize_url_path
from .release_age import ReleaseTimeLookup

logger = structlog.get_logger("agent-airlock.mcp_spec.oidc_publish_window_guard")


_FIXTURE_PACKAGE = "agent_airlock.data"
_FIXTURE_RESOURCE_NAME = "oidc_publish_blast_2026_10_28.json"


# Registry tarball path — ``/<pkg>/-/<tail>.tgz``. Captures the package name
# (with optional scope) and the file name so the guard can read the version
# off its ``-<version>.tgz`` end. Matched against the percent-decoded path of a
# URL on one of :data:`_NPM_REGISTRY_HOSTS`.
_NPM_TARBALL_PATH_RE = re.compile(
    r"^/(?P<pkg>(?:@[\w.-]+/)?[\w.-]+)/-/(?P<tail>[\w.-]+\.tgz)$",
    re.IGNORECASE,
)

#: The npm registry and the Yarn alias that serves the same tarballs at the same paths.
_NPM_REGISTRY_HOSTS: frozenset[str] = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})

_PEP503_SEPARATORS_RE = re.compile(r"[-_.]+")
_RELEASE_RE = re.compile(r"\d+(?:\.\d+)*")


def _normalise_version(version: str) -> str:
    """A version as npm's ``semver.clean`` and PEP 440 compare it.

    Surrounding whitespace, any leading ``=`` / ``v`` and ``+build`` metadata are
    dropped and case is folded; a pure release loses its trailing zero components, so
    ``2.6.2.0`` and ``2.6.2`` (equal under PEP 440) normalise alike.
    """
    text = version.strip().lstrip("=vV").strip().split("+", 1)[0].lower()
    if _RELEASE_RE.fullmatch(text):
        try:
            parts = [int(part) for part in text.split(".")]
        except ValueError:  # a component past int()'s digit limit: compare as written
            return text
        while len(parts) > 1 and parts[-1] == 0:
            parts.pop()
        text = ".".join(str(part) for part in parts)
    return text


def _normalise_name(ecosystem: str, name: str) -> str:
    """A package name as its registry compares it (PEP 503 for PyPI, case-folded npm)."""
    if ecosystem == "pypi":
        return _PEP503_SEPARATORS_RE.sub("-", name.strip()).lower()
    return name.strip().lower()


def _split_spec(spec: str) -> tuple[str, str | None]:
    """Split a package spec into ``(name, version-or-None)``.

    Reads ``name@1.2.3``, ``@scope/name@1.2.3``, an npm alias
    (``alias@npm:name@1.2.3`` / ``npm:name@1.2.3``) and a pip pin
    (``name==1.2.3``, ``name===1.2.3``, ``name[extra]==1.2.3 ; marker``).
    """
    text = spec.strip()
    if "@npm:" in text:
        text = text.split("@npm:", 1)[1]
    elif text.lower().startswith("npm:"):
        text = text[4:]
    if "==" in text:
        name, _, version = text.partition("==")
        version = version.lstrip("=").split(";", 1)[0]
        return name.split("[", 1)[0].strip(), version.strip()
    at = text.rfind("@")
    if at > 0:
        return text[:at].strip(), text[at + 1 :].strip()
    return text.split("[", 1)[0].strip(), None


#: Where a package spec names a URL to install from: npm reads a bare URL, and
#: ``name@<url>`` / ``alias@<url>``, as a remote tarball (npm-package-arg ``type: remote``).
_SPEC_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def _spec_url(spec: str) -> str | None:
    """The URL a package spec installs from (``<url>``, ``name@<url>``), or None."""
    match = _SPEC_URL_RE.search(spec)
    return spec[match.start() :].strip() if match is not None else None


#: Characters that end a PyPI project name in a PEP 508 requirement: a version specifier,
#: an extra, a marker or a direct reference.
_PEP508_NAME_END_RE = re.compile(r"[\s<>=!~;\[(,@]")

#: ``_kind`` spellings of PyPI; anything else is read as npm, as ``blast_list`` reads it.
_PYPI_SPELLINGS = frozenset({"pypi", "pip"})


def _kind(ecosystem: str) -> str:
    """``pypi`` or ``npm``: the index a whole-package entry or an advisory id is kept under."""
    return "pypi" if ecosystem.strip().lower() in _PYPI_SPELLINGS else "npm"


def _spec_kinds(spec: str) -> tuple[str, ...] | None:
    """The ecosystem a package spec's own syntax names, or None for a bare name."""
    text = spec.strip()
    lowered = text.lower()
    if text.startswith("@") or "@npm:" in lowered or lowered.startswith("npm:"):
        return ("npm",)
    if any(token in text for token in ("==", "~=", "!=", ">=", "<=", "[", ";", " @ ")):
        return ("pypi",)
    if re.search(r"[^@\s]@[^@\s]", text):
        return ("npm",)  # name@version: pip spells a pin "==", and a URL " @ "
    return None


#: ``installs_from`` values, and the ecosystems a bare name is then read in.
_INSTALLS_FROM: Mapping[str, tuple[str, ...]] = {
    "npm": ("npm",),
    "pypi": ("pypi",),
    "pip": ("pypi",),
    "any": ("npm", "pypi"),
}


def _spec_names(spec: str) -> list[str]:
    """The package names a spec can install: as npm splits it, and as PEP 508 does."""
    npm_name, _ = _split_spec(spec)
    pep508_name = _PEP508_NAME_END_RE.split(spec.strip(), maxsplit=1)[0]
    return [name for name in dict.fromkeys((npm_name, pep508_name)) if name]


def _version_target(name: str, version: str) -> tuple[str, str]:
    """The package and version a ``version`` field installs, beside package ``name``.

    Yarn and pnpm write a registry version as ``npm:1.2.3``, and an alias in the version
    field as ``npm:@scope/real@1.2.3``, which installs ``@scope/real``. Until 0.10.28 both
    were compared as written, and matched nothing.
    """
    text = version.strip()
    if not text.lower().startswith("npm:"):
        return name, text
    target = text[4:].strip()
    if "@" in target[1:]:
        aliased, aliased_version = _split_spec(target)
        if aliased_version:
            return aliased, aliased_version
    return name, target


def _normalised_path(path: str) -> str:
    """A URL path with its dot segments resolved and empty segments dropped.

    Node's ``new URL()`` resolves ``.`` and ``..`` (and their percent-encoded spellings)
    before the registry sees the path, so ``/@tanstack/x/../history/-/...`` fetches
    ``@tanstack/history``. Empty segments are dropped as well, which can only refuse more.
    The shared resolver (``.._url_paths``) is called with ``strip_path_params`` off: npm
    has no servlet path parameters, so its behaviour is unchanged.
    """
    return normalize_url_path(path)


def _texts(value: object) -> list[str] | None:
    """A field as a list of strings, or ``None`` when its shape cannot be read.

    ``None`` is an absent field; a string is one value; UTF-8 ``bytes`` are decoded; a
    list, tuple, set or frozenset is read item by item, each a string or UTF-8 bytes.
    """
    if value is None:
        return []
    items = list(value) if isinstance(value, (list, tuple, set, frozenset)) else [value]
    out: list[str] = []
    for item in items:
        if isinstance(item, (bytes, bytearray)):
            try:
                item = bytes(item).decode("utf-8")
            except UnicodeDecodeError:
                return None
        if not isinstance(item, str):
            return None
        out.append(item)
    return out


@dataclass(frozen=True)
class _AgeQuery:
    """One spec's release-age question: ``(kind, normalised name, exact version)`` per
    registry it may come from, the spec as asked, and how a refusal names it."""

    lookups: tuple[tuple[str, str, str | None], ...]
    requested: str
    label: str


#: Spec prefixes that install from somewhere other than a registry: git, a path, a link.
_NON_REGISTRY_PREFIXES: tuple[str, ...] = (
    "git+",
    "git:",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
    "file:",
    "link:",
    "workspace:",
    "portal:",
    "patch:",
    "http:",
    "https:",
)

_NPM_EXACT_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
    re.ASCII,
)
_PYPI_EXACT_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]*", re.ASCII)


def _is_registry_spec(spec: str, embedded: str | None) -> bool:
    """Whether a package spec installs from a registry (not git, a path or a URL)."""
    text = spec.strip().lower()
    if "@npm:" in text:
        text = text.split("@npm:", 1)[1]
    elif text.startswith("npm:"):
        text = text[4:]
    if not text or text.startswith(_NON_REGISTRY_PREFIXES) or text[0] in "./~\\":
        return False
    if " @ " in text or "://" in text:
        return False  # a PEP 508 direct reference, or a URL
    if not text.startswith("@") and "/" in text.split("@", 1)[0]:
        return False  # npm's GitHub shorthand, user/repo
    version = (embedded or "").strip().lower()
    return not (version.startswith(_NON_REGISTRY_PREFIXES) or "/" in version)


def _exact_npm_version(version: str) -> str | None:
    """``version`` when it names one npm release; None for a range or a dist-tag."""
    text = version.strip().lstrip("=").lstrip("vV")
    return text if _NPM_EXACT_VERSION_RE.fullmatch(text) else None


def _exact_pypi_version(version: str) -> str | None:
    """``version`` when it names one PyPI release; None for a wildcard or anything else."""
    text = version.strip()
    return text if _PYPI_EXACT_VERSION_RE.fullmatch(text) and "*" not in text else None


def _age_label(kind: str, name: str, version: str | None) -> str:
    if version is None:
        return f"{name} (the version the registry installs by default)"
    return f"{name}=={version}" if kind == "pypi" else f"{name}@{version}"


def _span(span: timedelta, *, compact: bool = False) -> str:
    """``4 d 0 h``; with ``compact``, ``7 d`` or ``12 h`` when that is all of it."""
    total = int(span.total_seconds())
    days, rest = divmod(total, 86_400)
    hours = rest // 3_600
    if compact and rest == 0:
        return f"{days} d"
    if compact and days == 0 and rest % 3_600 == 0:
        return f"{hours} h"
    return f"{days} d {hours} h"


def _is_str_tuple(value: object, length: int) -> bool:
    return (
        isinstance(value, tuple)
        and len(value) == length
        and all(isinstance(part, str) for part in value)
    )


class OIDCPublishWindowVerdict(str, enum.Enum):
    """Stable reason codes for :class:`OIDCPublishWindowDecision`."""

    ALLOW = "allow"
    DENY_BLAST_LIST_PAIR = "deny_blast_list_pair"
    DENY_BLAST_LIST_TARBALL_URL = "deny_blast_list_tarball_url"
    # A scoped npm name whose basename a listed MCP malware package carries under another
    # scope (0.10.36, GHSA-m5xq-h2p4-962g).
    DENY_RESCOPED_MALWARE_NAME = "deny_rescoped_malware_name"
    # A registry version younger than ``min_release_age``, or one whose publish time the
    # lookup could not tell (0.10.36, GHSA-h82f-cjm4-g22r).
    DENY_RELEASE_TOO_NEW = "deny_release_too_new"
    DENY_RELEASE_AGE_UNKNOWN = "deny_release_age_unknown"
    # Arguments the guard cannot read: not a mapping, or a package / version / url that
    # is not text or a list of text (0.10.28).
    DENY_UNINSPECTABLE = "deny_uninspectable"


@dataclass(frozen=True)
class OIDCPublishWindowDecision:
    """Outcome of a single :meth:`OIDCPublishWindowGuard.evaluate` call.

    Mirrors the field shape of :class:`AllowlistVerdict`,
    :class:`OutcomesRubricDecision`, and :class:`FilterEvalRCEDecision`
    — both expose ``allowed: bool`` so an integrator can chain guards
    on a single short-circuit predicate.

    Attributes:
        allowed: True iff no blast-list pattern matched.
        verdict: A stable :class:`OIDCPublishWindowVerdict` value.
        detail: Free-form human-readable explanation.
        matched_ecosystem: ``npm`` / ``pypi`` / ``None``.
        matched_package: Package name from the matched entry, or
            ``None`` when ``allowed=True``.
        matched_version: Version from the matched entry, or ``None``
            when no version was extracted.
    """

    allowed: bool
    verdict: OIDCPublishWindowVerdict
    detail: str
    matched_ecosystem: str | None
    matched_package: str | None
    matched_version: str | None


def load_blast_list_from_2026_05_11() -> frozenset[tuple[str, str, str]]:
    """Load the blast list of the 2026-05-11 TanStack incident as a frozenset.

    The data is the current dated snapshot (:data:`_FIXTURE_RESOURCE_NAME`), copied
    from GHSA-g7cv-rxg3-hmpx; the name keeps the incident date.

    Uses :func:`importlib.resources.files` so the fixture path is
    correct whether the package is installed editable or via wheel.

    Returns:
        Frozenset of ``(ecosystem, name, version)`` tuples.

    Raises:
        FileNotFoundError: Fixture missing (broken install).
        ValueError: Fixture present but malformed.
    """
    raw = (files(_FIXTURE_PACKAGE) / _FIXTURE_RESOURCE_NAME).read_text(encoding="utf-8")
    payload = json.loads(raw)
    entries_raw = payload.get("entries")
    if not isinstance(entries_raw, list):
        raise ValueError(f"fixture {_FIXTURE_RESOURCE_NAME} malformed: 'entries' must be a list")
    out: set[tuple[str, str, str]] = set()
    for row in entries_raw:
        if not isinstance(row, dict):
            raise ValueError(
                f"fixture {_FIXTURE_RESOURCE_NAME} malformed: each entry must be a dict"
            )
        out.add((str(row["ecosystem"]), str(row["name"]), str(row["version"])))
    return frozenset(out)


class OIDCPublishWindowGuard:
    """Fail-closed gate on package+version pairs from the 2026-05-11 blast list.

    Default: empty blast list → allow-all. Operators must explicitly
    enrol pairs they want denied (or call the factory which loads the
    curated 2026-05-11 fixture).

    Args:
        blast_list: Frozenset of ``(ecosystem, name, version)`` tuples
            the gate denies. Empty (default) allows everything — the
            factory in :mod:`agent_airlock.policy_presets` is the
            recommended entrypoint that loads the curated fixture.
        blocked_packages: Frozenset of ``(ecosystem, name)`` tuples whose every version is
            denied, and a request naming no version too (malware advisories that call every
            release malicious). Empty by default, which leaves the guard as it was.
        advisories: ``(ecosystem, name)`` to the advisory id a deny message names, as
            :class:`~agent_airlock.mcp_spec.malware_advisory_feed.MalwareBlastList` keeps it.
        installs_from: The registry the guarded tool installs from: ``"npm"``, ``"pypi"``
            or ``"any"``. Required with ``blocked_packages``. A bare name (``{"package":
            "x", "version": "1.0"}``) says nothing about its ecosystem, and npm malware
            squats real PyPI names (``pydantic`` and ``typing-extensions`` among them), so
            only the operator can say which list a bare name is checked against. A spec whose
            syntax names an ecosystem (``x==1.0`` is PyPI, ``@scope/x`` or ``x@1.0`` npm, a
            tarball URL npm) is read there whatever this says. Pairs are not affected.
        rescoped_names: Lowercased npm basename to ``(listed full name, advisory ids)``,
            as :func:`~agent_airlock.mcp_spec.malware_advisory_feed.rescoped_name_index`
            builds it (v0.10.36). A scoped npm name the pair and whole-package lookups did
            not match, whose basename is here and which is neither listed itself nor on
            ``rescope_allow``, is refused at every version
            (``DENY_RESCOPED_MALWARE_NAME``). Empty by default.
        rescope_allow: Full npm names (``@yourco/md-doc-mcp``) never refused by the
            rescoped-name check: a legitimate package that shares a listed basename.
        min_release_age: Refuse a registry version published less than this long before the
            call (``DENY_RELEASE_TOO_NEW``), as pnpm's ``minimumReleaseAge``, npm's
            ``--before`` and uv's ``exclude-newer`` do (v0.10.36, GHSA-h82f-cjm4-g22r). Off
            (None) by default. Checked after every list, so a listed release reports its own
            verdict; a git, path or non-registry URL spec is not looked up. A spec with no
            exact version (none, a range, a dist-tag) is judged by the version the registry
            installs by default.
        release_time_lookup: When a version was published
            (:data:`~agent_airlock.mcp_spec.release_age.ReleaseTimeLookup`);
            :func:`~agent_airlock.mcp_spec.release_age.registry_release_time_lookup` asks
            the registries. Required with ``min_release_age``.
        unknown_release_age: ``"deny"`` (the default) refuses a version whose publish time
            the lookup cannot tell (``DENY_RELEASE_AGE_UNKNOWN``); ``"allow"`` lets it
            through.
        release_age_allow: Full package names the release-age check skips: your own
            package published today.
        clock: The current time, aware; ``datetime.now(timezone.utc)`` by default. Tests
            pin it.

    Raises:
        TypeError: ``blast_list`` or ``blocked_packages`` is not a frozenset, an entry is
            not a tuple of strings of the right length, ``advisories`` is not a mapping
            from ``(ecosystem, name)`` to a string, ``rescoped_names`` is not a mapping
            from a string to a 2-tuple of strings, ``rescope_allow`` or
            ``release_age_allow`` is not a frozenset of strings, ``min_release_age`` is not
            a ``timedelta``, or ``release_time_lookup`` or ``clock`` is not callable.
        ValueError: ``blocked_packages`` is given without ``installs_from``,
            ``installs_from`` is not one of its values, ``min_release_age`` is negative or
            set without ``release_time_lookup``, or ``unknown_release_age`` is neither
            ``"allow"`` nor ``"deny"``.
    """

    def __init__(
        self,
        *,
        blast_list: frozenset[tuple[str, str, str]] = frozenset(),
        blocked_packages: frozenset[tuple[str, str]] = frozenset(),
        advisories: Mapping[tuple[str, str], str] | None = None,
        installs_from: str | None = None,
        rescoped_names: Mapping[str, tuple[str, str]] | None = None,
        rescope_allow: frozenset[str] = frozenset(),
        min_release_age: timedelta | None = None,
        release_time_lookup: ReleaseTimeLookup | None = None,
        unknown_release_age: Literal["allow", "deny"] = "deny",
        release_age_allow: frozenset[str] = frozenset(),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(blast_list, frozenset):
            raise TypeError(
                f"blast_list must be a frozenset[tuple[str,str,str]]; "
                f"got {type(blast_list).__name__}"
            )
        for entry in blast_list:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 3
                or not all(isinstance(part, str) for part in entry)
            ):
                raise TypeError(
                    "blast_list entries must be 3-tuples of str (ecosystem, name, version); "
                    f"got {entry!r}"
                )
        self._blast_list = blast_list
        # Index normalised (ecosystem-kind, name) → normalised version → the entry as
        # listed, so every spelling of a pair finds the entry and reports it verbatim.
        self._index: dict[tuple[str, str], dict[str, tuple[str, str, str]]] = {}
        for ecosystem, name, version in blast_list:
            kind = "pypi" if ecosystem.strip().lower() == "pypi" else "npm"
            key = (kind, _normalise_name(kind, name))
            self._index.setdefault(key, {})[_normalise_version(version)] = (
                ecosystem,
                name,
                version,
            )
        if not isinstance(blocked_packages, frozenset):
            raise TypeError(
                "blocked_packages must be a frozenset[tuple[str,str]]; "
                f"got {type(blocked_packages).__name__}"
            )
        # (kind, normalised name) -> the entry as listed.
        self._blocked: dict[tuple[str, str], tuple[str, str]] = {}
        for package in blocked_packages:
            if not _is_str_tuple(package, 2):
                raise TypeError(
                    f"blocked_packages entries must be 2-tuples of str (ecosystem, name); "
                    f"got {package!r}"
                )
            kind = _kind(package[0])
            self._blocked[(kind, _normalise_name(kind, package[1]))] = package
        if advisories is not None and not isinstance(advisories, Mapping):
            raise TypeError(f"advisories must be a mapping; got {type(advisories).__name__}")
        if installs_from is not None and (
            not isinstance(installs_from, str) or installs_from.lower() not in _INSTALLS_FROM
        ):
            raise ValueError(f"installs_from must be 'npm', 'pypi' or 'any'; got {installs_from!r}")
        if blocked_packages and installs_from is None:
            raise ValueError(
                "blocked_packages needs installs_from: 'npm', 'pypi' or 'any'. A bare package "
                "name does not say which registry it is for, and npm malware squats real PyPI "
                "names, so the guard cannot choose for you"
            )
        self._bare_kinds = _INSTALLS_FROM[installs_from.lower()] if installs_from else ()
        self._advisories: dict[tuple[str, str], str] = {}
        for key, advisory in (advisories or {}).items():
            if not _is_str_tuple(key, 2) or not isinstance(advisory, str):
                raise TypeError(
                    "advisories must map (ecosystem, name) 2-tuples of str to a str; "
                    f"got {key!r}: {advisory!r}"
                )
            kind = _kind(key[0])
            self._advisories[(kind, _normalise_name(kind, key[1]))] = advisory
        if rescoped_names is not None and not isinstance(rescoped_names, Mapping):
            raise TypeError(
                f"rescoped_names must be a mapping; got {type(rescoped_names).__name__}"
            )
        self._rescoped: dict[str, tuple[str, str]] = {}
        for basename, listed in (rescoped_names or {}).items():
            if not isinstance(basename, str) or not _is_str_tuple(listed, 2):
                raise TypeError(
                    "rescoped_names must map a basename str to a (full name, advisory ids) "
                    f"2-tuple of str; got {basename!r}: {listed!r}"
                )
            self._rescoped[basename.strip().lower()] = listed
        if not isinstance(rescope_allow, frozenset):
            raise TypeError(
                f"rescope_allow must be a frozenset[str]; got {type(rescope_allow).__name__}"
            )
        for allowed in rescope_allow:
            if not isinstance(allowed, str):
                raise TypeError(f"rescope_allow members must be str; got {allowed!r}")
        self._rescope_allow = frozenset(_normalise_name("npm", name) for name in rescope_allow)
        self._init_release_age(
            min_release_age, release_time_lookup, unknown_release_age, release_age_allow, clock
        )

    def _init_release_age(
        self,
        min_release_age: object,
        release_time_lookup: object,
        unknown_release_age: object,
        release_age_allow: object,
        clock: object,
    ) -> None:
        """Check and store the release-age keywords (0.10.36)."""
        if min_release_age is not None:
            if not isinstance(min_release_age, timedelta):
                raise TypeError(
                    "min_release_age must be a datetime.timedelta; "
                    f"got {type(min_release_age).__name__}"
                )
            if min_release_age < timedelta(0):
                raise ValueError(f"min_release_age cannot be negative; got {min_release_age}")
            if release_time_lookup is None:
                raise ValueError(
                    "min_release_age needs release_time_lookup, which says when a version was "
                    "published: registry_release_time_lookup() asks the npm registry and PyPI"
                )
        if release_time_lookup is not None and not callable(release_time_lookup):
            raise TypeError(
                f"release_time_lookup must be callable; got {type(release_time_lookup).__name__}"
            )
        if not isinstance(unknown_release_age, str):
            raise TypeError(
                "unknown_release_age must be 'allow' or 'deny'; "
                f"got {type(unknown_release_age).__name__}"
            )
        if unknown_release_age not in ("allow", "deny"):
            raise ValueError(
                f"unknown_release_age must be 'allow' or 'deny'; got {unknown_release_age!r}"
            )
        if not isinstance(release_age_allow, frozenset):
            raise TypeError(
                "release_age_allow must be a frozenset[str]; "
                f"got {type(release_age_allow).__name__}"
            )
        for allowed in release_age_allow:
            if not isinstance(allowed, str):
                raise TypeError(f"release_age_allow members must be str; got {allowed!r}")
        if clock is not None and not callable(clock):
            raise TypeError(f"clock must be callable; got {type(clock).__name__}")
        self._min_release_age: timedelta | None = min_release_age
        self._release_time_lookup = release_time_lookup
        self._unknown_release_age = unknown_release_age
        self._release_age_allow = frozenset(
            (kind, _normalise_name(kind, name))
            for name in release_age_allow
            for kind in ("npm", "pypi")
        )
        self._clock = clock

    def evaluate(self, args: Mapping[str, Any] | None) -> OIDCPublishWindowDecision:
        """Decide whether the call args target a blast-list entry.

        Args:
            args: The tool call's argument dict. ``None`` is allowed
                (no args to inspect). ``package``, ``version`` and ``url``
                are each read as a string, UTF-8 bytes, or a list of them;
                ``package`` may carry its version (``name@1.2.3``,
                ``name==1.2.3``). ``version`` is read only beside a
                ``package``. Arguments that are not a mapping, and a field
                of any other shape, are refused (``DENY_UNINSPECTABLE``).

        Returns:
            :class:`OIDCPublishWindowDecision`. Callers map
            ``allowed=False`` to a refusal at the Airlock decorator
            boundary.
        """
        if args is None:
            return self._allow("no args to inspect")
        if not isinstance(args, Mapping):
            return self._deny_uninspectable("args", f"a {type(args).__name__}, not a mapping")

        # 1) Direct package+version pair, in every spelling of the pair.
        packages = _texts(args.get("package"))
        if packages is None:
            return self._deny_uninspectable("package", self._shape(args.get("package")))
        versions = _texts(args.get("version")) if packages else []
        if versions is None:
            return self._deny_uninspectable("version", self._shape(args.get("version")))
        # Release-age queries, answered only after every list has been checked (0.10.36).
        aging: list[_AgeQuery] = []
        for spec in packages:
            # A package spec that is (or ends in) a registry tarball URL installs that
            # tarball: until 0.10.28 it was read as a name and matched nothing.
            remote = _spec_url(spec)
            if remote is not None:
                decision = self._inspect_tarball_url(remote, aging)
                if decision is not None:
                    return decision
                continue
            name, embedded = _split_spec(spec)
            candidates = ([embedded] if embedded else []) + versions
            for version in candidates:
                target, target_version = _version_target(name, version)
                entry = self._lookup(target, target_version)
                if entry is not None:
                    return self._deny_pair(entry, spec, version, self._advisory_for(entry))
            # 1b) A package every version of which is malicious, whatever version is asked.
            requested = embedded or (versions[0] if versions else None)
            for candidate in _spec_names(spec):
                blocked = self._blocked_entry(candidate, _spec_kinds(spec) or self._bare_kinds)
                if blocked is not None:
                    return self._deny_package(blocked, spec, requested, "package")
            for version in versions:
                target, _ = _version_target(name, version)
                if target != name:
                    blocked = self._blocked_entry(target, ("npm",))
                    if blocked is not None:
                        return self._deny_package(blocked, spec, version, "package")
            # 1c) A listed MCP malware package's basename under another scope (0.10.36).
            for target in dict.fromkeys(
                [name] + [_version_target(name, version)[0] for version in versions]
            ):
                rescoped = self._rescoped_entry(target)
                if rescoped is not None:
                    return self._deny_rescoped(target, rescoped, spec, requested, "package")
            if self._min_release_age is not None:
                query = self._age_query(spec, name, embedded, versions)
                if query is not None:
                    aging.append(query)

        # 2) Registry tarball URL pointing at a blast-list pair.
        urls = _texts(args.get("url"))
        if urls is None:
            return self._deny_uninspectable("url", self._shape(args.get("url")))
        for url in urls:
            decision = self._inspect_tarball_url(url, aging)
            if decision is not None:
                return decision

        # 3) A registry version too new to have been reviewed (0.10.36, GHSA-h82f-cjm4-g22r).
        for query in aging:
            decision = self._release_age_decision(query)
            if decision is not None:
                return decision

        return self._allow("no blast-list pattern matched")

    def _lookup(self, name: str, version: str) -> tuple[str, str, str] | None:
        """The blast-list entry ``(name, version)`` spells, in either ecosystem, or None."""
        wanted = _normalise_version(version)
        for kind in ("npm", "pypi"):
            entry = self._index.get((kind, _normalise_name(kind, name)), {}).get(wanted)
            if entry is not None:
                return entry
        return None

    def _blocked_entry(self, name: str, kinds: tuple[str, ...]) -> tuple[str, str] | None:
        """The whole-package entry ``name`` spells in one of ``kinds``, or None."""
        for kind in kinds:
            entry = self._blocked.get((kind, _normalise_name(kind, name)))
            if entry is not None:
                return entry
        return None

    def _rescoped_entry(self, name: str) -> tuple[str, str] | None:
        """``(listed full name, advisory ids)`` when scoped npm ``name`` is a rescope, else None.

        A rescope is a scoped name whose basename ``rescoped_names`` carries, that is not on
        ``rescope_allow`` and is not itself listed (a listed name is judged by its pairs).
        """
        if not self._rescoped:
            return None
        full = _normalise_name("npm", name)
        scope, slash, base = full.partition("/")
        if not (scope.startswith("@") and len(scope) > 1 and slash and base):
            return None
        listed = self._rescoped.get(base)
        if listed is None or full in self._rescope_allow:
            return None
        if ("npm", full) in self._index or ("npm", full) in self._blocked:
            return None
        if _normalise_name("npm", listed[0]) == full:
            return None
        return listed

    def _deny_rescoped(
        self,
        name: str,
        listed: tuple[str, str],
        requested: str,
        version: str | None,
        what: str,
    ) -> OIDCPublishWindowDecision:
        """Refuse a rescoped MCP malware name at every version."""
        listed_name, advisory = listed
        logger.warning(
            "oidc_publish_window_rescoped_malware_name",
            package=name,
            listed_package=listed_name,
            requested=requested,
            requested_version=version,
            incident=advisory or "malware-blast-list",
        )
        cited = f", {advisory}" if advisory else ""
        return OIDCPublishWindowDecision(
            allowed=False,
            verdict=OIDCPublishWindowVerdict.DENY_RESCOPED_MALWARE_NAME,
            detail=(
                f"{name} shares the basename of {listed_name}{cited}: a listed MCP malware "
                f"package under another scope, refused at every version ({what} "
                f"{requested!r}). Put the full name on rescope_allow if it is yours"
            ),
            matched_ecosystem="npm",
            matched_package=listed_name,
            matched_version=None,
        )

    def _age_query(
        self, spec: str, name: str, embedded: str | None, versions: list[str]
    ) -> _AgeQuery | None:
        """What to look up for a registry spec's release age; None for git, path and URL specs."""
        if not _is_registry_spec(spec, embedded):
            return None
        version = embedded or (versions[0] if versions else None)
        lookups: list[tuple[str, str, str | None]] = []
        for kind in _spec_kinds(spec) or self._bare_kinds or ("npm", "pypi"):
            if kind == "npm":
                target, target_version = _version_target(name, version) if version else (name, None)
                npm_name = _normalise_name("npm", target)
                exact = _exact_npm_version(target_version) if target_version else None
                lookups.append(("npm", npm_name, exact))
            else:
                pypi_name = _PEP508_NAME_END_RE.split(spec.strip(), maxsplit=1)[0]
                exact = _exact_pypi_version(embedded) if embedded else None
                if exact is None and not embedded and version:
                    exact = _exact_pypi_version(version)
                lookups.append(("pypi", _normalise_name("pypi", pypi_name), exact))
        if not lookups or not all(found_name for _, found_name, _ in lookups):
            return None
        kind, first_name, first_version = lookups[0]
        return _AgeQuery(tuple(lookups), spec, _age_label(kind, first_name, first_version))

    def _published(self, kind: str, name: str, version: str | None) -> datetime | None:
        """The lookup's answer as an aware UTC time; None for anything it could not tell."""
        lookup = self._release_time_lookup
        if lookup is None:
            return None
        try:
            found = lookup(kind, name, version)
        except Exception as error:  # noqa: BLE001 - a lookup that fails is an unknown age
            logger.warning(
                "oidc_publish_window_release_lookup_failed",
                ecosystem=kind,
                package=name,
                version=version,
                error=type(error).__name__,
            )
            return None
        if not isinstance(found, datetime):
            return None
        if found.tzinfo is None:
            found = found.replace(tzinfo=timezone.utc)
        return found.astimezone(timezone.utc)

    def _now(self) -> datetime | None:
        now = self._clock() if self._clock is not None else datetime.now(timezone.utc)
        if not isinstance(now, datetime):
            return None
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now.astimezone(timezone.utc)

    def _release_age_decision(self, query: _AgeQuery) -> OIDCPublishWindowDecision | None:
        """Refuse a version younger than ``min_release_age``, or one whose age is unknown."""
        minimum = self._min_release_age
        if minimum is None:
            return None
        if any((kind, name) in self._release_age_allow for kind, name, _ in query.lookups):
            return None
        found = []
        for kind, name, version in query.lookups:
            published = self._published(kind, name, version)
            if published is not None:
                found.append((published, kind, name, version))
        now = self._now()
        required = _span(minimum, compact=True)
        if not found or now is None:
            if self._unknown_release_age == "allow":
                return None
            return self._deny_age_unknown(query, required, clock_failed=now is None)
        published, kind, name, version = max(found)  # the youngest release any registry has
        age = now - published
        if age >= minimum:
            return None
        label = _age_label(kind, name, version)
        stamp = published.strftime("%Y-%m-%dT%H:%M:%SZ")
        when = (
            f"{_span(age)} before this call"
            if age >= timedelta(0)
            else f"{_span(-age)} after this call's clock"
        )
        logger.warning(
            "oidc_publish_window_release_too_new",
            ecosystem=kind,
            package=name,
            version=version,
            published=stamp,
            requested=query.requested,
            min_release_age=required,
        )
        return OIDCPublishWindowDecision(
            allowed=False,
            verdict=OIDCPublishWindowVerdict.DENY_RELEASE_TOO_NEW,
            detail=f"{label} was published {stamp}, {when}; the policy requires {required}",
            matched_ecosystem=kind,
            matched_package=name,
            matched_version=version,
        )

    def _deny_age_unknown(
        self, query: _AgeQuery, required: str, *, clock_failed: bool
    ) -> OIDCPublishWindowDecision:
        kinds = " or ".join(sorted({kind for kind, _, _ in query.lookups}))
        why = (
            "the guard's clock did not return a datetime"
            if clock_failed
            else f"its publish time could not be read from the {kinds} registry"
        )
        logger.warning(
            "oidc_publish_window_release_age_unknown",
            requested=query.requested,
            reason=why,
            min_release_age=required,
        )
        kind, name, version = query.lookups[0]
        return OIDCPublishWindowDecision(
            allowed=False,
            verdict=OIDCPublishWindowVerdict.DENY_RELEASE_AGE_UNKNOWN,
            detail=(
                f"{query.label}: {why}, and the policy requires {required} and refuses a "
                "version whose age it cannot tell (unknown_release_age='deny')"
            ),
            matched_ecosystem=kind if len(query.lookups) == 1 else None,
            matched_package=name,
            matched_version=version,
        )

    def _advisory_for(self, entry: tuple[str, ...]) -> str | None:
        """The advisory id kept for an entry's ``(ecosystem, name)``, or None."""
        kind = _kind(entry[0])
        return self._advisories.get((kind, _normalise_name(kind, entry[1])))

    def _inspect_tarball_url(
        self, url: str, aging: list[_AgeQuery] | None = None
    ) -> OIDCPublishWindowDecision | None:
        """Return a deny decision if the URL targets a blast-list pair.

        The URL is read as Node's ``new URL()`` reads it: a backslash is a path separator
        and ``.`` / ``..`` segments (``%2e`` spellings included) are resolved. Its query,
        fragment, port and userinfo are set aside and its path is percent-decoded
        (``@scope%2fname``) before the tarball path is matched; the file name must then
        end in exactly ``-<version>.tgz`` for a listed version, so ``1.4.0`` does not
        match ``lib-11.4.0.tgz`` or ``lib-1.4.0-rc.1.tgz``. Until v0.10.28 any listed
        version appearing as a substring of the file name matched, which only stayed
        precise while every listed version carried a unique suffix, and a backslash or a
        dot segment hid the package from the path match.
        """
        text = url.strip()
        if text.lower().startswith(("http://", "https://")):
            text = text.replace("\\", "/")
        try:
            parts = urlsplit(text)
            host = (parts.hostname or "").rstrip(".")
        except ValueError:
            return None  # not a URL any client could fetch from the registry
        if parts.scheme.lower() not in ("http", "https") or host not in _NPM_REGISTRY_HOSTS:
            return None
        match = _NPM_TARBALL_PATH_RE.match(unquote(_normalised_path(parts.path)))
        if match is None:
            return None
        pkg = match.group("pkg")
        listed = self._index.get(("npm", _normalise_name("npm", pkg)), {})
        tail = match.group("tail").lower()
        blocked = self._blocked_entry(pkg, ("npm",))
        for entry in listed.values():
            ecosystem, name, blast_version = entry
            if not tail.endswith(f"-{blast_version.lower()}.tgz"):
                continue
            logger.warning(
                "oidc_publish_window_blast_tarball_url",
                package=name,
                version=blast_version,
                url=url,
                incident=self._advisory_for(entry) or "tanstack-oidc-blast-2026-05-11",
            )
            return OIDCPublishWindowDecision(
                allowed=False,
                verdict=OIDCPublishWindowVerdict.DENY_BLAST_LIST_TARBALL_URL,
                detail=(
                    f"tarball URL targets {name}@{blast_version}, which is on "
                    f"{self._list_name(self._advisory_for(entry))}"
                ),
                matched_ecosystem=ecosystem,
                matched_package=name,
                matched_version=blast_version,
            )
        if blocked is not None:
            return self._deny_package(blocked, url, None, "tarball URL")
        rescoped = self._rescoped_entry(pkg)
        if rescoped is not None:
            return self._deny_rescoped(pkg, rescoped, url, None, "tarball URL")
        if aging is not None and self._min_release_age is not None:
            basename = pkg.rsplit("/", 1)[-1]
            version = None
            if tail.startswith(f"{basename.lower()}-") and tail.endswith(".tgz"):
                version = _exact_npm_version(match.group("tail")[len(basename) + 1 : -4])
            npm_name = _normalise_name("npm", pkg)
            aging.append(
                _AgeQuery((("npm", npm_name, version),), url, _age_label("npm", npm_name, version))
            )
        return None

    @staticmethod
    def _shape(value: object) -> str:
        if isinstance(value, (list, tuple, set, frozenset)):
            return f"a {type(value).__name__} holding something other than text"
        if isinstance(value, (bytes, bytearray)):
            return "bytes that are not UTF-8"
        return f"a {type(value).__name__}, not text"

    @staticmethod
    def _allow(detail: str) -> OIDCPublishWindowDecision:
        return OIDCPublishWindowDecision(
            allowed=True,
            verdict=OIDCPublishWindowVerdict.ALLOW,
            detail=detail,
            matched_ecosystem=None,
            matched_package=None,
            matched_version=None,
        )

    @staticmethod
    def _list_name(advisory: str | None) -> str:
        """What a deny message calls the list: the advisory when known, else the incident."""
        if advisory:
            return f"the malware blast list ({advisory})"
        return "the tanstack-oidc-blast-2026-05-11 blast list"

    @classmethod
    def _deny_pair(
        cls, entry: tuple[str, str, str], spec: str, version: str, advisory: str | None = None
    ) -> OIDCPublishWindowDecision:
        ecosystem, name, blast_version = entry
        logger.warning(
            "oidc_publish_window_blast_pair",
            ecosystem=ecosystem,
            package=name,
            version=blast_version,
            requested_package=spec,
            requested_version=version,
            incident=advisory or "tanstack-oidc-blast-2026-05-11",
        )
        return OIDCPublishWindowDecision(
            allowed=False,
            verdict=OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR,
            detail=(
                f"package {name!r} version {blast_version!r} (requested as {spec!r} / "
                f"{version!r}) is on {cls._list_name(advisory)}"
            ),
            matched_ecosystem=ecosystem,
            matched_package=name,
            matched_version=blast_version,
        )

    def _deny_package(
        self, entry: tuple[str, str], requested: str, version: str | None, what: str
    ) -> OIDCPublishWindowDecision:
        """Refuse a package every version of which is malicious; ``matched_version`` is None."""
        ecosystem, name = entry
        advisory = self._advisory_for(entry)
        logger.warning(
            "oidc_publish_window_blocked_package",
            ecosystem=ecosystem,
            package=name,
            requested=requested,
            requested_version=version,
            incident=advisory or "malware-blast-list",
        )
        asked = f" version {version!r}" if version else " with no version"
        verdict = (
            OIDCPublishWindowVerdict.DENY_BLAST_LIST_TARBALL_URL
            if what == "tarball URL"
            else OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR
        )
        return OIDCPublishWindowDecision(
            allowed=False,
            verdict=verdict,
            detail=(
                f"{what} {requested!r} asks for {ecosystem} package {name!r}{asked}; every "
                f"version of it is on {self._list_name(advisory)}"
            ),
            matched_ecosystem=ecosystem,
            matched_package=name,
            matched_version=None,
        )

    @staticmethod
    def _deny_uninspectable(field_name: str, what: str) -> OIDCPublishWindowDecision:
        logger.warning(
            "oidc_publish_window_uninspectable",
            field=field_name,
            reason=what,
            incident="tanstack-oidc-blast-2026-05-11",
        )
        return OIDCPublishWindowDecision(
            allowed=False,
            verdict=OIDCPublishWindowVerdict.DENY_UNINSPECTABLE,
            detail=(
                f"{field_name!r} is {what}, so it cannot be checked against the blast list; "
                "refused rather than skipped"
            ),
            matched_ecosystem=None,
            matched_package=None,
            matched_version=None,
        )


__all__ = [
    "OIDCPublishWindowDecision",
    "OIDCPublishWindowGuard",
    "OIDCPublishWindowVerdict",
    "load_blast_list_from_2026_05_11",
]
