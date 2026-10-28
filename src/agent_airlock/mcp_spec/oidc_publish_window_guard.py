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
its Yarn alias. Arguments that are not a mapping, and a field of any other
shape, are refused (``DENY_UNINSPECTABLE``). Until v0.10.28 the guard
compared exact strings only, so each of those spellings walked past it, and
a top-level list raised ``AttributeError``.

Honest scope
------------
- The guard is a **known-bad blast-list** denier, NOT a generic OIDC
  anomaly detector. The architectural fix is in npm's per-publish-
  review feature request (see postmortem "Remediation Guidance").
- It matches exact releases only. A range (``^1.146.0``, ``>=2.6.2``)
  that could resolve to a listed release is not resolved here.
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
  per Aikido) is not in the list; pass those pairs as a caller-supplied
  ``blast_list`` from their own advisories.

Primary sources
---------------
- GHSA-g7cv-rxg3-hmpx (CVE-2026-45321), the affected-version table:
  https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- TanStack postmortem (2026-05-11):
  https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Aikido — Mini Shai-Hulud Is Back (2026-05-11, cross-ecosystem):
  https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
"""

from __future__ import annotations

import enum
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Any
from urllib.parse import unquote, urlsplit

from .._log import structlog

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


class OIDCPublishWindowVerdict(str, enum.Enum):
    """Stable reason codes for :class:`OIDCPublishWindowDecision`."""

    ALLOW = "allow"
    DENY_BLAST_LIST_PAIR = "deny_blast_list_pair"
    DENY_BLAST_LIST_TARBALL_URL = "deny_blast_list_tarball_url"
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

    Raises:
        TypeError: ``blast_list`` is not a frozenset, or any entry is
            not a 3-tuple of strings.
    """

    def __init__(
        self,
        *,
        blast_list: frozenset[tuple[str, str, str]] = frozenset(),
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
        for spec in packages:
            name, embedded = _split_spec(spec)
            candidates = ([embedded] if embedded else []) + versions
            for version in candidates:
                entry = self._lookup(name, version)
                if entry is not None:
                    return self._deny_pair(entry, spec, version)

        # 2) Registry tarball URL pointing at a blast-list pair.
        urls = _texts(args.get("url"))
        if urls is None:
            return self._deny_uninspectable("url", self._shape(args.get("url")))
        for url in urls:
            decision = self._inspect_tarball_url(url)
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

    def _inspect_tarball_url(self, url: str) -> OIDCPublishWindowDecision | None:
        """Return a deny decision if the URL targets a blast-list pair.

        The URL's query, fragment, port and userinfo are set aside and its path is
        percent-decoded (``@scope%2fname``) before the tarball path is matched; the
        file name must then end in exactly ``-<version>.tgz`` for a listed version, so
        ``1.4.0`` does not match ``lib-11.4.0.tgz`` or ``lib-1.4.0-rc.1.tgz``. Until
        v0.10.28 any listed version appearing as a substring of the file name matched,
        which only stayed precise while every listed version carried a unique suffix.
        """
        try:
            parts = urlsplit(url.strip())
            host = (parts.hostname or "").rstrip(".")
        except ValueError:
            return None  # not a URL any client could fetch from the registry
        if parts.scheme.lower() not in ("http", "https") or host not in _NPM_REGISTRY_HOSTS:
            return None
        match = _NPM_TARBALL_PATH_RE.match(unquote(parts.path))
        if match is None:
            return None
        pkg = match.group("pkg")
        listed = self._index.get(("npm", _normalise_name("npm", pkg)), {})
        tail = match.group("tail").lower()
        for entry in listed.values():
            ecosystem, name, blast_version = entry
            if not tail.endswith(f"-{blast_version.lower()}.tgz"):
                continue
            logger.warning(
                "oidc_publish_window_blast_tarball_url",
                package=name,
                version=blast_version,
                url=url,
                incident="tanstack-oidc-blast-2026-05-11",
            )
            return OIDCPublishWindowDecision(
                allowed=False,
                verdict=OIDCPublishWindowVerdict.DENY_BLAST_LIST_TARBALL_URL,
                detail=(
                    f"tarball URL targets {name}@{blast_version}, which is on the "
                    "tanstack-oidc-blast-2026-05-11 blast list"
                ),
                matched_ecosystem=ecosystem,
                matched_package=name,
                matched_version=blast_version,
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
    def _deny_pair(
        entry: tuple[str, str, str], spec: str, version: str
    ) -> OIDCPublishWindowDecision:
        ecosystem, name, blast_version = entry
        logger.warning(
            "oidc_publish_window_blast_pair",
            ecosystem=ecosystem,
            package=name,
            version=blast_version,
            requested_package=spec,
            requested_version=version,
            incident="tanstack-oidc-blast-2026-05-11",
        )
        return OIDCPublishWindowDecision(
            allowed=False,
            verdict=OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR,
            detail=(
                f"package {name!r} version {blast_version!r} (requested as {spec!r} / "
                f"{version!r}) is on the tanstack-oidc-blast-2026-05-11 blast list"
            ),
            matched_ecosystem=ecosystem,
            matched_package=name,
            matched_version=blast_version,
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
