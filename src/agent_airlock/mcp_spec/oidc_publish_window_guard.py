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

The guard ships with a curated 2026-05-11 fixture
(``data/oidc_publish_blast_2026_05_11.json``) loadable via
:func:`load_blast_list_from_2026_05_11`. Operators regenerate when
new entries are confirmed (see `docs/policies/...`).

Why structural (no SDK import)
------------------------------
Pure-data preset: the blast list is a frozenset of
``(ecosystem, name, version)`` tuples, the URL detector is a
compiled regex. No ``npm`` / ``pypi`` package metadata client is
loaded.

Honest scope
------------
- The guard is a **known-bad blast-list** denier, NOT a generic OIDC
  anomaly detector. The architectural fix is in npm's per-publish-
  review feature request (see postmortem "Remediation Guidance").
- The fixture is a point-in-time snapshot. Operators must regenerate
  on new confirmed blast-list extensions; Sunday review surfaces
  this as a checklist item.

Primary sources
---------------
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

import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.oidc_publish_window_guard")


_FIXTURE_PACKAGE = "agent_airlock.data"
_FIXTURE_RESOURCE_NAME = "oidc_publish_blast_2026_05_11.json"


# Registry tarball URL — match the npm-registry CDN path. Captures the
# package name (with optional scope) and the tail of the path so the
# guard can extract the version-bearing fragment for blast-list lookup.
_NPM_REGISTRY_TARBALL_RE = re.compile(
    r"^https://registry\.npmjs\.org/(?P<pkg>(?:@[\w.-]+/)?[\w.-]+)/-/(?P<tail>[\w.-]+\.tgz)$",
    re.IGNORECASE,
)


class OIDCPublishWindowVerdict(str, enum.Enum):
    """Stable reason codes for :class:`OIDCPublishWindowDecision`."""

    ALLOW = "allow"
    DENY_BLAST_LIST_PAIR = "deny_blast_list_pair"
    DENY_BLAST_LIST_TARBALL_URL = "deny_blast_list_tarball_url"


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
    """Load the 2026-05-11 TanStack/Aikido fixture as a frozenset.

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
            if not isinstance(entry, tuple) or len(entry) != 3:
                raise TypeError(
                    f"blast_list entries must be 3-tuple (ecosystem, name, version); got {entry!r}"
                )
        self._blast_list = blast_list
        # Index by (name, version) for O(1) pair lookup, by name for URL match.
        self._by_pair: dict[tuple[str, str], str] = {
            (name, version): ecosystem for ecosystem, name, version in blast_list
        }
        self._versions_by_name: dict[str, frozenset[str]] = {}
        for ecosystem, name, version in blast_list:
            _ = ecosystem  # noqa: F841 — indexed above by ecosystem too
            self._versions_by_name.setdefault(name, frozenset())
            self._versions_by_name[name] = self._versions_by_name[name] | {version}

    def evaluate(self, args: Mapping[str, Any] | None) -> OIDCPublishWindowDecision:
        """Decide whether the call args target a blast-list entry.

        Args:
            args: The tool call's argument dict. ``None`` is allowed
                (no args to inspect).

        Returns:
            :class:`OIDCPublishWindowDecision`. Callers map
            ``allowed=False`` to a refusal at the Airlock decorator
            boundary.
        """
        if args is None:
            return OIDCPublishWindowDecision(
                allowed=True,
                verdict=OIDCPublishWindowVerdict.ALLOW,
                detail="no args to inspect",
                matched_ecosystem=None,
                matched_package=None,
                matched_version=None,
            )

        # 1) Direct package+version pair.
        package = args.get("package")
        version = args.get("version")
        if isinstance(package, str) and isinstance(version, str):
            ecosystem = self._by_pair.get((package, version))
            if ecosystem is not None:
                logger.warning(
                    "oidc_publish_window_blast_pair",
                    ecosystem=ecosystem,
                    package=package,
                    version=version,
                    incident="tanstack-oidc-blast-2026-05-11",
                )
                return OIDCPublishWindowDecision(
                    allowed=False,
                    verdict=OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR,
                    detail=(
                        f"package {package!r} version {version!r} is on the "
                        "tanstack-oidc-blast-2026-05-11 blast list"
                    ),
                    matched_ecosystem=ecosystem,
                    matched_package=package,
                    matched_version=version,
                )

        # 2) Registry tarball URL pointing at a blast-list pair.
        url = args.get("url")
        if isinstance(url, str):
            decision = self._inspect_tarball_url(url)
            if decision is not None:
                return decision

        return OIDCPublishWindowDecision(
            allowed=True,
            verdict=OIDCPublishWindowVerdict.ALLOW,
            detail="no blast-list pattern matched",
            matched_ecosystem=None,
            matched_package=None,
            matched_version=None,
        )

    def _inspect_tarball_url(self, url: str) -> OIDCPublishWindowDecision | None:
        """Return a deny decision if the URL targets a blast-list pair."""
        match = _NPM_REGISTRY_TARBALL_RE.match(url)
        if match is None:
            return None
        pkg = match.group("pkg")
        # ``versions_by_name`` is keyed on the full scoped name as it
        # appears in the blast list (e.g. ``@tanstack/react-router``).
        candidate_versions = self._versions_by_name.get(pkg)
        if not candidate_versions:
            return None
        # The tail looks like ``react-router-1.146.0-compromised-2026-05-11.tgz``
        # — we don't try to parse semver, we just check whether any
        # blast-list version for this package is a substring of the
        # tail. False positives are vanishingly rare because the
        # blast-list versions carry the ``-compromised-2026-05-11``
        # suffix.
        tail = match.group("tail")
        for blast_version in candidate_versions:
            if blast_version in tail:
                logger.warning(
                    "oidc_publish_window_blast_tarball_url",
                    package=pkg,
                    version=blast_version,
                    url=url,
                    incident="tanstack-oidc-blast-2026-05-11",
                )
                return OIDCPublishWindowDecision(
                    allowed=False,
                    verdict=OIDCPublishWindowVerdict.DENY_BLAST_LIST_TARBALL_URL,
                    detail=(
                        f"tarball URL targets {pkg}@{blast_version}, which is on the "
                        "tanstack-oidc-blast-2026-05-11 blast list"
                    ),
                    matched_ecosystem="npm",
                    matched_package=pkg,
                    matched_version=blast_version,
                )
        return None


__all__ = [
    "OIDCPublishWindowDecision",
    "OIDCPublishWindowGuard",
    "OIDCPublishWindowVerdict",
    "load_blast_list_from_2026_05_11",
]
