"""Derive the G0, G and LP policy tiers for one server from its clean side alone.

:func:`derive` takes a :class:`~.clean.CleanServer`, which holds no poisoned tool, attack
query or recorded outcome, and returns plain data (:class:`TierPolicy`). It builds no
``agent_airlock`` object: a ``FilesystemPolicy`` resolves its roots against the working
directory and the host's symlinks, so :mod:`.stubs` builds those after the replay has
moved into its scratch directory. ``derive`` itself is pure.

Tiers:

* **G0** - the call contract only: ghost arguments refused (``UnknownArgsMode.BLOCK``) and
  required arguments enforced. No tool allowlist.
* **G** - G0 plus ``SecurityPolicy(allowed_tools=<the clean prompt's Tool: names>,
  default_deny=True)``. The poisoned tool is not on the list, so a call to it is refused by
  construction.
* **LP** - G plus per-tool scopes from :mod:`.lp_labels`, for the servers that have clean
  queries. A tool labelled ``fs`` gets a ``FilesystemPolicy`` whose roots come from the
  paths in the server's clean queries; ``url_allowlist`` gets an ``EndpointPolicy`` listing
  the hosts in those queries plus the label's extra hosts; ``url_open_web`` gets
  ``EndpointPolicy()`` (private, loopback, link-local and metadata targets refused) and an
  ``SSRFEgressGuard`` pre-check that decodes literal-IP encodings without DNS. A server with
  no clean queries gets G, and the fallback is reported.

Root derivation, from absolute and ``~/`` paths only (a relative name in a sentence says
nothing about where it lives): a file grants its parent directory when it sits at least
two levels below ``/`` (or ``~``), else only itself; a directory grants itself; ``/`` and
``~`` are never granted. A path is a file when its last component has an extension.
Deny patterns are ``RESTRICTIVE_FILESYSTEM_POLICY``'s minus its system-directory globs
(``/etc/**`` and friends, which the roots already exclude and which macOS's ``/private``
symlinks would make host-dependent) and minus any pattern that a clean-query path
matches; every removal is recorded.

When a labelled scope cannot be derived (an ``fs`` tool on a server whose clean queries
name no absolute path, an allowlisted tool with no host), the tool gets no scope, i.e. G,
and the fallback is recorded. It never gets an empty ``allowed_roots`` or
``allowed_endpoints``, which ``agent_airlock`` reads as "no restriction", and it never gets
a deny-all scope either: that would make a tool with a required path argument unusable
and credit LP with refusals that no clean usage justifies.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from agent_airlock.filesystem import RESTRICTIVE_FILESYSTEM_POLICY

from .clean import CleanServer
from .lp_labels import FS, LABELS, URL_ALLOWLIST, URL_OPEN_WEB, ToolLabel


class Tier(str, Enum):
    """The three policy tiers, weakest first."""

    G0 = "G0"
    G = "G"
    LP = "LP"


SYSTEM_DIR_GLOBS = ("/etc/**", "/proc/**", "/sys/**", "/dev/**")
"""Removed from the LP deny list: the roots already exclude these directories."""

GLOB_METACHARACTERS = frozenset("*?[")
"""``SecurityPolicy`` matches tool names with ``fnmatch``; a name holding one of these
would widen the allowlist, so no such name is ever listed or replayed."""

# An absolute or home-relative path, starting at a word boundary the way a path starts in
# prose: after whitespace, a quote, a bracket, a comma or ``=``.
_PATH_RE = re.compile(r"(?:^|(?<=[\s'\"`(\[{,=]))(~?/[^\s'\"`,;)\]}<>|]*)")
_URL_RE = re.compile(r"https?://[^\s'\"`<>()\[\]{},|]+", re.IGNORECASE)
_TRAILING = ".,;:!?"


@dataclass(frozen=True)
class PathEvidence:
    """A path found in a clean query, with the index of the query it came from."""

    path: str
    query_index: int


@dataclass(frozen=True)
class FsRoots:
    """Roots granted from the clean queries, and candidates that were never granted."""

    roots: tuple[str, ...]
    refused: tuple[str, ...] = ()
    evidence: tuple[PathEvidence, ...] = ()


@dataclass(frozen=True)
class FsScope:
    """What :mod:`.stubs` turns into one tool's ``FilesystemPolicy``.

    Attributes:
        roots: Normalised POSIX root strings (never empty); one starting with ``~`` is
            granted in both its literal and its ``expanduser`` form (see :mod:`.stubs`).
        deny_patterns: Glob patterns refused inside the roots.
        max_path_depth: ``RESTRICTIVE_FILESYSTEM_POLICY``'s depth cap.
        allow_symlinks: ``RESTRICTIVE_FILESYSTEM_POLICY``'s symlink setting.
    """

    roots: tuple[str, ...]
    deny_patterns: tuple[str, ...]
    max_path_depth: int
    allow_symlinks: bool


@dataclass(frozen=True)
class EndpointScope:
    """What :mod:`.stubs` turns into one tool's ``EndpointPolicy`` (and SSRF pre-check).

    Attributes:
        kind: ``"allowlist"`` (``hosts`` is never empty) or ``"open_web"``.
        hosts: Allowed hostnames for an allowlist.
        ssrf_precheck: Run an ``SSRFEgressGuard`` over the arguments before the call.
    """

    kind: str
    hosts: tuple[str, ...] = ()
    ssrf_precheck: bool = False


@dataclass(frozen=True)
class ToolScope:
    """One tool's LP scopes (either may be absent)."""

    fs: FsScope | None = None
    endpoint: EndpointScope | None = None


@dataclass(frozen=True)
class TierPolicy:
    """The policy one tier applies to one server.

    Attributes:
        server_key: The server it is for.
        tier: The tier asked for.
        effective: The tier applied (``G`` for an LP request on a server without clean
            queries).
        allowed_tools: The allowlist, or ``None`` under G0.
        scopes: Per-tool LP scopes (empty below LP).
        notes: Fallbacks and deny-pattern removals, citing clean queries by index only.
    """

    server_key: str
    tier: Tier
    effective: Tier
    allowed_tools: tuple[str, ...] | None
    scopes: Mapping[str, ToolScope] = field(default_factory=dict)
    notes: tuple[str, ...] = ()


def _strip_trailing(text: str) -> str:
    while text and text[-1] in _TRAILING:
        text = text[:-1]
    return text


def extract_paths(queries: Iterable[str]) -> list[PathEvidence]:
    """Absolute and ``~/`` paths in the queries, trailing punctuation removed."""
    out: list[PathEvidence] = []
    for index, query in enumerate(queries):
        for match in _PATH_RE.finditer(query):
            path = _strip_trailing(match.group(1))
            if path in {"", "~"}:
                continue
            out.append(PathEvidence(path=posixpath.normpath(path), query_index=index))
    return out


def _depth(path: str) -> int:
    """Components below ``/`` (or below ``~`` for a home-relative path)."""
    parts = PurePosixPath(path).parts
    return len(parts) - 1 if parts and parts[0] in {"/", "~"} else len(parts)


def _is_file(path: str) -> bool:
    name = PurePosixPath(path).name
    stem, dot, ext = name.rpartition(".")
    return bool(dot) and bool(stem) and bool(ext)


def root_for(path: str) -> str:
    """The root one clean-query path grants (before the ``/`` / ``~`` refusal)."""
    if _is_file(path) and _depth(path) >= 2:
        return posixpath.dirname(path)
    return path


def derive_fs_roots(queries: Iterable[str]) -> FsRoots:
    """Roots from the clean queries' paths; ``/`` and ``~`` are refused, never granted."""
    evidence = extract_paths(queries)
    granted: list[str] = []
    refused: list[str] = []
    for item in evidence:
        root = root_for(item.path)
        bucket = refused if root in {"/", "~"} else granted
        if root not in bucket:
            bucket.append(root)
    # A root inside another granted root adds nothing.
    minimal = [r for r in granted if not any(r != o and _within(r, o) for o in granted)]
    return FsRoots(roots=tuple(sorted(minimal)), refused=tuple(refused), evidence=tuple(evidence))


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def derive_deny_patterns(
    evidence: Iterable[PathEvidence],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(kept patterns, removal notes)`` for one server's LP filesystem scope."""
    from agent_airlock.filesystem import _matches_deny_pattern  # same matching as the gate

    items = list(evidence)
    kept: list[str] = []
    notes: list[str] = []
    for pattern in RESTRICTIVE_FILESYSTEM_POLICY.deny_patterns:
        if pattern in SYSTEM_DIR_GLOBS:
            notes.append(f"deny pattern {pattern!r} removed: system-directory glob")
            continue
        hit = next(
            (e for e in items if _matches_deny_pattern(PurePosixPath(e.path), [pattern])), None
        )
        if hit is not None:
            notes.append(
                f"deny pattern {pattern!r} removed: matches the path in "
                f"clean_querys[{hit.query_index}]"
            )
            continue
        kept.append(pattern)
    return tuple(kept), tuple(notes)


def extract_hosts(queries: Iterable[str]) -> list[tuple[str, int]]:
    """``(hostname, query index)`` for every http(s) URL in the queries."""
    out: list[tuple[str, int]] = []
    for index, query in enumerate(queries):
        for match in _URL_RE.finditer(query):
            url = _strip_trailing(match.group(0))
            try:
                host = urlsplit(url).hostname
            except ValueError:
                continue
            if host:
                out.append((host.lower(), index))
    return out


def derive_hosts(queries: Iterable[str]) -> tuple[str, ...]:
    """Distinct hostnames of the clean queries' URLs, sorted."""
    return tuple(sorted({host for host, _ in extract_hosts(queries)}))


def _fs_scope(roots: FsRoots, deny: tuple[str, ...]) -> FsScope | None:
    if not roots.roots or roots.refused:
        return None
    return FsScope(
        roots=roots.roots,
        deny_patterns=deny,
        max_path_depth=RESTRICTIVE_FILESYSTEM_POLICY.max_path_depth,
        allow_symlinks=RESTRICTIVE_FILESYSTEM_POLICY.allow_symlinks,
    )


def _endpoint_scope(label: ToolLabel, hosts: tuple[str, ...]) -> EndpointScope | None:
    if URL_ALLOWLIST in label.scopes:
        granted = tuple(sorted(set(hosts) | {h.lower() for h in label.extra_hosts}))
        return EndpointScope(kind="allowlist", hosts=granted) if granted else None
    if URL_OPEN_WEB in label.scopes:
        return EndpointScope(kind="open_web", ssrf_precheck=True)
    return None


def _lp_scopes(server: CleanServer) -> tuple[dict[str, ToolScope], list[str]]:
    labels = LABELS.get(server.key)
    if labels is None:
        raise KeyError(f"no LP labels for server {server.key!r}, which has clean queries")
    unknown = sorted(set(labels) - set(server.tool_names))
    missing = sorted(set(server.tool_names) - set(labels))
    if unknown or missing:
        raise ValueError(
            f"LP labels for {server.key!r} do not match its tool blocks "
            f"(unknown {unknown}, missing {missing})"
        )
    roots = derive_fs_roots(server.clean_queries)
    hosts = derive_hosts(server.clean_queries)
    notes: list[str] = []
    wants_fs = any(FS in label.scopes for label in labels.values())
    fs_scope = None
    if wants_fs:
        deny, removals = derive_deny_patterns(roots.evidence)
        fs_scope = _fs_scope(roots, deny)
        if fs_scope is not None:
            notes.extend(removals)
    if wants_fs and roots.refused:
        notes.append(
            f"{len(roots.refused)} candidate root(s) would grant '/' or '~'; the server's "
            "fs-labelled tools fall back to G"
        )
    scopes: dict[str, ToolScope] = {}
    for tool_name in server.tool_names:
        label = labels[tool_name]
        fs = fs_scope if FS in label.scopes else None
        endpoint = _endpoint_scope(label, hosts)
        if FS in label.scopes and fs is None and not roots.refused:
            notes.append(f"{tool_name}: fs label, no clean-query root; falls back to G")
        if URL_ALLOWLIST in label.scopes and endpoint is None:
            notes.append(f"{tool_name}: allowlist label, no host; falls back to G")
        if fs is not None or endpoint is not None:
            scopes[tool_name] = ToolScope(fs=fs, endpoint=endpoint)
    return scopes, notes


def derive(server: CleanServer, tier: Tier | str) -> TierPolicy:
    """The policy ``tier`` applies to ``server``, from the server's clean side alone.

    Raises:
        KeyError: An LP request for a server with clean queries but no labels.
        ValueError: A tool name carries a glob metacharacter, or the labels do not match
            the server's tool blocks.
    """
    tier = Tier(tier)
    bad = [n for n in server.tool_names if GLOB_METACHARACTERS & set(n)]
    if bad:
        raise ValueError(f"{server.key}: tool names with glob metacharacters {bad}")
    if tier is Tier.G0:
        return TierPolicy(server.key, tier, Tier.G0, allowed_tools=None)
    allowed = server.tool_names
    if tier is Tier.G:
        return TierPolicy(server.key, tier, Tier.G, allowed_tools=allowed)
    if not server.has_clean_queries:
        return TierPolicy(
            server.key,
            tier,
            Tier.G,
            allowed_tools=allowed,
            notes=("no clean queries: LP falls back to G",),
        )
    scopes, notes = _lp_scopes(server)
    return TierPolicy(
        server.key, tier, Tier.LP, allowed_tools=allowed, scopes=scopes, notes=tuple(notes)
    )
