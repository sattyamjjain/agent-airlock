"""Zero-click MCP config-file diff guard (v0.5.7+, CVE-2026-30615 class).

Motivation
----------
[CVE-2026-30615](https://nvd.nist.gov/vuln/detail/CVE-2026-30615) — the
Windsurf zero-click — disclosed that an attacker-controlled HTML page
could rewrite the IDE's ``.windsurf/mcp.json`` from prompt injection
alone, after which the IDE auto-launched the new STDIO server. Patched
in Windsurf's latest release; the **class** generalises to any IDE that
auto-reads project-local MCP config (VS Code, Cursor, Claude Code,
JetBrains, etc.).

This module provides a synchronous "diff-on-demand" check: callers
pass in the previous SHA-256 (which they stored from the last clean
audit) plus the current file bytes, and get back a structured
``ConfigDiffReport``. New STDIO server entries that lack a trusted
signer raise :class:`UnsignedMCPServerAdded`; an existing entry whose
``command``, ``args``, ``env`` key set or ``url`` changed raises
:class:`MCPCommandMutationDetected`; and a config the guard cannot read
as strict JSON (JSONC comments, a trailing comma, a repeated key, a
doubled BOM) raises :class:`MCPConfigUnreadable` instead of reading as a
config with no servers (v0.10.28).

This is **not** a kernel watcher. The v0.5.8 roadmap covers the
long-running daemon variant; for v0.5.7 we ship the synchronous API
that IDE-host integrators can call before each tool invocation.

Primary sources
---------------
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-30615
- Tenable: https://www.tenable.com/cve/CVE-2026-30615
- VS Code 1.112 sandboxing context: https://code.visualstudio.com/updates/v1_112
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.zero_click_config_guard")


# Default IDE config locations the guard knows about. Paths use
# ``~`` placeholder; callers can pass already-expanded paths or
# extend this list.
DEFAULT_WATCHED_PATHS: tuple[Path, ...] = (
    Path(".vscode/mcp.json"),
    Path(".cursor/mcp.json"),
    Path(".windsurf/mcp.json"),
    Path(".claude/mcp.json"),
    Path("~/.config/claude-code/mcp.json"),
    Path("~/.cursor/mcp.json"),
    Path("~/.config/Code/User/mcp.json"),
    Path("~/.windsurf/mcp.json"),
)


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class UnsignedMCPServerAdded(AirlockError):
    """A new ``mcpServers`` entry appeared in the diff with no trusted signer.

    Attributes:
        path: The config file the diff was taken on.
        server_name: The name of the offending entry.
        signer: The signer field on the entry, or empty when missing.
    """

    def __init__(
        self,
        *,
        path: Path,
        server_name: str,
        signer: str = "",
    ) -> None:
        self.path = path
        self.server_name = server_name
        self.signer = signer
        super().__init__(
            f"new MCP server entry {server_name!r} added to {path} "
            f"without trusted signer (signer={signer!r}) — refusing "
            "(CVE-2026-30615 zero-click class)"
        )


class MCPCommandMutationDetected(AirlockError):
    """An existing ``mcpServers`` entry's spawn identity changed.

    The advisory pattern: an attacker doesn't add a new entry — they
    flip the argv on an existing one to point to a malicious binary.
    Since v0.10.28 the identity is what :class:`McpConfigPinSet`
    fingerprints — ``command``, ``args`` and the ``env`` key set — plus a
    remote entry's ``url``; until then only ``command`` was compared, so
    swapping ``args`` or adding ``LD_PRELOAD`` to ``env`` passed.

    Attributes:
        path: The config file the diff was taken on.
        server_name: The name of the mutated entry.
        fields: The identity fields that changed.
    """

    def __init__(
        self,
        *,
        path: Path,
        server_name: str,
        fields: tuple[str, ...] = ("command",),
    ) -> None:
        self.path = path
        self.server_name = server_name
        self.fields = fields
        super().__init__(
            f"existing MCP server entry {server_name!r} in {path} had its "
            f"{', '.join(fields)} mutated — refusing (CVE-2026-30615 class)"
        )


class MCPConfigUnreadable(AirlockError):
    """A config (or its trusted baseline) could not be read, so it cannot be diffed.

    Raised instead of reading the config as one with no servers: until v0.10.28 a
    JSONC comment or trailing comma, a duplicated key, a doubled BOM or an
    ``mcpServers`` that was not an object all diffed as "no servers", so the new
    entry they carried was never checked. IDE hosts parse ``mcp.json`` more
    leniently than :func:`json.loads`, and a duplicated key is read first-wins by
    some parsers and last-wins by others, so a config the guard cannot read
    exactly is refused rather than guessed at.

    Attributes:
        path: The config file the diff was taken on.
        which: ``"new"`` (the current content) or ``"old"`` (the trusted baseline).
        reason: What could not be read.
    """

    def __init__(self, *, path: Path, which: str, reason: str) -> None:
        self.path = path
        self.which = which
        self.reason = reason
        super().__init__(
            f"{which} MCP config {path} cannot be read ({reason}) — refusing rather "
            "than diffing it as a config with no servers (CVE-2026-30615 class)"
        )


# -----------------------------------------------------------------------------
# Config policy
# -----------------------------------------------------------------------------


@dataclass
class ConfigFileWatchPolicy:
    """Policy applied by :func:`audit_config_diff`.

    Attributes:
        watched_paths: Filesystem locations the guard recognises. The
            default seed covers eight known IDE-host locations
            (Cursor, VS Code, Claude Code, Windsurf, project-local).
        require_signer_for_new_servers: If True, every new
            ``mcpServers`` entry must carry a ``signer`` field whose
            value is in ``signer_allowlist``.
        quarantine_on_diff: Reserved — when True, the v0.5.8 watcher
            will copy the offending file into ``~/.airlock/quarantine/``
            instead of letting the IDE auto-load it. The v0.5.7
            synchronous API only logs intent.
        signer_allowlist: Trusted signer identifiers. Empty means "any
            non-empty signer is acceptable" — a deliberate choice so
            integrators can adopt the guard in stages.
    """

    watched_paths: tuple[Path, ...] = field(default_factory=lambda: DEFAULT_WATCHED_PATHS)
    require_signer_for_new_servers: bool = True
    quarantine_on_diff: bool = True
    signer_allowlist: frozenset[str] = field(default_factory=frozenset)


# -----------------------------------------------------------------------------
# ConfigDiffReport
# -----------------------------------------------------------------------------


@dataclass
class ConfigDiffReport:
    """Structured outcome of a ``audit_config_diff`` call."""

    path: Path
    old_sha256: str | None
    new_sha256: str
    added_servers: tuple[str, ...]
    mutated_command_servers: tuple[str, ...]
    quarantined: bool = False


# -----------------------------------------------------------------------------
# Diff machinery
# -----------------------------------------------------------------------------


#: Where a host keeps its server map: Claude Code, Cursor and Windsurf use
#: ``mcpServers``; VS Code's ``mcp.json`` uses ``servers`` (read since v0.10.28 —
#: until then a VS Code config always diffed as one with no servers).
_SERVER_MAP_KEYS: tuple[str, ...] = ("mcpServers", "servers")

#: What an existing entry is compared on: the fields :class:`McpConfigPinSet`
#: fingerprints (``command``, ``args``, the ``env`` key set) plus a remote
#: entry's ``url``. Env *values* rotate legitimately and are not compared.
_IDENTITY_FIELDS: tuple[str, ...] = ("command", "args", "env", "url")


class _UnreadableConfig(ValueError):
    """Internal: why a config blob could not be read (surfaced as MCPConfigUnreadable)."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook``: a key twice in one object is read differently by different
    parsers (first wins in some, last in others), so it is refused rather than guessed."""
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _UnreadableConfig(f"key {key!r} appears twice in one object")
        out[key] = value
    return out


def _as_bytes(content: object) -> bytes:
    """The config blob as bytes; a ``str`` is encoded, any other type is unreadable."""
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, (bytes, bytearray, memoryview)):
        return bytes(content)
    raise _UnreadableConfig(f"content is a {type(content).__name__}, not bytes")


def _parse_servers(content: bytes) -> dict[str, Any]:
    """Extract the server map (``mcpServers`` and ``servers``) from a config blob.

    A config with neither key has no servers. Anything that is not strict JSON (a JSONC
    comment or trailing comma, a doubled BOM, bytes that are not UTF-8, nesting deeper
    than the parser can follow), a key that appears twice in one object, a top level
    that is not an object, a server map that is not an object and a server name under
    both keys raise :class:`_UnreadableConfig`. Until v0.10.28 every one of them read as
    ``{}``, so the entries they carried were never checked.
    """
    try:
        data = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except _UnreadableConfig:
        raise
    except (ValueError, RecursionError) as exc:  # JSONDecodeError, UnicodeDecodeError
        raise _UnreadableConfig(f"not strict JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise _UnreadableConfig(f"the top level is a {type(data).__name__}, not an object")
    servers: dict[str, Any] = {}
    for key in _SERVER_MAP_KEYS:
        if key not in data:
            continue
        block = data[key]
        if not isinstance(block, dict):
            raise _UnreadableConfig(f"{key!r} is a {type(block).__name__}, not an object")
        for name, entry in block.items():
            if name in servers:
                raise _UnreadableConfig(f"server {name!r} is named under more than one key")
            servers[name] = entry
    return servers


def _server_signer(entry: Mapping[str, Any]) -> str:
    """Best-effort signer extraction. Empty when missing / non-string."""
    signer = entry.get("signer", "")
    return signer if isinstance(signer, str) else ""


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _entry_identity(entry: object) -> dict[str, str] | None:
    """The comparable identity of one server entry, or ``None`` when it cannot be read.

    ``env`` is read the way :class:`McpConfigPinSet` reads it (a mapping, or a sequence
    of ``KEY=VALUE`` strings); an entry that is not an object, or whose ``env`` is any
    other shape, cannot be compared and is refused by the caller.
    """
    if not isinstance(entry, Mapping):
        return None
    env_keys = _env_keys_of(entry)
    if env_keys is None:
        return None
    return {
        "command": _canonical(entry.get("command")),
        "args": _canonical(entry.get("args")),
        "env": _canonical(sorted(set(env_keys))),
        "url": _canonical(entry.get("url")),
    }


def audit_config_diff(
    path: Path,
    old_sha256: str | None,
    new_content: bytes,
    cfg: ConfigFileWatchPolicy,
    *,
    old_content: bytes | None = None,
) -> ConfigDiffReport:
    """Audit a config-file diff against the policy.

    The server map is read from ``mcpServers`` and from VS Code's ``servers`` key, as
    strict JSON. A config that cannot be read exactly is refused
    (:class:`MCPConfigUnreadable`) rather than read as one with no servers.

    Args:
        path: The config file's path on disk (used for error messages
            and reports; not re-read).
        old_sha256: SHA-256 of the previously-trusted state, or
            ``None`` if this is the first audit.
        new_content: The current file's bytes (a ``str`` is encoded as UTF-8).
        cfg: Active :class:`ConfigFileWatchPolicy`.
        old_content: Optional — when supplied, the diff also detects
            mutated existing server entries: a changed ``command``,
            ``args``, ``env`` key set or ``url``. Without it, the guard
            can only flag *new* entries.

    Returns:
        :class:`ConfigDiffReport` summarising what changed.

    Raises:
        MCPConfigUnreadable: ``new_content`` or ``old_content`` is not strict
            JSON, repeats a key within one object, or has a server map or an
            existing entry the diff cannot read.
        UnsignedMCPServerAdded: A new entry has no trusted signer and
            ``cfg.require_signer_for_new_servers`` is True.
        MCPCommandMutationDetected: An existing entry's ``command``,
            ``args``, ``env`` key set or ``url`` changed and ``old_content``
            was supplied.
    """
    try:
        new_bytes = _as_bytes(new_content)
        new_servers = _parse_servers(new_bytes)
    except _UnreadableConfig as exc:
        raise MCPConfigUnreadable(path=path, which="new", reason=str(exc)) from exc
    new_sha = hashlib.sha256(new_bytes).hexdigest()
    old_servers: dict[str, Any] = {}
    if old_content is not None:
        try:
            old_servers = _parse_servers(_as_bytes(old_content))
        except _UnreadableConfig as exc:
            raise MCPConfigUnreadable(path=path, which="old", reason=str(exc)) from exc

    added: list[str] = []
    for name, entry in new_servers.items():
        if name in old_servers:
            continue
        added.append(name)
        if not cfg.require_signer_for_new_servers:
            continue
        if not isinstance(entry, Mapping):
            raise UnsignedMCPServerAdded(path=path, server_name=name, signer="")
        signer = _server_signer(entry)
        if not signer:
            raise UnsignedMCPServerAdded(path=path, server_name=name, signer="")
        if cfg.signer_allowlist and signer not in cfg.signer_allowlist:
            raise UnsignedMCPServerAdded(path=path, server_name=name, signer=signer)

    mutated: list[str] = []
    for name, entry in new_servers.items():
        if name not in old_servers:
            continue
        new_identity = _entry_identity(entry)
        if new_identity is None:
            # Until v0.10.28 an entry that was not an object was skipped here.
            raise MCPConfigUnreadable(
                path=path,
                which="new",
                reason=(
                    f"server {name!r} is not an object with an env mapping or "
                    "KEY=VALUE list, so it cannot be compared with the trusted entry"
                ),
            )
        old_identity = _entry_identity(old_servers[name])
        changed = tuple(
            f
            for f in _IDENTITY_FIELDS
            if old_identity is None or old_identity[f] != new_identity[f]
        )
        if changed:
            mutated.append(name)
            raise MCPCommandMutationDetected(path=path, server_name=name, fields=changed)

    _emit_otel_span(path=path, old_sha256=old_sha256 or "<none>", new_sha256=new_sha)
    logger.debug(
        "config_diff_audited",
        path=str(path),
        added=added,
        mutated=mutated,
    )
    return ConfigDiffReport(
        path=path,
        old_sha256=old_sha256,
        new_sha256=new_sha,
        added_servers=tuple(added),
        mutated_command_servers=tuple(mutated),
        quarantined=False,
    )


def _emit_otel_span(*, path: Path, old_sha256: str, new_sha256: str) -> None:
    """Best-effort emit of the ``airlock.config.diff.audit`` span."""
    with contextlib.suppress(Exception):  # pragma: no cover
        from ..observability import end_span, start_span

        ctx = start_span("airlock.config.diff.audit", str(path))
        ctx.set_attribute("airlock.config.old_sha256", old_sha256)
        ctx.set_attribute("airlock.config.new_sha256", new_sha256)
        end_span(ctx)


# -----------------------------------------------------------------------------
# Spawn-time config pin (v0.8.23+, CVE-2026-30615 zero-click class)
# -----------------------------------------------------------------------------
#
# :func:`audit_config_diff` above is the *config-file* defence: it diffs the
# bytes of an ``mcp.json`` between two reads and refuses unsigned new entries
# / mutated command arrays. That guards the write path. The pin below is the
# complementary *spawn-time* defence: at the moment an MCP client is about to
# spawn a STDIO server, it fingerprints the **resolved** spawn config and
# refuses anything that does not match an operator-pinned known-good
# fingerprint — fail-closed (raises, never warns). This catches the
# zero-click pattern even when the mutation never touched a watched file
# (e.g. the host resolved the config from memory, an env override, or a
# launcher), which is exactly the gap a config-file diff cannot see.
#
# The fingerprint covers ``{name, command, args, env-keys}``. Env *values*
# are deliberately excluded — they legitimately rotate (tokens, secrets) and
# pinning them would force a re-pin on every rotation; the *keys* are what an
# injection adds (e.g. a new ``LD_PRELOAD``), so the key set is pinned.


class McpConfigPinViolation(AirlockError):
    """A STDIO MCP server spawn config does not match its pinned fingerprint.

    Raised **fail-closed** (never warned) by :meth:`McpConfigPinSet.check`
    for the CVE-2026-30615 zero-click class — either the server name is not
    in the pin set at all (an injected entry), a previously-pinned server's
    ``command`` / ``args`` / ``env``-keys changed between registration and
    spawn (a mutated entry), or the spawn config's ``env`` / ``args`` has a
    shape the pin cannot read (v0.10.24).

    Attributes:
        server_name: The offending STDIO server name.
        reason: ``"unpinned"`` (not in the pin set), ``"mutated"``
            (fingerprint mismatch) or ``"unreadable"`` (an ``env`` /
            ``args`` shape the pin cannot read).
        expected_fingerprint: The pinned fingerprint, or ``None`` when
            the server was unpinned.
        actual_fingerprint: The fingerprint of the resolved spawn config,
            or ``""`` when it could not be read.
        detail: What could not be read, for an ``"unreadable"`` refusal.
    """

    def __init__(
        self,
        *,
        server_name: str,
        reason: str,
        expected_fingerprint: str | None,
        actual_fingerprint: str,
        detail: str = "",
    ) -> None:
        self.server_name = server_name
        self.reason = reason
        self.expected_fingerprint = expected_fingerprint
        self.actual_fingerprint = actual_fingerprint
        self.detail = detail
        if reason == "unpinned":
            msg = (
                f"STDIO MCP server {server_name!r} is not in the config pin set — "
                f"refusing to spawn an unpinned server (CVE-2026-30615 zero-click "
                f"class); fingerprint={actual_fingerprint}"
            )
        elif reason == "unreadable":
            msg = (
                f"STDIO MCP server {server_name!r} spawn config cannot be read ({detail}) — "
                f"refusing rather than comparing a pin to a config it could not see "
                f"(CVE-2026-30615 class)"
            )
        else:
            msg = (
                f"STDIO MCP server {server_name!r} spawn config does not match its "
                f"pinned fingerprint — refusing (CVE-2026-30615 mutation class); "
                f"expected={expected_fingerprint} actual={actual_fingerprint}"
            )
        super().__init__(msg)


@dataclass(frozen=True)
class McpServerPin:
    """A pinned known-good STDIO MCP server fingerprint.

    Attributes:
        name: The MCP server name (the join key).
        fingerprint: SHA-256 hex of the canonical
            ``{name, command, args, env-keys}`` payload.
    """

    name: str
    fingerprint: str


def fingerprint_mcp_server(
    *,
    name: str,
    command: str,
    args: Iterable[str] = (),
    env_keys: Iterable[str] = (),
) -> str:
    """Compute the canonical fingerprint of a STDIO MCP server spawn config.

    The payload is order-stable: ``args`` order is significant (it's the
    argv), ``env_keys`` are sorted (a mapping has no order), and the JSON is
    emitted with sorted keys + tight separators so the hash is reproducible
    across processes.

    Args:
        name: The MCP server name.
        command: The program/launcher (e.g. ``"uvx"``).
        args: The argument vector (order significant).
        env_keys: The environment variable **names** the server is allowed
            to receive (values are intentionally not pinned).

    Returns:
        SHA-256 hex digest string.
    """
    payload = json.dumps(
        {
            "name": name,
            "command": command,
            "args": list(args),
            "env_keys": sorted(env_keys),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _env_keys_of(entry: Mapping[str, Any]) -> list[str] | None:
    """Resolve env-key names from a config entry, or ``None`` when they cannot be read.

    ``env`` is read as a mapping (its keys) or a sequence of ``KEY=VALUE`` / ``KEY``
    strings (the part before ``=``); ``env_keys``, when ``env`` is absent, as a sequence
    of key strings. Until v0.10.24 an ``env`` that was not a mapping resolved to *no*
    keys, so a pin with no env admitted ``{"env": ["LD_PRELOAD=/tmp/x.so"]}``. Any other
    shape now returns ``None``, which every caller refuses.
    """
    env = entry.get("env")
    if env is not None:
        if isinstance(env, Mapping):
            return [str(k) for k in env]
        return _string_keys(env, split_assignment=True)
    env_keys = entry.get("env_keys")
    if env_keys is None:
        return []
    return _string_keys(env_keys, split_assignment=False)


def _string_keys(value: object, *, split_assignment: bool) -> list[str] | None:
    """Read a sequence of key strings, or ``None`` for any other shape or a non-str item."""
    if not isinstance(value, (list, tuple, set, frozenset)):
        return None
    keys: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return None
        keys.append(item.partition("=")[0] if split_assignment else item)
    return keys


def _spawn_fingerprint(entry: Mapping[str, Any], name: str) -> str | None:
    """Fingerprint a spawn config, or ``None`` when its env keys or ``args`` cannot be read."""
    env_keys = _env_keys_of(entry)
    if env_keys is None:
        return None
    args = entry.get("args")
    try:
        return fingerprint_mcp_server(
            name=name,
            command=str(entry["command"]),
            args=() if args is None else args,
            env_keys=env_keys,
        )
    except (TypeError, ValueError, RecursionError):
        # A non-iterable args, an item json cannot encode (bytes, objects), or an args
        # that contains itself (json: "Circular reference detected", 0.10.26).
        return None


def _unreadable_field(entry: Mapping[str, Any]) -> str:
    """Name what :func:`_spawn_fingerprint` could not read, for the refusal message."""
    if _env_keys_of(entry) is None:
        return "env must be a mapping or a sequence of KEY=VALUE strings (env_keys: key strings)"
    return "args must be a sequence of JSON values"


class McpConfigPinSet:
    """Fail-closed spawn-time pin for known-good STDIO MCP server configs.

    Built from an operator-supplied known-good manifest, this rejects any
    STDIO server whose resolved spawn config does not match a pinned
    ``{name, command, args, env-keys}`` fingerprint — covering both the
    *injected* (unpinned name) and *mutated* (fingerprint changed) cases of
    the CVE-2026-30615 zero-click pattern. :meth:`check` raises
    :class:`McpConfigPinViolation` (it never warns) and emits an audit event
    on the existing structlog + JSON-Lines audit channels.

    Args:
        pins: The known-good :class:`McpServerPin` set.
        audit_path: Optional path for the JSON-Lines audit logger. When
            ``None`` the JSONL channel is a no-op; the structlog channel
            still fires.

    Raises:
        ValueError: Two pins share a ``name``.
    """

    def __init__(
        self,
        pins: Iterable[McpServerPin],
        *,
        audit_path: Path | str | None = None,
    ) -> None:
        index: dict[str, str] = {}
        for pin in pins:
            if pin.name in index:
                raise ValueError(f"duplicate pin for MCP server {pin.name!r}")
            index[pin.name] = pin.fingerprint
        self._pins = index
        self._audit_path = audit_path

    @classmethod
    def from_manifest(
        cls,
        manifest: Iterable[Mapping[str, Any]],
        *,
        audit_path: Path | str | None = None,
    ) -> McpConfigPinSet:
        """Build a pin set from a known-good manifest.

        Args:
            manifest: Iterable of entries, each with ``name`` + ``command``
                and optional ``args`` and ``env`` (dict) / ``env_keys``
                (list). Env values are ignored; only the key set is pinned.
            audit_path: Forwarded to the constructor.

        Returns:
            A :class:`McpConfigPinSet`.

        Raises:
            ValueError: An entry's ``env`` / ``env_keys`` or ``args`` cannot be read
                (see :meth:`check`); a pin over a shape the guard cannot read would
                silently pin less than the operator wrote.
        """
        pins: list[McpServerPin] = []
        for entry in manifest:
            name = str(entry["name"])
            fingerprint = _spawn_fingerprint(entry, name)
            if fingerprint is None:
                raise ValueError(f"manifest entry {name!r}: {_unreadable_field(entry)}")
            pins.append(McpServerPin(name=name, fingerprint=fingerprint))
        return cls(pins, audit_path=audit_path)

    @property
    def pinned_names(self) -> tuple[str, ...]:
        """The names of every pinned server (sorted)."""
        return tuple(sorted(self._pins))

    def check(self, server_config: Mapping[str, Any]) -> None:
        """Fail-closed: raise unless the resolved spawn config matches a pin.

        Args:
            server_config: The resolved STDIO spawn config — ``name`` +
                ``command`` and optional ``args`` and ``env`` / ``env_keys``.
                ``env`` is read as a mapping or a sequence of ``KEY=VALUE``
                strings; any other shape is refused, never read as "no keys".

        Raises:
            McpConfigPinViolation: The server is unpinned (injected), its
                fingerprint does not match the pin (mutated), or its ``env`` /
                ``args`` cannot be read (unreadable).
            KeyError: ``server_config`` is missing ``name`` or ``command``.
        """
        if not isinstance(server_config, Mapping):
            # A config that is not a mapping has no name to look up and no fields to
            # fingerprint; until 0.10.26 this raised ``TypeError`` instead of the refusal.
            kind = type(server_config).__name__
            self._emit_audit(server_name="", reason="unreadable", actual="")
            raise McpConfigPinViolation(
                server_name="",
                reason="unreadable",
                expected_fingerprint=None,
                actual_fingerprint="",
                detail=f"server_config must be a mapping, got {kind}",
            )
        name = str(server_config["name"])
        expected = self._pins.get(name)
        fingerprint = _spawn_fingerprint(server_config, name)
        if fingerprint is None:
            self._emit_audit(server_name=name, reason="unreadable", actual="")
            raise McpConfigPinViolation(
                server_name=name,
                reason="unreadable",
                expected_fingerprint=expected,
                actual_fingerprint="",
                detail=_unreadable_field(server_config),
            )
        actual = fingerprint
        if expected is None:
            self._emit_audit(server_name=name, reason="unpinned", actual=actual)
            raise McpConfigPinViolation(
                server_name=name,
                reason="unpinned",
                expected_fingerprint=None,
                actual_fingerprint=actual,
            )
        if actual != expected:
            self._emit_audit(server_name=name, reason="mutated", actual=actual)
            raise McpConfigPinViolation(
                server_name=name,
                reason="mutated",
                expected_fingerprint=expected,
                actual_fingerprint=actual,
            )

    def _emit_audit(self, *, server_name: str, reason: str, actual: str) -> None:
        """Emit the block on the existing structlog + JSON-Lines audit channels."""
        logger.warning(
            "mcp_config_pin_blocked",
            server_name=server_name,
            reason=reason,
            actual_fingerprint=actual,
            cve="CVE-2026-30615",
        )
        # JSON-Lines audit record on the canonical channel. Only the
        # file-write is best-effort suppressed (a no-op logger when no
        # audit_path is configured, or an unwritable path) — the call
        # shape itself is verified by the test suite, not swallowed.
        from ..audit import get_audit_logger

        with contextlib.suppress(OSError):
            get_audit_logger(self._audit_path).log(
                tool_name=f"mcp_server:{server_name}",
                blocked=True,
                block_reason=f"mcp_config_pin:{reason}",
                args={
                    "guard": "mcp_config_pin",
                    "cve": "CVE-2026-30615",
                    "reason": reason,
                    "actual_fingerprint": actual,
                },
            )


__all__ = [
    "DEFAULT_WATCHED_PATHS",
    "ConfigDiffReport",
    "ConfigFileWatchPolicy",
    "MCPCommandMutationDetected",
    "MCPConfigUnreadable",
    "McpConfigPinSet",
    "McpConfigPinViolation",
    "McpServerPin",
    "UnsignedMCPServerAdded",
    "audit_config_diff",
    "fingerprint_mcp_server",
]
