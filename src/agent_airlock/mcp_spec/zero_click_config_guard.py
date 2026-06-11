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
signer raise :class:`UnsignedMCPServerAdded`.

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

import structlog

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
    """An existing ``mcpServers`` entry's ``command`` array changed shape.

    The advisory pattern: an attacker doesn't add a new entry — they
    flip the argv on an existing one to point to a malicious binary.
    """

    def __init__(self, *, path: Path, server_name: str) -> None:
        self.path = path
        self.server_name = server_name
        super().__init__(
            f"existing MCP server entry {server_name!r} in {path} had its "
            "command array mutated — refusing (CVE-2026-30615 class)"
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


def _parse_servers(content: bytes) -> dict[str, Any]:
    """Extract the ``mcpServers`` mapping from a config blob.

    Returns ``{}`` if the file isn't valid JSON or the key is absent.
    Strict-mode parsing is the caller's responsibility — the guard's
    job is to detect the diff shape, not the file's overall validity.
    """
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return {}
    return servers


def _server_signer(entry: dict[str, Any]) -> str:
    """Best-effort signer extraction. Empty when missing / non-string."""
    signer = entry.get("signer", "")
    return signer if isinstance(signer, str) else ""


def _command_array(entry: dict[str, Any]) -> tuple[str, ...]:
    """Command array as a tuple of strings; empty if missing."""
    cmd = entry.get("command")
    if isinstance(cmd, list):
        return tuple(str(x) for x in cmd)
    if isinstance(cmd, str):
        return (cmd,)
    return ()


def audit_config_diff(
    path: Path,
    old_sha256: str | None,
    new_content: bytes,
    cfg: ConfigFileWatchPolicy,
    *,
    old_content: bytes | None = None,
) -> ConfigDiffReport:
    """Audit a config-file diff against the policy.

    Args:
        path: The config file's path on disk (used for error messages
            and reports; not re-read).
        old_sha256: SHA-256 of the previously-trusted state, or
            ``None`` if this is the first audit.
        new_content: The current file's bytes.
        cfg: Active :class:`ConfigFileWatchPolicy`.
        old_content: Optional — when supplied, the diff also detects
            mutated ``command`` arrays on existing server entries.
            Without it, the guard can only flag *new* entries.

    Returns:
        :class:`ConfigDiffReport` summarising what changed.

    Raises:
        UnsignedMCPServerAdded: A new entry has no trusted signer and
            ``cfg.require_signer_for_new_servers`` is True.
        MCPCommandMutationDetected: An existing entry's ``command``
            array changed and ``old_content`` was supplied.
    """
    new_sha = hashlib.sha256(new_content).hexdigest()
    new_servers = _parse_servers(new_content)
    old_servers: dict[str, Any] = {}
    if old_content is not None:
        old_servers = _parse_servers(old_content)

    added: list[str] = []
    for name, entry in new_servers.items():
        if name in old_servers:
            continue
        added.append(name)
        if not cfg.require_signer_for_new_servers:
            continue
        if not isinstance(entry, dict):
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
        if not isinstance(entry, dict) or not isinstance(old_servers[name], dict):
            continue
        if _command_array(entry) != _command_array(old_servers[name]):
            mutated.append(name)
            raise MCPCommandMutationDetected(path=path, server_name=name)

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
    in the pin set at all (an injected entry), or a previously-pinned
    server's ``command`` / ``args`` / ``env``-keys changed between
    registration and spawn (a mutated entry).

    Attributes:
        server_name: The offending STDIO server name.
        reason: ``"unpinned"`` (not in the pin set) or ``"mutated"``
            (fingerprint mismatch).
        expected_fingerprint: The pinned fingerprint, or ``None`` when
            the server was unpinned.
        actual_fingerprint: The fingerprint of the resolved spawn config.
    """

    def __init__(
        self,
        *,
        server_name: str,
        reason: str,
        expected_fingerprint: str | None,
        actual_fingerprint: str,
    ) -> None:
        self.server_name = server_name
        self.reason = reason
        self.expected_fingerprint = expected_fingerprint
        self.actual_fingerprint = actual_fingerprint
        if reason == "unpinned":
            msg = (
                f"STDIO MCP server {server_name!r} is not in the config pin set — "
                f"refusing to spawn an unpinned server (CVE-2026-30615 zero-click "
                f"class); fingerprint={actual_fingerprint}"
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


def _env_keys_of(entry: Mapping[str, Any]) -> list[str]:
    """Resolve env-key names from a config entry (``env`` dict or ``env_keys`` list)."""
    env = entry.get("env")
    if isinstance(env, Mapping):
        return [str(k) for k in env]
    env_keys = entry.get("env_keys")
    if isinstance(env_keys, (list, tuple, set, frozenset)):
        return [str(k) for k in env_keys]
    return []


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
        """
        pins = [
            McpServerPin(
                name=str(entry["name"]),
                fingerprint=fingerprint_mcp_server(
                    name=str(entry["name"]),
                    command=str(entry["command"]),
                    args=entry.get("args", ()),
                    env_keys=_env_keys_of(entry),
                ),
            )
            for entry in manifest
        ]
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

        Raises:
            McpConfigPinViolation: The server is unpinned (injected) or its
                fingerprint does not match the pin (mutated).
            KeyError: ``server_config`` is missing ``name`` or ``command``.
        """
        name = str(server_config["name"])
        actual = fingerprint_mcp_server(
            name=name,
            command=str(server_config["command"]),
            args=server_config.get("args", ()),
            env_keys=_env_keys_of(server_config),
        )
        expected = self._pins.get(name)
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
    "McpConfigPinSet",
    "McpConfigPinViolation",
    "McpServerPin",
    "UnsignedMCPServerAdded",
    "audit_config_diff",
    "fingerprint_mcp_server",
]
