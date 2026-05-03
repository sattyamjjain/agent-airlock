"""Runtime argv allowlist enforcement (v0.6.1+).

OX/BackBox re-published the 200K-server MCP-STDIO matrix on 2026-05-01
with a patch list. The v0.5.7 signed-manifest registry already pins
allowed argv tuples — this module is the **runtime gate** that fails
closed when an MCP server boots with argv outside the signed manifest.

Why a separate module
---------------------
:func:`agent_airlock.mcp_spec.manifest_only_mode.launch_from_manifest`
*spawns* a manifest's argv. It does the right thing when it's the
spawn path. The runtime allowlist is the **inverse** path: a hosted
MCP runtime has *already* received an argv vector (from the host
process, a launcher, or an arbitrary integrator) and asks "am I
allowed to keep going?" The answer is always one of:

- :class:`AllowlistVerdict(allowed=True, ...)` — exact argv0 + tail
  match against a registered, signature-valid manifest.
- :class:`AllowlistVerdict(allowed=False, ...)` — anything else.

The function never spawns. It returns a verdict — callers wire that
into their own kill-switch.

Primary sources
---------------
- BackBox/OX (2026-05-01) — re-publication of the 200K MCP-STDIO matrix:
  https://news.backbox.org/2026/05/01/200000-mcp-servers-expose-a-command-execution-flaw-that-anthropic-calls-a-feature/
- OX Security (2026-04-15) — original write-up:
  https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path

import structlog

from ..mcp_spec.manifest_only_mode import (
    ManifestNotRegisteredError,
    ManifestRegistry,
    ManifestSignatureError,
    ManifestSigningKeyError,
    StdioManifest,
    _load_signing_key,
)

logger = structlog.get_logger("agent-airlock.runtime.manifest_only_allowlist")


class AllowlistVerdictReason(str, enum.Enum):
    """Stable reason codes for :class:`AllowlistVerdict`."""

    ALLOWED = "allowed"
    EMPTY_MANIFEST = "empty_manifest"
    UNKNOWN_SERVER = "unknown_server"
    SIGNATURE_INVALID = "signature_invalid"
    SIGNING_KEY_MISSING = "signing_key_missing"
    ARGV_MISMATCH = "argv_mismatch"
    EXTRA_INLINE_FLAG = "extra_inline_flag"
    MALFORMED_ARGV = "malformed_argv"


@dataclass(frozen=True)
class AllowlistVerdict:
    """Outcome of a single :func:`enforce_allowlist` call.

    Attributes:
        allowed: True iff the argv exactly matches the signed manifest.
        reason: A stable :class:`AllowlistVerdictReason` value.
        detail: Free-form human-readable explanation.
        manifest_id: The manifest the argv was checked against.
    """

    allowed: bool
    reason: AllowlistVerdictReason
    detail: str
    manifest_id: str


# argv flags whose presence indicates an inline-code injection vector
# (CVE-2026-30616 class). Even if the rest of the argv matches the
# manifest, an extra ``--code`` / ``-c`` / ``--exec`` is denied.
_INLINE_CODE_FLAGS: frozenset[str] = frozenset({"--code", "-c", "--exec", "-e"})


def _load_registry_from_path(manifest_path: Path) -> ManifestRegistry:
    """Build a :class:`ManifestRegistry` from a JSON manifest file.

    The on-disk format is a JSON array of dicts with keys
    ``manifest_id``, ``command`` (list[str]), ``env_allowlist``
    (list[str]), ``cwd`` (str | null), and ``signer`` (str). The
    registry is signed at load time using ``AIRLOCK_MANIFEST_SIGNING_KEY``.

    An empty file or missing path produces an empty registry — callers
    interpret that as ``EMPTY_MANIFEST`` and fail closed.

    Raises:
        ManifestSigningKeyError: The env-var signing key is absent or
            shorter than 32 chars (re-raised from
            ``manifest_only_mode._load_signing_key``).
    """
    import json

    registry = ManifestRegistry()
    if not manifest_path.exists():
        return registry
    raw = manifest_path.read_text(encoding="utf-8").strip()
    if not raw:
        return registry
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest file {manifest_path} is not valid JSON: {exc}") from exc
    if not isinstance(entries, list):
        raise ValueError(f"manifest file {manifest_path} must be a JSON list")
    key = _load_signing_key()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"manifest file {manifest_path} contains a non-dict entry: {entry!r}")
        manifest = StdioManifest(
            manifest_id=str(entry["manifest_id"]),
            command=tuple(entry["command"]),
            env_allowlist=frozenset(entry.get("env_allowlist", [])),
            cwd=entry.get("cwd"),
            signer=str(entry.get("signer", "unknown")),
        )
        registry.register(manifest, key)
    return registry


def enforce_allowlist(
    server_name: str,
    argv: list[str],
    manifest_path: Path,
    *,
    registry: ManifestRegistry | None = None,
) -> AllowlistVerdict:
    """Decide whether ``argv`` is allowed for ``server_name``.

    Args:
        server_name: The manifest_id the caller claims to be booting.
        argv: The full argv vector the caller proposes to use. Must
            be non-empty.
        manifest_path: Path to a JSON manifest registry. Loaded once
            per call (callers can cache by passing ``registry=``).
        registry: Pre-built registry (test seam). When set,
            ``manifest_path`` is ignored.

    Returns:
        :class:`AllowlistVerdict`. Callers map ``allowed=False`` to
        a non-zero process exit.
    """
    if not argv:
        return AllowlistVerdict(
            allowed=False,
            reason=AllowlistVerdictReason.MALFORMED_ARGV,
            detail="argv is empty",
            manifest_id=server_name,
        )

    if registry is None:
        try:
            registry = _load_registry_from_path(manifest_path)
        except ManifestSigningKeyError as exc:
            return AllowlistVerdict(
                allowed=False,
                reason=AllowlistVerdictReason.SIGNING_KEY_MISSING,
                detail=str(exc),
                manifest_id=server_name,
            )

    if not registry.list_ids():
        return AllowlistVerdict(
            allowed=False,
            reason=AllowlistVerdictReason.EMPTY_MANIFEST,
            detail=f"manifest registry at {manifest_path} is empty — fail-closed",
            manifest_id=server_name,
        )

    try:
        key = _load_signing_key()
        manifest = registry.resolve(server_name, key)
    except ManifestNotRegisteredError:
        return AllowlistVerdict(
            allowed=False,
            reason=AllowlistVerdictReason.UNKNOWN_SERVER,
            detail=f"server {server_name!r} not in signed manifest",
            manifest_id=server_name,
        )
    except ManifestSignatureError as exc:
        return AllowlistVerdict(
            allowed=False,
            reason=AllowlistVerdictReason.SIGNATURE_INVALID,
            detail=str(exc),
            manifest_id=server_name,
        )
    except ManifestSigningKeyError as exc:
        return AllowlistVerdict(
            allowed=False,
            reason=AllowlistVerdictReason.SIGNING_KEY_MISSING,
            detail=str(exc),
            manifest_id=server_name,
        )

    extra_inline = _INLINE_CODE_FLAGS.intersection(argv) - _INLINE_CODE_FLAGS.intersection(
        manifest.command
    )
    if extra_inline:
        return AllowlistVerdict(
            allowed=False,
            reason=AllowlistVerdictReason.EXTRA_INLINE_FLAG,
            detail=(
                f"argv carries inline-code flag(s) {sorted(extra_inline)} "
                "outside the signed manifest — refuses by CVE-2026-30616 class"
            ),
            manifest_id=server_name,
        )

    if tuple(argv) != manifest.command:
        return AllowlistVerdict(
            allowed=False,
            reason=AllowlistVerdictReason.ARGV_MISMATCH,
            detail=(f"argv {argv!r} does not match signed manifest {list(manifest.command)!r}"),
            manifest_id=server_name,
        )

    logger.info(
        "manifest_allowlist_allow",
        manifest_id=server_name,
        argv0=argv[0],
        argv_len=len(argv),
    )
    return AllowlistVerdict(
        allowed=True,
        reason=AllowlistVerdictReason.ALLOWED,
        detail="argv exactly matches signed manifest",
        manifest_id=server_name,
    )


__all__ = [
    "AllowlistVerdict",
    "AllowlistVerdictReason",
    "enforce_allowlist",
]
