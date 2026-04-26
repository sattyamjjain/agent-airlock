"""Manifest-only execution mode for MCP STDIO transport (v0.5.7+).

Motivation
----------
OX Security's 2026-04-15 deep dive established that arbitrary strings
reaching ``StdioServerParameters.command`` is "the" agent-supply-chain
class of bug, and Anthropic confirmed the SDK validates nothing — that
sanitization is "the developer's responsibility." Manifest-only mode
is the design that makes runtime sanitization unnecessary because
**argv never originates from runtime input**.

The shape:

1. Pre-register a :class:`StdioManifest` with a fixed ``command`` tuple
   under a stable ``manifest_id``. The registration step requires an
   HMAC-SHA256 signature.
2. At runtime, callers ask :func:`launch_from_manifest` for the
   manifest by ID. The function rejects any attempt to override
   ``command``, ``cwd``, or ``env`` outside the manifest's allowlist.

There is no surface for a runtime caller to inject argv. The v0.5.1
``validate_stdio_command`` allowlist becomes redundant because the
allowlist is now the *manifest*, signed at registration time.

Three modes are now available via ``SecurityPolicy.stdio_mode``:

- ``"allowlist"`` (default) — v0.5.1 behavior, runtime argv with
  validate_stdio_command.
- ``"manifest_only"`` — only :func:`launch_from_manifest` may spawn
  STDIO subprocesses; ``validate_stdio_command`` raises.
- ``"disabled"`` — no STDIO subprocesses, period.

Allowlist mode remains the **default** so existing v0.5.1 callers
keep working.

HMAC key storage
----------------
The signing key is loaded from ``AIRLOCK_MANIFEST_SIGNING_KEY``. We
refuse to start with a key shorter than 32 bytes (encoded length
≥ 32 chars).

Primary sources
---------------
- OX Security (2026-04-15): https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
- The Hacker News (2026-04-16): https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
- Cloudflare enterprise MCP (2026-04-22): https://blog.cloudflare.com/enterprise-mcp/
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import subprocess  # nosec B404 — manifest-only spawn is the entire point
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.manifest_only_mode")


_HMAC_KEY_ENV = "AIRLOCK_MANIFEST_SIGNING_KEY"
_HMAC_MIN_LEN = 32


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class ManifestNotRegisteredError(AirlockError):
    """Raised when ``resolve()`` is called with an unknown manifest id."""

    def __init__(self, *, manifest_id: str) -> None:
        self.manifest_id = manifest_id
        super().__init__(
            f"manifest {manifest_id!r} is not registered — manifest-only mode "
            "refuses to spawn ad-hoc commands"
        )


class ManifestSignatureError(AirlockError):
    """Raised when a stored manifest's HMAC signature no longer verifies."""

    def __init__(self, *, manifest_id: str) -> None:
        self.manifest_id = manifest_id
        super().__init__(
            f"manifest {manifest_id!r} HMAC signature is invalid — refusing to "
            "launch (signing-key rotated or registry tampered with)"
        )


class ManifestRuntimeOverrideAttempted(AirlockError):
    """Raised when a runtime caller passes argv / env / cwd directly.

    The manifest-only contract is that the *only* parameters
    :func:`launch_from_manifest` accepts are the manifest_id and a
    runtime-env dict whose keys must lie inside the manifest's
    ``env_allowlist``.
    """


class ManifestSigningKeyError(AirlockError):
    """Raised when the HMAC signing key is missing or too short."""


# -----------------------------------------------------------------------------
# StdioManifest
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class StdioManifest:
    """Immutable description of an STDIO subprocess spawn.

    Attributes:
        manifest_id: Stable identifier (e.g. ``"local-fs"``,
            ``"python-mcp-server-everything"``). Used by callers to
            refer to this manifest at runtime.
        command: The exact argv tuple. Stored as a ``tuple[str, ...]``
            so it cannot be mutated after registration.
        env_allowlist: The set of environment variable NAMES that
            :func:`launch_from_manifest` is allowed to pass through
            from the runtime env. Values are taken from the runtime
            env at launch time. An empty allowlist means "inherit
            nothing."
        cwd: Optional working directory. Must be an absolute path.
        signer: Free-form identifier for who signed this manifest
            (e.g. ``"sre-team"``, ``"build-system"``).
        sha256: SHA-256 of the canonical manifest bytes — recorded so
            the registry can detect tamper without re-running HMAC.
        registered_at: UTC timestamp of registration.
    """

    manifest_id: str
    command: tuple[str, ...]
    env_allowlist: frozenset[str] = field(default_factory=frozenset)
    cwd: str | None = None
    signer: str = "unknown"
    sha256: str = ""
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _canonical_manifest_bytes(manifest: StdioManifest) -> bytes:
    """Stable serialisation for signing + digesting.

    Excludes the ``sha256`` and ``registered_at`` fields (those are
    derived) so the digest is reproducible.
    """
    payload = {
        "manifest_id": manifest.manifest_id,
        "command": list(manifest.command),
        "env_allowlist": sorted(manifest.env_allowlist),
        "cwd": manifest.cwd,
        "signer": manifest.signer,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_signing_key() -> bytes:
    raw = os.environ.get(_HMAC_KEY_ENV, "")
    if len(raw) < _HMAC_MIN_LEN:
        raise ManifestSigningKeyError(
            f"{_HMAC_KEY_ENV} is missing or shorter than {_HMAC_MIN_LEN} bytes — "
            "manifest-only mode refuses to start without a strong signing key"
        )
    return raw.encode("utf-8")


def _hmac_sign(key: bytes, manifest: StdioManifest) -> str:
    return hmac.new(key, _canonical_manifest_bytes(manifest), hashlib.sha256).hexdigest()


# -----------------------------------------------------------------------------
# ManifestRegistry
# -----------------------------------------------------------------------------


class ManifestRegistry:
    """In-memory store of signed manifests.

    Each registry instance is isolated — registering a manifest in one
    does not make it resolvable in another. Tenancy boundaries are
    therefore enforced at the registry level by the caller.
    """

    def __init__(self) -> None:
        self._entries: dict[str, tuple[StdioManifest, str]] = {}

    def register(self, manifest: StdioManifest, signing_key: bytes) -> StdioManifest:
        """Register and sign a manifest.

        Returns the manifest with ``sha256`` populated.

        Raises:
            ManifestSigningKeyError: If the supplied key is too short.
        """
        if len(signing_key) < _HMAC_MIN_LEN:
            raise ManifestSigningKeyError(
                f"signing key shorter than {_HMAC_MIN_LEN} bytes — refusing to register"
            )
        canonical = _canonical_manifest_bytes(manifest)
        digest = hashlib.sha256(canonical).hexdigest()
        signed = StdioManifest(
            manifest_id=manifest.manifest_id,
            command=tuple(manifest.command),
            env_allowlist=frozenset(manifest.env_allowlist),
            cwd=manifest.cwd,
            signer=manifest.signer,
            sha256=digest,
            registered_at=manifest.registered_at,
        )
        signature = _hmac_sign(signing_key, signed)
        self._entries[signed.manifest_id] = (signed, signature)
        logger.info(
            "manifest_registered",
            manifest_id=signed.manifest_id,
            signer=signed.signer,
            sha256=digest,
        )
        return signed

    def resolve(self, manifest_id: str, signing_key: bytes) -> StdioManifest:
        """Return the manifest, or raise on unknown / tampered.

        Raises:
            ManifestNotRegisteredError: If ``manifest_id`` is unknown.
            ManifestSignatureError: If the stored signature does not
                verify against the supplied key.
        """
        entry = self._entries.get(manifest_id)
        if entry is None:
            raise ManifestNotRegisteredError(manifest_id=manifest_id)
        manifest, expected = entry
        actual = _hmac_sign(signing_key, manifest)
        if not hmac.compare_digest(expected, actual):
            raise ManifestSignatureError(manifest_id=manifest_id)
        return manifest

    def list_ids(self) -> list[str]:
        return sorted(self._entries.keys())


# -----------------------------------------------------------------------------
# launch_from_manifest
# -----------------------------------------------------------------------------


def launch_from_manifest(
    manifest_id: str,
    registry: ManifestRegistry,
    runtime_env: Mapping[str, str] | None = None,
    *,
    signing_key: bytes | None = None,
    allowed_cwd_prefixes: tuple[str, ...] = (),
    _popen_factory: type[subprocess.Popen] | None = None,
    **forbidden_overrides: object,
) -> subprocess.Popen:
    """Spawn the manifest's command. Runtime callers cannot override argv.

    Args:
        manifest_id: The stable id passed to
            :meth:`ManifestRegistry.register`.
        registry: The registry the manifest lives in.
        runtime_env: Optional dict of env-var values. Only keys that
            also appear in the manifest's ``env_allowlist`` are
            forwarded; everything else is silently dropped (the
            forbidden-overrides path applies to *positional* values
            like argv / cwd, not env).
        signing_key: HMAC key for resolving the manifest. If omitted,
            falls back to ``AIRLOCK_MANIFEST_SIGNING_KEY`` env var.
        allowed_cwd_prefixes: Whitelist of absolute path prefixes the
            manifest's ``cwd`` must start with. Empty tuple means "no
            prefix check" — only the absolute-path requirement applies.
        _popen_factory: Test seam for injecting a fake Popen. Library
            users should never set this.
        **forbidden_overrides: Any extra kwargs (in particular
            ``command``, ``argv``, ``cwd``) are rejected with
            :class:`ManifestRuntimeOverrideAttempted`. The whole point
            of manifest-only mode is that runtime can't hand-roll argv.

    Returns:
        The :class:`subprocess.Popen` handle.

    Raises:
        ManifestRuntimeOverrideAttempted: If the caller passed argv /
            cwd / command / env (other than the explicit
            ``runtime_env`` parameter).
        ManifestNotRegisteredError: If ``manifest_id`` is unknown.
        ManifestSignatureError: If the manifest's signature is invalid.
    """
    if forbidden_overrides:
        raise ManifestRuntimeOverrideAttempted(
            f"manifest-only mode rejects runtime kwargs "
            f"{sorted(forbidden_overrides.keys())} — only manifest_id and "
            "runtime_env are accepted"
        )

    key = signing_key if signing_key is not None else _load_signing_key()
    manifest = registry.resolve(manifest_id, key)

    # Build env strictly from the manifest's allowlist.
    env: dict[str, str] = {}
    if runtime_env is not None:
        for name in manifest.env_allowlist:
            value = runtime_env.get(name)
            if value is not None:
                env[name] = value

    # Validate cwd is absolute + under an allowed prefix (when prefixes given).
    cwd = manifest.cwd
    if cwd is not None:
        if not Path(cwd).is_absolute():
            raise ManifestRuntimeOverrideAttempted(
                f"manifest {manifest_id!r} cwd {cwd!r} is not absolute"
            )
        if allowed_cwd_prefixes and not any(cwd.startswith(p) for p in allowed_cwd_prefixes):
            raise ManifestRuntimeOverrideAttempted(
                f"manifest {manifest_id!r} cwd {cwd!r} not under allowed prefixes "
                f"{allowed_cwd_prefixes}"
            )

    _emit_otel_span(
        manifest_id=manifest.manifest_id,
        signer=manifest.signer,
        sha256=manifest.sha256,
    )
    logger.info(
        "manifest_launch",
        manifest_id=manifest.manifest_id,
        signer=manifest.signer,
        sha256=manifest.sha256,
        argv_len=len(manifest.command),
    )
    factory = _popen_factory or subprocess.Popen
    return factory(  # nosec B603 — argv comes from a signed registry, not user input
        list(manifest.command),
        cwd=cwd,
        env=env if env else None,
        shell=False,
    )


def _emit_otel_span(*, manifest_id: str, signer: str, sha256: str) -> None:
    """Best-effort emit of the ``airlock.stdio.manifest.launch`` span.

    Falls through silently if the OTel provider isn't configured —
    spans are observability, not load-bearing for security.
    """
    with contextlib.suppress(Exception):  # pragma: no cover
        from ..observability import end_span, start_span

        ctx = start_span("airlock.stdio.manifest.launch", manifest_id)
        ctx.set_attribute("airlock.stdio.manifest.signer", signer)
        ctx.set_attribute("airlock.stdio.manifest.sha256", sha256)
        end_span(ctx)


__all__ = [
    "ManifestNotRegisteredError",
    "ManifestRegistry",
    "ManifestRuntimeOverrideAttempted",
    "ManifestSignatureError",
    "ManifestSigningKeyError",
    "StdioManifest",
    "launch_from_manifest",
]
