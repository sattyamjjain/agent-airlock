"""Claude Opus 4.7 Auto Memory / Auto Dream read/write guard (v0.5.2+).

Opus 4.7 GA (2026-04-16/17) introduced **Auto Memory** and **Auto Dream**
— filesystem-backed persistent notes that survive across sessions. Two
new risks:

1. **Memory poisoning.** An earlier-session prompt injection that gets
   consolidated into durable notes becomes a persistent compromise of
   every subsequent session that reads the same tenant's memory.
2. **Cross-tenant leakage.** A session running for tenant A pulling
   tenant B's notes because the memory path is not scoped.

This module wraps the read/write surface so every call is:

- **Tenant-scoped** — the path must begin with ``/memory/{tenant_id}/``.
- **Quota-bounded** — reads above ``max_read_bytes_per_call`` refused.
- **Redacted on write** — secrets are stripped before persistence
  using :func:`agent_airlock.sanitizer.sanitize_output` (the same
  redaction surface the audit log uses).
- **Observable** — every call emits an OpenTelemetry span
  ``airlock.auto_memory.read`` or ``.write`` with ``tenant_id``,
  ``bytes``, ``redacted_count`` attributes.

Usage::

    from agent_airlock.integrations.claude_auto_memory import (
        AutoMemoryAccessPolicy, guarded_read, guarded_write,
    )

    policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
    guarded_read(policy, "/memory/acct-42/plan.md", raw_read_fn)
    guarded_write(policy, "/memory/acct-42/plan.md", "...",
                  raw_write_fn)

References
----------
- Anthropic — What's new in Claude 4.7 (2026-04-17):
  https://platform.claude.com/docs/en/about-claude/models/whats-new-claude-4-7
- Auto Dream mechanics write-up:
  https://claudefa.st/blog/guide/mechanics/auto-dream
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import structlog

from ..exceptions import AirlockError
from ..sanitizer import sanitize_output

logger = structlog.get_logger("agent-airlock.integrations.claude_auto_memory")

_HMAC_ENV_VAR = "AIRLOCK_MEMORY_HMAC_KEY"
_DEFAULT_MAX_CHAIN_DEPTH = 8


@dataclass
class AutoMemoryAccessPolicy:
    """Per-tenant access policy for Claude Opus 4.7 Auto Memory.

    Attributes:
        tenant_id: The tenant this session belongs to. All reads and
            writes must reference paths under ``/memory/{tenant_id}/``.
        allowed_paths: Optional extra per-path allow-list WITHIN the
            tenant scope. Empty means "any path under the tenant root".
        max_read_bytes_per_call: Reject reads larger than this. Default
            64 KiB — matches the canonical Auto Dream note size.
        forbid_cross_tenant: If True (default), a path not under the
            tenant root raises :class:`AutoMemoryCrossTenantError`.
        redact_on_write: If True (default), every write passes through
            the sanitizer redaction surface before persisting.
    """

    tenant_id: str
    allowed_paths: list[str] = field(default_factory=list)
    max_read_bytes_per_call: int = 64_000
    forbid_cross_tenant: bool = True
    redact_on_write: bool = True


class AutoMemoryCrossTenantError(AirlockError):
    """Raised when a session tries to read or write outside its tenant."""

    def __init__(self, *, tenant_id: str, attempted_path: str) -> None:
        self.tenant_id = tenant_id
        self.attempted_path = attempted_path
        super().__init__(
            f"tenant {tenant_id!r} attempted to access {attempted_path!r} "
            "(must begin with /memory/<tenant_id>/)"
        )


class AutoMemoryQuotaError(AirlockError):
    """Raised when a read exceeds the per-call byte quota."""

    def __init__(self, *, bytes_requested: int, limit: int) -> None:
        self.bytes_requested = bytes_requested
        self.limit = limit
        super().__init__(
            f"auto-memory read of {bytes_requested} bytes exceeds per-call limit {limit}"
        )


class MemoryProvenanceError(AirlockError):
    """Raised when a signed memory entry's HMAC does not verify.

    Motivating incident: Anthropic's 2026-04-19 default-on Auto Memory
    rollout created a class of cross-project memory reads. A tampered
    entry is indistinguishable from a legitimate one unless it's
    signed — this error fires when the signature check fails.
    """

    def __init__(self, *, tenant_id: str, path: str) -> None:
        self.tenant_id = tenant_id
        self.path = path
        super().__init__(
            f"memory provenance HMAC mismatch for tenant {tenant_id!r} "
            f"at {path!r} — entry was tampered with or signed with a "
            "different key"
        )


class MemoryChainTooDeepError(AirlockError):
    """Raised when a consolidation chain exceeds ``max_chain_depth``.

    Long chains are a poisoning signal — a hostile earlier session
    propagating into every downstream consolidation."""

    def __init__(self, *, depth: int, limit: int) -> None:
        self.depth = depth
        self.limit = limit
        super().__init__(
            f"consolidation chain depth {depth} exceeds limit {limit} — "
            "memory poisoning signal, refusing to consolidate further"
        )


@dataclass
class MemoryEntry:
    """A signed, provenance-tracked Auto Memory write (v0.5.3+).

    Attributes:
        tenant_id: Owning tenant.
        path: Absolute memory path under ``/memory/{tenant_id}/``.
        content: The (already-redacted) payload that was persisted.
        created_at: Unix timestamp when this entry was written.
        consolidated_from_session_id: The session that triggered this
            write (not necessarily the session whose content appears
            — see ``consolidation_chain``).
        consolidation_chain: Ordered list of session IDs that
            contributed to this entry. Latest-consolidation-last.
        sha256_before_redact: Hex digest of the pre-redaction payload.
            Stored so a later audit can detect silent content drift
            without revealing the plaintext.
        sha256_after_redact: Hex digest of the persisted payload.
        redacted_token_count: How many secrets the sanitizer
            stripped before persistence.
        signature: HMAC-SHA256 over the canonical JSON serialization
            of all the above fields, keyed from the
            ``AIRLOCK_MEMORY_HMAC_KEY`` env var.
    """

    tenant_id: str
    path: str
    content: str
    created_at: float = field(default_factory=time.time)
    consolidated_from_session_id: str | None = None
    consolidation_chain: list[str] = field(default_factory=list)
    sha256_before_redact: str = ""
    sha256_after_redact: str = ""
    redacted_token_count: int = 0
    signature: str = ""


def _signing_key() -> bytes:
    """Load the HMAC signing key from env. Fail closed if absent."""
    raw = os.environ.get(_HMAC_ENV_VAR)
    if not raw:
        raise MemoryProvenanceError(
            tenant_id="<none>",
            path=f"<{_HMAC_ENV_VAR} unset>",
        )
    return raw.encode("utf-8")


def _canonical_entry_bytes(entry: MemoryEntry) -> bytes:
    """Deterministic JSON serialization for stable HMAC computation.

    The ``signature`` field is excluded — we sign over everything
    else, then attach the result.
    """
    payload = asdict(entry)
    payload.pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_memory_entry(entry: MemoryEntry) -> str:
    """Compute + attach the HMAC-SHA256 signature on ``entry``.

    Returns the hex digest that was stored on ``entry.signature``.
    """
    sig = hmac.new(_signing_key(), _canonical_entry_bytes(entry), hashlib.sha256).hexdigest()
    entry.signature = sig
    return sig


def verify_memory_entry(entry: MemoryEntry) -> None:
    """Verify ``entry.signature`` or raise :class:`MemoryProvenanceError`."""
    expected = hmac.new(_signing_key(), _canonical_entry_bytes(entry), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, entry.signature):
        raise MemoryProvenanceError(tenant_id=entry.tenant_id, path=entry.path)


def consolidate_memory(
    tenant_id: str,
    path: str,
    content: str,
    source_session_ids: list[str],
    *,
    max_chain_depth: int = _DEFAULT_MAX_CHAIN_DEPTH,
) -> MemoryEntry:
    """Build a signed :class:`MemoryEntry` with a recorded chain.

    Args:
        tenant_id: Owning tenant. Must match the path prefix.
        path: Must start with ``/memory/{tenant_id}/``.
        content: The payload to persist. Passed through
            :func:`agent_airlock.sanitizer.sanitize_output`.
        source_session_ids: Ordered list of session IDs that
            contributed — the chain.
        max_chain_depth: Refuse to consolidate when the chain would
            exceed this length. Default 8.

    Raises:
        MemoryChainTooDeepError: Chain length exceeds the limit.
        MemoryProvenanceError: Signing key is unavailable.
    """
    if len(source_session_ids) > max_chain_depth:
        raise MemoryChainTooDeepError(depth=len(source_session_ids), limit=max_chain_depth)

    before_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    sanitized = sanitize_output(content)
    after_digest = hashlib.sha256(sanitized.content.encode("utf-8")).hexdigest()

    latest = source_session_ids[-1] if source_session_ids else None
    entry = MemoryEntry(
        tenant_id=tenant_id,
        path=path,
        content=sanitized.content,
        consolidated_from_session_id=latest,
        consolidation_chain=list(source_session_ids),
        sha256_before_redact=before_digest,
        sha256_after_redact=after_digest,
        redacted_token_count=len(sanitized.detections),
    )
    sign_memory_entry(entry)

    _emit_span(
        "airlock.auto_memory.consolidate",
        {
            "tenant_id": tenant_id,
            "path": path,
            "chain_depth": len(source_session_ids),
            "redacted_count": entry.redacted_token_count,
        },
    )
    return entry


def _tenant_root(tenant_id: str) -> str:
    return f"/memory/{tenant_id}/"


def _check_scope(policy: AutoMemoryAccessPolicy, path: str) -> None:
    if policy.forbid_cross_tenant and not path.startswith(_tenant_root(policy.tenant_id)):
        raise AutoMemoryCrossTenantError(
            tenant_id=policy.tenant_id,
            attempted_path=path,
        )
    if policy.allowed_paths and path not in policy.allowed_paths:
        # Allow-list is additive to scope; if set, path must appear verbatim.
        raise AutoMemoryCrossTenantError(
            tenant_id=policy.tenant_id,
            attempted_path=path,
        )


def _get_tracer() -> Any:
    """Return an OTel tracer if available, else a no-op stand-in."""
    try:
        from opentelemetry import trace

        return trace.get_tracer("agent_airlock.integrations.claude_auto_memory")
    except ImportError:  # pragma: no cover — opentelemetry is an optional extra
        return None


def _emit_span(
    name: str,
    attributes: dict[str, Any],
) -> None:
    """Emit an OTel span carrying the audit attributes.

    If ``opentelemetry`` is not installed (it's an optional dep in
    agent-airlock) this falls back to a structlog line so the audit
    information is still captured.
    """
    tracer = _get_tracer()
    if tracer is not None:
        with tracer.start_as_current_span(name) as span:  # pragma: no cover
            for k, v in attributes.items():
                span.set_attribute(k, v)
        return
    logger.info(name, **attributes)


def guarded_read(
    policy: AutoMemoryAccessPolicy,
    path: str,
    raw_read: Callable[[str], bytes],
) -> bytes:
    """Execute a tenant-scoped, quota-bounded Auto Memory read.

    Args:
        policy: The tenant's access policy.
        path: Absolute memory path requested by the session.
        raw_read: The underlying read callable (``path -> bytes``).

    Returns:
        The bytes read.

    Raises:
        AutoMemoryCrossTenantError: Path outside the tenant root.
        AutoMemoryQuotaError: Read payload exceeds the quota.
    """
    _check_scope(policy, path)
    data = raw_read(path)
    if len(data) > policy.max_read_bytes_per_call:
        raise AutoMemoryQuotaError(
            bytes_requested=len(data),
            limit=policy.max_read_bytes_per_call,
        )
    _emit_span(
        "airlock.auto_memory.read",
        {
            "tenant_id": policy.tenant_id,
            "bytes": len(data),
            "path": path,
            "redacted_count": 0,
        },
    )
    return data


def guarded_write(
    policy: AutoMemoryAccessPolicy,
    path: str,
    content: str,
    raw_write: Callable[[str, str], None],
) -> int:
    """Execute a tenant-scoped, redaction-enforced Auto Memory write.

    Args:
        policy: The tenant's access policy.
        path: Absolute memory path to write.
        content: The string payload. Redacted before persistence when
            ``policy.redact_on_write`` is True (default).
        raw_write: The underlying write callable (``(path, content) -> None``).

    Returns:
        The number of secrets redacted (``0`` when
        ``redact_on_write=False`` or the payload was clean).

    Raises:
        AutoMemoryCrossTenantError: Path outside the tenant root.
    """
    _check_scope(policy, path)
    redacted_count = 0
    payload = content
    if policy.redact_on_write:
        result = sanitize_output(content)
        payload = result.content
        redacted_count = len(result.detections)
    raw_write(path, payload)
    _emit_span(
        "airlock.auto_memory.write",
        {
            "tenant_id": policy.tenant_id,
            "bytes": len(payload.encode("utf-8", errors="replace")),
            "path": path,
            "redacted_count": redacted_count,
        },
    )
    return redacted_count


__all__ = [
    "AutoMemoryAccessPolicy",
    "AutoMemoryCrossTenantError",
    "AutoMemoryQuotaError",
    "guarded_read",
    "guarded_write",
]
