"""Session-snapshot integrity guard (v0.5.2+).

Motivation
----------
On 2026-04-15 OpenAI shipped the "next evolution" of the Agents SDK,
introducing **session snapshots** that serialize agent state and allow
rehydration into a fresh sandbox container. Seven managed providers
are first-class: Blaxel, Cloudflare, Daytona, E2B, Modal, Runloop,
Vercel. OpenAI's own framing separates the harness from the compute to
keep credentials out of model-generated code paths.

The implication for a runtime firewall is: **the snapshot is a new
tamper surface.** A hostile or corrupted snapshot replayed into a
container can smuggle tool calls, cached credentials, or prompt-
injection payloads past first-hop validation. Worse, if your cost
tracker resets on rehydration, the attacker gets a fresh token budget
every time they replay.

This module adds four checks that run before a snapshot is trusted:

1. **SHA-256 integrity** — recompute and compare.
2. **Freshness** — reject snapshots older than ``max_age_seconds``.
3. **Size cap** — reject snapshots over ``max_bytes`` (DoS guard,
   default 25 MiB).
4. **Signer allow-list** — optional, refuses any ``signed_by`` not on
   the approved list.
5. **Secret redaction** — refuses snapshots whose serialized body
   carries plaintext secrets (delegates to
   :func:`agent_airlock.sanitizer.sanitize_output`).

Usage::

    from agent_airlock.mcp_spec.session_guard import (
        SessionSnapshotRef, SnapshotGuardConfig, verify_snapshot,
    )

    cfg = SnapshotGuardConfig()
    verify_snapshot(ref, raw_bytes, cfg)
    # raises SnapshotIntegrityError on any failure.

Cost-tracker carry-forward is handled separately — call
:func:`carry_forward_cost` on your ``CostTracker`` when rehydrating.

References
----------
- OpenAI Agents SDK next evolution (2026-04-15):
  https://openai.com/index/the-next-evolution-of-the-agents-sdk/
- Sandboxes guide (2026-04-15):
  https://developers.openai.com/api/docs/guides/agents/sandboxes
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

import structlog

from ..exceptions import AirlockError

if TYPE_CHECKING:
    from ..cost_tracking import CostTracker

logger = structlog.get_logger("agent-airlock.mcp_spec.session_guard")

SnapshotProvider = Literal[
    "blaxel",
    "cloudflare",
    "daytona",
    "e2b",
    "modal",
    "runloop",
    "vercel",
]

_KNOWN_PROVIDERS: frozenset[str] = frozenset(
    {"blaxel", "cloudflare", "daytona", "e2b", "modal", "runloop", "vercel"}
)


DEFAULT_MAX_BYTES = 25 * 1024 * 1024  # 25 MiB
DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60  # 24 hours


@dataclass
class SessionSnapshotRef:
    """Metadata for a serialized session snapshot.

    Attributes:
        snapshot_id: Provider-assigned identifier.
        provider: One of the seven OpenAI-sanctioned managed sandboxes.
        digest_sha256: Expected SHA-256 hex digest of the raw payload.
        signed_by: Optional signer identity (e.g. KMS key alias). None
            means unsigned.
        created_at: UTC timestamp of snapshot creation.
        size_bytes: Expected size; compared against the raw payload.
    """

    snapshot_id: str
    provider: SnapshotProvider
    digest_sha256: str
    signed_by: str | None
    created_at: datetime
    size_bytes: int


@dataclass
class SnapshotGuardConfig:
    """Policy applied by :func:`verify_snapshot`."""

    max_bytes: int = DEFAULT_MAX_BYTES
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS
    require_signer_allowlist: frozenset[str] = field(default_factory=frozenset)
    enforce_secret_redaction: bool = True


class SnapshotIntegrityError(AirlockError):
    """Raised when a snapshot fails any integrity check."""

    def __init__(self, *, rule: str, detail: str) -> None:
        self.rule = rule
        self.detail = detail
        super().__init__(f"snapshot integrity check failed [{rule}]: {detail}")


def verify_snapshot(
    ref: SessionSnapshotRef,
    raw: bytes,
    cfg: SnapshotGuardConfig,
) -> None:
    """Verify a serialized session snapshot before trusting it.

    Args:
        ref: Metadata supplied by the sandbox provider.
        raw: The raw bytes of the snapshot payload.
        cfg: Policy to apply.

    Raises:
        SnapshotIntegrityError: On any rule failure. The ``rule``
            attribute identifies which check fired.
    """
    if ref.provider not in _KNOWN_PROVIDERS:
        raise SnapshotIntegrityError(
            rule="unknown_provider",
            detail=(
                f"provider {ref.provider!r} is not one of the seven "
                f"sanctioned providers: {sorted(_KNOWN_PROVIDERS)}"
            ),
        )

    # 1. Size cap (DoS guard).
    if len(raw) > cfg.max_bytes:
        raise SnapshotIntegrityError(
            rule="oversize",
            detail=(f"snapshot is {len(raw)} bytes, exceeds cap {cfg.max_bytes} bytes"),
        )

    # 2. Size metadata consistency — catches simple truncation attacks.
    if ref.size_bytes != len(raw):
        raise SnapshotIntegrityError(
            rule="size_mismatch",
            detail=(f"ref.size_bytes={ref.size_bytes} != len(raw)={len(raw)}"),
        )

    # 3. SHA-256 integrity.
    actual_digest = hashlib.sha256(raw).hexdigest()
    if actual_digest != ref.digest_sha256.lower():
        raise SnapshotIntegrityError(
            rule="digest_mismatch",
            detail=(
                f"recomputed SHA-256 {actual_digest} does not match "
                f"ref.digest_sha256 {ref.digest_sha256!r}"
            ),
        )

    # 4. Freshness.
    now = datetime.now(tz=timezone.utc)
    ref_created = ref.created_at
    if ref_created.tzinfo is None:
        ref_created = ref_created.replace(tzinfo=timezone.utc)
    age = (now - ref_created).total_seconds()
    if age > cfg.max_age_seconds:
        raise SnapshotIntegrityError(
            rule="stale",
            detail=(f"snapshot age {age:.0f}s exceeds max {cfg.max_age_seconds}s"),
        )

    # 5. Signer allow-list (only if caller asked).
    if cfg.require_signer_allowlist:
        if ref.signed_by is None:
            raise SnapshotIntegrityError(
                rule="unsigned",
                detail="signer allow-list is enforced but ref.signed_by is None",
            )
        if ref.signed_by not in cfg.require_signer_allowlist:
            raise SnapshotIntegrityError(
                rule="unknown_signer",
                detail=(f"signer {ref.signed_by!r} is not in the allow-list"),
            )

    # 6. Secret redaction check on the decoded payload. Best-effort:
    # we attempt to decode as UTF-8; if the snapshot is binary
    # (cloudpickle, protobuf) we skip this check and rely on the
    # upstream sandbox provider's own handling.
    if cfg.enforce_secret_redaction:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is not None:
            from ..sanitizer import sanitize_output

            result = sanitize_output(text)
            if result.detections:
                raise SnapshotIntegrityError(
                    rule="embedded_secret",
                    detail=(
                        f"snapshot payload contains "
                        f"{len(result.detections)} sensitive token(s); "
                        "refuse to rehydrate"
                    ),
                )

    logger.debug(
        "snapshot_verified",
        snapshot_id=ref.snapshot_id,
        provider=ref.provider,
        bytes=len(raw),
    )


def carry_forward_cost(tracker: CostTracker, prior_total_tokens: int) -> None:
    """Charge a rehydrated session's prior token usage forward.

    Prevents a "reset-the-budget" attack where a hostile snapshot
    is replayed to wipe the cost tracker. Creates a synthetic
    ``CostRecord`` labelled ``"rehydrated_session"`` so the
    ``CostTracker.get_summary()`` call after rehydration reflects the
    real cumulative token spend.

    Args:
        tracker: The live ``CostTracker`` to augment.
        prior_total_tokens: Token count captured before the snapshot.
    """
    if prior_total_tokens <= 0:
        return
    # Inject a bookkeeping record. Use the tracker's public track()
    # context manager so thread-safety is preserved.
    with tracker.track("rehydrated_session") as ctx:
        ctx.set_tokens(input_tokens=prior_total_tokens, output_tokens=0)


class SnapshotAwareTransport:
    """Mixin for sandbox transports that support snapshot rehydration.

    Drop this into any of the seven supported sandbox backends (Blaxel,
    Cloudflare, Daytona, E2B, Modal, Runloop, Vercel). The mixin adds
    a single method :meth:`rehydrate_with_guard` that verifies the
    snapshot and carries forward cost before handing control back to
    the concrete transport's own rehydration path.
    """

    def rehydrate_with_guard(
        self,
        ref: SessionSnapshotRef,
        raw: bytes,
        cfg: SnapshotGuardConfig,
        tracker: CostTracker | None = None,
        prior_total_tokens: int = 0,
    ) -> None:
        """Verify + rehydrate; concrete transport overrides the actual load."""
        verify_snapshot(ref, raw, cfg)
        if tracker is not None:
            carry_forward_cost(tracker, prior_total_tokens)


__all__ = [
    "DEFAULT_MAX_AGE_SECONDS",
    "DEFAULT_MAX_BYTES",
    "SessionSnapshotRef",
    "SnapshotAwareTransport",
    "SnapshotGuardConfig",
    "SnapshotIntegrityError",
    "SnapshotProvider",
    "carry_forward_cost",
    "verify_snapshot",
]
