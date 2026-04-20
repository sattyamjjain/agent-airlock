"""Session-snapshot integrity guard regression tests (v0.5.2+).

Covers the OpenAI Agents SDK "next evolution" (2026-04-15) session-
snapshot surface. The seven sanctioned providers are Blaxel, Cloudflare,
Daytona, E2B, Modal, Runloop, and Vercel.

Primary sources
---------------
- OpenAI Agents SDK next evolution (2026-04-15):
  https://openai.com/index/the-next-evolution-of-the-agents-sdk/
- Sandboxes guide (2026-04-15):
  https://developers.openai.com/api/docs/guides/agents/sandboxes
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from agent_airlock import CostTracker
from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.session_guard import (
    DEFAULT_MAX_BYTES,
    SessionSnapshotRef,
    SnapshotAwareTransport,
    SnapshotGuardConfig,
    SnapshotIntegrityError,
    carry_forward_cost,
    verify_snapshot,
)


def _ref(
    raw: bytes,
    provider: str = "e2b",
    signed_by: str | None = None,
    created_at: datetime | None = None,
) -> SessionSnapshotRef:
    return SessionSnapshotRef(
        snapshot_id="snap-abc123",
        provider=provider,  # type: ignore[arg-type]
        digest_sha256=hashlib.sha256(raw).hexdigest(),
        signed_by=signed_by,
        created_at=created_at or datetime.now(tz=timezone.utc),
        size_bytes=len(raw),
    )


class TestSnapshotVerify:
    def test_01_digest_match_passes(self) -> None:
        raw = b'{"agent":"ok","tokens":10}'
        verify_snapshot(_ref(raw), raw, SnapshotGuardConfig())

    def test_02_digest_mismatch_raises(self) -> None:
        raw = b"original"
        ref = _ref(raw)
        with pytest.raises(SnapshotIntegrityError) as exc:
            verify_snapshot(ref, b"tampered", SnapshotGuardConfig())
        # size_mismatch fires first because len differs; that's correct behavior.
        assert exc.value.rule in {"digest_mismatch", "size_mismatch"}

    def test_03_stale_snapshot_rejected(self) -> None:
        raw = b"old"
        old_time = datetime.now(tz=timezone.utc) - timedelta(days=3)
        ref = _ref(raw, created_at=old_time)
        with pytest.raises(SnapshotIntegrityError) as exc:
            verify_snapshot(ref, raw, SnapshotGuardConfig())
        assert exc.value.rule == "stale"

    def test_04_oversize_snapshot_rejected(self) -> None:
        raw = b"X" * (DEFAULT_MAX_BYTES + 1)
        ref = _ref(raw)
        with pytest.raises(SnapshotIntegrityError) as exc:
            verify_snapshot(ref, raw, SnapshotGuardConfig())
        assert exc.value.rule == "oversize"

    def test_05_unknown_signer_rejected(self) -> None:
        raw = b"{}"
        ref = _ref(raw, signed_by="evil-key")
        cfg = SnapshotGuardConfig(require_signer_allowlist=frozenset({"good-key"}))
        with pytest.raises(SnapshotIntegrityError) as exc:
            verify_snapshot(ref, raw, cfg)
        assert exc.value.rule == "unknown_signer"

    def test_06_redaction_enforced(self) -> None:
        """A plaintext AWS secret in the snapshot must refuse rehydration."""
        # Use a payload that sanitizer recognises. AWS access key IDs
        # start with 'AKIA' followed by 16 uppercase alphanumerics.
        raw = b"state=ok; creds=AKIAIOSFODNN7EXAMPLE"
        ref = _ref(raw)
        with pytest.raises(SnapshotIntegrityError) as exc:
            verify_snapshot(ref, raw, SnapshotGuardConfig())
        assert exc.value.rule == "embedded_secret"

    def test_07_all_seven_providers_accepted(self) -> None:
        raw = b"{}"
        for provider in ("blaxel", "cloudflare", "daytona", "e2b", "modal", "runloop", "vercel"):
            verify_snapshot(_ref(raw, provider=provider), raw, SnapshotGuardConfig())

    def test_08_unknown_provider_rejected(self) -> None:
        raw = b"{}"
        ref = _ref(raw, provider="attacker-cloud")
        with pytest.raises(SnapshotIntegrityError) as exc:
            verify_snapshot(ref, raw, SnapshotGuardConfig())
        assert exc.value.rule == "unknown_provider"


class TestCostCarryForward:
    def test_prior_tokens_charged_forward(self) -> None:
        tracker = CostTracker()
        carry_forward_cost(tracker, prior_total_tokens=12_345)
        assert tracker.get_summary().total_tokens == 12_345

    def test_zero_prior_noop(self) -> None:
        tracker = CostTracker()
        carry_forward_cost(tracker, prior_total_tokens=0)
        assert tracker.get_summary().total_tokens == 0

    def test_cannot_reset_budget_via_rehydration(self) -> None:
        """Replaying an older snapshot must NOT wipe cumulative usage."""
        tracker = CostTracker()
        with tracker.track("first_call") as ctx:
            ctx.set_tokens(input_tokens=500, output_tokens=500)
        # Simulate rehydration from an older snapshot that saw 200 tokens.
        carry_forward_cost(tracker, prior_total_tokens=200)
        # Total is the sum; the attacker cannot "rewind".
        assert tracker.get_summary().total_tokens == 1200


class TestTransportMixin:
    def test_rehydrate_with_guard_ok(self) -> None:
        raw = b'{"agent":"ok"}'
        t = SnapshotAwareTransport()
        tracker = CostTracker()
        t.rehydrate_with_guard(
            _ref(raw), raw, SnapshotGuardConfig(), tracker=tracker, prior_total_tokens=42
        )
        assert tracker.get_summary().total_tokens == 42

    def test_rehydrate_with_guard_rejects_tampered(self) -> None:
        raw = b'{"agent":"ok"}'
        ref = _ref(raw)
        t = SnapshotAwareTransport()
        with pytest.raises(AirlockError):
            t.rehydrate_with_guard(ref, b"tampered", SnapshotGuardConfig())
