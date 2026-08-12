"""Reasoning-block replay binding guard — regression for arXiv:2605.27157.

The repo's stated position (arXiv:2605.27157, upheld by action_contradiction_gate and
sequence_guard) is behaviour over reasoning-trust. This guard does not change that: it never
reads the block, it only *binds* the opaque payload to a session/model/lease and refuses
cross-context replay. These are the decisions the paper's threat model demands.
"""

from __future__ import annotations

import pytest

from agent_airlock import (
    ReasoningReplayError,
    ReasoningReplayGuard,
    ReasoningReplayVerdict,
)

_BLOCK = b"opaque-encrypted-reasoning-block-\x00\x01\x02"
_SESSION = "sess-A"
_MODEL = "claude-opus-5"
_LEASE = "lease-1"


class TestReasoningReplayArxiv2605_27157:
    def test_same_session_replay_allowed(self) -> None:
        guard = ReasoningReplayGuard()
        guard.bind(_BLOCK, session_id=_SESSION, model=_MODEL, lease=_LEASE)
        d = guard.check_replay(_BLOCK, session_id=_SESSION, model=_MODEL, lease=_LEASE)
        assert d.allowed
        assert d.verdict is ReasoningReplayVerdict.REPLAY_MATCH

    def test_cross_session_replay_refused(self) -> None:
        guard = ReasoningReplayGuard()
        guard.bind(_BLOCK, session_id=_SESSION, model=_MODEL, lease=_LEASE)
        d = guard.check_replay(_BLOCK, session_id="sess-B", model=_MODEL, lease=_LEASE)
        assert not d.allowed
        assert d.verdict is ReasoningReplayVerdict.REFUSE_SESSION_MISMATCH

    def test_cross_model_replay_refused(self) -> None:
        guard = ReasoningReplayGuard()
        guard.bind(_BLOCK, session_id=_SESSION, model=_MODEL, lease=_LEASE)
        d = guard.check_replay(_BLOCK, session_id=_SESSION, model="gpt-4o", lease=_LEASE)
        assert not d.allowed
        assert d.verdict is ReasoningReplayVerdict.REFUSE_MODEL_MISMATCH

    def test_absent_binding_is_untrusted_not_trusted(self) -> None:
        # A block that was never minted here, replayed as if returned, is refused — not
        # waved through. Absent binding == untrusted.
        guard = ReasoningReplayGuard()
        d = guard.check_replay(b"never-minted-here", session_id=_SESSION, model=_MODEL)
        assert not d.allowed
        assert d.verdict is ReasoningReplayVerdict.REFUSE_UNBOUND

    def test_check_replay_or_raise_raises_on_refusal(self) -> None:
        guard = ReasoningReplayGuard()
        guard.bind(_BLOCK, session_id=_SESSION, model=_MODEL, lease=_LEASE)
        with pytest.raises(ReasoningReplayError):
            guard.check_replay_or_raise(_BLOCK, session_id="sess-B", model=_MODEL, lease=_LEASE)

    def test_first_mint_is_authoritative(self) -> None:
        # Re-minting the same block under a new context must not launder it: the first
        # binding wins, so the second context's replay is still refused.
        guard = ReasoningReplayGuard()
        guard.bind(_BLOCK, session_id=_SESSION, model=_MODEL, lease=_LEASE)
        guard.bind(_BLOCK, session_id="sess-EVIL", model=_MODEL, lease=_LEASE)
        d = guard.check_replay(_BLOCK, session_id="sess-EVIL", model=_MODEL, lease=_LEASE)
        assert not d.allowed
        assert d.verdict is ReasoningReplayVerdict.REFUSE_SESSION_MISMATCH

    def test_lease_mismatch_refused(self) -> None:
        guard = ReasoningReplayGuard()
        guard.bind(_BLOCK, session_id=_SESSION, model=_MODEL, lease=_LEASE)
        d = guard.check_replay(_BLOCK, session_id=_SESSION, model=_MODEL, lease="lease-2")
        assert not d.allowed
        assert d.verdict is ReasoningReplayVerdict.REFUSE_LEASE_MISMATCH

    def test_guard_never_reads_the_payload(self) -> None:
        # The binding is a SHA-256 fingerprint, not the plaintext — the decision exposes the
        # hash, never the block content.
        guard = ReasoningReplayGuard()
        d = guard.bind(_BLOCK, session_id=_SESSION, model=_MODEL)
        assert d.fingerprint is not None and len(d.fingerprint) == 64
        assert _BLOCK.decode("latin-1") not in (d.detail + (d.fingerprint or ""))
