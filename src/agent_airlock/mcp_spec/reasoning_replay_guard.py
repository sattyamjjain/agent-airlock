"""Reasoning-block replay binding guard (v0.8.70+, arXiv:2605.27157 anchor).

This repo's position is **behaviour over reasoning-trust**:
:mod:`agent_airlock.action_contradiction_gate` and :mod:`agent_airlock.sequence_guard` both
refuse to trust a model's *stated* reasoning, citing arXiv:2605.27157. This guard does **not**
change that position. It closes a different gap.

A provider-returned **encrypted / opaque reasoning block** (e.g. a redacted or signed thinking
block) arrives as an opaque string, is passed back on the next turn to continue the thought, and
**nothing checks that the block belongs to this session**. A block minted in one session — or by
a different model — that is replayed into another is accepted today.

This guard does not parse, decode, or interpret the block — consistent with the "don't trust
reasoning" position; it never reads what the block *says*. It **binds** it:

- :meth:`ReasoningReplayGuard.bind` — on first sight, record a SHA-256 of the opaque payload
  against the current ``session_id`` / ``model`` / ``lease``.
- :meth:`ReasoningReplayGuard.check_replay` — on replay, **refuse** when the binding does not
  match (a different session, model, or lease), and treat an **absent** binding as *untrusted*
  (a block never minted here) rather than trusted. Deny-by-default.

Limit: this stops **replay** — a block minted elsewhere reused here. It does **nothing** about a
payload that was malicious the first time it arrived; binding proves provenance-within-session,
not benignity.

Primary source (retrieved 2026-08-12):
  https://arxiv.org/abs/2605.27157
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.reasoning_replay_guard")

__all__ = [
    "ReasoningReplayDecision",
    "ReasoningReplayError",
    "ReasoningReplayGuard",
    "ReasoningReplayVerdict",
]


class ReasoningReplayVerdict(str, enum.Enum):
    """Stable reason codes for :class:`ReasoningReplayDecision`."""

    BOUND_FIRST_SEEN = "bound_first_seen"  # allow: recorded against the session on first sight
    REPLAY_MATCH = "replay_match"  # allow: replay binding matches
    REFUSE_SESSION_MISMATCH = "refuse_session_mismatch"  # bound to a different session
    REFUSE_MODEL_MISMATCH = "refuse_model_mismatch"  # bound to a different model
    REFUSE_LEASE_MISMATCH = "refuse_lease_mismatch"  # bound to a different lease
    REFUSE_UNBOUND = "refuse_unbound"  # replay of a block never minted here — untrusted


@dataclass(frozen=True)
class ReasoningReplayDecision:
    """Outcome of a single :meth:`ReasoningReplayGuard.bind` / ``check_replay`` call.

    Exposes ``allowed: bool`` for chain-friendly composition, like the other guard decisions.

    Attributes:
        allowed: True iff the block may be used in the presented context.
        verdict: A stable :class:`ReasoningReplayVerdict` value.
        detail: Free-form human-readable explanation.
        fingerprint: SHA-256 of the opaque payload (never its plaintext).
        session_id: The session the check was made against.
        model: The model the check was made against.
        lease: The lease the check was made against.
        fix_hints: Operator-actionable remediation hints.
    """

    allowed: bool
    verdict: ReasoningReplayVerdict
    detail: str
    fingerprint: str | None = None
    session_id: str | None = None
    model: str | None = None
    lease: str | None = None
    fix_hints: list[str] = field(default_factory=list)


class ReasoningReplayError(AirlockError):
    """Raised on a refused reasoning-block replay (fail-closed).

    Carries the :class:`ReasoningReplayDecision` and exposes ``fix_hints``.
    """

    def __init__(self, decision: ReasoningReplayDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        super().__init__(decision.detail)


@dataclass(frozen=True)
class _Binding:
    session_id: str
    model: str
    lease: str


class ReasoningReplayGuard:
    """Bind opaque reasoning blocks to a session/model/lease; refuse cross-context replay.

    Stateful: keeps an in-memory ``fingerprint -> binding`` map that survives across turns within
    the process. Instantiate one per binding scope. The guard never inspects the payload beyond
    hashing it.
    """

    def __init__(self) -> None:
        self._bindings: dict[str, _Binding] = {}

    @staticmethod
    def _fingerprint(payload: str | bytes) -> str:
        data = payload.encode("utf-8") if isinstance(payload, str) else payload
        return hashlib.sha256(data).hexdigest()

    def bind(
        self,
        payload: str | bytes,
        *,
        session_id: str,
        model: str,
        lease: str = "*",
    ) -> ReasoningReplayDecision:
        """Record a reasoning block on first sight (mint).

        The first binding for a fingerprint is authoritative: a later ``bind`` with a different
        (session, model, lease) does not overwrite it, so a mint cannot be laundered by re-minting
        under a new context. Returns a ``BOUND_FIRST_SEEN`` decision (always allowed).
        """
        fingerprint = self._fingerprint(payload)
        self._bindings.setdefault(fingerprint, _Binding(session_id, model, lease))
        return ReasoningReplayDecision(
            allowed=True,
            verdict=ReasoningReplayVerdict.BOUND_FIRST_SEEN,
            detail=(
                f"reasoning block bound to session={session_id!r} model={model!r} lease={lease!r}"
            ),
            fingerprint=fingerprint,
            session_id=session_id,
            model=model,
            lease=lease,
        )

    def check_replay(
        self,
        payload: str | bytes,
        *,
        session_id: str,
        model: str,
        lease: str = "*",
    ) -> ReasoningReplayDecision:
        """Verify a replayed reasoning block against its binding. Deny-by-default.

        Refuses when the block is bound to a different session, model, or lease, and refuses an
        **unbound** block (one never minted here) as untrusted — the check never binds.
        """
        fingerprint = self._fingerprint(payload)
        bound = self._bindings.get(fingerprint)

        if bound is None:
            return ReasoningReplayDecision(
                allowed=False,
                verdict=ReasoningReplayVerdict.REFUSE_UNBOUND,
                detail=(
                    "reasoning block was never minted in this binding scope; an unbound block "
                    "replayed as a returned reasoning block is treated as untrusted, not trusted"
                ),
                fingerprint=fingerprint,
                session_id=session_id,
                model=model,
                lease=lease,
                fix_hints=["Only pass back a reasoning block this session actually minted."],
            )

        if bound.session_id != session_id:
            verdict = ReasoningReplayVerdict.REFUSE_SESSION_MISMATCH
            why = f"bound to session {bound.session_id!r}, replayed into {session_id!r}"
        elif bound.model != model:
            verdict = ReasoningReplayVerdict.REFUSE_MODEL_MISMATCH
            why = f"bound to model {bound.model!r}, replayed against {model!r}"
        elif bound.lease != lease:
            verdict = ReasoningReplayVerdict.REFUSE_LEASE_MISMATCH
            why = f"bound to lease {bound.lease!r}, replayed against {lease!r}"
        else:
            return ReasoningReplayDecision(
                allowed=True,
                verdict=ReasoningReplayVerdict.REPLAY_MATCH,
                detail="reasoning block replay matches its session/model/lease binding",
                fingerprint=fingerprint,
                session_id=session_id,
                model=model,
                lease=lease,
            )

        return ReasoningReplayDecision(
            allowed=False,
            verdict=verdict,
            detail=f"reasoning-block replay refused: {why}",
            fingerprint=fingerprint,
            session_id=session_id,
            model=model,
            lease=lease,
            fix_hints=[
                "A reasoning block is valid only in the session/model/lease that minted it."
            ],
        )

    def check_replay_or_raise(
        self,
        payload: str | bytes,
        *,
        session_id: str,
        model: str,
        lease: str = "*",
    ) -> ReasoningReplayDecision:
        """Like :meth:`check_replay` but raises :class:`ReasoningReplayError` on refusal."""
        decision = self.check_replay(payload, session_id=session_id, model=model, lease=lease)
        if not decision.allowed:
            logger.warning(
                "reasoning_replay_refused",
                verdict=decision.verdict.value,
                fingerprint=decision.fingerprint,
                session_id=session_id,
                model=model,
                lease=lease,
            )
            raise ReasoningReplayError(decision)
        return decision
