"""Fail-closed terminal-claim guard (v0.8.25+, Goal-Autopilot anchor).

Goal-Autopilot (arXiv:2606.11688, "A Verifiable Anti-Fabrication Firewall for
Unattended Long-Horizon Agents", 2026-06-10) frames the core unattended-agent
risk: a long-horizon agent **confidently reports success it never verified**.
Its No-False-Success result enforces a hard floor — *no terminal "done" claim
is admitted unless its falsifiable gate actually executed and passed* — and
proves the worst case degrades to an **honest stall, never a fabricated
success**.

This module is that floor as an agent-airlock guard. It holds a registry of
falsifiable checks keyed by claim. On a terminal/``done`` tool-call it verifies
the matching check **ran and passed in THIS execution**; if not, it fails
closed and returns a recoverable *honest stall* outcome instead of admitting
the terminal claim.

Why a per-run token (forgery resistance)
----------------------------------------
A check "passed" is only trusted if the guard itself executed it this run. The
guard mints a fresh ``run_token`` at construction; :meth:`DoneReceiptGuard.run`
stamps each receipt with that token as proof of execution. A receipt that is
merely *present* — fabricated, replayed from a previous run, or constructed
without ever calling the check — does not carry the live token and is rejected
as forged. This is the difference between "a check object exists" and "the
check ran and passed now".

Recoverable by design
---------------------
Every stall is ``recoverable=True``: the honest move is to run the named check
and retry, not to abort. As Goal-Autopilot puts it, an honest stall is
recoverable; a confident wrong ``done`` is not.

Zero-runtime-dep: stdlib ``secrets`` / ``time`` only — the Pydantic-only core
is preserved.

Primary source:
  https://arxiv.org/abs/2606.11688
"""

from __future__ import annotations

import enum
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

import structlog

from .exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.done_receipt_guard")

# A falsifiable check: a zero-arg callable returning True iff the claim holds.
# It must be able to FAIL (return False / raise) — a check that can only return
# True is not falsifiable and provides no evidence.
FalsifiableCheck = Callable[[], bool]


class DoneClaimVerdict(str, enum.Enum):
    """Stable reason codes for :class:`DoneClaimDecision`."""

    ALLOW = "allow"
    STALL_NO_RECEIPT = "stall_no_receipt"  # claim made, check never ran this run
    STALL_CHECK_FAILED = "stall_check_failed"  # check ran and returned False
    STALL_FORGED_RECEIPT = "stall_forged_receipt"  # receipt present but not executed this run
    STALL_UNKNOWN_CLAIM = "stall_unknown_claim"  # no falsifiable check registered for claim


@dataclass(frozen=True)
class CheckReceipt:
    """Evidence that a falsifiable check executed (and its pass/fail) this run.

    Attributes:
        claim: The terminal claim this receipt is evidence for.
        passed: True iff the check returned True when executed.
        run_token: The guard's per-run token, stamped at execution time. A
            receipt whose ``run_token`` does not match the guard's live token
            is forged / stale and is rejected.
        executed: True iff the guard actually ran the check to produce this
            receipt. A hand-built receipt left at the default ``False`` is
            rejected even before the token check.
        elapsed_ms: Wall-time the check took, for the audit trail.
    """

    claim: str
    passed: bool
    run_token: str
    executed: bool = False
    elapsed_ms: float = 0.0


@dataclass(frozen=True)
class DoneClaimDecision:
    """Outcome of a single :meth:`DoneReceiptGuard.check_done` call.

    Mirrors the v0.7.x / v0.8.x guard decision family — exposes
    ``allowed: bool`` so integrators can chain on one short-circuit predicate.

    Attributes:
        allowed: True iff the terminal claim is admitted (its check ran and
            passed this run). False = fail-closed honest stall.
        verdict: A stable :class:`DoneClaimVerdict` value.
        detail: Free-form human-readable explanation.
        claim: The terminal claim evaluated.
        recoverable: Always True for a stall — the agent should run the named
            check and retry, not abort. (An honest stall is recoverable; a
            confident wrong ``done`` is not.)
        fix_hints: LLM-actionable remediation hints.
    """

    allowed: bool
    verdict: DoneClaimVerdict
    detail: str
    claim: str
    recoverable: bool = False
    fix_hints: list[str] = field(default_factory=list)


class NoFalseSuccessStall(AirlockError):
    """Raised by the ``no_false_success`` preset's ``check`` on a fail-closed stall.

    Carries the :class:`DoneClaimDecision` and exposes ``fix_hints`` +
    ``recoverable`` so an upstream airlock layer can route the refusal into a
    retry of the named check rather than an abort (an honest stall is
    recoverable; a confident wrong ``done`` is not).

    Attributes:
        decision: The stall decision that triggered the refusal.
        fix_hints: LLM-actionable remediation hints.
        recoverable: Always True — run the named check and retry.
    """

    def __init__(self, decision: DoneClaimDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        self.recoverable = decision.recoverable
        super().__init__(decision.detail)


class DoneReceiptGuard:
    """Fail-closed gate that rejects a terminal claim without a live, passing receipt.

    Construct with a registry of falsifiable checks keyed by claim. Run a check
    with :meth:`run` (which stamps a receipt with the live run token), then call
    :meth:`check_done` on the terminal/``done`` claim — it is admitted only when
    a receipt for that claim exists, was executed THIS run, and passed.

    Args:
        checks: Mapping of claim → falsifiable check (zero-arg ``() -> bool``).
        run_token: The per-run execution token. Defaults to a fresh random
            token; pass a fixed value only for deterministic tests.

    Raises:
        TypeError: a registered check is not callable.
    """

    def __init__(
        self,
        checks: Mapping[str, FalsifiableCheck],
        *,
        run_token: str | None = None,
    ) -> None:
        for claim, fn in checks.items():
            if not callable(fn):
                raise TypeError(f"check for claim {claim!r} is not callable: {fn!r}")
        self._checks: dict[str, FalsifiableCheck] = dict(checks)
        self._run_token = run_token or secrets.token_hex(16)
        self._receipts: dict[str, CheckReceipt] = {}

    @property
    def run_token(self) -> str:
        """The live per-run execution token receipts are bound to."""
        return self._run_token

    @property
    def registered_claims(self) -> tuple[str, ...]:
        """The claims that have a falsifiable check registered (sorted)."""
        return tuple(sorted(self._checks))

    def run(self, claim: str) -> CheckReceipt:
        """Execute the falsifiable check for ``claim`` and record a live receipt.

        Args:
            claim: The claim whose check to execute.

        Returns:
            The :class:`CheckReceipt` (also stored internally), stamped with the
            live run token and the executed pass/fail.

        Raises:
            KeyError: no check is registered for ``claim``.
        """
        if claim not in self._checks:
            raise KeyError(f"no falsifiable check registered for claim {claim!r}")
        start = _now_ms()
        try:
            passed = bool(self._checks[claim]())
        except Exception as exc:  # a check that raises is a FAIL, not a crash
            logger.warning("done_receipt_check_raised", claim=claim, error=str(exc))
            passed = False
        receipt = CheckReceipt(
            claim=claim,
            passed=passed,
            run_token=self._run_token,
            executed=True,
            elapsed_ms=round(_now_ms() - start, 3),
        )
        self._receipts[claim] = receipt
        logger.info("done_receipt_recorded", claim=claim, passed=passed)
        return receipt

    def check_done(
        self,
        claim: str,
        *,
        receipt: CheckReceipt | None = None,
    ) -> DoneClaimDecision:
        """Admit a terminal claim only if its check ran and passed this run.

        Args:
            claim: The terminal/``done`` claim being made.
            receipt: Optional externally-supplied receipt. When omitted, the
                guard uses the receipt it recorded via :meth:`run`. An external
                receipt is still validated against the live run token — a
                fabricated one is rejected as forged.

        Returns:
            :class:`DoneClaimDecision`. ``allowed=False`` is a recoverable
            honest stall; map it to a retry of the named check, not an abort.
        """
        if claim not in self._checks:
            return self._stall(
                DoneClaimVerdict.STALL_UNKNOWN_CLAIM,
                claim,
                f"terminal claim {claim!r} has no registered falsifiable check; "
                f"cannot verify success",
                [
                    f"Register a falsifiable check for {claim!r} before claiming done.",
                    f"Known claims: {', '.join(self.registered_claims) or '<none>'}",
                ],
            )

        effective = receipt if receipt is not None else self._receipts.get(claim)
        if effective is None:
            return self._stall(
                DoneClaimVerdict.STALL_NO_RECEIPT,
                claim,
                f"terminal claim {claim!r} made but its check never executed this run",
                [
                    f"Run the {claim!r} check this execution (guard.run({claim!r})) "
                    f"and only then claim done.",
                ],
            )

        # Forgery floor: the receipt must have been executed AND carry the live
        # run token. A present-but-not-executed receipt, or one stamped with a
        # stale/foreign token (replayed or fabricated), is rejected.
        if not effective.executed or not _token_matches(effective.run_token, self._run_token):
            return self._stall(
                DoneClaimVerdict.STALL_FORGED_RECEIPT,
                claim,
                f"receipt for {claim!r} is not bound to this execution "
                f"(executed={effective.executed}, token_match="
                f"{_token_matches(effective.run_token, self._run_token)}) — refusing",
                [
                    "A receipt only counts if THIS guard executed the check this run.",
                    f"Call guard.run({claim!r}) to produce a live receipt; do not "
                    f"construct or replay one.",
                ],
            )

        if not effective.passed:
            return self._stall(
                DoneClaimVerdict.STALL_CHECK_FAILED,
                claim,
                f"the {claim!r} check executed this run and FAILED — refusing the terminal claim",
                [
                    f"The {claim!r} check returned false. Do the work so the check "
                    f"passes, then re-run it and claim done.",
                ],
            )

        logger.info("done_claim_allowed", claim=claim)
        return DoneClaimDecision(
            allowed=True,
            verdict=DoneClaimVerdict.ALLOW,
            detail=f"terminal claim {claim!r} verified: check executed this run and passed",
            claim=claim,
            recoverable=False,
            fix_hints=[],
        )

    def _stall(
        self,
        verdict: DoneClaimVerdict,
        claim: str,
        detail: str,
        fix_hints: list[str],
    ) -> DoneClaimDecision:
        logger.warning("done_claim_stalled", claim=claim, verdict=verdict.value)
        return DoneClaimDecision(
            allowed=False,
            verdict=verdict,
            detail=detail,
            claim=claim,
            recoverable=True,
            fix_hints=fix_hints,
        )


def _now_ms() -> float:
    import time

    return time.monotonic() * 1000.0


def _token_matches(a: str, b: str) -> bool:
    """Constant-time token compare (tokens are unforgeable secrets)."""
    import hmac

    return bool(a) and bool(b) and hmac.compare_digest(a, b)


__all__ = [
    "CheckReceipt",
    "DoneClaimDecision",
    "DoneClaimVerdict",
    "DoneReceiptGuard",
    "FalsifiableCheck",
    "NoFalseSuccessStall",
]
