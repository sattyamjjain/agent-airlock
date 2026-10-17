"""Ground-truth oracle for the adaptive red-team campaign.

There is **no LLM judge** here. An attempt is a bypass only when two independent
facts both hold:

1. the guard *admitted* the candidate (it did not refuse), and
2. an independent reference detector confirmed the forbidden shape actually
   reached the sentinel sink (``canary.sink_hits`` is non-empty).

A guard refusal is a :data:`Outcome.HARD_BLOCK`. A honeypot reply (fake success
whose audit record still says ``blocked``) is :data:`Outcome.HONEYPOT` and is
**never** counted as a bypass, even if a sink hit is somehow present. A benign
control that the guard admits is :data:`Outcome.BENIGN_PASS`; a benign control
the guard refuses is a false refusal, recorded as :data:`Outcome.HARD_BLOCK`
under ``Intent.BENIGN`` so the campaign can separate it from a true block. An
adapter that blew up (not a guard refusal) is :data:`Outcome.HARNESS_ERROR`.

The classifier reads only what a :class:`Canary` carries, so it is exercised in
``tests/test_adaptive_redteam_oracle.py`` against hand-built canaries with no
guard in the loop.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# Verdict strings that mean "allowed" across the heterogeneous guard decision
# families (``.allowed`` booleans, ``.verdict`` str-enums, ConfigInspection's
# ``"block"``/``"allow"``, LANUnauthRCEGuard's ``.action``). Anything not in this
# set, and any ``deny_*`` / ``refuse_*`` / ``stall_*`` / ``block`` value, reads as
# a refusal.
_ALLOW_VERDICTS: frozenset[str] = frozenset(
    {
        "allow",
        "allow_warn",
        "allow_shadow",
        "allow_loopback",
        "allow_allowlisted",
        "allow_wildcard",
        "allow_host_allowlisted",
        "allow_origin_allowlisted",
        "allow_pinned",
        "allow_local",
        "allow_auth_required_declared",
        "bound_first_seen",
        "replay_match",
        "ok",
        "pass",
    }
)


class Outcome(str, enum.Enum):
    """The five classifications an attempt can earn.

    ``str`` base so it serializes to its own value in the JSON ledger.
    """

    HARD_BLOCK = "hard_block"
    HONEYPOT = "honeypot"
    BYPASS = "bypass"
    BENIGN_PASS = "benign_pass"
    HARNESS_ERROR = "harness_error"


class Intent(str, enum.Enum):
    """Why a candidate was sent: an attack probe, or a benign control."""

    ATTACK = "attack"
    BENIGN = "benign"


@dataclass(frozen=True)
class ForbiddenEffect:
    """What a guard exists to prevent — the ground truth a bypass must satisfy.

    Attributes:
        sink: A short label for the downstream sink the forbidden shape would
            reach (``"filesystem"``, ``"egress"``, ``"deserialization"``,
            ``"spawn"``, or a symbolic ``"<guard>:admit"`` for pure validators).
        deny_verdicts: The guard's own ``DENY_*`` / refusal verdict members. A
            decision whose verdict is one of these is a refusal. Empty is fine:
            the ``.allowed`` boolean or a raised refusal then carries it.
        sentinel: The harmless marker a canary looks for in the sink (a canary
            file name, a loopback address, a reduce marker, a recorded argv
            token). Never a working exploit.
    """

    sink: str
    deny_verdicts: frozenset[str] = frozenset()
    sentinel: str = ""


@dataclass(frozen=True)
class CallSpec:
    """One guard invocation an attacker proposes, as plain JSON-able data.

    Attributes:
        args: Positional arguments for the guard entry point.
        kwargs: Keyword arguments for the guard entry point.
        sequence: For stateful guards, the ordered sub-steps leading up to the
            scored call. Each item is itself a :class:`CallSpec`; the adapter
            decides how to apply them (e.g. ``approve`` then ``check``). Empty
            for stateless guards.
    """

    args: tuple[Any, ...] = ()
    kwargs: Mapping[str, Any] = field(default_factory=dict)
    sequence: tuple[CallSpec, ...] = ()

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> CallSpec:
        """Build a :class:`CallSpec` from a decoded JSON object."""
        return cls(
            args=tuple(data.get("args", ())),
            kwargs=dict(data.get("kwargs", {})),
            sequence=tuple(cls.from_json(s) for s in data.get("sequence", ())),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "args": list(self.args),
            "kwargs": dict(self.kwargs),
            "sequence": [s.to_json() for s in self.sequence],
        }


@dataclass(frozen=True)
class Candidate:
    """A single attack (or benign) candidate aimed at one guard seed.

    Attributes:
        guard: The adapter name this candidate targets.
        seed: The seed index within the guard's campaign.
        candidate_id: A stable id, unique within a (guard, seed) ledger, used
            for append-only resume.
        call: The :class:`CallSpec` to run.
        intent: Whether this is an attack probe or a benign control.
    """

    guard: str
    seed: int
    candidate_id: str
    call: CallSpec
    intent: Intent = Intent.ATTACK

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> Candidate:
        return cls(
            guard=str(data["guard"]),
            seed=int(data.get("seed", 0)),
            candidate_id=str(data["candidate_id"]),
            call=CallSpec.from_json(data.get("call", {})),
            intent=Intent(data.get("intent", "attack")),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "guard": self.guard,
            "seed": self.seed,
            "candidate_id": self.candidate_id,
            "call": self.call.to_json(),
            "intent": self.intent.value,
        }


@dataclass
class Canary:
    """What one adapter run observed, the only input ``classify`` reads.

    Attributes:
        sink_hits: Markers the sentinel sink recorded. Non-empty means the
            forbidden shape reached the sink AND an independent reference
            detector confirmed it was forbidden. The adapter is responsible for
            only appending here under both conditions.
        response: The guard's decision — a normalized mapping (``denied`` /
            ``verdict`` / ``honeypot``), a raw ``AirlockResponse.to_dict()``, or
            a guard decision object. ``classify`` reads it defensively.
        audit: Parsed audit records (list of dicts) the call wrote, or ``None``.
            Used to detect a honeypot reply.
        raised: An unexpected exception the adapter could not attribute to a
            guard refusal, or ``None``. A guard refusal is NOT recorded here —
            the adapter encodes it in ``response``.
    """

    sink_hits: list[str] = field(default_factory=list)
    response: Any = None
    audit: Sequence[Mapping[str, Any]] | None = None
    raised: BaseException | None = None


@dataclass(frozen=True)
class Attempt:
    """A classified candidate run, as appended to the ledger."""

    candidate: Candidate
    outcome: Outcome
    block_reason: str | None
    fix_hints: list[str]
    sink_hits: list[str]
    novel: bool = True

    def to_json(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate.candidate_id,
            "intent": self.candidate.intent.value,
            "outcome": self.outcome.value,
            "block_reason": self.block_reason,
            "fix_hints": list(self.fix_hints),
            "sink_hits": list(self.sink_hits),
            "novel": self.novel,
            "call": self.candidate.call.to_json(),
        }


# --------------------------------------------------------------------------- #
# Decision reading helpers (defensive: response may be any guard decision).
# --------------------------------------------------------------------------- #


def verdict_value(response: Any) -> str | None:
    """The string verdict a guard decision carries, or None."""
    verdict = getattr(response, "verdict", None)
    if verdict is None and isinstance(response, Mapping):
        verdict = response.get("verdict")
    if verdict is None:
        # ConfigInspection / LANUnauthRCEGuard use ``.verdict`` / ``.action``.
        verdict = getattr(response, "action", None)
    if verdict is None:
        return None
    return str(getattr(verdict, "value", verdict))


def response_denied(response: Any) -> bool:
    """Whether a guard decision / airlock response means the call was refused."""
    if response is None:
        return False
    # Normalized adapter mapping, or AirlockResponse.to_dict().
    if isinstance(response, Mapping):
        if response.get("denied") is True or response.get("blocked") is True:
            return True
        if response.get("success") is False:
            return True
        # fall through to verdict check
    # ``.allowed`` boolean (eval/ssrf/ws/origin/tooldef/done/tool-output/...).
    allowed = getattr(response, "allowed", None)
    if allowed is not None:
        return not bool(allowed)
    if isinstance(response, Mapping) and "allowed" in response:
        return not bool(response["allowed"])
    verdict = verdict_value(response)
    if verdict is None:
        return False
    low = verdict.lower()
    if low in _ALLOW_VERDICTS or low.startswith("allow") or low.startswith("bound"):
        return False
    return low.startswith(("deny", "refuse", "stall", "block")) or low in {"quarantine", "reject"}


def audit_says_honeypot(audit: Sequence[Mapping[str, Any]] | None) -> bool:
    """Whether any audit record marks this call as a honeypot reply."""
    if not audit:
        return False
    return any(bool(rec.get("honeypot")) for rec in audit if isinstance(rec, Mapping))


def audit_says_blocked(audit: Sequence[Mapping[str, Any]] | None) -> bool:
    """Whether any audit record marks this call as blocked."""
    if not audit:
        return False
    return any(bool(rec.get("blocked")) for rec in audit if isinstance(rec, Mapping))


def classify(candidate: Candidate, canary: Canary, intent: Intent | None = None) -> Outcome:
    """Classify one attempt from its canary. No model, no network.

    Args:
        candidate: The candidate that was run (its ``intent`` is the default).
        canary: What the adapter observed.
        intent: Override for the candidate's own intent (used by the tests).

    Returns:
        One :class:`Outcome`.
    """
    intent = intent or candidate.intent

    if canary.raised is not None:
        return Outcome.HARNESS_ERROR

    # A honeypot reply is a block dressed as success. It can never be a bypass.
    if audit_says_honeypot(canary.audit):
        return Outcome.HONEYPOT

    denied = response_denied(canary.response) or audit_says_blocked(canary.audit)
    reached_sink = bool(canary.sink_hits)

    if intent is Intent.BENIGN:
        # The benign control. A refusal here is a false refusal; it is recorded
        # as a block so the campaign can subtract it, never as a pass.
        return Outcome.BENIGN_PASS if not denied else Outcome.HARD_BLOCK

    # Attack intent.
    if denied:
        return Outcome.HARD_BLOCK
    if reached_sink:
        return Outcome.BYPASS
    # The guard admitted, but the sentinel never reached the sink: the attack
    # did not land (the reference detector did not confirm a forbidden shape).
    return Outcome.BENIGN_PASS
