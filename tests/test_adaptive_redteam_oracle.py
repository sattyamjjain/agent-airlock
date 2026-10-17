"""The oracle on synthetic canaries — one case per outcome, and the invariants.

No guard is in the loop here: ``classify`` reads only a :class:`Canary`, so these
cases are hand-built. The load-bearing invariant is that a honeypot reply is never
a bypass, even when a sentinel sink fired.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT / "src"), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from benchmarks.adaptive_redteam.oracle import (  # noqa: E402
    CallSpec,
    Canary,
    Candidate,
    Intent,
    Outcome,
    classify,
    response_denied,
    verdict_value,
)


def _candidate(intent: Intent = Intent.ATTACK) -> Candidate:
    return Candidate(
        guard="g", seed=0, candidate_id="g-0", call=CallSpec(kwargs={"x": 1}), intent=intent
    )


def test_hard_block_when_guard_refused_attack() -> None:
    canary = Canary(response={"denied": True, "verdict": "deny_x"})
    assert classify(_candidate(), canary) is Outcome.HARD_BLOCK


def test_bypass_when_admitted_and_sink_reached() -> None:
    canary = Canary(response={"denied": False}, sink_hits=["egress:169.254.169.254"])
    assert classify(_candidate(), canary) is Outcome.BYPASS


def test_benign_pass_when_admitted_attack_but_no_sink() -> None:
    canary = Canary(response={"denied": False}, sink_hits=[])
    assert classify(_candidate(), canary) is Outcome.BENIGN_PASS


def test_benign_control_admitted_is_benign_pass() -> None:
    canary = Canary(response={"denied": False})
    assert classify(_candidate(Intent.BENIGN), canary) is Outcome.BENIGN_PASS


def test_benign_control_refused_is_false_refusal_hard_block() -> None:
    canary = Canary(response={"denied": True, "verdict": "deny_x"})
    assert classify(_candidate(Intent.BENIGN), canary) is Outcome.HARD_BLOCK


def test_honeypot_is_never_bypass_even_with_sink_hit() -> None:
    # Fake success, but the audit record says blocked+honeypot, and a sink hit is
    # present: the oracle must still classify it as honeypot, not bypass.
    canary = Canary(
        response={"denied": False, "success": True},
        audit=[{"blocked": True, "honeypot": True}],
        sink_hits=["egress:169.254.169.254"],
    )
    assert classify(_candidate(), canary) is Outcome.HONEYPOT


def test_harness_error_when_adapter_raised() -> None:
    canary = Canary(raised=RuntimeError("adapter blew up"))
    assert classify(_candidate(), canary) is Outcome.HARNESS_ERROR


def test_audit_blocked_counts_as_denied() -> None:
    canary = Canary(response={"success": True}, audit=[{"blocked": True}])
    assert classify(_candidate(), canary) is Outcome.HARD_BLOCK


def test_response_denied_reads_airlock_response_dict() -> None:
    assert response_denied({"success": False, "block_reason": "policy_violation"})
    assert not response_denied({"success": True})


def test_response_denied_reads_allowed_boolean() -> None:
    class Decision:
        allowed = False
        verdict = "deny_metadata"

    assert response_denied(Decision())


def test_response_denied_reads_verdict_enum_values() -> None:
    class AllowDecision:
        verdict = "allow_loopback"

    class DenyDecision:
        verdict = "deny_forbidden_host"

    assert not response_denied(AllowDecision())
    assert response_denied(DenyDecision())
    assert verdict_value(DenyDecision()) == "deny_forbidden_host"


def test_callspec_round_trip() -> None:
    spec = CallSpec(kwargs={"url": "x"}, sequence=(CallSpec(kwargs={"tool": "read"}),))
    assert CallSpec.from_json(spec.to_json()) == spec


def test_candidate_round_trip() -> None:
    cand = _candidate()
    assert Candidate.from_json(cand.to_json()) == cand
