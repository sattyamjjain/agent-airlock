"""Tests for the v0.8.25 fail-closed terminal-claim guard (no_false_success).

Goal-Autopilot (arXiv:2606.11688) enforces a hard floor for unattended
long-horizon agents: no terminal "done" claim is admitted unless its
falsifiable gate actually executed and passed this run, and the worst case
degrades to an *honest stall, never a fabricated success*. These tests pin the
three core cases from the brief plus the forgery / replay floor:

- (a) a terminal claim with a passing receipt → allowed;
- (b) a terminal claim with NO receipt / a non-executed check → fail-closed
  stall (recoverable);
- (c) a forged receipt (check object present but never executed) → fail-closed.

Honest stall is recoverable; a confident wrong done is not — so every stall
carries ``recoverable=True``.
"""

from __future__ import annotations

import pytest

from agent_airlock import (
    AirlockConfig,
    CheckReceipt,
    DoneClaimVerdict,
    DoneReceiptGuard,
    NoFalseSuccessStall,
    no_false_success_defaults,
)


def _checks(state: dict) -> dict:
    """A registry of falsifiable checks keyed by claim, backed by mutable state."""
    return {
        "tests_green": lambda: state.get("tests_pass", False),
        "deploy_live": lambda: state.get("deployed", False),
    }


# ---------------------------------------------------------------------------
# (a) passing receipt → allowed
# ---------------------------------------------------------------------------


class TestPassingReceiptAllowed:
    def test_executed_and_passed_is_allowed(self) -> None:
        state = {"tests_pass": True}
        guard = DoneReceiptGuard(_checks(state))
        receipt = guard.run("tests_green")  # executes the check THIS run
        assert receipt.executed is True
        assert receipt.passed is True
        decision = guard.check_done("tests_green")
        assert decision.allowed is True
        assert decision.verdict is DoneClaimVerdict.ALLOW
        assert decision.recoverable is False  # success is terminal, not a stall

    def test_preset_check_returns_decision_on_pass(self) -> None:
        preset = no_false_success_defaults({"tests_green": lambda: True})
        preset["guard"].run("tests_green")
        decision = preset["check"]("tests_green")  # does not raise
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# (b) no receipt / non-executed check → fail-closed stall (recoverable)
# ---------------------------------------------------------------------------


class TestNoReceiptStalls:
    def test_no_receipt_is_fail_closed_stall(self) -> None:
        guard = DoneReceiptGuard(_checks({"tests_pass": True}))
        # The check would pass — but it was never run this execution.
        decision = guard.check_done("tests_green")
        assert decision.allowed is False
        assert decision.verdict is DoneClaimVerdict.STALL_NO_RECEIPT
        assert decision.recoverable is True
        assert decision.fix_hints  # tells the agent to run the check + retry

    def test_executed_but_failed_check_stalls(self) -> None:
        state = {"tests_pass": False}
        guard = DoneReceiptGuard(_checks(state))
        guard.run("tests_green")  # executes, returns False
        decision = guard.check_done("tests_green")
        assert decision.allowed is False
        assert decision.verdict is DoneClaimVerdict.STALL_CHECK_FAILED
        assert decision.recoverable is True

    def test_unknown_claim_stalls(self) -> None:
        guard = DoneReceiptGuard(_checks({}))
        decision = guard.check_done("colonize_mars")
        assert decision.allowed is False
        assert decision.verdict is DoneClaimVerdict.STALL_UNKNOWN_CLAIM
        assert decision.recoverable is True

    def test_check_that_raises_counts_as_fail_not_crash(self) -> None:
        def boom() -> bool:
            raise RuntimeError("check blew up")

        guard = DoneReceiptGuard({"risky": boom})
        guard.run("risky")  # must not propagate the exception
        decision = guard.check_done("risky")
        assert decision.verdict is DoneClaimVerdict.STALL_CHECK_FAILED

    def test_preset_check_raises_recoverable_stall(self) -> None:
        preset = no_false_success_defaults({"x": lambda: False})
        preset["guard"].run("x")
        with pytest.raises(NoFalseSuccessStall) as exc:
            preset["check"]("x")
        assert exc.value.recoverable is True
        assert exc.value.decision.verdict is DoneClaimVerdict.STALL_CHECK_FAILED


# ---------------------------------------------------------------------------
# (c) forged receipt (present but never executed) → fail-closed
# ---------------------------------------------------------------------------


class TestForgedReceiptStalls:
    def test_receipt_present_but_not_executed_is_forged(self) -> None:
        guard = DoneReceiptGuard(_checks({"tests_pass": True}))
        # A hand-built receipt: claims passed, but executed=False (default) and
        # carries no live run token — never actually ran the check.
        forged = CheckReceipt(claim="tests_green", passed=True, run_token="made-up")
        decision = guard.check_done("tests_green", receipt=forged)
        assert decision.allowed is False
        assert decision.verdict is DoneClaimVerdict.STALL_FORGED_RECEIPT
        assert decision.recoverable is True

    def test_receipt_with_executed_true_but_wrong_token_is_forged(self) -> None:
        guard = DoneReceiptGuard(_checks({"tests_pass": True}))
        forged = CheckReceipt(
            claim="tests_green", passed=True, run_token="not-the-live-token", executed=True
        )
        decision = guard.check_done("tests_green", receipt=forged)
        assert decision.verdict is DoneClaimVerdict.STALL_FORGED_RECEIPT

    def test_replayed_receipt_from_another_run_is_forged(self) -> None:
        # A genuine receipt from run A, replayed into run B, must not pass —
        # each run mints a distinct token.
        run_a = DoneReceiptGuard(_checks({"tests_pass": True}), run_token="run-A")
        run_b = DoneReceiptGuard(_checks({"tests_pass": True}), run_token="run-B")
        genuine_a = run_a.run("tests_green")
        assert genuine_a.passed is True
        decision = run_b.check_done("tests_green", receipt=genuine_a)
        assert decision.verdict is DoneClaimVerdict.STALL_FORGED_RECEIPT

    def test_live_receipt_passed_explicitly_is_accepted(self) -> None:
        # Passing the guard's own live receipt back in is fine (not forged).
        guard = DoneReceiptGuard(_checks({"tests_pass": True}))
        live = guard.run("tests_green")
        decision = guard.check_done("tests_green", receipt=live)
        assert decision.allowed is True


# ---------------------------------------------------------------------------
# Construction, metadata, config flag, exports
# ---------------------------------------------------------------------------


class TestStructure:
    def test_non_callable_check_raises(self) -> None:
        with pytest.raises(TypeError, match="not callable"):
            DoneReceiptGuard({"bad": "not-a-callable"})  # type: ignore[dict-item]

    def test_run_unknown_claim_raises_keyerror(self) -> None:
        guard = DoneReceiptGuard({"a": lambda: True})
        with pytest.raises(KeyError):
            guard.run("nonexistent")

    def test_registered_claims_sorted(self) -> None:
        guard = DoneReceiptGuard({"z": lambda: True, "a": lambda: True})
        assert guard.registered_claims == ("a", "z")

    def test_distinct_run_tokens_by_default(self) -> None:
        g1 = DoneReceiptGuard({"a": lambda: True})
        g2 = DoneReceiptGuard({"a": lambda: True})
        assert g1.run_token != g2.run_token  # fresh per instance

    def test_preset_canonical_metadata(self) -> None:
        preset = no_false_success_defaults({"a": lambda: True})
        assert preset["preset_id"] == "no_false_success"
        assert preset["default_action"] == "deny"
        assert preset["severity"] == "high"
        assert preset["owasp"] == "ASI06"
        assert preset["advisory_url"] == "https://arxiv.org/abs/2606.11688"
        assert isinstance(preset["guard"], DoneReceiptGuard)

    def test_config_flag_default_off(self) -> None:
        assert AirlockConfig().require_done_receipt is False

    def test_config_flag_constructor_on(self) -> None:
        assert AirlockConfig(require_done_receipt=True).require_done_receipt is True

    def test_config_flag_from_toml(self, tmp_path) -> None:
        toml = tmp_path / "airlock.toml"
        toml.write_text("[airlock]\nrequire_done_receipt = true\n")
        assert AirlockConfig.from_toml(toml).require_done_receipt is True

    def test_public_exports_present(self) -> None:
        import agent_airlock as a

        for name in (
            "DoneReceiptGuard",
            "DoneClaimDecision",
            "DoneClaimVerdict",
            "CheckReceipt",
            "NoFalseSuccessStall",
            "no_false_success_defaults",
        ):
            assert hasattr(a, name) and name in a.__all__


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
