"""Tests for the v0.8.24 trace-redaction guard + per-tenant watermark.

Why traces are an extraction surface: an emitted trace that records tuned
thresholds, tool-call args, and recovered strategies hands a competitor the
*recipe*. The verifier only needs the *evidence* (gate ran / policy fired /
pass-fail). This suite pins the core guarantees:

- a trace that leaks a tuned threshold pre-redaction must NOT leak it
  post-redaction, while the verifier-evidence field survives;
- the per-tenant watermark round-trips (embed → detect), and a wrong
  tenant / wrong key / tampered trace does not falsely detect;
- the policy is OFF by default (backward compat) and ON under STRICT.

Watermark design is RedAct-style behavioural watermarking; see
``agent_airlock.trace_redaction`` for the cited references.
"""

from __future__ import annotations

import json

import pytest

from agent_airlock import (
    ProtectedFieldClass,
    SecurityPolicy,
    TraceRedactionPolicy,
    trace_redact,
    verify_watermark,
)
from agent_airlock.policy import STRICT_POLICY
from agent_airlock.trace_redaction import WATERMARK_KEY

_TUNED = 0.8137  # the tuned threshold an attacker wants to distill


def _leaky_trace() -> dict:
    """A trace that leaks the recipe alongside verifier-critical evidence."""
    return {
        "tool_name": "score_lead",
        "blocked": False,
        "block_reason": None,
        "policy_id": "strict-v1",
        "verdict": "pass",
        "passed": True,
        "tuned_threshold": _TUNED,  # PROTECTED — tuned recipe
        "tool_args": {"prompt": "PROPRIETARY-SYSTEM-PROMPT", "k": 12},  # PROTECTED
        "recovered_strategy": "buy when RSI<30 then scale in",  # PROTECTED
        "nested": {"temperature": 0.42, "reason": "policy fired"},
    }


def _policy() -> TraceRedactionPolicy:
    return TraceRedactionPolicy(enabled=True, tenant_id="acme-co", watermark_secret="s3cr3t")


# ---------------------------------------------------------------------------
# Recipe dropped, evidence preserved
# ---------------------------------------------------------------------------


class TestRedactionDropsRecipeKeepsEvidence:
    def test_tuned_threshold_leaks_pre_redaction(self) -> None:
        # Sanity: the raw trace really does carry the secret.
        assert str(_TUNED) in json.dumps(_leaky_trace())

    def test_tuned_threshold_does_not_leak_post_redaction(self) -> None:
        redacted, _ = trace_redact(_leaky_trace(), _policy())
        blob = json.dumps(redacted)
        assert str(_TUNED) not in blob
        assert "PROPRIETARY-SYSTEM-PROMPT" not in blob
        assert "RSI<30" not in blob
        assert "0.42" not in blob  # nested tuned value also gone

    def test_verifier_evidence_survives(self) -> None:
        redacted, _ = trace_redact(_leaky_trace(), _policy())
        assert redacted["blocked"] is False
        assert redacted["policy_id"] == "strict-v1"
        assert redacted["verdict"] == "pass"
        assert redacted["passed"] is True
        assert redacted["nested"]["reason"] == "policy fired"

    def test_protected_field_becomes_evidence_stub(self) -> None:
        redacted, _ = trace_redact(_leaky_trace(), _policy())
        stub = redacted["tuned_threshold"]
        assert stub["_redacted"] is True
        assert stub["class"] == ProtectedFieldClass.TUNED_THRESHOLD.value
        assert stub["value"] == _policy().placeholder

    def test_pass_fail_bool_bit_preserved_in_protected_field(self) -> None:
        # A protected field whose value is a bare bool keeps the pass/fail bit
        # (verifier evidence) while still being marked redacted.
        pol = _policy()
        redacted, _ = trace_redact({"strategy_passed": True}, pol)
        assert redacted["strategy_passed"]["_redacted"] is True
        assert redacted["strategy_passed"]["pass_fail"] is True

    def test_report_localized_rewritten_preserved(self) -> None:
        _, report = trace_redact(_leaky_trace(), _policy())
        localized_paths = {p for p, _ in report.localized}
        assert {"tuned_threshold", "tool_args", "recovered_strategy", "nested.temperature"} <= (
            localized_paths
        )
        assert set(report.rewritten) == localized_paths
        assert {"tool_name", "blocked", "policy_id", "verdict", "passed", "nested.reason"} <= set(
            report.preserved
        )


# ---------------------------------------------------------------------------
# Watermark round-trip + false-alarm resistance
# ---------------------------------------------------------------------------


class TestWatermark:
    def test_watermark_round_trips(self) -> None:
        pol = _policy()
        redacted, report = trace_redact(_leaky_trace(), pol)
        assert WATERMARK_KEY in redacted
        verdict = verify_watermark(redacted, pol)
        assert verdict.detected is True
        assert verdict.reason == "detected"
        assert verdict.tenant_fp == report.tenant_fp

    def test_wrong_tenant_not_detected(self) -> None:
        redacted, _ = trace_redact(_leaky_trace(), _policy())
        other = TraceRedactionPolicy(enabled=True, tenant_id="other-co", watermark_secret="s3cr3t")
        verdict = verify_watermark(redacted, other)
        assert verdict.detected is False
        assert verdict.reason == "tenant_mismatch"

    def test_wrong_key_not_detected(self) -> None:
        redacted, _ = trace_redact(_leaky_trace(), _policy())
        same_tenant_wrong_key = TraceRedactionPolicy(
            enabled=True, tenant_id="acme-co", watermark_secret="WRONG"
        )
        verdict = verify_watermark(redacted, same_tenant_wrong_key)
        assert verdict.detected is False
        assert verdict.reason == "token_mismatch"

    def test_tampered_trace_not_detected(self) -> None:
        pol = _policy()
        redacted, _ = trace_redact(_leaky_trace(), pol)
        redacted["passed"] = False  # flip evidence after watermarking
        verdict = verify_watermark(redacted, pol)
        assert verdict.detected is False
        assert verdict.reason == "token_mismatch"

    def test_unwatermarked_trace_not_detected(self) -> None:
        verdict = verify_watermark({"tool_name": "x", "blocked": True}, _policy())
        assert verdict.detected is False
        assert verdict.reason == "no_watermark"

    def test_watermark_survives_json_serialization_roundtrip(self) -> None:
        pol = _policy()
        redacted, _ = trace_redact(_leaky_trace(), pol)
        reparsed = json.loads(json.dumps(redacted))
        assert verify_watermark(reparsed, pol).detected is True


# ---------------------------------------------------------------------------
# Policy composition: OFF by default, ON under STRICT
# ---------------------------------------------------------------------------


class TestPolicyComposition:
    def test_disabled_policy_is_passthrough(self) -> None:
        redacted, report = trace_redact(_leaky_trace(), TraceRedactionPolicy(enabled=False))
        assert redacted["tuned_threshold"] == _TUNED  # unchanged
        assert WATERMARK_KEY not in redacted
        assert report.watermark_token == ""

    def test_security_policy_default_off(self) -> None:
        assert SecurityPolicy().trace_redaction is None

    def test_strict_preset_enables_redaction(self) -> None:
        assert STRICT_POLICY.trace_redaction is not None
        assert STRICT_POLICY.trace_redaction.enabled is True

    def test_custom_classifier_runs_first(self) -> None:
        # A custom classifier can localize a field the default patterns miss.
        def classify(name: str, value: object) -> ProtectedFieldClass | None:
            if name == "secret_knob":
                return ProtectedFieldClass.TUNED_THRESHOLD
            return None

        pol = TraceRedactionPolicy(
            enabled=True, tenant_id="t", watermark_secret="k", classifier=classify
        )
        redacted, _ = trace_redact({"secret_knob": 1.23, "blocked": True}, pol)
        assert redacted["secret_knob"]["_redacted"] is True
        assert redacted["blocked"] is True  # preserved field untouched

    def test_preserved_field_never_redacted_even_if_pattern_matches(self) -> None:
        # 'reason' is in the preserved set; even though it's free text it must
        # survive (it carries 'policy fired' evidence).
        pol = _policy()
        redacted, _ = trace_redact({"reason": "threshold gate fired", "blocked": True}, pol)
        assert redacted["reason"] == "threshold gate fired"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    """In-process tests assert exit codes (deterministic regardless of the
    shared-structlog stdout/stderr quirk); the subprocess test asserts the
    real `python -m` entrypoint emits clean JSON on stdout."""

    def _write(self, tmp_path, *, tenant: str = "acme-co", secret: str = "s3cr3t"):
        redacted, _ = trace_redact(
            _leaky_trace(),
            TraceRedactionPolicy(enabled=True, tenant_id=tenant, watermark_secret=secret),
        )
        path = tmp_path / "t.json"
        path.write_text(json.dumps(redacted))
        return path

    def test_cli_detected_returns_0(self, tmp_path) -> None:
        from agent_airlock.cli.trace import main

        path = self._write(tmp_path)
        rc = main(
            [
                "verify-watermark",
                str(path),
                "--tenant",
                "acme-co",
                "--secret",
                "s3cr3t",
                "--redaction-report",
                "--format",
                "json",
            ]
        )
        assert rc == 0

    def test_cli_wrong_secret_returns_1(self, tmp_path) -> None:
        from agent_airlock.cli.trace import main

        path = self._write(tmp_path)
        rc = main(["verify-watermark", str(path), "--tenant", "acme-co", "--secret", "WRONG"])
        assert rc == 1

    def test_cli_bad_path_returns_2(self, tmp_path) -> None:
        from agent_airlock.cli.trace import main

        rc = main(["verify-watermark", str(tmp_path / "nope.json")])
        assert rc == 2

    def test_cli_subprocess_emits_clean_json_stdout(self, tmp_path) -> None:
        # The documented invocation: `python -m agent_airlock.cli.trace ...`.
        # A fresh process routes structlog diagnostics to stderr, so stdout is
        # clean machine-readable JSON.
        import subprocess
        import sys

        path = self._write(tmp_path)
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_airlock.cli.trace",
                "verify-watermark",
                str(path),
                "--tenant",
                "acme-co",
                "--secret",
                "s3cr3t",
                "--redaction-report",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)  # must parse cleanly — no log noise on stdout
        assert out["detected"] is True
        assert any(
            item["path"] == "tuned_threshold" for item in out["redaction_report"]["localized"]
        )


def test_no_new_runtime_dependency() -> None:
    """The redaction core is stdlib-only — assert no third-party import."""
    import agent_airlock.trace_redaction as mod

    src = (mod.__file__ or "").strip()
    assert src.endswith("trace_redaction.py")
    # hashlib / hmac / json / dataclasses / enum / structlog are the only deps;
    # structlog is already a core dep. No pydantic, no new wheels.
    import inspect

    text = inspect.getsource(mod)
    for forbidden in ("import requests", "import numpy", "import pydantic"):
        assert forbidden not in text


# A module-level fixture-free guard so the suite fails loudly if exports drift.
def test_public_exports_present() -> None:
    import agent_airlock as a

    for name in (
        "TraceRedactionPolicy",
        "RedactionReport",
        "WatermarkVerdict",
        "ProtectedFieldClass",
        "trace_redact",
        "verify_watermark",
    ):
        assert hasattr(a, name) and name in a.__all__


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
