"""Skill-resistant trace redaction + per-tenant watermark (v0.8.24+).

Why traces are an extraction surface
------------------------------------
An agent's emitted trace / receipt is not just an audit artifact — it is a
*distillation target*. A trace that records the tuned thresholds a policy
fired on, the exact tool-call arguments, and the recovered intermediate
formulas/strategies hands a competitor the **recipe**: enough to clone the
behaviour without paying for the search that found it. The verifier, by
contrast, only needs the *evidence* — that the gate ran, which policy fired,
and the pass/fail — never the recipe.

This module is the RedAct-style answer: when a trace is emitted to a
**non-local** sink, run a redaction pass that (a) localizes protected fields
with a configurable field-classifier, (b) rewrites them to keep the
verifier-critical evidence while dropping the recipe, and (c) embeds a
per-tenant behavioural watermark so a leaked trace is provably yours.

Design references (behavioural watermarking of agent reasoning traces — this
is a "RedAct-style" composition of these published ideas; agent-airlock does
not reproduce any paper's benchmark):

- Agent Guide — a simple agent behavioural watermarking framework
  (https://arxiv.org/abs/2504.05871)
- CoTGuard — chain-of-thought triggering for copyright protection in
  multi-agent LLM systems (https://arxiv.org/abs/2505.19405)
- Distilling the Thought, Watermarking the Answer — semantic-guided
  watermark for large reasoning models (https://arxiv.org/abs/2601.05144)

Zero-runtime-dep: stdlib ``hashlib`` / ``hmac`` / ``json`` only — the
Pydantic-only core is preserved.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.trace_redaction")

# Reserved key the watermark is embedded under. Excluded from the watermark
# payload (a watermark cannot sign itself) and from redaction classification.
WATERMARK_KEY = "_airlock_watermark"
WATERMARK_SCHEME = "redact-hmac-v1"


class ProtectedFieldClass(str, enum.Enum):
    """The protected-field categories the classifier localizes."""

    TUNED_THRESHOLD = "tuned_threshold"
    TOOL_CALL_ARGS = "tool_call_args"
    RECOVERED_STRATEGY = "recovered_strategy"
    GENERIC_PROTECTED = "generic_protected"


# Default field-name → class patterns (substring match on the lowercased key).
# Ordered: the first matching class wins. Operators can extend / replace via
# ``TraceRedactionPolicy.protected_patterns`` or a custom ``classifier``.
DEFAULT_PROTECTED_PATTERNS: tuple[tuple[str, ProtectedFieldClass], ...] = (
    ("threshold", ProtectedFieldClass.TUNED_THRESHOLD),
    ("tuned", ProtectedFieldClass.TUNED_THRESHOLD),
    ("temperature", ProtectedFieldClass.TUNED_THRESHOLD),
    ("top_k", ProtectedFieldClass.TUNED_THRESHOLD),
    ("top_p", ProtectedFieldClass.TUNED_THRESHOLD),
    ("cutoff", ProtectedFieldClass.TUNED_THRESHOLD),
    ("weight", ProtectedFieldClass.TUNED_THRESHOLD),
    ("hyperparam", ProtectedFieldClass.TUNED_THRESHOLD),
    ("tool_args", ProtectedFieldClass.TOOL_CALL_ARGS),
    ("tool_call", ProtectedFieldClass.TOOL_CALL_ARGS),
    ("arguments", ProtectedFieldClass.TOOL_CALL_ARGS),
    ("args_preview", ProtectedFieldClass.TOOL_CALL_ARGS),
    ("call_args", ProtectedFieldClass.TOOL_CALL_ARGS),
    ("formula", ProtectedFieldClass.RECOVERED_STRATEGY),
    ("strategy", ProtectedFieldClass.RECOVERED_STRATEGY),
    ("recipe", ProtectedFieldClass.RECOVERED_STRATEGY),
    ("intermediate", ProtectedFieldClass.RECOVERED_STRATEGY),
    ("reasoning", ProtectedFieldClass.RECOVERED_STRATEGY),
    ("chain_of_thought", ProtectedFieldClass.RECOVERED_STRATEGY),
    ("scratchpad", ProtectedFieldClass.RECOVERED_STRATEGY),
    ("rationale", ProtectedFieldClass.RECOVERED_STRATEGY),
)

# Verifier-critical fields preserved verbatim — the evidence a verifier needs
# (the gate ran / the policy fired / the pass-fail). NEVER redacted, even if a
# protected pattern would otherwise match.
DEFAULT_PRESERVED_FIELDS: frozenset[str] = frozenset(
    {
        "timestamp",
        "tool_name",
        "blocked",
        "block_reason",
        "policy_id",
        "policy_hash",
        "verdict",
        "passed",
        "pass_fail",
        "allowed",
        "decision",
        "gate",
        "gate_ran",
        "policy_fired",
        "cve",
        "owasp",
        "severity",
        "reason",
        "agent_id",
        "session_id",
        "redaction_applied",
    }
)


# A custom classifier maps ``(field_name, value)`` to a protected class, or
# ``None`` to leave the field unprotected.
FieldClassifier = Callable[[str, Any], "ProtectedFieldClass | None"]


@dataclass(frozen=True)
class TraceRedactionPolicy:
    """Opt-in policy for redacting + watermarking traces at the non-local sink.

    **Deny-by-default OFF** (``enabled=False``) so existing deployments are
    byte-for-byte unchanged. The STRICT preset turns it ON. Composes with the
    existing :class:`agent_airlock.policy.SecurityPolicy` pipeline as an
    additive optional field; stdlib-only (no new runtime dependency).

    Attributes:
        enabled: Master switch. OFF preserves prior behaviour exactly.
        tenant_id: Per-tenant identifier the watermark binds to. A leaked
            trace carrying this watermark is provably yours.
        watermark_secret: HMAC key. When empty, a key is derived from
            ``tenant_id`` (so a watermark is still tenant-bound, but a
            dedicated secret is strongly recommended for unforgeability).
        protected_patterns: ``(substring, class)`` pairs matched against the
            lowercased field name. Defaults to :data:`DEFAULT_PROTECTED_PATTERNS`.
        preserved_fields: Verifier-critical field names kept verbatim.
            Defaults to :data:`DEFAULT_PRESERVED_FIELDS`.
        classifier: Optional custom ``(name, value) -> class | None`` that
            runs **before** the pattern table (its non-None result wins).
        placeholder: The marker string written in place of a dropped value.
    """

    enabled: bool = False
    tenant_id: str = ""
    watermark_secret: str = ""
    protected_patterns: tuple[tuple[str, ProtectedFieldClass], ...] = DEFAULT_PROTECTED_PATTERNS
    preserved_fields: frozenset[str] = DEFAULT_PRESERVED_FIELDS
    classifier: FieldClassifier | None = None
    placeholder: str = "[REDACTED:trace-redaction]"

    def _key(self) -> bytes:
        """The HMAC key — explicit secret, else derived from the tenant id."""
        secret = self.watermark_secret or f"airlock-tenant::{self.tenant_id}"
        return secret.encode("utf-8")

    def classify(self, field_name: str, value: Any) -> ProtectedFieldClass | None:
        """Localize a field: return its protected class, or None if not protected.

        A verifier-critical (preserved) field always returns None. A custom
        ``classifier`` runs first; otherwise the pattern table is consulted.
        """
        if field_name in self.preserved_fields:
            return None
        if self.classifier is not None:
            result = self.classifier(field_name, value)
            if result is not None:
                return result
        lowered = field_name.lower()
        for substring, klass in self.protected_patterns:
            if substring in lowered:
                return klass
        return None


@dataclass(frozen=True)
class RedactionReport:
    """What a :func:`trace_redact` pass localized / rewrote / preserved.

    Attributes:
        localized: ``(json_path, class)`` for every protected field found.
        rewritten: The json paths whose recipe value was dropped.
        preserved: The verifier-critical json paths kept verbatim.
        watermark_token: The embedded HMAC token (hex), or ``""`` when the
            policy was disabled.
        tenant_fp: The tenant fingerprint embedded for attribution.
    """

    localized: tuple[tuple[str, str], ...]
    rewritten: tuple[str, ...]
    preserved: tuple[str, ...]
    watermark_token: str
    tenant_fp: str


@dataclass(frozen=True)
class WatermarkVerdict:
    """Outcome of :func:`verify_watermark`.

    Attributes:
        detected: True iff a valid, untampered watermark for this tenant key
            is present. Detection is cryptographic (keyed HMAC match), so a
            true watermark detects deterministically and an unrelated trace
            does not forge one.
        tenant_fp: The tenant fingerprint carried by the trace (``""`` if no
            watermark field was present).
        reason: Stable reason code (``"detected"`` / ``"no_watermark"`` /
            ``"tenant_mismatch"`` / ``"token_mismatch"`` / ``"malformed"``).
        detail: Free-form explanation.
    """

    detected: bool
    tenant_fp: str
    reason: str
    detail: str


def _tenant_fingerprint(tenant_id: str) -> str:
    """A non-secret, stable fingerprint identifying the tenant in a trace."""
    return hashlib.sha256(f"airlock-tenant-fp::{tenant_id}".encode()).hexdigest()[:16]


def _canonical(payload: Mapping[str, Any]) -> bytes:
    """Deterministic canonical bytes of a payload (watermark key excluded)."""
    without = {k: v for k, v in payload.items() if k != WATERMARK_KEY}
    return json.dumps(without, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _compute_token(policy: TraceRedactionPolicy, payload: Mapping[str, Any]) -> str:
    """The keyed HMAC binding the (watermark-free) payload to the tenant key."""
    return hmac.new(policy._key(), _canonical(payload), hashlib.sha256).hexdigest()


def _redact_node(
    node: Any,
    policy: TraceRedactionPolicy,
    path: str,
    report_localized: list[tuple[str, str]],
    report_rewritten: list[str],
    report_preserved: list[str],
) -> Any:
    """Recursively rewrite a trace node, recording the redaction report."""
    if isinstance(node, Mapping):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key == WATERMARK_KEY:
                out[key] = value
                continue
            child_path = f"{path}.{key}" if path else str(key)
            klass = policy.classify(str(key), value)
            if klass is not None:
                # Localized → rewrite: keep the evidence (the field existed,
                # its class, and a pass/fail bool when the value *is* one),
                # drop the recipe (the actual numbers/strings/structures).
                report_localized.append((child_path, klass.value))
                report_rewritten.append(child_path)
                out[key] = _rewrite_value(value, klass, policy)
            else:
                if str(key) in policy.preserved_fields:
                    report_preserved.append(child_path)
                out[key] = _redact_node(
                    value,
                    policy,
                    child_path,
                    report_localized,
                    report_rewritten,
                    report_preserved,
                )
        return out
    if isinstance(node, (list, tuple)):
        return [
            _redact_node(
                item,
                policy,
                f"{path}[{idx}]",
                report_localized,
                report_rewritten,
                report_preserved,
            )
            for idx, item in enumerate(node)
        ]
    return node


def _rewrite_value(value: Any, klass: ProtectedFieldClass, policy: TraceRedactionPolicy) -> Any:
    """Replace a protected value with a verifier-evidence stub (recipe dropped).

    The stub records that the field existed and its class. When the value is
    itself a pass/fail boolean, that single bit (verifier-critical) survives;
    every other shape collapses to the placeholder so no tuned threshold,
    argument, or recovered strategy leaks.
    """
    stub: dict[str, Any] = {"_redacted": True, "class": klass.value}
    if isinstance(value, bool):
        # A bare bool is pass/fail evidence, not a recipe — keep the bit.
        stub["pass_fail"] = value
    else:
        stub["value"] = policy.placeholder
    return stub


def trace_redact(
    trace: Mapping[str, Any],
    policy: TraceRedactionPolicy,
) -> tuple[dict[str, Any], RedactionReport]:
    """Redact a trace for a non-local sink and embed the per-tenant watermark.

    Args:
        trace: The trace / receipt dict about to leave the boundary.
        policy: The :class:`TraceRedactionPolicy`. When disabled, the trace is
            returned unchanged with an empty report (no watermark embedded).

    Returns:
        ``(redacted_trace, report)``. The redacted trace carries a
        :data:`WATERMARK_KEY` block when the policy is enabled.
    """
    if not policy.enabled:
        return dict(trace), RedactionReport((), (), (), "", "")

    localized: list[tuple[str, str]] = []
    rewritten: list[str] = []
    preserved: list[str] = []
    redacted = _redact_node(trace, policy, "", localized, rewritten, preserved)

    tenant_fp = _tenant_fingerprint(policy.tenant_id)
    token = _compute_token(policy, redacted)
    redacted[WATERMARK_KEY] = {
        "scheme": WATERMARK_SCHEME,
        "tenant_fp": tenant_fp,
        "token": token,
    }

    logger.info(
        "trace_redacted",
        localized=len(localized),
        rewritten=len(rewritten),
        preserved=len(preserved),
        tenant_fp=tenant_fp,
    )
    return redacted, RedactionReport(
        localized=tuple(localized),
        rewritten=tuple(rewritten),
        preserved=tuple(preserved),
        watermark_token=token,
        tenant_fp=tenant_fp,
    )


def verify_watermark(
    trace: Mapping[str, Any],
    policy: TraceRedactionPolicy,
) -> WatermarkVerdict:
    """Detect the per-tenant watermark in a (possibly leaked) trace.

    Detection is cryptographic: the embedded token must equal the keyed HMAC
    of the watermark-free payload under this tenant's key (constant-time
    compare). A genuine watermark detects deterministically (high
    true-detection); an unrelated trace cannot forge a valid token under the
    secret key (low false-alarm).

    Args:
        trace: The trace to inspect.
        policy: The policy whose tenant key + id the trace is checked against.

    Returns:
        A :class:`WatermarkVerdict`.
    """
    mark = trace.get(WATERMARK_KEY)
    if not isinstance(mark, Mapping):
        return WatermarkVerdict(False, "", "no_watermark", "no watermark block present")
    embedded_token = mark.get("token")
    embedded_fp = str(mark.get("tenant_fp", ""))
    if not isinstance(embedded_token, str) or not embedded_token:
        return WatermarkVerdict(False, embedded_fp, "malformed", "watermark token missing/invalid")

    expected_fp = _tenant_fingerprint(policy.tenant_id)
    if embedded_fp != expected_fp:
        return WatermarkVerdict(
            False,
            embedded_fp,
            "tenant_mismatch",
            f"watermark tenant_fp {embedded_fp!r} != expected {expected_fp!r}",
        )

    expected_token = _compute_token(policy, trace)
    if hmac.compare_digest(embedded_token, expected_token):
        return WatermarkVerdict(True, embedded_fp, "detected", "valid tenant watermark")
    return WatermarkVerdict(
        False,
        embedded_fp,
        "token_mismatch",
        "watermark token does not match — trace tampered or wrong key",
    )


def merge_protected_patterns(
    extra: Iterable[tuple[str, ProtectedFieldClass]],
) -> tuple[tuple[str, ProtectedFieldClass], ...]:
    """Convenience: append operator patterns to the default table."""
    return DEFAULT_PROTECTED_PATTERNS + tuple(extra)


__all__ = [
    "DEFAULT_PRESERVED_FIELDS",
    "DEFAULT_PROTECTED_PATTERNS",
    "FieldClassifier",
    "ProtectedFieldClass",
    "RedactionReport",
    "TraceRedactionPolicy",
    "WATERMARK_KEY",
    "WATERMARK_SCHEME",
    "WatermarkVerdict",
    "merge_protected_patterns",
    "trace_redact",
    "verify_watermark",
]
