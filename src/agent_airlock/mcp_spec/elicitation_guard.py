"""``ElicitationGuard`` — runtime mitigation for MCP ``tool/elicitation`` (v0.6.0+).

MCP spec PR #1487 (2026-04-28) introduces server-initiated
``tool/elicitation`` round-trips: a server can pause a tool execution
mid-flight and request additional user input. The host renders the
elicitation as if it came from the user's own system, which makes it a
clean injection vector — a hostile server can craft elicitations that
look authoritative ("Please confirm your password to continue") and
the user has no signal that the prompt originated server-side.

This guard classifies each elicitation payload into one of four
:class:`ElicitationClass` values and emits a :class:`Verdict` per the
preset's per-class action map. The default safe posture is:

* ``credential_request`` → ``block``
* ``policy_override`` → ``block``
* ``destructive_confirmation`` → ``relay_with_warning``
* ``benign`` → ``relay_with_origin_badge``

The spec PR's own example payloads must round-trip clean; the guard's
classifier is conservative-scoped to that constraint.

Reference
---------
* MCP spec PR #1487 (2026-04-28):
  https://github.com/modelcontextprotocol/specification/pull/1487
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.elicitation_guard")

Verdict = Literal["allow", "relay_with_origin_badge", "relay_with_warning", "block"]


class ElicitationClass(str, Enum):
    """Coarse classification of an elicitation payload."""

    BENIGN = "benign"
    CREDENTIAL_REQUEST = "credential_request"
    POLICY_OVERRIDE = "policy_override"
    DESTRUCTIVE_CONFIRMATION = "destructive_confirmation"


# Patterns are conservative on purpose. Each list captures the smallest
# set of phrases that distinguishes the class; the spec PR's example
# payloads ("Choose a workspace", "Pick a branch") must NOT match.

_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:enter|provide|confirm|re-?enter)\s+(?:your\s+)?password\b"),
    re.compile(r"(?i)\bapi[\s_-]?(?:key|token|secret)\b"),
    re.compile(r"(?i)\b(?:bearer|access|refresh)\s+token\b"),
    re.compile(r"(?i)\b(?:ssh|gpg)\s+(?:key|passphrase)\b"),
    re.compile(r"(?i)\b(?:credit\s*card|cvv|cvc|cardholder)\b"),
    re.compile(r"(?i)\bone[\s-]?time\s+(?:password|code)\b"),
    re.compile(r"(?i)\b(?:2fa|mfa|totp|otp)\s+code\b"),
    re.compile(r"(?i)\bseed\s+phrase\b"),
)

_POLICY_OVERRIDE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b"),
    re.compile(r"(?i)\bdisregard\s+(?:prior|previous)\s+(?:safety|policies)\b"),
    re.compile(r"(?i)\b(?:system\s+)?override\b"),
    re.compile(r"(?i)\bunrestricted\s+mode\b"),
    re.compile(r"(?i)\byou\s+are\s+(?:now\s+)?(?:in\s+)?developer\s+mode\b"),
    re.compile(r"(?i)\bjailbreak\b"),
    re.compile(r"(?i)\b<\s*system\s*>"),
)

_DESTRUCTIVE_CONFIRMATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bconfirm\s+(?:the\s+)?(?:deletion|destruction|removal)\b"),
    re.compile(r"(?i)\bdrop\s+(?:database|table|schema)\b"),
    re.compile(r"(?i)\b(?:rm|delete)\s+-rf\b"),
    re.compile(r"(?i)\bproceed\s+with\s+(?:wipe|format|reset)\b"),
)


class ElicitationGuardError(AirlockError):
    """Raised by :meth:`ElicitationGuard.evaluate_or_raise` on a block verdict."""

    def __init__(
        self,
        message: str,
        *,
        classification: ElicitationClass,
        server_origin: str,
    ) -> None:
        self.classification = classification
        self.server_origin = server_origin
        super().__init__(message)


@dataclass(frozen=True)
class ElicitationInspection:
    """Result of one ``ElicitationGuard.evaluate`` call."""

    verdict: Verdict
    classification: ElicitationClass
    server_origin: str
    payload_excerpt: str
    duration_ms: float
    matches: tuple[str, ...] = field(default_factory=tuple)
    rendered_payload: str | None = None
    """Final payload (with origin badge or warning prefix) when the
    verdict is one of the relay variants. ``None`` for ``block``."""


class ElicitationGuard:
    """Inspect an MCP ``tool/elicitation`` payload before relay.

    The guard is configured with a per-class action map:

    >>> guard = ElicitationGuard()
    >>> guard.evaluate({"prompt": "Choose a workspace"}, server_origin="github").verdict
    'relay_with_origin_badge'
    """

    _DEFAULT_ACTIONS: dict[ElicitationClass, Verdict] = {
        ElicitationClass.BENIGN: "relay_with_origin_badge",
        ElicitationClass.CREDENTIAL_REQUEST: "block",
        ElicitationClass.POLICY_OVERRIDE: "block",
        ElicitationClass.DESTRUCTIVE_CONFIRMATION: "relay_with_warning",
    }

    def __init__(
        self,
        *,
        actions: dict[ElicitationClass, Verdict] | None = None,
        allowlist_origins: frozenset[str] = frozenset(),
        max_payload_bytes: int = 16 * 1024,
    ) -> None:
        self.actions = dict(self._DEFAULT_ACTIONS)
        if actions:
            self.actions.update(actions)
        self.allowlist_origins = allowlist_origins
        self.max_payload_bytes = max_payload_bytes

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _normalise(self, text: str) -> str:
        """NFKC + strip Unicode-format codepoints to defeat confusables."""
        nfkc = unicodedata.normalize("NFKC", text)
        return "".join(c for c in nfkc if unicodedata.category(c) != "Cf")

    def _classify_payload(self, text: str) -> tuple[ElicitationClass, list[str]]:
        normalised = self._normalise(text)
        matches: list[str] = []
        for pat in _CREDENTIAL_PATTERNS:
            m = pat.search(normalised)
            if m:
                matches.append(m.group(0))
                return ElicitationClass.CREDENTIAL_REQUEST, matches
        for pat in _POLICY_OVERRIDE_PATTERNS:
            m = pat.search(normalised)
            if m:
                matches.append(m.group(0))
                return ElicitationClass.POLICY_OVERRIDE, matches
        for pat in _DESTRUCTIVE_CONFIRMATION_PATTERNS:
            m = pat.search(normalised)
            if m:
                matches.append(m.group(0))
                return ElicitationClass.DESTRUCTIVE_CONFIRMATION, matches
        return ElicitationClass.BENIGN, matches

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        elicitation_msg: dict[str, Any] | str,
        *,
        server_origin: str,
        session_ctx: dict[str, Any] | None = None,  # noqa: ARG002 — reserved
    ) -> ElicitationInspection:
        """Inspect an elicitation payload from ``server_origin``.

        Args:
            elicitation_msg: Either a string prompt or the dict shape
                from MCP spec PR #1487 (``{"prompt": str, "schema": ...}``).
                Extra keys are tolerated.
            server_origin: A short id for the originating server (e.g.
                ``"github"`` / ``"jira-mcp"``). Recorded in audit logs;
                used to gate the ``allowlist_origins`` short-circuit.
            session_ctx: Optional session metadata. Currently
                unused; reserved for future "in-flight tool name"
                checks.
        """
        started = time.perf_counter()

        if isinstance(elicitation_msg, str):
            text = elicitation_msg
        elif isinstance(elicitation_msg, dict):
            parts: list[str] = []
            for key in ("prompt", "message", "title", "description"):
                value = elicitation_msg.get(key)
                if isinstance(value, str):
                    parts.append(value)
            text = "\n".join(parts) if parts else ""
        else:
            raise TypeError(
                f"elicitation_msg must be str or dict, got {type(elicitation_msg).__name__}"
            )

        encoded = text.encode("utf-8")[: self.max_payload_bytes]
        text = encoded.decode("utf-8", errors="replace")

        classification, raw_matches = self._classify_payload(text)
        verdict = self.actions[classification]

        if classification == ElicitationClass.BENIGN and server_origin in self.allowlist_origins:
            verdict = "allow"

        rendered: str | None
        if verdict == "block":
            rendered = None
        elif verdict == "relay_with_warning":
            rendered = f"⚠ destructive action requested by server '{server_origin}': {text}"
        elif verdict == "relay_with_origin_badge":
            rendered = f"[server: {server_origin}] {text}"
        else:  # allow
            rendered = text

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        excerpt = text[:160]
        logger.info(
            "elicitation_inspect",
            server_origin=server_origin,
            classification=classification.value,
            verdict=verdict,
            duration_ms=round(elapsed_ms, 3),
            matches=len(raw_matches),
        )
        return ElicitationInspection(
            verdict=verdict,
            classification=classification,
            server_origin=server_origin,
            payload_excerpt=excerpt,
            duration_ms=elapsed_ms,
            matches=tuple(raw_matches),
            rendered_payload=rendered,
        )

    def evaluate_or_raise(
        self,
        elicitation_msg: dict[str, Any] | str,
        *,
        server_origin: str,
        session_ctx: dict[str, Any] | None = None,
    ) -> ElicitationInspection:
        result = self.evaluate(
            elicitation_msg, server_origin=server_origin, session_ctx=session_ctx
        )
        if result.verdict == "block":
            raise ElicitationGuardError(
                f"server elicitation refused: classification="
                f"{result.classification.value}, origin={server_origin!r}",
                classification=result.classification,
                server_origin=server_origin,
            )
        return result


__all__ = [
    "ElicitationClass",
    "ElicitationGuard",
    "ElicitationGuardError",
    "ElicitationInspection",
    "Verdict",
]
