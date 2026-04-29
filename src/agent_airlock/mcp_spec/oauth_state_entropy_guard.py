"""``OAuthStateEntropyGuard`` — OAuth ``state`` injection mitigation (v0.6.0+).

The previewed BlackHat Asia 2026 talk (2026-04-24) demonstrates indirect
prompt injection via the OAuth ``state`` parameter: attackers stuff
base64-encoded prompt strings into ``state`` and the agent's OAuth
callback handler decodes and incorporates them into a system message.

Airlock's existing ``oauth_audit`` guard validates issuer + audience
claims but does not inspect the ``state`` payload at all. This guard
plugs that gap.

Algorithm
---------

1. Detect JWT tri-segment shape (``head.payload.sig``); if matched,
   skip prompt-injection scan on the body — JWT signing layer is out
   of scope.
2. Compute Shannon entropy of the raw bytes. High-entropy nonces
   (>= 3.0 bits/byte) skip the decode + scan.
3. Try base64, url-safe base64, hex, and JSON decoders; the first
   decoder whose output is printable ASCII is used.
4. Run the prompt-injection trigger-phrase scan on the decoded text.

Reference
---------
* BlackHat Asia 2026 talk preview (2026-04-24):
  https://www.blackhat.com/asia-26/briefings/schedule/#oauth-state-injection
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.oauth_state_entropy_guard")

Verdict = Literal["allow", "warn", "block"]

# Conservative trigger-phrase set; matches PRMetadataGuard intent.
_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bignore\s+(?:all\s+)?previous\s+instructions\b"),
    re.compile(r"(?i)\bdisregard\s+(?:prior|previous)\s+(?:safety|policies)\b"),
    re.compile(r"(?i)\b(?:system\s+)?override\b"),
    re.compile(r"(?i)\bunrestricted\s+mode\b"),
    re.compile(r"(?i)\byou\s+are\s+(?:now\s+)?developer\s+mode\b"),
    re.compile(r"(?i)\b<\s*system\s*>"),
    re.compile(r"(?i)\bexecute\s+the\s+following\b"),
    re.compile(r"(?i)\bexfiltrat\w*\b"),
)


class OAuthStateInjectionError(AirlockError):
    """Raised by :meth:`OAuthStateEntropyGuard.evaluate_or_raise` on block."""

    def __init__(
        self,
        message: str,
        *,
        decoded_excerpt: str,
        decoder: str,
        match: str,
    ) -> None:
        self.decoded_excerpt = decoded_excerpt
        self.decoder = decoder
        self.match = match
        super().__init__(message)


@dataclass(frozen=True)
class OAuthStateInspection:
    """Result of one ``OAuthStateEntropyGuard.evaluate`` call."""

    verdict: Verdict
    detail: str
    decoder: str | None = None
    decoded_excerpt: str | None = None
    matches: tuple[str, ...] = field(default_factory=tuple)
    duration_ms: float = 0.0


class OAuthStateEntropyGuard:
    """Detect prompt-injection payloads smuggled via OAuth ``state``."""

    def __init__(
        self,
        *,
        max_state_bytes: int = 2048,
        entropy_skip_threshold: float = 3.0,
    ) -> None:
        self.max_state_bytes = max_state_bytes
        self.entropy_skip_threshold = entropy_skip_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, oauth_callback: dict[str, Any]) -> OAuthStateInspection:
        started = time.perf_counter()
        state = oauth_callback.get("state", "")
        if not isinstance(state, str):
            return self._finalise(started, "warn", "state is not a string", None, None, ())
        if state == "":
            return self._finalise(started, "warn", "state is empty", None, None, ())
        if len(state.encode("utf-8")) > self.max_state_bytes:
            return self._finalise(
                started,
                "block",
                f"state exceeds {self.max_state_bytes} byte cap",
                "size_cap",
                state[:80],
                (),
            )

        if self._looks_like_jwt(state):
            return self._finalise(
                started, "allow", "state matches JWT tri-segment shape", None, None, ()
            )

        # Try the decoders FIRST. Random nonces have high raw-byte
        # entropy too, but they don't decode into printable ASCII —
        # whereas a base64-encoded injection payload does. So entropy
        # is only a useful short-circuit when no decoder hit, otherwise
        # the encoded form's high entropy would let injection through.
        decoded, decoder = self._best_decode(state)
        if decoded is None:
            entropy_bps = self._shannon_entropy(state)
            if entropy_bps >= self.entropy_skip_threshold:
                return self._finalise(
                    started,
                    "allow",
                    f"high-entropy nonce ({entropy_bps:.2f} bits/byte)",
                    None,
                    None,
                    (),
                )
            return self._finalise(
                started,
                "allow",
                "no decoder produced printable ASCII",
                None,
                None,
                (),
            )

        matches: list[str] = []
        for pat in _INJECTION_PATTERNS:
            m = pat.search(decoded)
            if m:
                matches.append(m.group(0))

        if matches:
            return self._finalise(
                started,
                "block",
                f"decoded state contains injection trigger via {decoder}",
                decoder,
                decoded[:160],
                tuple(matches),
            )
        return self._finalise(
            started,
            "allow",
            f"decoded via {decoder}; no injection trigger",
            decoder,
            decoded[:160],
            (),
        )

    def evaluate_or_raise(self, oauth_callback: dict[str, Any]) -> OAuthStateInspection:
        result = self.evaluate(oauth_callback)
        if result.verdict == "block":
            raise OAuthStateInjectionError(
                f"OAuth state refused: {result.detail}",
                decoded_excerpt=result.decoded_excerpt or "",
                decoder=result.decoder or "",
                match=result.matches[0] if result.matches else "",
            )
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_jwt(s: str) -> bool:
        parts = s.split(".")
        return len(parts) == 3 and all(p for p in parts)

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        data = s.encode("utf-8", errors="replace")
        if not data:
            return 0.0
        freq: dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        n = len(data)
        ent = -sum((c / n) * math.log2(c / n) for c in freq.values())
        return ent

    def _best_decode(self, state: str) -> tuple[str | None, str | None]:
        # Try url-safe base64, then standard base64, then hex, then JSON.
        for decoder, fn in (
            ("url-safe-base64", _try_urlsafe_b64),
            ("base64", _try_b64),
            ("hex", _try_hex),
            ("json", _try_json),
        ):
            decoded = fn(state)
            if decoded and self._is_printable(decoded):
                return decoded, decoder
        return None, None

    @staticmethod
    def _is_printable(s: str) -> bool:
        if not s:
            return False
        printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in ("\n", "\t"))
        return (printable / max(len(s), 1)) > 0.85

    def _finalise(
        self,
        started: float,
        verdict: Verdict,
        detail: str,
        decoder: str | None,
        decoded_excerpt: str | None,
        matches: tuple[str, ...],
    ) -> OAuthStateInspection:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        logger.info(
            "oauth_state_inspect",
            verdict=verdict,
            decoder=decoder,
            duration_ms=round(elapsed_ms, 3),
            matches=len(matches),
        )
        return OAuthStateInspection(
            verdict=verdict,
            detail=detail,
            decoder=decoder,
            decoded_excerpt=decoded_excerpt,
            matches=matches,
            duration_ms=elapsed_ms,
        )


def _try_urlsafe_b64(s: str) -> str | None:
    pad = "=" * (-len(s) % 4)
    try:
        decoded = base64.urlsafe_b64decode(s + pad)
    except (binascii.Error, ValueError):
        return None
    return decoded.decode("utf-8", errors="replace")


def _try_b64(s: str) -> str | None:
    pad = "=" * (-len(s) % 4)
    try:
        decoded = base64.b64decode(s + pad, validate=False)
    except (binascii.Error, ValueError):
        return None
    return decoded.decode("utf-8", errors="replace")


def _try_hex(s: str) -> str | None:
    if len(s) % 2:
        return None
    try:
        decoded = bytes.fromhex(s)
    except ValueError:
        return None
    return decoded.decode("utf-8", errors="replace")


def _try_json(s: str) -> str | None:
    try:
        parsed = json.loads(s)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, str):
        return parsed
    if isinstance(parsed, dict):
        return json.dumps(parsed)
    return None


__all__ = [
    "OAuthStateEntropyGuard",
    "OAuthStateInjectionError",
    "OAuthStateInspection",
    "Verdict",
]
