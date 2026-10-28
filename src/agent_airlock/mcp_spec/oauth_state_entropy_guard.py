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

1. Detect the JWT tri-segment shape (``head.payload.sig``: three base64url
   segments whose header decodes to a JSON object). The JWT signing layer
   is out of scope, but the payload segment is decoded and scanned for the
   trigger phrases.
2. Try url-safe base64, base64, hex, and JSON decoders, on the state as
   written and percent-decoded, and scan the output of every one that
   decodes for the trigger phrases (not only the first printable one).
3. Read the state as plain text too: the trigger-phrase scan runs on it as
   written, percent-decoded, and with ``-`` / ``_`` / ``+`` / ``.`` / ``~``
   read as spaces, and a state that reads as natural-language prose (three
   or more words making up at least two thirds of its whitespace-separated
   tokens, one of them four letters or longer) is refused unless it is a
   JSON object or array. The prose check reads the state as given and with
   %-escapes decoded, never with ``+`` as a space (a decoded standard-base64
   nonce carries literal ``+``). An opaque nonce has no whitespace, so it is
   never prose.
4. Only then does Shannon entropy label an allowed state (a high-entropy
   nonce is >= 3.0 bits/byte).

Every scan reads the text a lenient reader sees as well: NFKC-folded, with
an undecodable byte (U+FFFD), a format character (zero-width, bidi) or a
control character dropped, and read as a space. Bytes are decoded leniently,
not strictly: a random-bytes nonce is not UTF-8 either.

Until 0.10.28 the undecoded text was never scanned, so plain-text
instructions passed as a "high-entropy nonce" (English runs ~4 bits/byte),
two dots made any text a JWT, one undecodable byte or zero-width character
inside a trigger phrase hid it, a ``list`` (``parse_qs`` output) or
``bytes`` state was a warning, and a callback that was not a mapping
crashed. Every element of a list state is read now and the worst verdict
wins; ``bytes`` are decoded; any other shape, and a callback that is not a
mapping, is refused.

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
import unicodedata
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal
from urllib.parse import unquote, unquote_plus

from .._log import structlog
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

#: Characters a token-shaped state may join words with; read as spaces for the scan.
_WORD_JOINERS = re.compile(r"[-_+.~]+")

#: A word as prose writes it: two or more letters, lowercase or Capitalized, or three or
#: more in ALL CAPS. A two-letter ALL-CAPS token (``KU``) is as common in random base64 as
#: in prose, so it does not count.
_PROSE_WORD = re.compile(r"^(?:[A-Za-z][a-z]+|[A-Z]{3,})$")

#: Punctuation prose wraps a word in, stripped before :data:`_PROSE_WORD` is tried.
_PROSE_PUNCTUATION = "\"'`.,;:!?()[]{}<>"

#: The fewest words that make a state read as prose.
_PROSE_MIN_WORDS = 3

#: Prose has at least one word this long; a run of short random base64 segments does not.
_PROSE_LONG_WORD = 4

#: The base64url alphabet of a JWT segment.
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

_SEVERITY: dict[str, int] = {"allow": 0, "warn": 1, "block": 2}


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


@dataclass(frozen=True)
class _Finding:
    """One state value's verdict, before timing and logging."""

    verdict: Verdict
    detail: str
    decoder: str | None = None
    excerpt: str | None = None
    matches: tuple[str, ...] = ()


#: ASCII control characters other than the whitespace ones a phrase may contain.
_ASCII_CONTROLS = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")

#: Whitespace control characters, which separate words rather than hide inside them.
_WHITESPACE_CONTROLS = frozenset("\t\n\r\x0b\x0c")


def _invisible(char: str) -> bool:
    """An undecodable byte (U+FFFD), a format character, or a non-whitespace control."""
    if char == "�":
        return True
    category = unicodedata.category(char)
    return category == "Cf" or (category == "Cc" and char not in _WHITESPACE_CONTROLS)


def _unique(texts: list[str]) -> list[str]:
    return list(dict.fromkeys(texts))


def _lenient_forms(text: str) -> list[str]:
    """``text``, and what a lenient reader sees: NFKC-folded, invisibles dropped or spaced.

    One undecodable byte or zero-width character inside "ignore" broke the trigger
    pattern, while a consumer that drops it (or a model reading it) still sees the word.
    """
    if text.isascii():
        if not _ASCII_CONTROLS.search(text):
            return [text]
        return _unique([text, _ASCII_CONTROLS.sub("", text), _ASCII_CONTROLS.sub(" ", text)])
    folded = unicodedata.normalize("NFKC", text)
    dropped = "".join(c for c in folded if not _invisible(c))
    spaced = "".join(" " if _invisible(c) else c for c in folded)
    return _unique([text, folded, dropped, spaced])


def _visible(text: str) -> str:
    """``text`` with its invisible characters dropped (the lenient reader's text)."""
    if text.isascii():
        return _ASCII_CONTROLS.sub("", text)
    return "".join(c for c in unicodedata.normalize("NFKC", text) if not _invisible(c))


def _scan(text: str) -> tuple[str, ...]:
    """Every trigger phrase ``text`` contains, read leniently, one per pattern."""
    found: list[str] = []
    forms = _lenient_forms(text)
    for pat in _INJECTION_PATTERNS:
        for form in forms:
            m = pat.search(form)
            if m:
                found.append(m.group(0))
                break
    return tuple(found)


def _is_json_structure(text: str) -> bool:
    """Whether ``text`` parses as a JSON object or array (structure, not prose)."""
    try:
        return isinstance(json.loads(text), (dict, list))
    except (ValueError, RecursionError):
        return False


def _reads_as_prose(text: str) -> bool:
    """Whether ``text``, read leniently, is natural language.

    Three or more words, making up at least two thirds of the whitespace-separated tokens,
    one of them four letters or longer. Measured against 400,000 random standard-base64
    nonces with every ``+`` read as a space (the worst case for an opaque nonce), none
    reads as prose.
    """
    for form in _lenient_forms(text):
        tokens = form.split()
        if len(tokens) < _PROSE_MIN_WORDS:
            continue
        words = [
            word
            for word in (token.strip(_PROSE_PUNCTUATION) for token in tokens)
            if _PROSE_WORD.match(word)
        ]
        if (
            len(words) >= _PROSE_MIN_WORDS
            and len(words) * 3 >= len(tokens) * 2
            and any(len(word) >= _PROSE_LONG_WORD for word in words)
        ):
            return True
    return False


def _state_values(state: Any) -> tuple[list[str], _Finding | None]:
    """The text values a ``state`` parameter carries, or the refusal of its shape.

    ``None`` is an absent state. A ``str`` is one value and ``bytes`` are decoded to one;
    a ``list`` / ``tuple`` (``parse_qs`` gives a list) is every element, each of which
    must be a ``str`` or ``bytes``. Any other shape is refused rather than warned about.
    """
    if state is None:
        return [], None
    items = list(state) if isinstance(state, (list, tuple)) else [state]
    values: list[str] = []
    for index, item in enumerate(items):
        if isinstance(item, (bytes, bytearray, memoryview)):
            item = bytes(item).decode("utf-8", errors="replace")
        if not isinstance(item, str):
            where = f"state[{index}]" if isinstance(state, (list, tuple)) else "state"
            return [], _Finding(
                "block",
                f"{where} is a {type(item).__name__}, not a string; refusing a shape the "
                "guard cannot read",
                "shape",
            )
        values.append(item)
    return values, None


def _plain_variants(state: str) -> list[str]:
    """``state`` as written, percent-decoded, and with word joiners read as spaces."""
    variants: list[str] = []
    for text in (state, unquote_plus(state)):
        for variant in (text, _WORD_JOINERS.sub(" ", text)):
            if variant not in variants:
                variants.append(variant)
    return variants


#: The constructor default; any other value warns (see ``OAuthStateEntropyGuard``).
_DEFAULT_ENTROPY_SKIP_THRESHOLD = 3.0


class OAuthStateEntropyGuard:
    """Detect prompt-injection payloads smuggled via OAuth ``state``."""

    def __init__(
        self,
        *,
        max_state_bytes: int = 2048,
        entropy_skip_threshold: float = 3.0,
    ) -> None:
        """Configure the guard.

        Args:
            max_state_bytes: A longer ``state`` is blocked before any decoding.
            entropy_skip_threshold: Deprecated; removal in v1.0.0. It never changed a
                verdict: every ``state`` is scanned whatever its entropy, and the value
                only picks the wording of an ``allow`` detail. Setting it away from its
                default emits a ``FutureWarning`` so it is not read as a security knob.
        """
        if entropy_skip_threshold != _DEFAULT_ENTROPY_SKIP_THRESHOLD:
            warnings.warn(
                "OAuthStateEntropyGuard(entropy_skip_threshold=...) has no effect on any "
                "verdict: every state is scanned whatever its entropy. Deprecated; it "
                "will be removed in v1.0.0.",
                FutureWarning,
                stacklevel=2,
            )
        self.max_state_bytes = max_state_bytes
        self.entropy_skip_threshold = entropy_skip_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, oauth_callback: Mapping[str, Any]) -> OAuthStateInspection:
        """Inspect the ``state`` parameter of an OAuth callback.

        Args:
            oauth_callback: The callback's parameters as a mapping (a ``state`` value may
                be a ``str``, ``bytes``, or a list of them, as ``parse_qs`` returns).

        Returns:
            The inspection. A callback that is not a mapping, and a ``state`` of no
            readable shape, are ``block``; an absent or empty ``state`` is ``warn``. For
            a list ``state`` the worst element's verdict is returned.
        """
        started = time.perf_counter()
        if not isinstance(oauth_callback, Mapping):
            return self._finalise(
                started,
                _Finding(
                    "block",
                    f"callback is a {type(oauth_callback).__name__}, not a mapping of "
                    "callback parameters; refusing rather than guessing where state is",
                    "shape",
                ),
            )
        values, refusal = _state_values(oauth_callback.get("state"))
        if refusal is not None:
            return self._finalise(started, refusal)
        if not values:
            return self._finalise(started, _Finding("warn", "state is empty"))
        worst_index, worst = 0, self._inspect(values[0])
        for index in range(1, len(values)):
            if worst.verdict == "block":
                break
            finding = self._inspect(values[index])
            if _SEVERITY[finding.verdict] > _SEVERITY[worst.verdict]:
                worst_index, worst = index, finding
        if len(values) > 1:
            worst = replace(worst, detail=f"state[{worst_index}]: {worst.detail}")
        return self._finalise(started, worst)

    def evaluate_or_raise(self, oauth_callback: Mapping[str, Any]) -> OAuthStateInspection:
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

    def _inspect(self, state: str) -> _Finding:
        """The verdict on one ``state`` string."""
        if state == "":
            return _Finding("warn", "state is empty")
        if len(state.encode("utf-8")) > self.max_state_bytes:
            return _Finding(
                "block", f"state exceeds {self.max_state_bytes} byte cap", "size_cap", state[:80]
            )
        jwt = self._jwt_finding(state)
        if jwt is not None:
            return jwt
        # Every decoder's output is scanned, not only the first printable one: a decoder
        # that turns the state into printable garbage first must not hide what a later
        # one decodes it to (a JSON state also "decodes" as lenient base64).
        decodings = _decodings(state)
        for decoder, decoded in decodings:
            matches = _scan(decoded)
            if matches:
                return _Finding(
                    "block",
                    f"decoded state contains injection trigger via {decoder}",
                    decoder,
                    decoded[:160],
                    matches,
                )
        plain = self._plain_text_finding(state)
        if plain is not None:
            return plain
        for decoder, decoded in decodings:
            # Random nonces have high raw-byte entropy too, but they don't decode into
            # printable text, whereas an encoded payload does; JSON is text by definition.
            if decoder.endswith("json") or self._is_printable(_visible(decoded)):
                return _Finding(
                    "allow", f"decoded via {decoder}; no injection trigger", decoder, decoded[:160]
                )
        entropy_bps = self._shannon_entropy(state)
        if entropy_bps >= self.entropy_skip_threshold:
            return _Finding("allow", f"high-entropy nonce ({entropy_bps:.2f} bits/byte)")
        return _Finding("allow", "no decoder produced printable ASCII")

    def _jwt_finding(self, state: str) -> _Finding | None:
        """A JWT-shaped state's verdict (its payload scanned), or None if it is not one."""
        if not self._looks_like_jwt(state):
            return None
        payload = _b64url_text(state.split(".")[1]) or ""
        matches = _scan(payload)
        if matches:
            return _Finding(
                "block",
                "JWT-shaped state carries an injection trigger in its payload",
                "jwt-payload",
                payload[:160],
                matches,
            )
        return _Finding("allow", "state matches JWT tri-segment shape")

    @staticmethod
    def _plain_text_finding(state: str) -> _Finding | None:
        """Refuse a state whose plain text carries a trigger phrase or reads as prose."""
        for variant in _plain_variants(state):
            matches = _scan(variant)
            if matches:
                return _Finding(
                    "block",
                    "plain-text state contains injection trigger",
                    "plain-text",
                    variant[:160],
                    matches,
                )
        if _is_json_structure(state) or _is_json_structure(unquote_plus(state)):
            # A JSON object or array is structure, read through its decoded form; a JSON
            # string literal is just quoted text, so it is read as prose like any other.
            return None
        # The state as given (``parse_qs`` has already decoded it) and with %-escapes
        # decoded, but never with "+" read as a space: a decoded standard-base64 nonce
        # carries literal "+" characters, and reading them as spaces split it into words.
        for text in _unique([state, unquote(state)]):
            if _reads_as_prose(text):
                return _Finding(
                    "block",
                    "plain-text state reads as natural-language prose, not an opaque nonce",
                    "plain-text",
                    text[:160],
                )
        return None

    @staticmethod
    def _looks_like_jwt(s: str) -> bool:
        """Three base64url segments whose header decodes to a JSON object."""
        parts = s.split(".")
        if len(parts) != 3 or not all(_BASE64URL.match(part) for part in parts):
            return False
        header = _b64url_text(parts[0])
        if header is None:
            return False
        try:
            return isinstance(json.loads(header), dict)
        except (ValueError, RecursionError):
            return False

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

    @staticmethod
    def _is_printable(s: str) -> bool:
        if not s:
            return False
        printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in ("\n", "\t"))
        return (printable / max(len(s), 1)) > 0.85

    def _finalise(self, started: float, finding: _Finding) -> OAuthStateInspection:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        logger.info(
            "oauth_state_inspect",
            verdict=finding.verdict,
            decoder=finding.decoder,
            duration_ms=round(elapsed_ms, 3),
            matches=len(finding.matches),
        )
        return OAuthStateInspection(
            verdict=finding.verdict,
            detail=finding.detail,
            decoder=finding.decoder,
            decoded_excerpt=finding.excerpt,
            matches=finding.matches,
            duration_ms=elapsed_ms,
        )


def _b64url_text(segment: str) -> str | None:
    """A base64url segment decoded to text, or None if it does not decode."""
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


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
    # A RecursionError is how the json codec refuses deep nesting (a 2 KB state can
    # hold a thousand brackets); until 0.10.28 it escaped evaluate(). ensure_ascii=False
    # keeps the characters a consumer reads: re-escaped as \uXXXX, a zero-width or
    # fullwidth character inside a phrase was text no lenient form could fold back.
    try:
        parsed = json.loads(s)
        if isinstance(parsed, (dict, list)):
            return json.dumps(parsed, ensure_ascii=False)
    except (ValueError, RecursionError):
        return None
    if isinstance(parsed, str):
        return parsed
    return None


def _decodings(state: str) -> list[tuple[str, str]]:
    """Every ``(decoder, text)`` the state decodes to, as written and percent-decoded.

    Bytes are decoded leniently (``errors="replace"``): a random-bytes nonce is not UTF-8,
    so a strict decode would refuse it, and :func:`_scan` reads the lenient forms anyway.
    """
    unquoted = unquote_plus(state)
    candidates = [(state, "")]
    if unquoted != state:
        candidates.append((unquoted, "percent-decoded-"))
    found: list[tuple[str, str]] = []
    for text, prefix in candidates:
        for decoder, fn in (
            ("url-safe-base64", _try_urlsafe_b64),
            ("base64", _try_b64),
            ("hex", _try_hex),
            ("json", _try_json),
        ):
            decoded = fn(text)
            if decoded:
                found.append((f"{prefix}{decoder}", decoded))
    return found


__all__ = [
    "OAuthStateEntropyGuard",
    "OAuthStateInjectionError",
    "OAuthStateInspection",
    "Verdict",
]
