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

Every string the user is shown or asked for is classified: the whole payload is
walked, so a ``prompt`` / ``message`` / ``title`` / ``description`` at any depth, a
``requestedSchema`` property's name, title, description and choice labels, and a
JSON-RPC envelope's ``params.message`` are all read, as is a value that is a list or
``bytes``. Until 0.10.28 only those four keys at the top level were read, and the text
was cut at ``max_payload_bytes`` before it was classified. Input nested deeper than 32
levels, containing itself, or holding a value of no JSON shape is
:attr:`ElicitationClass.UNINSPECTABLE` (``block`` by default).

Text is classified as a host may show it: ``bytes`` are decoded as UTF-8 strictly, and
bytes that are not UTF-8, or a string holding a lone surrogate (what ``json.loads``
gives for ``"\\udcff"``), are uninspectable too. A format character, or a control
character other than tab, newline and carriage return, is read both as nothing
(``"pass\\x00word"`` is "password") and as a gap (``"enter\\x00your password"``), and
the worse class wins. Until 0.10.28 bytes were decoded with ``errors="replace"`` and
control characters were kept, so ``b"Please enter your pass\\xffword"`` and
``"pass\\x00word"`` were relayed as benign, and a lone surrogate raised
``UnicodeEncodeError`` instead of a verdict.

Reference
---------
* MCP spec PR #1487 (2026-04-28):
  https://github.com/modelcontextprotocol/specification/pull/1487
"""

from __future__ import annotations

import re
import time
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.elicitation_guard")

Verdict = Literal["allow", "relay_with_origin_badge", "relay_with_warning", "block"]

#: What :meth:`ElicitationGuard.evaluate` reads: a prompt string (or its bytes), the
#: mapping shape of an elicitation (or its JSON-RPC envelope), or a list of either.
ElicitationPayload = Mapping[str, Any] | str | bytes | list[Any] | tuple[Any, ...]


class ElicitationClass(str, Enum):
    """Coarse classification of an elicitation payload."""

    BENIGN = "benign"
    CREDENTIAL_REQUEST = "credential_request"
    POLICY_OVERRIDE = "policy_override"
    DESTRUCTIVE_CONFIRMATION = "destructive_confirmation"
    #: The payload could not be read whole (deeper than 32 levels, containing itself,
    #: holding a value of no JSON shape, bytes that are not UTF-8 or a string with a lone
    #: surrogate), so nothing about it was classified.
    UNINSPECTABLE = "uninspectable"


#: Nesting depth past which a payload is refused as uninspectable rather than walked.
_MAX_DEPTH = 32

#: Keys whose text the host renders as the elicitation's prompt. Read first at every
#: level, in this order, so the rendered payload reads as it did before 0.10.28.
_DISPLAY_KEYS: tuple[str, ...] = ("prompt", "message", "title", "description")


#: A lone surrogate: a ``str`` can hold one, but it is no character and encodes to nothing.
_SURROGATE = re.compile("[\ud800-\udfff]")

#: The ASCII control characters a host shows as nothing or as a gap: all but tab, newline
#: and carriage return.
_ASCII_HIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class _Uninspectable(Exception):
    """Internal: the walk met input it cannot read whole."""


def _decode(value: bytes | bytearray | memoryview) -> str:
    """UTF-8, strictly: a replaced byte inside a phrase hid it from every pattern."""
    try:
        return bytes(value).decode("utf-8")
    except UnicodeDecodeError:
        raise _Uninspectable("a bytes value is not valid UTF-8") from None


def _hidden(char: str) -> bool:
    """A format character, or a control character other than tab, newline and CR."""
    category = unicodedata.category(char)
    return category == "Cf" or (category == "Cc" and char not in "\t\n\r")


class _TextWalk:
    """Collects every string in an elicitation payload, and the subset a host displays.

    Keys are text too: a ``requestedSchema`` property's name is the label of the field
    the user is asked to fill when it has no ``title``.
    """

    def __init__(self) -> None:
        self.scanned: list[str] = []
        self.displayed: list[str] = []

    def walk(self, value: Any, *, display: bool, depth: int, ancestors: frozenset[int]) -> None:
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = _decode(value)
        if isinstance(value, str):
            if _SURROGATE.search(value):
                raise _Uninspectable("a string holds a lone surrogate, which is not text")
            self.scanned.append(value)
            if display:
                self.displayed.append(value)
            return
        if value is None or isinstance(value, (bool, int, float)):
            return  # carries no text a pattern could match
        if not isinstance(value, (Mapping, list, tuple, set, frozenset)):
            raise _Uninspectable(f"a {type(value).__name__} value has no JSON shape")
        if depth >= _MAX_DEPTH:
            raise _Uninspectable(f"the payload nests deeper than {_MAX_DEPTH} levels")
        if id(value) in ancestors:
            raise _Uninspectable("the payload contains itself")
        inner = ancestors | {id(value)}
        if isinstance(value, Mapping):
            self._walk_mapping(value, display=display, depth=depth, ancestors=inner)
            return
        for item in value:
            self.walk(item, display=display, depth=depth + 1, ancestors=inner)

    def _walk_mapping(
        self, value: Mapping[Any, Any], *, display: bool, depth: int, ancestors: frozenset[int]
    ) -> None:
        keys = [key for key in _DISPLAY_KEYS if key in value]
        keys += [key for key in value if key not in _DISPLAY_KEYS]
        for key in keys:
            self.walk(key, display=False, depth=depth + 1, ancestors=ancestors)
            shown = display or (isinstance(key, str) and key in _DISPLAY_KEYS)
            self.walk(value[key], display=shown, depth=depth + 1, ancestors=ancestors)


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
        ElicitationClass.UNINSPECTABLE: "block",
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

    def _readings(self, text: str) -> list[str]:
        """``text`` NFKC-folded (confusables), with its hidden characters dropped, and spaced.

        A host may show a format character, or a control character other than tab,
        newline and CR, as nothing (``"pass\\x00word"`` reads "password") or as a gap
        (``"enter\\x00your password"``), so text holding one has both readings.
        """
        nfkc = unicodedata.normalize("NFKC", text)
        if nfkc.isascii():
            if not _ASCII_HIDDEN.search(nfkc):
                return [nfkc]
            return [_ASCII_HIDDEN.sub("", nfkc), _ASCII_HIDDEN.sub(" ", nfkc)]
        dropped = "".join(c for c in nfkc if not _hidden(c))
        if len(dropped) == len(nfkc):
            return [nfkc]
        return [dropped, "".join(" " if _hidden(c) else c for c in nfkc)]

    def _classify_payload(self, text: str) -> tuple[ElicitationClass, list[str]]:
        """The most severe class any reading of ``text`` matches, and the matched phrase."""
        readings = self._readings(text)
        for classification, patterns in (
            (ElicitationClass.CREDENTIAL_REQUEST, _CREDENTIAL_PATTERNS),
            (ElicitationClass.POLICY_OVERRIDE, _POLICY_OVERRIDE_PATTERNS),
            (ElicitationClass.DESTRUCTIVE_CONFIRMATION, _DESTRUCTIVE_CONFIRMATION_PATTERNS),
        ):
            for pat in patterns:
                for reading in readings:
                    m = pat.search(reading)
                    if m:
                        return classification, [m.group(0)]
        return ElicitationClass.BENIGN, []

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        elicitation_msg: ElicitationPayload,
        *,
        server_origin: str,
        session_ctx: dict[str, Any] | None = None,  # noqa: ARG002 — reserved
    ) -> ElicitationInspection:
        """Inspect an elicitation payload from ``server_origin``.

        Every string in the payload is classified, keys included; the text is not cut
        at ``max_payload_bytes`` first (that cap bounds only the rendered payload).

        Args:
            elicitation_msg: A string prompt (or ``bytes``), the mapping shape from MCP
                spec PR #1487 (``{"prompt": str, "schema": ...}``, or a full
                ``elicitation/create`` JSON-RPC message), or a list of either. Extra
                keys are read too.
            server_origin: A short id for the originating server (e.g.
                ``"github"`` / ``"jira-mcp"``). Recorded in audit logs;
                used to gate the ``allowlist_origins`` short-circuit.
            session_ctx: Optional session metadata. Currently
                unused; reserved for future "in-flight tool name"
                checks.

        Raises:
            TypeError: ``elicitation_msg`` is not a string, ``bytes``, mapping, list or
                tuple. A value of another shape nested inside one is
                :attr:`ElicitationClass.UNINSPECTABLE` instead.
        """
        started = time.perf_counter()

        if not isinstance(
            elicitation_msg, (str, bytes, bytearray, memoryview, Mapping, list, tuple)
        ):
            raise TypeError(
                "elicitation_msg must be str, bytes, a mapping or a list, got "
                f"{type(elicitation_msg).__name__}"
            )
        walk = _TextWalk()
        classification: ElicitationClass
        raw_matches: list[str]
        try:
            walk.walk(
                elicitation_msg,
                display=not isinstance(elicitation_msg, (Mapping, list, tuple)),
                depth=0,
                ancestors=frozenset(),
            )
        except _Uninspectable as exc:
            logger.warning(
                "elicitation_uninspectable", server_origin=server_origin, reason=str(exc)
            )
            classification, raw_matches = ElicitationClass.UNINSPECTABLE, []
        else:
            classification, raw_matches = self._classify_payload("\n".join(walk.scanned))
        verdict = self.actions.get(classification, "block")

        encoded = "\n".join(walk.displayed).encode("utf-8")[: self.max_payload_bytes]
        text = encoded.decode("utf-8", errors="replace")

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
        elicitation_msg: ElicitationPayload,
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
    "ElicitationPayload",
    "Verdict",
]
