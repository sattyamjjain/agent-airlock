"""Output sanitization for Agent-Airlock.

Provides PII detection, secret masking, and token truncation to prevent
sensitive data leakage back to LLMs and control output costs.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ._log import structlog

logger = structlog.get_logger("agent-airlock.sanitizer")


class SensitiveDataType(str, Enum):
    """Types of sensitive data that can be detected."""

    # PII
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"

    # India-specific PII
    AADHAAR = "aadhaar"  # 12-digit Indian ID
    PAN = "pan"  # Indian Permanent Account Number
    UPI_ID = "upi_id"  # Unified Payments Interface ID
    IFSC = "ifsc"  # Indian Financial System Code
    PERSONAL_NAME_DEVANAGARI = "personal_name_devanagari"  # v0.8.9 — Indic-script names
    INDIA_MOBILE = "india_mobile"  # v0.8.46 — +91 / trunk-0 prefixed 10-digit mobile

    # Secrets
    API_KEY = "api_key"
    PASSWORD = "password"  # nosec B105 - enum value name, not actual password
    AWS_KEY = "aws_key"
    PRIVATE_KEY = "private_key"
    JWT = "jwt"
    CONNECTION_STRING = "connection_string"


class MaskingStrategy(str, Enum):
    """Strategies for masking sensitive data."""

    FULL = "full"  # Replace entirely with [REDACTED]
    PARTIAL = "partial"  # Keep first/last few chars: sk-****-abcd
    TYPE_ONLY = "type_only"  # Replace with [EMAIL], [SSN], etc.
    HASH = "hash"  # Replace with hash prefix: [SHA256:a1b2c3...]


@dataclass
class SanitizationResult:
    """Result of sanitizing content."""

    original_length: int
    sanitized_length: int
    content: str
    was_truncated: bool = False
    detections: list[dict[str, Any]] = field(default_factory=list)
    detection_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "original_length": self.original_length,
            "sanitized_length": self.sanitized_length,
            "was_truncated": self.was_truncated,
            "detection_count": self.detection_count,
            "detections": self.detections,
        }


# Compiled regex patterns for sensitive data detection
PATTERNS: dict[SensitiveDataType, re.Pattern[str]] = {
    # PII Patterns
    SensitiveDataType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    SensitiveDataType.PHONE: re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
    ),
    SensitiveDataType.SSN: re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
    SensitiveDataType.CREDIT_CARD: re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"  # Visa
        r"5[1-5][0-9]{14}|"  # Mastercard
        r"3[47][0-9]{13}|"  # Amex
        r"6(?:011|5[0-9]{2})[0-9]{12})\b"  # Discover
    ),
    SensitiveDataType.IP_ADDRESS: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    # India-specific PII Patterns
    SensitiveDataType.AADHAAR: re.compile(
        r"\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b"  # 12 digits, starts with 2-9
    ),
    SensitiveDataType.PAN: re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"  # ABCDE1234F format
    ),
    # NPCI UPI handle (PSP/bank) allowlist. Curated to real, widely-used
    # handles; expanded in v0.8.37 to cover WhatsApp Pay, the major private
    # banks, Paytm Payments Bank, Slice and CRED. Each is anchored to a word
    # boundary so longer handles (e.g. @axisbank) win over shorter prefixes.
    SensitiveDataType.UPI_ID: re.compile(
        r"\b[a-zA-Z0-9._-]+@(?:"
        # PhonePe / Google Pay / Paytm / Amazon / wallets
        r"ybl|ibl|axl|apl|paytm|okaxis|okicici|okhdfcbank|oksbi|phonepe|gpay|"
        r"airtel|jio|freecharge|mobikwik|amazonpay|"
        # WhatsApp Pay
        r"waicici|wahdfcbank|waaxis|wasbi|"
        # Axis Bank ecosystem
        r"axisbank|axisb|okbizaxis|naviaxis|"
        # HDFC / ICICI / IDFC / Kotak
        r"hdfcbank|payzapp|icici|pockets|idfcbank|idfcfirst|kotak|kmbl|kmb|"
        # Yes / Federal / IndusInd / RBL / DBS / AU / BoB
        r"yesbank|yapl|yesg|fbl|federal|indus|indusind|rbl|dbs|aubank|barodampay|"
        # Paytm Payments Bank handles
        r"ptsbi|ptaxis|pthdfc|ptyes|"
        # Slice / CRED
        r"superyes|timecosmos|cred|"
        # PSU / generic
        r"sbi|pnb|boi|cnrb|upi"
        r")\b",
        re.IGNORECASE,
    ),
    SensitiveDataType.IFSC: re.compile(
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b"  # 4 letters + 0 + 6 alphanumeric
    ),
    # V0.8.9 Devanagari (Unicode U+0900–U+097F) personal-name span heuristic.
    # Matches 2+ Devanagari word characters surrounded by word boundaries.
    # The Hindi-noun allowlist further down filters common non-name words
    # (greetings, pronouns, interrogatives) to cut false positives.
    SensitiveDataType.PERSONAL_NAME_DEVANAGARI: re.compile(r"[ऀ-ॿ]{2,}(?:\s+[ऀ-ॿ]{2,})*"),
    # v0.8.46 India mobile. Deliberately REQUIRES an explicit country/trunk
    # prefix (``+91`` / ``91`` / leading ``0``) followed by a 10-digit number
    # starting 6-9. A *bare* 10-digit run is already caught by the (US-shaped)
    # PHONE pattern above.
    #
    # This comment used to end: "so the two never match the same span
    # (offset-based reverse-splice masking cannot corrupt)". The first half was
    # true and the conclusion did not follow from it. Distinct spans still
    # *overlap*: ``+91-9876543210`` is INDIA_MOBILE ``(0, 14)`` and PHONE
    # ``(4, 14)``, and overlap is all the old reverse-splice masker needed to
    # corrupt the text around them. Masking no longer depends on this property
    # either way — see :func:`merge_overlapping_detections`.
    SensitiveDataType.INDIA_MOBILE: re.compile(r"(?<!\d)(?:\+?91[\s-]?|0)[6-9]\d{9}(?!\d)"),
    # Secret Patterns
    SensitiveDataType.API_KEY: re.compile(
        r"\b(?:"
        r"sk-[a-zA-Z0-9]{20,}|"  # OpenAI
        r"sk-ant-[a-zA-Z0-9-]{20,}|"  # Anthropic
        r"AIza[0-9A-Za-z_-]{35}|"  # Google
        r"ghp_[a-zA-Z0-9]{36}|"  # GitHub PAT
        r"gho_[a-zA-Z0-9]{36}|"  # GitHub OAuth
        r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}|"  # GitHub fine-grained
        r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"  # Slack
        r")\b"
    ),
    SensitiveDataType.AWS_KEY: re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    SensitiveDataType.PASSWORD: re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
    ),
    SensitiveDataType.PRIVATE_KEY: re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    SensitiveDataType.JWT: re.compile(r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b"),
    SensitiveDataType.CONNECTION_STRING: re.compile(
        r"(?i)(?:"
        r"mongodb(?:\+srv)?://[^\s]+|"
        r"postgres(?:ql)?://[^\s]+|"
        r"mysql://[^\s]+|"
        r"redis://[^\s]+|"
        r"amqp://[^\s]+|"
        r"Server=[^;]+;.*(?:Password|Pwd)=[^;]+"
        r")"
    ),
}

# Default masking configuration
DEFAULT_MASK_CONFIG: dict[SensitiveDataType, MaskingStrategy] = {
    SensitiveDataType.EMAIL: MaskingStrategy.PARTIAL,
    SensitiveDataType.PHONE: MaskingStrategy.PARTIAL,
    SensitiveDataType.SSN: MaskingStrategy.FULL,
    SensitiveDataType.CREDIT_CARD: MaskingStrategy.PARTIAL,
    SensitiveDataType.IP_ADDRESS: MaskingStrategy.PARTIAL,
    # India-specific PII
    SensitiveDataType.AADHAAR: MaskingStrategy.PARTIAL,  # Show last 4 digits
    SensitiveDataType.PAN: MaskingStrategy.PARTIAL,  # Show first 2 + last 2
    SensitiveDataType.UPI_ID: MaskingStrategy.PARTIAL,  # Show @bank suffix
    SensitiveDataType.IFSC: MaskingStrategy.TYPE_ONLY,  # Bank codes are semi-public
    SensitiveDataType.PERSONAL_NAME_DEVANAGARI: MaskingStrategy.PARTIAL,  # v0.8.9
    SensitiveDataType.INDIA_MOBILE: MaskingStrategy.PARTIAL,  # v0.8.46 — reveal last 3
    # Secrets
    SensitiveDataType.API_KEY: MaskingStrategy.PARTIAL,
    SensitiveDataType.AWS_KEY: MaskingStrategy.PARTIAL,
    SensitiveDataType.PASSWORD: MaskingStrategy.FULL,
    SensitiveDataType.PRIVATE_KEY: MaskingStrategy.FULL,
    SensitiveDataType.JWT: MaskingStrategy.PARTIAL,
    SensitiveDataType.CONNECTION_STRING: MaskingStrategy.FULL,
}


def _mask_value(
    value: str,
    data_type: SensitiveDataType,
    strategy: MaskingStrategy,
) -> str:
    """Apply masking strategy to a sensitive value.

    Args:
        value: The sensitive value to mask.
        data_type: Type of sensitive data.
        strategy: Masking strategy to apply.

    Returns:
        Masked value string.
    """
    if strategy == MaskingStrategy.FULL:
        return "[REDACTED]"

    if strategy == MaskingStrategy.TYPE_ONLY:
        return f"[{data_type.value.upper()}]"

    if strategy == MaskingStrategy.HASH:
        import hashlib

        hash_prefix = hashlib.sha256(value.encode()).hexdigest()[:8]
        return f"[SHA256:{hash_prefix}...]"

    # PARTIAL masking - show first and last few characters
    if len(value) <= 8:
        return "*" * len(value)

    if data_type in (SensitiveDataType.EMAIL, SensitiveDataType.UPI_ID):
        # Show first char of local part and keep the domain / @bank suffix
        # (the bank handle is semi-public; the VPA / mailbox local part is the
        # identifying value, so it is masked).
        parts = value.split("@")
        if len(parts) == 2:
            local, domain = parts
            masked_local = local[0] + "***" if len(local) > 1 else "***"
            return f"{masked_local}@{domain}"

    if data_type == SensitiveDataType.CREDIT_CARD:
        # Show last 4 digits only
        return "**** **** **** " + value[-4:]

    if data_type == SensitiveDataType.AADHAAR:
        # UIDAI masked-Aadhaar standard: reveal only the last 4 digits
        # (the first 8 are never shown). The default first-3 + last-3 fall-
        # through would leak 6 of the 12 digits — too much for an Aadhaar.
        # Operate on the digit characters so separators (spaces / hyphens)
        # don't change the revealed count.
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4:
            return "*" * (len(digits) - 4) + digits[-4:]

    if data_type == SensitiveDataType.PAN:
        # Reveal first 2 + last 2 (PAN is ABCDE1234F; the 5-letter prefix and
        # the digits are the identifying part, so keep the revealed span minimal).
        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    if data_type == SensitiveDataType.INDIA_MOBILE:
        # Reveal only the last 3 digits of the subscriber number. Operate on the
        # digit characters so the +91/0 prefix and separators don't change the
        # revealed count: +91-XXXXX-<last3>.
        digits = re.sub(r"\D", "", value)
        return f"+91-XXXXX-{digits[-3:]}" if len(digits) >= 3 else f"+91-XXXXX-{digits}"

    if data_type in (SensitiveDataType.API_KEY, SensitiveDataType.AWS_KEY):
        # Show prefix and last 4 chars
        return value[:7] + "..." + value[-4:]

    if data_type == SensitiveDataType.JWT:
        # Show just the header type
        return value[:10] + "...[JWT]"

    # Default partial: show first 3 and last 3
    return value[:3] + "***" + value[-3:]


# --- V0.8.9 Indic PII helpers --------------------------------------------
# The two arrays below are the standard Verhoeff dihedral-group tables.
# Provided in canonical form so the algorithm reads identically to the
# reference; no symmetry shortcuts. Verhoeff is the algorithm UIDAI uses
# to generate Aadhaar's last digit — a checksum gate cuts the regex's
# false-positive rate (any 12-digit number starting 2-9 currently passes
# the bare regex; only ~1 in 10 of those pass Verhoeff).
_VERHOEFF_D: tuple[tuple[int, ...], ...] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P: tuple[tuple[int, ...], ...] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def _verhoeff_check(num: str) -> bool:
    """Return True if ``num`` (a digits-only string) passes Verhoeff.

    Reference: Verhoeff, J. (1969) "Error Detecting Decimal Codes".
    Used by UIDAI for Aadhaar's last-digit checksum. The function is
    deliberately tolerant of input length — Aadhaar is 12 digits but
    the algorithm itself works for any length.
    """
    if not num.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


# v0.8.46 — valid PAN holder-type codes (the 4th character of a PAN encodes the
# assessee category). Any other letter in that position is not a real PAN, so
# gating on this set cuts false positives on random ``[A-Z]{5}[0-9]{4}[A-Z]``
# strings. Canonical Income-Tax set: P(individual) C(company) H(HUF) F(firm/LLP)
# A(AOP) T(trust) B(body of individuals) L(local authority) J(artificial
# juridical person) G(government).
_PAN_ENTITY_TYPES: frozenset[str] = frozenset("PCHFATBLJG")


def _pan_entity_char_valid(value: str) -> bool:
    """Return True if the PAN's 4th character is a valid holder-type code."""
    return len(value) >= 4 and value[3] in _PAN_ENTITY_TYPES


# Common high-frequency Devanagari tokens that are NOT personal names.
# This list is intentionally small — it covers the most-likely false
# positives (greetings, pronouns, common interrogatives, basic
# connectives) so the heuristic doesn't mask every line of Hindi prose.
# Production callers who need a proper NER should layer one on top.
_DEVANAGARI_NON_NAME_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Greetings / pleasantries
        "नमस्ते",
        "नमस्कार",
        "धन्यवाद",
        "शुभ",
        "स्वागत",
        # Yes/no
        "हाँ",
        "हां",
        "जी",
        "नहीं",
        # Pronouns
        "मैं",
        "हम",
        "तुम",
        "आप",
        "वह",
        "वे",
        "यह",
        "ये",
        # Interrogatives
        "क्या",
        "कौन",
        "कब",
        "कहाँ",
        "कैसे",
        "क्यों",
        "कितना",
        "कितने",
        # Connectives / particles
        "और",
        "या",
        "लेकिन",
        "किन्तु",
        "परन्तु",
        "अगर",
        "तो",
        "भी",
        "ही",
        # Common verbs / copulas
        "है",
        "हैं",
        "था",
        "थी",
        "थे",
        "होगा",
        "होगी",
        "होंगे",
        # Common nouns
        "नाम",
        "घर",
        "देश",
        "दिन",
        "रात",
        "समय",
        "साल",
        "महीना",
        # Quality adjectives
        "अच्छा",
        "अच्छी",
        "बुरा",
        "बुरी",
        "बड़ा",
        "बड़ी",
        "छोटा",
        "छोटी",
    }
)


def _filter_devanagari_non_names(value: str) -> bool:
    """Return True if a Devanagari match should be KEPT as a name.

    Filters out tokens whose every word is in the common-noun allowlist;
    a multi-word span keeps if even one word is unrecognized (likely a
    proper noun). Single-word matches are kept unless they're in the
    allowlist.
    """
    words = value.split()
    if not words:
        return False
    # Drop if every word is a known non-name token
    return not all(w in _DEVANAGARI_NON_NAME_ALLOWLIST for w in words)


def _normalize_pii_locales(locales: list[str] | None) -> frozenset[str]:
    """Coerce ``pii_locales`` to a normalized frozenset of lowercase codes."""
    if not locales:
        return frozenset()
    return frozenset(loc.strip().lower() for loc in locales if loc)


# India-locale types that ``sanitize_output`` adds to the default PII set
# when ``pii_locales=["in"]`` is supplied. Existing callers who manually
# pass ``types=[...]`` continue to work unchanged.
_INDIA_LOCALE_PII_TYPES: tuple[SensitiveDataType, ...] = (
    SensitiveDataType.AADHAAR,
    SensitiveDataType.PAN,
    SensitiveDataType.UPI_ID,
    SensitiveDataType.IFSC,
    SensitiveDataType.PERSONAL_NAME_DEVANAGARI,
    SensitiveDataType.INDIA_MOBILE,
)


def detect_sensitive_data(
    content: str,
    types: list[SensitiveDataType] | None = None,
    pii_locales: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Detect sensitive data in content.

    Args:
        content: Text content to scan.
        types: Types of sensitive data to detect. If None, detect all.
        pii_locales: V0.8.9 opt-in locale tags. When ``"in"`` is included,
            Aadhaar matches are filtered through a Verhoeff checksum
            (cuts false positives) and Devanagari name matches are
            filtered against the common-noun allowlist. Locale-gating is
            additive and does NOT change behavior for callers that pass
            ``types`` explicitly without the locale flag.

    Returns:
        List of detection dictionaries with type, value, and position.
    """
    types = types or list(SensitiveDataType)
    locales = _normalize_pii_locales(pii_locales)
    indic_gate = "in" in locales
    detections: list[dict[str, Any]] = []

    for data_type in types:
        pattern = PATTERNS.get(data_type)
        if not pattern:  # pragma: no cover - all types have patterns
            continue

        for match in pattern.finditer(content):
            # For password pattern, use the captured group
            if data_type == SensitiveDataType.PASSWORD:
                value = match.group(1) if match.lastindex else match.group(0)
            else:
                value = match.group(0)

            # V0.8.9: Aadhaar Verhoeff gate (opt-in). When the caller
            # signals India locale, drop matches that don't pass
            # the UIDAI Verhoeff checksum.
            if indic_gate and data_type == SensitiveDataType.AADHAAR:
                digits_only = re.sub(r"[\s-]", "", value)
                if not _verhoeff_check(digits_only):
                    continue

            # v0.8.46: PAN entity-char gate (opt-in). When the caller signals
            # India locale, drop PAN-shaped matches whose 4th character is not a
            # valid holder-type code (cuts false positives on random
            # [A-Z]{5}[0-9]{4}[A-Z] strings).
            if (
                indic_gate
                and data_type == SensitiveDataType.PAN
                and not _pan_entity_char_valid(value)
            ):
                continue

            # V0.8.9: Devanagari name allowlist (opt-in). Drop matches
            # that are entirely common Hindi non-name tokens.
            if (
                indic_gate
                and data_type == SensitiveDataType.PERSONAL_NAME_DEVANAGARI
                and not _filter_devanagari_non_names(value)
            ):
                continue

            detections.append(
                {
                    "type": data_type.value,
                    "value": value,
                    "start": match.start(),
                    "end": match.end(),
                    "full_match": match.group(0),
                }
            )

    # Sort by position
    detections.sort(key=lambda d: d["start"])
    return detections


#: Declaration order of :class:`SensitiveDataType`, used only to break a tie
#: deterministically. It is not a specificity ranking and must not be read as one.
_TYPE_ORDER: dict[str, int] = {t.value: i for i, t in enumerate(SensitiveDataType)}


#: How much plaintext a strategy leaves behind, least protective first. A cluster
#: of overlapping detections is masked with the most protective strategy any of
#: its members asked for, so merging two spans can never reveal more than the
#: stricter of them would have on its own.
_STRATEGY_RANK: dict[MaskingStrategy, int] = {
    MaskingStrategy.PARTIAL: 0,
    MaskingStrategy.TYPE_ONLY: 1,
    MaskingStrategy.HASH: 2,
    MaskingStrategy.FULL: 3,
}


def merge_overlapping_detections(
    content: str,
    detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge each cluster of overlapping detections into one span covering their union.

    Patterns are matched independently per entity type, so the same characters
    are routinely claimed twice. ``+91-9876543210`` is both an ``india_mobile``
    span at ``(0, 14)`` and a ``phone`` span at ``(4, 14)``. Masking both is not
    merely redundant, it is incorrect: the second replacement indexes into a
    string the first one already resized.

    **The union, not the longest member.** Keeping only the longest span is safe
    when one span contains the other, which is the common case, but real inputs
    also produce *partial* overlaps. ``123-45-6789 4111-1111-1111-1111`` yields
    ``ssn`` at ``(0, 11)`` and ``aadhaar`` at ``(7, 21)``; neither contains the
    other. Keeping the longer one masks ``(7, 21)`` and leaves ``123-45-``
    standing, which converts a formatting bug into an unmasked SSN prefix.
    Covering the union cannot do that, and it makes the chain case safe too: if
    ``A`` overlaps ``B`` and ``B`` overlaps ``C``, all three collapse into one
    fully masked region rather than leaving the ends of ``A`` and ``C`` exposed.

    Args:
        content: The original text the offsets refer to.
        detections: Detections as returned by :func:`detect_sensitive_data`.

    Returns:
        A new list sorted by ``start``, one entry per overlapping cluster. A
        merged entry reports the longest member's ``type``, carries ``value``
        re-sliced to the union, and lists every contributing type in
        ``members``. Where a cluster merged more than one detection it also
        carries ``absorbed``, so a match that was folded in is still visible to
        an audit reader instead of vanishing from the record.
    """
    if not detections:
        return []

    clusters: list[list[dict[str, Any]]] = []
    for detection in sorted(detections, key=lambda d: (d["start"], d["end"])):
        if clusters and detection["start"] < max(m["end"] for m in clusters[-1]):
            clusters[-1].append(detection)
        else:
            clusters.append([detection])

    merged: list[dict[str, Any]] = []
    for cluster in clusters:
        # The longest member names the cluster; ties fall back to the type's
        # declaration order purely so the choice is stable. There is no
        # confidence score on a detection to break it on.
        primary = min(
            cluster,
            key=lambda d: (
                -(d["end"] - d["start"]),
                d["start"],
                _TYPE_ORDER.get(d["type"], len(_TYPE_ORDER)),
            ),
        )
        if len(cluster) == 1:
            merged.append(primary)
            continue

        start = min(m["start"] for m in cluster)
        end = max(m["end"] for m in cluster)
        entry = dict(primary)
        entry["start"] = start
        entry["end"] = end
        entry["value"] = content[start:end]
        entry["full_match"] = content[start:end]
        entry["members"] = sorted({m["type"] for m in cluster})
        entry["absorbed"] = sorted({m["type"] for m in cluster if m["type"] != primary["type"]})
        merged.append(entry)

    merged.sort(key=lambda d: d["start"])
    return merged


def _cluster_strategy(
    detection: dict[str, Any],
    mask_config: dict[SensitiveDataType, MaskingStrategy],
) -> MaskingStrategy:
    """The most protective strategy any member of a merged cluster asked for."""
    members = detection.get("members")
    if not members:
        return mask_config.get(SensitiveDataType(detection["type"]), MaskingStrategy.FULL)
    strategies = []
    for name in members:
        try:
            strategies.append(mask_config.get(SensitiveDataType(name), MaskingStrategy.FULL))
        except ValueError:  # a workspace custom pattern, not a built-in type
            strategies.append(MaskingStrategy.FULL)
    return max(strategies, key=lambda s: _STRATEGY_RANK.get(s, len(_STRATEGY_RANK)))


def _render_masked(
    content: str,
    spans: list[tuple[int, int, str]],
) -> str:
    """Rebuild ``content`` with ``spans`` replaced, in one left-to-right pass.

    The replaced-in-place version of this walked the detections in reverse and
    did ``result[:start] + masked + result[end:]`` against a string it had
    already modified. Reverse order keeps *earlier* offsets valid, but both
    offsets of the span being applied are read against the mutated string, so
    any length change from a previous replacement shifted ``end`` and the slice
    ate or duplicated neighbouring characters.

    Appending to an accumulator removes the class rather than the symptom:
    every offset is read against the original ``content``, which is never
    modified.

    Args:
        content: The original, unmodified text.
        spans: ``(start, end, replacement)`` tuples. Must not overlap; run
            :func:`merge_overlapping_detections` first.

    Returns:
        The rebuilt string.
    """
    out: list[str] = []
    cursor = 0
    for start, end, replacement in sorted(spans, key=lambda s: s[0]):
        out.append(content[cursor:start])
        out.append(replacement)
        cursor = end
    out.append(content[cursor:])
    return "".join(out)


def mask_sensitive_data(
    content: str,
    types: list[SensitiveDataType] | None = None,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
    pii_locales: list[str] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Mask sensitive data in content.

    Args:
        content: Text content to sanitize.
        types: Types of sensitive data to mask. If None, mask all.
        mask_config: Masking strategy per type. Uses defaults if not provided.
        pii_locales: V0.8.9 opt-in locale tags (forwarded to
            :func:`detect_sensitive_data`). When ``"in"`` is present,
            Aadhaar matches are Verhoeff-validated and Devanagari name
            matches are filtered through the common-noun allowlist.

    Returns:
        Tuple of (masked_content, list of detections).
    """
    mask_config = mask_config or DEFAULT_MASK_CONFIG
    detections = detect_sensitive_data(content, types, pii_locales=pii_locales)

    if not detections:
        return content, []

    # One detection per overlapping region, then a single left-to-right rebuild.
    # Both steps are required: resolving overlaps without the accumulator still
    # leaves correct-but-fragile index arithmetic, and the accumulator without
    # overlap resolution cannot represent two spans claiming the same characters.
    detections = merge_overlapping_detections(content, detections)

    spans: list[tuple[int, int, str]] = []
    for detection in detections:
        data_type = SensitiveDataType(detection["type"])
        strategy = _cluster_strategy(detection, mask_config)

        if data_type == SensitiveDataType.PASSWORD:
            # For passwords, we need to replace just the password value
            # but keep the "password=" prefix
            full_match = detection["full_match"]
            password_value = detection["value"]
            masked_value = _mask_value(password_value, data_type, strategy)
            replacement = full_match.replace(password_value, masked_value)
            detection["masked_as"] = "[REDACTED]"
        else:
            replacement = _mask_value(detection["value"], data_type, strategy)
            detection["masked_as"] = replacement

        spans.append((detection["start"], detection["end"], replacement))

    return _render_masked(content, spans), detections


def truncate_output(
    content: str,
    max_chars: int = 20000,
    add_summary: bool = True,
) -> tuple[str, bool]:
    """Truncate content if it exceeds maximum length.

    Args:
        content: Content to potentially truncate.
        max_chars: Maximum character length.
        add_summary: If True, add truncation notice.

    Returns:
        Tuple of (content, was_truncated).
    """
    if len(content) <= max_chars:
        return content, False

    # Reserve space for truncation notice
    notice = f"\n\n[OUTPUT TRUNCATED: Showing {max_chars:,} of {len(content):,} characters]"
    truncate_at = max_chars - len(notice) if add_summary else max_chars

    # Try to truncate at a natural boundary
    truncated = content[:truncate_at]

    # Find last newline for cleaner truncation
    last_newline = truncated.rfind("\n")
    if last_newline > truncate_at * 0.8:  # Only use if reasonably close
        truncated = truncated[:last_newline]

    if add_summary:
        truncated += notice

    logger.info(
        "output_truncated",
        original_length=len(content),
        truncated_length=len(truncated),
    )

    return truncated, True


def sanitize_output(
    content: Any,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    max_chars: int | None = None,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
    pii_locales: list[str] | None = None,
) -> SanitizationResult:
    """Sanitize output content.

    Converts content to string, masks sensitive data, and truncates if needed.

    Args:
        content: Content to sanitize (will be converted to string).
        mask_pii: If True, mask PII (email, phone, SSN, etc.).
        mask_secrets: If True, mask secrets (API keys, passwords, etc.).
        max_chars: Maximum output length. None for no limit.
        mask_config: Custom masking strategies per type.
        pii_locales: V0.8.9 opt-in locale tags. When ``"in"`` is present
            and ``mask_pii=True``, Aadhaar / PAN / UPI / IFSC / Devanagari
            name detection is added to the default PII set. The Aadhaar
            regex is gated with a Verhoeff checksum (cuts false positives
            on random 12-digit numbers) and Devanagari matches are
            filtered against a small common-noun allowlist. Existing
            callers that did not pass this argument get exactly the
            previous behavior — defaults are unchanged.

    Returns:
        SanitizationResult with sanitized content and metadata.
    """
    # Convert to string
    if isinstance(content, str):
        text = content
    elif isinstance(content, dict | list):
        try:
            text = json.dumps(content, indent=2, default=str)
        except (TypeError, ValueError):
            text = str(content)
    else:
        text = str(content)

    original_length = len(text)
    detections: list[dict[str, Any]] = []

    # Determine which types to mask
    types_to_mask: list[SensitiveDataType] = []

    if mask_pii:
        types_to_mask.extend(
            [
                SensitiveDataType.EMAIL,
                SensitiveDataType.PHONE,
                SensitiveDataType.SSN,
                SensitiveDataType.CREDIT_CARD,
                SensitiveDataType.IP_ADDRESS,
            ]
        )
        # V0.8.9: India locale opt-in. ``pii_locales=["in"]`` extends
        # the default PII set with Aadhaar / PAN / UPI / IFSC and the
        # new Devanagari name detector. Aadhaar matches are then
        # Verhoeff-gated inside ``detect_sensitive_data``.
        if "in" in _normalize_pii_locales(pii_locales):
            types_to_mask.extend(_INDIA_LOCALE_PII_TYPES)

    if mask_secrets:
        types_to_mask.extend(
            [
                SensitiveDataType.API_KEY,
                SensitiveDataType.PASSWORD,
                SensitiveDataType.AWS_KEY,
                SensitiveDataType.PRIVATE_KEY,
                SensitiveDataType.JWT,
                SensitiveDataType.CONNECTION_STRING,
            ]
        )

    # Mask sensitive data
    if types_to_mask:
        text, detections = mask_sensitive_data(
            text, types_to_mask, mask_config, pii_locales=pii_locales
        )

        if detections:
            logger.info(
                "sensitive_data_masked",
                detection_count=len(detections),
                types=[d["type"] for d in detections],
            )

    # Truncate if needed
    was_truncated = False
    if max_chars is not None and len(text) > max_chars:
        text, was_truncated = truncate_output(text, max_chars)

    return SanitizationResult(
        original_length=original_length,
        sanitized_length=len(text),
        content=text,
        was_truncated=was_truncated,
        detections=detections,
        detection_count=len(detections),
    )


@dataclass
class SanitizationConfig:
    """Configuration for output sanitization.

    Attributes:
        enabled: If False, skip all sanitization.
        mask_pii: Mask personally identifiable information.
        mask_secrets: Mask API keys, passwords, etc.
        max_output_chars: Maximum output length in characters.
        mask_strategies: Custom masking strategies per data type.
        pii_types: Specific PII types to mask (None = all).
        secret_types: Specific secret types to mask (None = all).
    """

    enabled: bool = True
    mask_pii: bool = True
    mask_secrets: bool = True
    max_output_chars: int | None = 20000
    mask_strategies: dict[SensitiveDataType, MaskingStrategy] = field(
        default_factory=lambda: dict(DEFAULT_MASK_CONFIG)
    )
    pii_types: list[SensitiveDataType] | None = None
    secret_types: list[SensitiveDataType] | None = None


@dataclass
class WorkspacePIIConfig:
    """Workspace-specific PII handling configuration.

    Allows different workspaces/tenants to have customized PII masking rules.

    Attributes:
        workspace_id: Identifier for this workspace configuration.
        mask_email_domains: Only mask emails from these domains. Empty list = mask all.
        allow_email_domains: Never mask emails from these domains.
        mask_phone_prefixes: Only mask phones with these prefixes. Empty list = mask all.
        allow_phone_prefixes: Never mask phones with these prefixes.
        custom_patterns: Workspace-specific regex patterns to detect and mask.
            Keys are pattern names, values are regex patterns.
        custom_strategies: Masking strategies for custom patterns.
        disabled_types: Sensitive data types to NOT mask for this workspace.
        enabled_types: If set, ONLY mask these types (overrides disabled_types).

    Example:
        config = WorkspacePIIConfig(
            workspace_id="enterprise-123",
            mask_email_domains=["competitor.com"],  # Only mask competitor emails
            allow_email_domains=["company.com"],  # Never mask internal emails
            custom_patterns={
                "employee_id": r"EMP-\\d{6}",  # Custom employee ID format
            },
        )
    """

    workspace_id: str
    mask_email_domains: list[str] = field(default_factory=list)
    allow_email_domains: list[str] = field(default_factory=list)
    mask_phone_prefixes: list[str] = field(default_factory=list)
    allow_phone_prefixes: list[str] = field(default_factory=list)
    custom_patterns: dict[str, str] = field(default_factory=dict)
    custom_strategies: dict[str, MaskingStrategy] = field(default_factory=dict)
    disabled_types: list[SensitiveDataType] = field(default_factory=list)
    enabled_types: list[SensitiveDataType] | None = None

    def should_mask_email(self, email: str) -> bool:
        """Determine if an email should be masked based on workspace rules.

        Args:
            email: The email address to check.

        Returns:
            True if the email should be masked, False otherwise.
        """
        domain = email.split("@")[-1].lower() if "@" in email else ""

        # Never mask allowed domains
        if any(domain.endswith(allowed.lower()) for allowed in self.allow_email_domains):
            return False

        # If mask_email_domains is set, only mask those domains
        if self.mask_email_domains:
            return any(domain.endswith(masked.lower()) for masked in self.mask_email_domains)

        # Default: mask all emails
        return True

    def should_mask_phone(self, phone: str) -> bool:
        """Determine if a phone number should be masked based on workspace rules.

        Args:
            phone: The phone number to check.

        Returns:
            True if the phone should be masked, False otherwise.
        """
        # Normalize phone for prefix checking
        normalized = re.sub(r"[^\d+]", "", phone)

        # Never mask allowed prefixes
        if any(normalized.startswith(allowed) for allowed in self.allow_phone_prefixes):
            return False

        # If mask_phone_prefixes is set, only mask those prefixes
        if self.mask_phone_prefixes:
            return any(normalized.startswith(prefix) for prefix in self.mask_phone_prefixes)

        # Default: mask all phones
        return True

    def get_active_types(self) -> list[SensitiveDataType]:
        """Get the list of sensitive data types that should be checked.

        Returns:
            List of SensitiveDataType that should be active for this workspace.
        """
        if self.enabled_types is not None:
            return self.enabled_types

        return [t for t in SensitiveDataType if t not in self.disabled_types]

    def get_custom_compiled_patterns(self) -> dict[str, re.Pattern[str]]:
        """Get compiled regex patterns for custom patterns.

        Returns:
            Dict mapping pattern name to compiled regex.
        """
        compiled: dict[str, re.Pattern[str]] = {}
        for name, pattern in self.custom_patterns.items():
            try:
                compiled[name] = re.compile(pattern)
            except re.error as e:
                logger.warning(
                    "invalid_custom_pattern",
                    workspace_id=self.workspace_id,
                    pattern_name=name,
                    error=str(e),
                )
        return compiled


#: Containers :func:`sanitize_structured` walks into; anything else is a leaf.
_WALKED_CONTAINERS = (dict, list, tuple, set, frozenset)


def sanitize_structured(
    value: Any,
    *,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
    pii_locales: list[str] | None = None,
) -> tuple[Any, int]:
    """Mask sensitive data in every string inside a dict, list, tuple or set.

    :func:`sanitize_output` turns a container into JSON text: the right input for
    detection and length accounting, but not something a tool can hand back, because its
    caller needs the same type. This walks the structure instead, masks each string value
    with the same detectors, and rebuilds only the containers that changed, so a tool
    returning ``{"content": [{"type": "text", "text": ...}]}`` still returns that shape.

    Dictionary keys and non-string leaves are left alone. A container reached a second
    time (a cycle) is returned as it is.

    Args:
        value: A string, a container of them, or any other leaf.
        mask_pii: As for :func:`sanitize_output`.
        mask_secrets: As for :func:`sanitize_output`.
        mask_config: As for :func:`sanitize_output`.
        pii_locales: As for :func:`sanitize_output`.

    Returns:
        ``(sanitized, detection_count)``. ``value`` itself comes back when nothing was
        masked, so an untouched result keeps its identity.
    """
    options: dict[str, Any] = {
        "mask_pii": mask_pii,
        "mask_secrets": mask_secrets,
        "mask_config": mask_config,
        "pii_locales": pii_locales,
    }
    return _walk_and_mask(value, options, set())


def _walk_and_mask(node: Any, options: dict[str, Any], seen: set[int]) -> tuple[Any, int]:
    if isinstance(node, str):
        result = sanitize_output(node, **options)
        return (result.content, result.detection_count) if result.detection_count else (node, 0)
    if not isinstance(node, _WALKED_CONTAINERS) or id(node) in seen:
        return node, 0
    seen.add(id(node))
    if isinstance(node, dict):
        pairs = [(key, _walk_and_mask(item, options, seen)) for key, item in node.items()]
        total = sum(count for _key, (_new, count) in pairs)
        if not total:
            return node, 0
        rebuilt = copy.copy(node)
        for key, (new, count) in pairs:
            if count:
                rebuilt[key] = new
        return rebuilt, total
    walked = [_walk_and_mask(item, options, seen) for item in node]
    total = sum(count for _new, count in walked)
    if not total:
        return node, 0
    return _rebuild_like(node, [new for new, _count in walked]), total


def _rebuild_like(node: Any, items: list[Any]) -> Any:
    """A container of ``node``'s own type holding ``items``."""
    if isinstance(node, list):
        rebuilt = copy.copy(node)
        rebuilt[:] = items
        return rebuilt
    if isinstance(node, tuple) and hasattr(node, "_fields"):
        namedtuple_type: Any = type(node)
        return namedtuple_type._make(items)
    try:
        return type(node)(items)
    except TypeError:  # a subclass whose constructor takes something else
        return tuple(items) if isinstance(node, tuple) else set(items)


def sanitize_with_workspace_config(
    content: Any,
    workspace_config: WorkspacePIIConfig,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    max_chars: int | None = None,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
) -> SanitizationResult:
    """Sanitize output with workspace-specific PII rules.

    Args:
        content: Content to sanitize.
        workspace_config: Workspace-specific configuration.
        mask_pii: If True, mask PII.
        mask_secrets: If True, mask secrets.
        max_chars: Maximum output length.
        mask_config: Custom masking strategies.

    Returns:
        SanitizationResult with sanitized content.
    """
    # Convert to string
    if isinstance(content, str):
        text = content
    elif isinstance(content, dict | list):
        try:
            text = json.dumps(content, indent=2, default=str)
        except (TypeError, ValueError):
            text = str(content)
    else:
        text = str(content)

    original_length = len(text)
    detections: list[dict[str, Any]] = []
    result_text = text

    # Get active types based on workspace config
    active_types = workspace_config.get_active_types()

    # Filter by PII/secrets flags
    types_to_check: list[SensitiveDataType] = []
    pii_types = {
        SensitiveDataType.EMAIL,
        SensitiveDataType.PHONE,
        SensitiveDataType.SSN,
        SensitiveDataType.CREDIT_CARD,
        SensitiveDataType.IP_ADDRESS,
    }
    secret_types = {
        SensitiveDataType.API_KEY,
        SensitiveDataType.PASSWORD,
        SensitiveDataType.AWS_KEY,
        SensitiveDataType.PRIVATE_KEY,
        SensitiveDataType.JWT,
        SensitiveDataType.CONNECTION_STRING,
    }

    if mask_pii:
        types_to_check.extend(t for t in active_types if t in pii_types)
    if mask_secrets:
        types_to_check.extend(t for t in active_types if t in secret_types)

    # Detect sensitive data
    mask_config = mask_config or DEFAULT_MASK_CONFIG
    all_detections = detect_sensitive_data(text, types_to_check)

    # Filter detections based on workspace rules
    filtered_detections: list[dict[str, Any]] = []
    for detection in all_detections:
        data_type = SensitiveDataType(detection["type"])

        # Apply workspace-specific filtering
        if data_type == SensitiveDataType.EMAIL and not workspace_config.should_mask_email(
            detection["value"]
        ):
            continue

        if data_type == SensitiveDataType.PHONE and not workspace_config.should_mask_phone(
            detection["value"]
        ):
            continue

        filtered_detections.append(detection)

    # Apply custom patterns
    custom_patterns = workspace_config.get_custom_compiled_patterns()
    for name, pattern in custom_patterns.items():
        for match in pattern.finditer(text):
            filtered_detections.append(
                {
                    "type": f"custom:{name}",
                    "value": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                    "full_match": match.group(0),
                }
            )

    # Same two steps as mask_sensitive_data, and required here for the same
    # reason. This path additionally mixes workspace custom patterns into the
    # built-in ones, so a custom pattern overlapping a built-in match is routine
    # rather than exotic.
    filtered_detections = merge_overlapping_detections(text, filtered_detections)

    spans: list[tuple[int, int, str]] = []
    for detection in filtered_detections:
        type_str = detection["type"]

        # Handle custom patterns
        if type_str.startswith("custom:"):
            pattern_name = type_str[7:]
            strategy = workspace_config.custom_strategies.get(pattern_name, MaskingStrategy.FULL)
            masked = (
                f"[{pattern_name.upper()}]"
                if strategy == MaskingStrategy.TYPE_ONLY
                else "[REDACTED]"
            )
            detection["masked_as"] = masked
        else:
            data_type = SensitiveDataType(type_str)
            strategy = _cluster_strategy(detection, mask_config)

            if data_type == SensitiveDataType.PASSWORD:
                full_match = detection["full_match"]
                password_value = detection["value"]
                masked_value = _mask_value(password_value, data_type, strategy)
                masked = full_match.replace(password_value, masked_value)
                detection["masked_as"] = "[REDACTED]"
            else:
                masked = _mask_value(detection["value"], data_type, strategy)
                detection["masked_as"] = masked

        spans.append((detection["start"], detection["end"], masked))
        detections.append(detection)

    result_text = _render_masked(text, spans)

    # No reverse() here any more. The old loop walked the detections backwards,
    # so it appended them in descending position and had to flip the list to
    # restore document order. This loop walks forwards, so the list is already
    # in order and flipping it would be the bug the flip used to fix.

    # Truncate if needed
    was_truncated = False
    if max_chars is not None and len(result_text) > max_chars:
        result_text, was_truncated = truncate_output(result_text, max_chars)

    if detections:
        logger.info(
            "workspace_sensitive_data_masked",
            workspace_id=workspace_config.workspace_id,
            detection_count=len(detections),
        )

    return SanitizationResult(
        original_length=original_length,
        sanitized_length=len(result_text),
        content=result_text,
        was_truncated=was_truncated,
        detections=detections,
        detection_count=len(detections),
    )
