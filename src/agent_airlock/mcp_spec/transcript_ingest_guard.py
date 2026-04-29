"""Guard for short-form-video transcript / on-screen-text ingestion (v0.5.9+).

Jiacheng Zhong's BlackHat Asia 2026 talk (2026-04-24) catalogued a
new payload family: short-form video transcripts and on-screen text
used as prompt-injection carriers. Agents that ingest video metadata
(YouTube / TikTok / Reels caption + creator-text + on-screen text)
need a guard that detects the same imperative-injection patterns the
``PRMetadataGuard`` catches in PR bodies — but in a different
ingestion context.

The guard reuses ``PRMetadataGuard``'s sanitiser at its core (the
imperative-detection regex set is the same threat model) and adds
:class:`SourceKind` tagging so audit logs record whether the override
arrived via a transcript line, an on-screen text overlay, a creator
handle, or a caption.

Reference
---------
* BlackHat Asia 2026 — TikTok agent attacks (Jiacheng Zhong, 2026-04-24):
  https://www.blackhat.com/asia-26/briefings/schedule/#tiktok-agent-attacks-zhong
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Literal

import structlog

from .pr_metadata_guard import PRMetadataGuard, SanitizedField

# Transcript-specific imperative patterns. PRMetadataGuard's regex set
# is conservative-scoped for PR bodies; the video-ingestion context
# legitimately blocks on patterns ("execute the following", "post
# credentials", "exfiltrate", "system override") that would be too
# aggressive in PR review but are clear smuggle in transcripts.
_TRANSCRIPT_IMPERATIVES: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bsystem[_\s]+override\b"),
    re.compile(r"(?i)\bexecute\s+the\s+following\b"),
    re.compile(r"(?i)\bpost\s+credentials?\b"),
    re.compile(r"(?i)\bexfiltrat\w*\b"),
    re.compile(r"(?i)\bexport\s+(?:the\s+)?(?:user\s+)?data\b"),
    re.compile(r"(?i)\bunrestricted\s+mode\b"),
    re.compile(r"(?i)\bdisregard\s+prior\s+(?:safety\s+)?(?:policies|instructions)\b"),
    re.compile(r"(?i)cat\s+~?/?\.?\s*aws/?\s*credentials?"),
)


def _strip_invisible_codepoints(text: str) -> str:
    """Replace Unicode-format / bidi codepoints with spaces.

    PR-metadata regexes use ``\b`` word boundaries; payloads that hide
    overrides between zero-width / RLO codepoints would otherwise
    sanitise into one long letter run with no word boundaries, and the
    regex would miss the match. Substituting a space preserves the
    intent of the override and restores boundary semantics.
    """
    out: list[str] = []
    for ch in text:
        if unicodedata.category(ch) == "Cf":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)

logger = structlog.get_logger("agent-airlock.mcp_spec.transcript_ingest_guard")

Verdict = Literal["allow", "warn", "block"]


class SourceKind(str, Enum):
    """Where in a video payload an offending text fragment originated."""

    TRANSCRIPT = "transcript"
    ON_SCREEN_TEXT = "on_screen_text"
    CAPTION = "caption"
    CREATOR_HANDLE = "creator_handle"
    TITLE = "title"


@dataclass(frozen=True)
class TranscriptInspection:
    """Result of one ``TranscriptIngestGuard.inspect`` call."""

    verdict: Verdict
    source_kind: SourceKind
    risk_score: float
    sanitized: SanitizedField
    reason: str


class TranscriptIngestGuard:
    """Apply the PR-metadata sanitiser to short-form-video text fields.

    ``inspect`` returns a :class:`TranscriptInspection` whose verdict
    is ``block`` when the underlying sanitiser flags an
    imperative-injection match, ``warn`` for soft matches, ``allow``
    otherwise.
    """

    def __init__(self, reject_threshold: float = 0.9) -> None:
        self._guard = PRMetadataGuard(reject_threshold=reject_threshold)
        self._reject_threshold = reject_threshold

    def inspect(
        self,
        text: str,
        source_kind: SourceKind | str = SourceKind.TRANSCRIPT,
    ) -> TranscriptInspection:
        """Inspect a single text field from a video metadata payload.

        Args:
            text: The raw text from the video field.
            source_kind: Which field the text was sourced from.
                Defaults to :attr:`SourceKind.TRANSCRIPT` since that
                is the most common ingestion path.

        Returns:
            A :class:`TranscriptInspection`. The ``verdict`` reflects
            ``risk_score`` against the same threshold the
            ``PRMetadataGuard`` uses for PR bodies.
        """
        kind = (
            source_kind
            if isinstance(source_kind, SourceKind)
            else SourceKind(source_kind)
        )
        # Substitute invisible codepoints with spaces *before* the
        # PR-metadata sanitiser so its word-boundary regexes still fire
        # on payloads that hide overrides between zero-width chars.
        normalised = _strip_invisible_codepoints(text)
        # ``PRMetadataGuard.sanitize`` accepts a ``VCSField`` literal
        # (pr_body / pr_title / commit_message / …). Video transcripts
        # don't fit any of those, but ``pr_body`` is the most permissive
        # and matches its threat-model assumptions (long-form text,
        # unauthenticated input).
        sanitized = self._guard.sanitize(normalised, source="pr_body")

        # Transcript-specific imperative scan: catches "system override",
        # "execute the following", "post credentials", etc. — patterns
        # too aggressive for PR bodies but clear smuggle in video text.
        transcript_matches = sum(
            1 for pat in _TRANSCRIPT_IMPERATIVES if pat.search(normalised)
        )
        boosted_score = sanitized.risk_score
        if transcript_matches > 0:
            # Same score-boost shape as PRMetadataGuard: 1 match -> 0.9,
            # 2 -> 0.95, 3+ -> 0.96+.
            boost = {1: 0.9, 2: 0.95}.get(transcript_matches, 0.96)
            boosted_score = max(boosted_score, boost)

        verdict: Verdict
        reason: str
        if boosted_score >= self._reject_threshold:
            verdict = "block"
            reason = (
                f"video {kind.value} contains model-targeting imperative "
                f"(score={boosted_score:.2f})"
            )
        elif boosted_score > 0.0:
            verdict = "warn"
            reason = (
                f"video {kind.value} contains weakly suspicious imperative "
                f"(score={boosted_score:.2f})"
            )
        else:
            verdict = "allow"
            reason = "no imperative pattern detected"
        logger.info(
            "transcript_inspect",
            source_kind=kind.value,
            verdict=verdict,
            risk_score=boosted_score,
            transcript_matches=transcript_matches,
        )
        return TranscriptInspection(
            verdict=verdict,
            source_kind=kind,
            risk_score=boosted_score,
            sanitized=sanitized,
            reason=reason,
        )


__all__ = [
    "SourceKind",
    "TranscriptIngestGuard",
    "TranscriptInspection",
    "Verdict",
]
