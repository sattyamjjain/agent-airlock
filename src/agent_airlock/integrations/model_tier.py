"""Model-capability-tier classification (v0.5.5+).

Maps an LLM ``model_id`` string to a :class:`ModelCapabilityTier`. The
classification seed set comes from the Anthropic Mythos Preview
disclosure (2026-04-23 InfoQ coverage) documenting autonomous zero-day
discovery capabilities in frontier models, plus recent Unit 42 / MITRE
CRT benchmarks on offensive-cyber reasoning in Claude Opus 4.x,
GPT-5-2-Codex, and similar.

The table is deliberately conservative:
- Unknown model IDs fall back to ``STANDARD`` (no extra restrictions).
- Prefix matching is used so e.g. ``"claude-opus-4-7"`` and
  ``"claude-opus-4-7[1m]"`` both classify as OFFENSIVE_CYBER_CAPABLE.

Source:
  https://www.infoq.com/news/2026/04/anthropic-claude-mythos/
"""

from __future__ import annotations

from ..capabilities import ModelCapabilityTier

# Prefixes (lower-cased) and their tier. Longer prefixes win on ties —
# order is maintained by the list below, with the longest / most
# specific prefix first within each tier group.
_TIER_PREFIX_TABLE: tuple[tuple[str, ModelCapabilityTier], ...] = (
    # Zero-day capable (Anthropic Mythos Preview, 2026-04-23 InfoQ)
    ("claude-mythos", ModelCapabilityTier.ZERO_DAY_CAPABLE),
    # Offensive-cyber capable (Unit 42 + MITRE CRT benchmarks, 2026-04)
    ("claude-opus-4-7", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
    ("claude-opus-4-6", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
    ("claude-opus-4", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
    ("claude-sonnet-4-6", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
    ("gpt-5-2-codex", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
    ("gpt-5-2", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
    ("o4", ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE),
    # Standard (examples — explicit entries help callers audit the table)
    ("claude-3", ModelCapabilityTier.STANDARD),
    ("gpt-4", ModelCapabilityTier.STANDARD),
    ("gpt-3.5", ModelCapabilityTier.STANDARD),
    ("llama", ModelCapabilityTier.STANDARD),
    ("gemini", ModelCapabilityTier.STANDARD),
    ("mistral", ModelCapabilityTier.STANDARD),
)


def classify_model(model_id: str) -> ModelCapabilityTier:
    """Return the :class:`ModelCapabilityTier` for a given model ID.

    Args:
        model_id: The model identifier as it appears in SDK calls
            (e.g. ``"claude-opus-4-7"``, ``"gpt-5-2-codex"``). Case-
            insensitive.

    Returns:
        The matched tier. Unknown / ambiguous IDs return
        :attr:`ModelCapabilityTier.STANDARD` (safe default — no extra
        restrictions apply, callers can layer their own policy).

    Examples:
        >>> classify_model("claude-opus-4-7")
        <ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE: 'offensive_cyber_capable'>

        >>> classify_model("claude-mythos-preview")
        <ModelCapabilityTier.ZERO_DAY_CAPABLE: 'zero_day_capable'>

        >>> classify_model("totally-made-up-model")
        <ModelCapabilityTier.STANDARD: 'standard'>
    """
    if not model_id:
        return ModelCapabilityTier.STANDARD
    normalized = model_id.strip().lower()
    for prefix, tier in _TIER_PREFIX_TABLE:
        if normalized.startswith(prefix):
            return tier
    return ModelCapabilityTier.STANDARD


__all__ = ["classify_model"]
