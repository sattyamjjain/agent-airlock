"""The Claude models the credit-funded benchmarks run, and the settings pinned for each.

Effort is pinned to each model's API default and recorded with every run, so a later
change to a default cannot silently change what a published number measured. Defaults
per the Claude API reference (2026-10): ``medium`` on Opus 5.5 and Haiku 5.5, ``high``
on Sonnet 5.5 and Fable 5.1.
"""

from __future__ import annotations

MODELS: dict[str, str] = {
    "h55": "claude-haiku-5-5",
    "s55": "claude-sonnet-5-5",
    "o55": "claude-opus-5-5",
    "f51": "claude-fable-5-1",
}
"""Short alias -> exact model id. Aliases appear in ``custom_id`` values, which the
Batch API caps at 64 characters."""

DEFAULT_EFFORT: dict[str, str] = {
    "claude-haiku-5-5": "medium",
    "claude-sonnet-5-5": "high",
    "claude-opus-5-5": "medium",
    "claude-fable-5-1": "high",
}

_ID_TO_ALIAS = {model_id: alias for alias, model_id in MODELS.items()}


def resolve_model(name: str) -> str:
    """Return the exact model id for an alias (``h55``) or an id (``claude-haiku-5-5``).

    Raises:
        ValueError: The name is neither a known alias nor a known id.
    """
    if name in MODELS:
        return MODELS[name]
    if name in _ID_TO_ALIAS:
        return name
    known = ", ".join(sorted(MODELS) + sorted(_ID_TO_ALIAS))
    raise ValueError(f"unknown model {name!r}; known: {known}")


def model_alias(model_id: str) -> str:
    """Return the short alias for an exact model id.

    Raises:
        ValueError: The id is not one of :data:`MODELS`.
    """
    try:
        return _ID_TO_ALIAS[model_id]
    except KeyError as exc:
        raise ValueError(f"no alias for model {model_id!r}") from exc
