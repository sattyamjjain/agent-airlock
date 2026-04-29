"""LangGraph prebuilt 1.0.11 ``ToolNode`` shape-compat shim (v0.5.9+).

LangGraph prebuilt 1.0.11 (2026-04-24) changed :class:`ToolNode` to
return a bare ``list[ToolMessage]`` instead of the historical
``{"messages": [...]}`` dict. Any downstream code that unwrapped the
dict will silently drop tool messages on a user who upgrades.

This shim normalises both shapes to ``list[ToolMessage]`` so airlock
audit / policy code can treat the surface uniformly. The probe is
lazy — neither :mod:`langgraph` nor :mod:`langchain_core` is imported
at module load — so the optional extra remains optional.

The :class:`ToolMessage` type is pinned to
:class:`langchain_core.messages.ToolMessage`, **not** the LangGraph
re-export, because LangGraph has shifted its public namespace twice
in the 1.x series; ``langchain_core`` is the stable home for the
class.

Reference
---------
* LangGraph prebuilt 1.0.11 release notes (2026-04-24):
  https://github.com/langchain-ai/langgraph/releases/tag/prebuilt%401.0.11
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.integrations.langgraph_toolnode_compat")

_DETECTED_PREBUILT_VERSION: str | None = None
_VERSION_PROBED: bool = False


def _detect_prebuilt_version() -> str | None:
    """Lazy probe of the installed ``langgraph.prebuilt`` package version.

    Returns the dotted version string (e.g. ``"1.0.11"``) when the
    package is importable, ``None`` otherwise. Does not raise — a
    missing dependency is the common case for users who only use the
    base LangChain bits.
    """
    global _DETECTED_PREBUILT_VERSION, _VERSION_PROBED
    if _VERSION_PROBED:
        return _DETECTED_PREBUILT_VERSION
    _VERSION_PROBED = True

    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            _DETECTED_PREBUILT_VERSION = version("langgraph-prebuilt")
        except PackageNotFoundError:
            try:
                _DETECTED_PREBUILT_VERSION = version("langgraph")
            except PackageNotFoundError:
                _DETECTED_PREBUILT_VERSION = None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("toolnode_compat_probe_failed", error=str(exc))
        _DETECTED_PREBUILT_VERSION = None
    return _DETECTED_PREBUILT_VERSION


def _is_post_1_0_11(version_str: str) -> bool:
    """Return ``True`` if ``version_str`` is at or beyond ``1.0.11``."""
    parts: list[int] = []
    for token in version_str.split("."):
        digits = ""
        for ch in token:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits:
            parts.append(int(digits))
        else:
            return False
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3]) >= (1, 0, 11)


def unwrap_toolnode_output(
    out: Any,
    version: str | None = None,
) -> list[Any]:
    """Normalise a ``ToolNode`` invocation result to ``list[ToolMessage]``.

    Args:
        out: The raw return value of ``ToolNode().invoke(...)``. May be
            either ``list[ToolMessage]`` (prebuilt >= 1.0.11) or
            ``{"messages": list[ToolMessage]}`` (prebuilt < 1.0.11).
        version: Optional explicit version hint; if omitted the probe
            runs lazily once. Useful for tests.

    Returns:
        The flattened ``list[ToolMessage]``. Returns an empty list
        rather than raising on an empty / unexpected shape so a single
        upstream change cannot blackhole every downstream audit.
    """
    if version is None:
        version = _detect_prebuilt_version()

    # Shape 1: bare list (1.0.11+). Test it first because the new shape
    # is what every fresh installation will see.
    if isinstance(out, list):
        return list(out)

    # Shape 2: legacy dict (< 1.0.11). Tolerate any other key alongside
    # ``"messages"`` so a third-party wrapper does not break the unwrap.
    if isinstance(out, dict):
        msgs = out.get("messages")
        if isinstance(msgs, list):
            return list(msgs)
        logger.warning(
            "toolnode_compat_dict_no_messages",
            keys=sorted(out.keys()),
            version=version,
        )
        return []

    # Shape 3: unknown — log and return empty rather than crash. The
    # alternative (raise) would break downstream audit on a single
    # upstream rev.
    logger.warning(
        "toolnode_compat_unknown_shape",
        type=type(out).__name__,
        version=version,
    )
    return []


__all__ = [
    "_DETECTED_PREBUILT_VERSION",
    "_detect_prebuilt_version",
    "_is_post_1_0_11",
    "unwrap_toolnode_output",
]
