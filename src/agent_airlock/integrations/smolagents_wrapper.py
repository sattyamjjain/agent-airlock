"""First-class HuggingFace ``smolagents`` integration (v0.6.0+).

smolagents 1.18 (2026-04-29) added native MCP transport. Users with
the smolagents installed base — non-trivial after the recent HF
campaign — now expect drop-in airlock coverage. This wrapper gives
them ``wrap_agent(agent, policy_bundle)`` and forwards every tool
call through the configured guard chain.

Reference
---------
* smolagents 1.18 release notes (2026-04-29):
  https://github.com/huggingface/smolagents/releases/tag/v1.18
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.integrations.smolagents_wrapper")


class GuardCallback(Protocol):
    """Minimum protocol every guard the wrapper invokes must satisfy."""

    def __call__(self, tool_name: str, args: dict[str, Any]) -> Any: ...


@dataclass
class PolicyBundle:
    """A small, self-contained bundle the wrapper enforces.

    A real airlock pack also carries presets + signatures, but for the
    wrapper's purposes a list of guard callbacks is enough.
    """

    bundle_id: str
    guards: tuple[GuardCallback, ...] = field(default_factory=tuple)


class SmolAgentsToolBlocked(AirlockError):
    """Raised when a guard refuses a smolagents tool call."""

    def __init__(self, message: str, *, tool_name: str, guard_id: str) -> None:
        self.tool_name = tool_name
        self.guard_id = guard_id
        super().__init__(message)


def wrap_agent(agent: Any, policy_bundle: PolicyBundle) -> Any:
    """Wrap a smolagents-shaped agent so every tool call routes through the bundle.

    The wrapper is structural: it only requires the agent to expose
    ``tools`` (a ``dict[str, Tool]`` or list with ``.name`` attribute)
    and that each tool has a ``forward`` / ``__call__`` method. We do
    not import ``smolagents`` at module load — keeps the integration
    optional.
    """
    tools = getattr(agent, "tools", None)
    if tools is None:
        raise AirlockError(
            "agent does not expose a `tools` attribute; not a smolagents-shaped object"
        )

    if isinstance(tools, dict):
        for name, tool in tools.items():
            tools[name] = _wrap_tool(tool, policy_bundle, fallback_name=str(name))
    elif isinstance(tools, list):
        for idx, tool in enumerate(tools):
            tools[idx] = _wrap_tool(
                tool, policy_bundle, fallback_name=getattr(tool, "name", f"tool_{idx}")
            )
    else:
        raise AirlockError(
            f"unrecognised agent.tools type {type(tools).__name__}; expected dict or list"
        )
    logger.info(
        "smolagents_agent_wrapped",
        bundle_id=policy_bundle.bundle_id,
        guard_count=len(policy_bundle.guards),
    )
    return agent


def _wrap_tool(tool: Any, policy_bundle: PolicyBundle, *, fallback_name: str) -> Any:
    """Replace ``tool.forward`` / ``tool.__call__`` with a guarded shim."""
    name = getattr(tool, "name", fallback_name)
    forward: Callable[..., Any] | None = getattr(tool, "forward", None)
    if forward is None and callable(tool):
        forward = tool
    if forward is None:
        raise AirlockError(f"tool {name!r} exposes neither `forward` nor `__call__`; cannot wrap")

    def _guarded(*args: Any, **kwargs: Any) -> Any:
        # smolagents passes args either positionally (rare) or as
        # kwargs. We forward both shapes to each guard.
        for guard in policy_bundle.guards:
            try:
                guard(name, kwargs or {"args": args})
            except AirlockError as exc:
                logger.warning(
                    "smolagents_tool_blocked",
                    tool=name,
                    error=str(exc),
                )
                raise SmolAgentsToolBlocked(
                    f"smolagents tool {name!r} refused: {exc}",
                    tool_name=name,
                    guard_id=getattr(guard, "__name__", "anonymous"),
                ) from exc
        return forward(*args, **kwargs)

    if hasattr(tool, "forward"):
        tool.forward = _guarded
        return tool
    # Fall back to wrapping the callable itself: smolagents tools
    # without an explicit ``forward`` attribute are rare, but when
    # they happen we replace the callable on the agent side via the
    # registry rewrite that ``wrap_agent`` does.
    return _guarded


__all__ = [
    "GuardCallback",
    "PolicyBundle",
    "SmolAgentsToolBlocked",
    "wrap_agent",
]
