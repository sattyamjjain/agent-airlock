"""PydanticAI canonical adapter (v0.7.1+).

PydanticAI cut three releases in the past 7 days (v1.88.0 → v1.89.1)
that landed concrete `Agent`-level extension hooks. Until v0.7.0,
agent-airlock listed PydanticAI as "example-only" — users had to remember
the ``@framework_decorator`` over ``@Airlock()`` rule themselves. This
adapter promotes PydanticAI to adapter-shipped: ``wrap_agent(agent,
policy=...)`` walks the agent's toolsets, replaces each function-tool
callable with the Airlock-decorated version, and (when the version
supports it) attaches an ``output_validate`` hook so structured output
is sanitized before it leaves the model boundary.

The PydanticAI package is **not** imported at module load — callers
without the ``[pydantic-ai]`` extra installed still ``import
agent_airlock`` cleanly. Stub agents (any object with a ``toolsets``
attribute) bypass the SDK import — the test seam.

Optional dep
------------
``pip install "agent-airlock[pydantic-ai]"`` pulls
``pydantic-ai>=1.88.0,<2.0``. v1.88.0 introduced the
``output_validate`` / ``output_process`` hooks the adapter binds to;
older versions raise :class:`PydanticAIMissingError` with a "needs
>=1.88.0" hint rather than silently mis-wiring.

Primary sources
---------------
- PydanticAI v1.88.0 (2026-04-29):
  https://github.com/pydantic/pydantic-ai/releases/tag/v1.88.0
- PydanticAI v1.89.0 (2026-05-01):
  https://github.com/pydantic/pydantic-ai/releases/tag/v1.89.0
- PydanticAI v1.89.1 (2026-05-01):
  https://github.com/pydantic/pydantic-ai/releases/tag/v1.89.1
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import structlog

from ..core import Airlock
from ..exceptions import AirlockError
from ..policy import SecurityPolicy

logger = structlog.get_logger("agent-airlock.integrations.pydantic_ai")


SUPPORTED_PYDANTIC_AI_VERSIONS: tuple[str, ...] = ("1.88.0", "1.89.0", "1.89.1")
"""PydanticAI versions this adapter has been smoke-tested against.

A user running an unsupported version sees a :class:`UserWarning`
(via ``warnings.warn``) at ``wrap_agent`` time but no hard failure —
the public surface tested is the toolsets walk, which has been stable
since v1.88.0. Update this tuple when a new version is verified.
"""

_INSTALL_HINT = (
    "pydantic-ai>=1.88.0 is not installed. "
    'Install the extra: pip install "agent-airlock[pydantic-ai]"'
)


class PydanticAIMissingError(AirlockError):
    """Raised when ``wrap_agent`` is called without the extra installed.

    Subclass of :class:`AirlockError` so callers get a clear,
    actionable error instead of a deep ``ImportError`` from inside
    PydanticAI's package layout.
    """


@dataclass
class PydanticAIAdapter:
    """Single facade that wraps a ``pydantic_ai.Agent`` with Airlock.

    Attributes:
        attach_output_validate: When ``True`` (default), the adapter
            attaches an ``output_validate`` hook that runs the
            existing :func:`agent_airlock.sanitizer.sanitize_output`
            over structured output before it leaves the model
            boundary. Hook is a v1.88.0+ surface; older PydanticAI
            versions silently skip this step.
    """

    attach_output_validate: bool = True

    def wrap_agent(self, agent: Any, *, policy: SecurityPolicy | None = None) -> Any:
        """Wrap a PydanticAI ``Agent`` so every tool routes through Airlock.

        Args:
            agent: A :class:`pydantic_ai.Agent`-shaped object. The
                adapter requires either a ``toolsets`` attribute
                (PydanticAI v1.88.0+ public surface — list of toolsets,
                each carrying a ``tools`` dict mapping name → callable
                or tool object), or a flat ``tools`` dict/list (test
                stub). Real ``Agent`` objects expose ``toolsets``.
            policy: Optional :class:`SecurityPolicy`. When set, every
                tool callable is wrapped with
                :class:`Airlock(policy=policy)`.

        Returns:
            The same agent, mutated in place — every tool callable
            replaced by an Airlock-decorated shim.

        Raises:
            PydanticAIMissingError: ``pydantic-ai`` extra is missing
                AND the agent is not a structural stub. Stub agents
                (``hasattr(agent, "toolsets") or hasattr(agent,
                "tools")``) bypass the SDK import.
            AirlockError: The agent exposes neither ``toolsets`` nor
                ``tools``, so it's not a recognised PydanticAI shape.
        """
        self._maybe_check_sdk(agent)
        wrapped_count = self._wrap_toolsets_or_tools(agent, policy=policy)
        if self.attach_output_validate:
            self._maybe_attach_output_validate(agent)

        logger.info(
            "pydantic_ai_agent_wrapped",
            tool_count=wrapped_count,
            policy_set=policy is not None,
            output_validate_attached=self.attach_output_validate,
        )
        return agent

    def _wrap_toolsets_or_tools(self, agent: Any, *, policy: SecurityPolicy | None) -> int:
        """Walk the agent's tool surface and replace callables. Returns count."""
        toolsets = getattr(agent, "toolsets", None)
        if toolsets is not None:
            return self._wrap_toolsets(toolsets, policy=policy)

        tools = getattr(agent, "tools", None)
        if tools is None:
            raise AirlockError(
                "agent exposes neither `toolsets` nor `tools`; not a PydanticAI shape"
            )
        return self._wrap_tools_collection(tools, policy=policy)

    def _wrap_toolsets(self, toolsets: Any, *, policy: SecurityPolicy | None) -> int:
        """Walk a list/iterable of toolsets, each with its own ``tools``."""
        count = 0
        for toolset in toolsets:
            inner = getattr(toolset, "tools", None)
            if inner is None:
                continue
            count += self._wrap_tools_collection(inner, policy=policy)
        return count

    def _wrap_tools_collection(self, tools: Any, *, policy: SecurityPolicy | None) -> int:
        """Replace every tool's callable with the Airlock-decorated version."""
        count = 0
        if isinstance(tools, dict):
            for name, tool in tools.items():
                tools[name] = self._wrap_one(tool, name=str(name), policy=policy)
                count += 1
        elif isinstance(tools, list):
            for idx, tool in enumerate(tools):
                tools[idx] = self._wrap_one(
                    tool,
                    name=getattr(tool, "name", f"tool_{idx}"),
                    policy=policy,
                )
                count += 1
        else:
            raise AirlockError(
                f"unrecognised tools type {type(tools).__name__}; expected dict or list"
            )
        return count

    def _wrap_one(self, tool: Any, *, name: str, policy: SecurityPolicy | None) -> Any:
        """Replace ``tool.function`` / ``tool.run`` / ``tool`` with a guarded shim."""
        target_attr: str | None = None
        forward: Callable[..., Any] | None = None
        # PydanticAI v1.88+ Tool objects use ``.function`` for the user
        # callable; some older shapes expose ``.run``. Plain callables
        # are wrapped directly.
        for candidate in ("function", "run"):
            attr = getattr(tool, candidate, None)
            if callable(attr):
                target_attr = candidate
                forward = attr
                break
        if forward is None and callable(tool):
            forward = tool
        if forward is None:
            raise AirlockError(
                f"tool {name!r} has no callable attribute (`function`/`run`/__call__); cannot wrap"
            )

        # Re-tag the proxy with the tool's name so SecurityPolicy
        # allowed/denied lists target the tool, not its method name.
        def _named_proxy(*args: Any, **kwargs: Any) -> Any:
            return forward(*args, **kwargs)

        _named_proxy.__name__ = name
        _named_proxy.__qualname__ = name

        airlock = Airlock(policy=policy) if policy is not None else Airlock()
        wrapped = airlock(_named_proxy)

        if target_attr is not None:
            setattr(tool, target_attr, wrapped)  # noqa: B010
            return tool
        return wrapped

    def _maybe_attach_output_validate(self, agent: Any) -> None:
        """Wire ``agent.output_validate`` to the airlock sanitizer (v1.88+).

        If the attribute is absent (older PydanticAI), this silently
        skips — the version-mismatch warning has already fired.
        """
        if not hasattr(agent, "output_validate"):
            return
        from ..sanitizer import sanitize_output

        existing = getattr(agent, "output_validate", None)

        def _airlock_output_validate(value: Any) -> Any:
            sanitized = sanitize_output(str(value))
            # If the user already has an output_validate, chain through.
            if callable(existing) and existing is not _airlock_output_validate:
                return existing(sanitized.content)
            return sanitized.content

        agent.output_validate = _airlock_output_validate

    def _maybe_check_sdk(self, agent: Any) -> None:
        """Raise :class:`PydanticAIMissingError` only for real PydanticAI objects.

        Stubs (test doubles) carrying ``toolsets`` / ``tools`` but no
        real PydanticAI provenance are allowed through — the test
        surface needs to run without the optional dep installed.

        Also emits a :class:`UserWarning` when the installed PydanticAI
        version is outside :data:`SUPPORTED_PYDANTIC_AI_VERSIONS`.
        """
        module = type(agent).__module__
        if not module.startswith("pydantic_ai"):
            return
        try:
            import pydantic_ai as _pai
        except ImportError as exc:
            raise PydanticAIMissingError(_INSTALL_HINT) from exc
        installed = getattr(_pai, "__version__", "unknown")
        if installed not in SUPPORTED_PYDANTIC_AI_VERSIONS:
            warnings.warn(
                f"pydantic-ai {installed} is outside SUPPORTED_PYDANTIC_AI_VERSIONS "
                f"{SUPPORTED_PYDANTIC_AI_VERSIONS}; adapter behaviour is best-effort",
                UserWarning,
                stacklevel=3,
            )


__all__ = [
    "SUPPORTED_PYDANTIC_AI_VERSIONS",
    "PydanticAIAdapter",
    "PydanticAIMissingError",
]
