"""CrewAI canonical adapter (v0.7.2+; closes issue #5).

CrewAI cut three releases in the past 7 days (v1.14.4 → v1.14.5a2).
v1.14.4 explicitly added native MCP server support and was the floor
that introduced the tool-call surface this adapter binds to. Until
v0.7.1, CrewAI was example-only — users had to remember the
``@framework_decorator`` over ``@Airlock()`` rule themselves. This
adapter promotes CrewAI to adapter-shipped: ``wrap_crew(crew,
policy=...)`` walks every Agent's tool registry, replaces each
tool's ``_run`` (or ``func``) callable with the Airlock-decorated
version, and walks task-level ``Task(tools=[...])`` overrides too.

The CrewAI package is **not** imported at module load — callers
without the ``[crewai]`` extra installed still ``import
agent_airlock`` cleanly. Stub crews / agents (any object with a
``agents`` or ``tools`` attribute) bypass the SDK import — the test
seam.

Optional dep
------------
``pip install "agent-airlock[crewai]"`` pulls
``crewai>=1.14.4,<2.0``. v1.14.4 is the floor because that's the
release that introduced native MCP server support; older versions
wire MCP through a different surface and would silently mis-wire.
The v1.14.5a1 / a2 alpha cycle is supported but not the floor —
operators on the alpha track should pin manually.

Closes
------
- Issue #5 (Add CrewAI native integration module, opened 2026-03-14):
  https://github.com/sattyamjjain/agent-airlock/issues/5

Primary sources
---------------
- CrewAI v1.14.4 (2026-04-30):
  https://github.com/crewAIInc/crewAI/releases/tag/1.14.4
- CrewAI v1.14.5a1 (2026-05-01):
  https://github.com/crewAIInc/crewAI/releases/tag/1.14.5a1
- CrewAI v1.14.5a2 (2026-05-04):
  https://github.com/crewAIInc/crewAI/releases/tag/1.14.5a2
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

logger = structlog.get_logger("agent-airlock.integrations.crewai")


SUPPORTED_CREWAI_VERSIONS: tuple[str, ...] = ("1.14.4", "1.14.5a1", "1.14.5a2")
"""CrewAI versions this adapter has been smoke-tested against.

A user running an unsupported version sees a :class:`UserWarning`
(via ``warnings.warn``) at ``wrap_crew`` / ``wrap_agent`` time but no
hard failure — the public surface tested is the agents/tools walk,
which has been stable since v1.14.4. Update this tuple when a new
version is verified.
"""

_INSTALL_HINT = (
    'crewai>=1.14.4 is not installed. Install the extra: pip install "agent-airlock[crewai]"'
)


class CrewAIMissingError(AirlockError):
    """Raised when ``wrap_crew`` / ``wrap_agent`` is called without the extra installed.

    Subclass of :class:`AirlockError` so callers get a clear,
    actionable error instead of a deep ``ImportError`` from inside
    CrewAI's package layout (which transitively imports
    ``litellm`` / ``chromadb`` / ``embedchain``).
    """


@dataclass
class CrewAIAdapter:
    """Single facade that wraps a ``crewai.Crew`` (or single ``Agent``) with Airlock.

    Usage::

        from agent_airlock.integrations.crewai import CrewAIAdapter
        from agent_airlock.policy import STRICT_POLICY

        crew = build_my_crewai_crew()
        adapter = CrewAIAdapter()
        adapter.wrap_crew(crew, policy=STRICT_POLICY)

        # Every tool callable on every Agent and every Task is now
        # Airlock-decorated. Existing CrewAI execution path is unchanged.
        result = crew.kickoff()
    """

    def wrap_crew(self, crew: Any, *, policy: SecurityPolicy | None = None) -> Any:
        """Wrap every ``Agent`` and ``Task`` tool on a CrewAI ``Crew``.

        Args:
            crew: A :class:`crewai.Crew`-shaped object exposing
                ``agents`` (list of Agent) and optionally ``tasks``
                (list of Task with ``tools=[...]`` overrides). Stubs
                only need an ``agents`` attribute.
            policy: Optional :class:`SecurityPolicy`. When set, every
                tool callable is wrapped with
                :class:`Airlock(policy=policy)`.

        Returns:
            The same crew, mutated in place — every tool callable
            replaced by an Airlock-decorated shim.

        Raises:
            CrewAIMissingError: ``crewai`` extra is missing AND the
                crew is not a structural stub.
            AirlockError: The crew exposes no ``agents`` attribute, so
                it's not a recognised CrewAI shape.
        """
        self._maybe_check_sdk(crew)

        agents = getattr(crew, "agents", None)
        if agents is None:
            raise AirlockError("crew exposes no `agents` attribute; not a CrewAI Crew shape")

        wrapped_count = 0
        for agent in agents:
            wrapped_count += self._wrap_agent_tools(agent, policy=policy)

        # Task-level tool overrides: Task(tools=[...]) wins over Agent.tools at runtime.
        tasks = getattr(crew, "tasks", None)
        if tasks is not None:
            for task in tasks:
                tools = getattr(task, "tools", None)
                if tools is not None:
                    wrapped_count += self._wrap_tools_collection(tools, policy=policy)

        logger.info(
            "crewai_crew_wrapped",
            agent_count=len(agents),
            tool_count=wrapped_count,
            policy_set=policy is not None,
        )
        return crew

    def wrap_agent(self, agent: Any, *, policy: SecurityPolicy | None = None) -> Any:
        """Wrap a single ``crewai.Agent``'s tool registry.

        Use this when you don't have a Crew yet (e.g. one-off
        researcher pattern) — :meth:`wrap_crew` is the preferred path
        when a Crew exists.

        Args:
            agent: A :class:`crewai.Agent`-shaped object exposing a
                ``tools`` list/dict.
            policy: Optional :class:`SecurityPolicy`.

        Returns:
            The same agent, mutated in place.
        """
        self._maybe_check_sdk(agent)
        wrapped_count = self._wrap_agent_tools(agent, policy=policy)
        logger.info(
            "crewai_agent_wrapped",
            tool_count=wrapped_count,
            policy_set=policy is not None,
        )
        return agent

    def _wrap_agent_tools(self, agent: Any, *, policy: SecurityPolicy | None) -> int:
        """Walk a single agent's tools and replace callables. Returns count."""
        tools = getattr(agent, "tools", None)
        if tools is None:
            return 0
        return self._wrap_tools_collection(tools, policy=policy)

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
        """Replace ``tool._run`` / ``tool.func`` / ``tool`` with a guarded shim.

        CrewAI ``BaseTool`` subclasses use ``_run`` for the user
        callable; ``@tool``-decorated callables are wrapped with a
        ``func`` attribute. Plain callables are wrapped directly.
        """
        target_attr: str | None = None
        forward: Callable[..., Any] | None = None
        for candidate in ("_run", "func"):
            attr = getattr(tool, candidate, None)
            if callable(attr):
                target_attr = candidate
                forward = attr
                break
        if forward is None and callable(tool):
            forward = tool
        if forward is None:
            raise AirlockError(
                f"tool {name!r} has no callable attribute (`_run`/`func`/__call__); cannot wrap"
            )

        # Re-tag the proxy with the tool's name so SecurityPolicy
        # allowed_tools / denied_tools lists target the tool's name,
        # not its method name.
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

    def _maybe_check_sdk(self, obj: Any) -> None:
        """Raise :class:`CrewAIMissingError` only for real CrewAI objects.

        Stubs (test doubles) carrying ``agents`` / ``tools`` but no
        real CrewAI provenance are allowed through — the test surface
        needs to run without the optional dep installed.

        Also emits a :class:`UserWarning` when the installed CrewAI
        version is outside :data:`SUPPORTED_CREWAI_VERSIONS`.
        """
        module = type(obj).__module__
        if not module.startswith("crewai"):
            return
        try:
            import crewai as _crewai
        except ImportError as exc:
            raise CrewAIMissingError(_INSTALL_HINT) from exc
        installed = getattr(_crewai, "__version__", "unknown")
        if installed not in SUPPORTED_CREWAI_VERSIONS:
            warnings.warn(
                f"crewai {installed} is outside SUPPORTED_CREWAI_VERSIONS "
                f"{SUPPORTED_CREWAI_VERSIONS}; adapter behaviour is best-effort",
                UserWarning,
                stacklevel=3,
            )


__all__ = [
    "SUPPORTED_CREWAI_VERSIONS",
    "CrewAIAdapter",
    "CrewAIMissingError",
]
