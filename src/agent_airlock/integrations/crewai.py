"""CrewAI canonical adapter (v0.7.2+; closes issue #5).

CrewAI cut three releases in the past 7 days (v1.14.4 → v1.14.5a2).
v1.14.4 explicitly added native MCP server support and was the floor
that introduced the tool-call surface this adapter binds to. Until
v0.7.1, CrewAI was example-only — users had to remember the
``@framework_decorator`` over ``@Airlock()`` rule themselves. This
adapter promotes CrewAI to adapter-shipped: ``wrap_crew(crew,
policy=...)`` walks every Agent's tool registry, replaces each
tool's ``func`` (or, for ``BaseTool`` subclasses, ``_run``) callable
with the Airlock-decorated version, and walks task-level
``Task(tools=[...])`` overrides too.

The CrewAI package is **not** imported at module load — callers
without the ``[crewai]`` extra installed still ``import
agent_airlock`` cleanly. Stub crews / agents (any object with a
``agents`` or ``tools`` attribute) bypass the SDK import — the test
seam.

Tools CrewAI adds at run time (0.10.28)
---------------------------------------
CrewAI builds more tools while a task runs than the agent was given:
delegation tools (``allow_delegation``), MCP tools (``agent.mcps``),
platform tools (``agent.apps``), code-execution, multimodal, memory and
input-file tools, and a skill loader. None of them exists when
``wrap_crew`` / ``wrap_agent`` walks the agent, and until 0.10.28 they ran
outside Airlock: on crewai 1.15.22 a deny-all policy did not stop a
delegation or an ``agent.mcps`` tool, in a crew or in ``Agent.kickoff``.
The adapter now also wraps, on the objects it is given (only them), the
methods that hand CrewAI the final tool list, and walks what they return:
``Crew._prepare_tools`` (every injected tool of a crew task, the
hierarchical manager's delegation tools included), ``Crew.copy`` (the
copies ``kickoff_for_each`` runs) and ``Agent._add_skill_loader_tool``
(the last step before a task or a ``kickoff`` parses its tools, in both
paths). Where those methods are missing, an agent configured to receive
such tools gets a ``UserWarning`` naming them instead of silence.

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

import functools
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .._log import structlog
from ..core import Airlock
from ..exceptions import AirlockError
from ..policy import SecurityPolicy
from ._tool_proxy import GUARDED_MARKER, already_guarded, is_guarded, mark_guarded, named_tool_proxy

logger = structlog.get_logger("agent-airlock.integrations.crewai")

#: Agent settings that make CrewAI add tools at run time, and what each adds. Named in the
#: warning when the adapter cannot reach the method that hands CrewAI those tools.
_RUNTIME_TOOL_SOURCES: dict[str, str] = {
    "allow_delegation": "delegation tools",
    "mcps": "MCP server tools (agent.mcps)",
    "apps": "platform tools (agent.apps)",
    "allow_code_execution": "code-execution tools",
    "multimodal": "multimodal tools",
    "memory": "memory tools",
    "skills": "a skill loader tool",
}


SUPPORTED_CREWAI_VERSIONS: tuple[str, ...] = ("1.14.4", "1.14.5a1", "1.14.5a2", "1.15.22")
"""CrewAI versions this adapter has been smoke-tested against.

A user running an unsupported version sees a :class:`UserWarning`
(via ``warnings.warn``) at ``wrap_crew`` / ``wrap_agent`` time but no
hard failure — the public surface tested is the agents/tools walk,
which has been stable since v1.14.4. Update this tuple when a new
version is verified.

1.15.22 was verified on a real ``Crew``: agent- and task-level tools were
wrapped, and under a deny-all policy ``Tool.run`` and the structured-tool
path an agent run uses were both refused without the tool body running.
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

        crew_hooked = self._hook_crew(crew, policy=policy)
        wrapped_count = 0
        for agent in agents:
            wrapped_count += self._wrap_agent_tools(agent, policy=policy)
            self._hook_agent(agent, policy=policy, crew_hooked=crew_hooked)
        manager = getattr(crew, "manager_agent", None)
        if manager is not None:
            wrapped_count += self._wrap_agent_tools(manager, policy=policy)
            self._hook_agent(manager, policy=policy, crew_hooked=crew_hooked)

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
            runtime_tools_hooked=crew_hooked,
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
        runtime_hooked = self._hook_agent(agent, policy=policy, crew_hooked=False)
        logger.info(
            "crewai_agent_wrapped",
            tool_count=wrapped_count,
            runtime_tools_hooked=runtime_hooked,
            policy_set=policy is not None,
        )
        return agent

    def _wrap_agent_tools(self, agent: Any, *, policy: SecurityPolicy | None) -> int:
        """Walk a single agent's tools and replace callables. Returns count."""
        tools = getattr(agent, "tools", None)
        if tools is None:
            return 0
        return self._wrap_tools_collection(tools, policy=policy)

    def _guard_runtime_tools(self, tools: Any, *, policy: SecurityPolicy | None) -> Any:
        """Guard the tools a CrewAI method just assembled, in place, and return them.

        Raises:
            AirlockError: The method returned something other than a tool list, so its
                tools cannot be read: the run is refused rather than let through.
        """
        if not isinstance(tools, list | dict):
            raise AirlockError(
                f"CrewAI returned a {type(tools).__name__} where a tool list was expected; "
                "agent-airlock cannot guard its tools, so the run is refused"
            )
        self._wrap_tools_collection(tools, policy=policy)
        return tools

    def _install_hook(
        self,
        owner: Any,
        attr: str,
        *,
        policy: SecurityPolicy | None,
        after: Callable[[Any], Any],
    ) -> bool:
        """Replace ``owner.attr`` (a method) by one that passes its result through ``after``.

        Set on the instance only. Idempotent: a hook already installed is kept (with the
        policy it was installed with). Returns whether ``owner`` now has the hook. The hook
        calls ``owner``'s own method, so a ``copy.copy`` / ``deepcopy`` of ``owner`` would
        share a hook running against ``owner``; CrewAI's own ``Crew.copy`` /
        ``Agent.copy`` rebuild the object instead, and ``Crew.copy`` is re-wrapped.
        """
        original = getattr(owner, attr, None)
        if not callable(original):
            return False
        if already_guarded(original, policy, tool=f"{type(owner).__name__}.{attr}"):
            return True

        @functools.wraps(original)
        def hooked(*args: Any, **kwargs: Any) -> Any:
            return after(original(*args, **kwargs))

        mark_guarded(hooked, policy)
        try:
            setattr(owner, attr, hooked)
        except (AttributeError, TypeError, ValueError):
            # A pydantic model (Crew, Agent) refuses to set a name that is not a field;
            # the instance dict still shadows the class's method.
            try:
                object.__setattr__(owner, attr, hooked)
            except (AttributeError, TypeError):  # a slotted object
                return False
        return True

    def _hook_crew(self, crew: Any, *, policy: SecurityPolicy | None) -> bool:
        """Guard the tools each crew task gets at run time, and the crews copied from it.

        ``Crew._prepare_tools`` adds a task's delegation, code-execution, multimodal,
        platform, MCP, memory and input-file tools (the hierarchical manager's included)
        to the agent's or task's own; ``Crew.copy`` builds the crews ``kickoff_for_each``
        and ``train`` run, which would otherwise start unwrapped.
        """
        hooked = self._install_hook(
            crew,
            "_prepare_tools",
            policy=policy,
            after=lambda tools: self._guard_runtime_tools(tools, policy=policy),
        )
        self._install_hook(
            crew,
            "copy",
            policy=policy,
            after=lambda clone: self.wrap_crew(clone, policy=policy),
        )
        return hooked

    def _hook_agent(self, agent: Any, *, policy: SecurityPolicy | None, crew_hooked: bool) -> bool:
        """Guard the final tool list an agent parses, in a crew task and in ``kickoff``.

        ``Agent._add_skill_loader_tool`` receives every tool the agent will run (its own,
        the task's, everything CrewAI added, the ``agent.mcps`` / ``agent.apps`` tools
        ``kickoff`` appends) and adds the skill loader, right before ``parse_tools``. When
        it is missing, an agent configured to receive run-time tools is reported.
        """
        hooked = self._install_hook(
            agent,
            "_add_skill_loader_tool",
            policy=policy,
            after=lambda tools: self._guard_runtime_tools(tools, policy=policy),
        )
        if not hooked:
            self._warn_runtime_sources(agent, crew_hooked=crew_hooked)
        return hooked

    def _warn_runtime_sources(self, agent: Any, *, crew_hooked: bool) -> None:
        """Name the run-time tools CrewAI may give ``agent`` that this walk cannot reach."""
        sources = [
            description
            for setting, description in _RUNTIME_TOOL_SOURCES.items()
            if getattr(agent, setting, None)
        ]
        if not sources:
            return
        where = (
            "outside a crew task (Agent.kickoff) and in its skill loader"
            if crew_hooked
            else "while its tasks run"
        )
        warnings.warn(
            f"agent-airlock cannot guard the tools CrewAI adds {where} for agent "
            f"{getattr(agent, 'role', None) or type(agent).__name__!r}: {', '.join(sources)}. "
            "Calls to them are NOT validated by agent-airlock on this CrewAI version.",
            UserWarning,
            stacklevel=4,
        )

    def _wrap_tools_collection(self, tools: Any, *, policy: SecurityPolicy | None) -> int:
        """Replace every tool's callable with the Airlock-decorated version.

        Idempotent per tool: a tool already guarded is left alone. CrewAI hands
        ``Task(agent=a)`` the agent's own ``tools`` list (the same object), so
        :meth:`wrap_crew` walks one list twice; before 0.10.25 that stacked a second
        Airlock layer on every tool and every allowed call wrote two audit records.
        """
        count = 0
        if isinstance(tools, dict):
            for name, tool in tools.items():
                if _already_guarded(tool, policy=policy, name=str(name)):
                    continue
                tools[name] = self._wrap_one(tool, name=str(name), policy=policy)
                count += 1
        elif isinstance(tools, list):
            for idx, tool in enumerate(tools):
                tool_name = getattr(tool, "name", f"tool_{idx}")
                if _already_guarded(tool, policy=policy, name=str(tool_name)):
                    continue
                tools[idx] = self._wrap_one(tool, name=tool_name, policy=policy)
                count += 1
        else:
            raise AirlockError(
                f"unrecognised tools type {type(tools).__name__}; expected dict or list"
            )
        return count

    def _wrap_one(self, tool: Any, *, name: str, policy: SecurityPolicy | None) -> Any:
        """Replace ``tool.func`` / ``tool._run`` / ``tool`` with a guarded shim.

        ``@tool``-decorated callables become a ``Tool`` whose ``func`` is the
        user callable; ``BaseTool`` subclasses implement ``_run``. Plain
        callables are wrapped directly.

        ``func`` is tried first. A ``Tool`` has a ``_run`` too, but it is a
        ``(*args, **kwargs)`` pass-through to ``func`` that ``Tool.run`` and
        ``Tool.arun`` never call, so wrapping it left both of those paths
        outside Airlock (verified on crewai 1.15.22: a deny-all policy did
        not stop ``Tool.run``) and gave strict validation no signature.
        """
        target_attr: str | None = None
        forward: Callable[..., Any] | None = None
        for candidate in ("func", "_run"):
            attr = getattr(tool, candidate, None)
            if callable(attr):
                target_attr = candidate
                forward = attr
                break
        if forward is None and callable(tool):
            forward = tool
        if forward is None:
            raise AirlockError(
                f"tool {name!r} has no callable attribute (`func`/`_run`/__call__); cannot wrap"
            )

        # The proxy carries the tool's name, so SecurityPolicy lists match the tool
        # rather than `_run` / `func`, and the tool's signature, so Airlock validates it.
        airlock = Airlock(policy=policy) if policy is not None else Airlock()
        wrapped = airlock(named_tool_proxy(forward, name=name))
        mark_guarded(wrapped, policy)

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


#: Kept under its 0.10.25 name; the marker is shared by every walker since 0.10.28.
_GUARDED_MARKER = GUARDED_MARKER

_CALLABLE_ATTRS = ("func", "_run")


def _is_guarded(tool: Any) -> bool:
    """True when ``tool`` (or its ``func`` / ``_run``) is already an Airlock shim."""
    return is_guarded(tool) or any(
        is_guarded(getattr(tool, candidate, None)) for candidate in _CALLABLE_ATTRS
    )


def _already_guarded(tool: Any, *, policy: SecurityPolicy | None, name: str) -> bool:
    """Whether a walk should leave ``tool`` alone: already guarded under ``policy``.

    A tool guarded under another policy is wrapped again, with a warning, so both apply.
    """
    for candidate in (tool, *(getattr(tool, attr, None) for attr in _CALLABLE_ATTRS)):
        if is_guarded(candidate):
            return already_guarded(candidate, policy, tool=name)
    return False


__all__ = [
    "SUPPORTED_CREWAI_VERSIONS",
    "CrewAIAdapter",
    "CrewAIMissingError",
]
