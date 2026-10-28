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

Toolset shapes walked (0.10.28)
-------------------------------
Until 0.10.28 only a toolset with its own ``tools`` was walked; every
other one was skipped without a word, and its tools ran under a deny-all
policy (verified on pydantic-ai 2.63.0). The walk now reaches:

* a function toolset (``tools``), whose ``Tool`` callables are guarded;
* a wrapper toolset (``prefixed``, ``filtered``, ``renamed``,
  ``prepared``, approval-required, durable...) through its ``wrapped``;
* a ``CombinedToolset`` through each of its ``toolsets``;
* a ``DynamicToolset``, whose factory is re-pointed so each toolset it
  builds during a run is walked before use;
* toolsets passed at run time (``agent.run(..., toolsets=[...])``),
  ``agent.override(...)`` ones, and tools registered after the wrap: the
  agent's ``_get_toolset``, through which every run builds its toolset,
  is wrapped so the run's toolset is walked first.

A toolset with no local callable to wrap (an MCP server, an external or
deferred toolset) is reported with a ``UserWarning``, never skipped in
silence; calls through it are not validated by agent-airlock. Policy
lists match the name a tool is registered under, not a prefixed or
renamed one.

Optional dep
------------
``pip install "agent-airlock[pydantic-ai]"`` pulls
``pydantic-ai>=1.88.0,<3.0``. v1.88.0 introduced the
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

import functools
import inspect
import warnings
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .._log import structlog
from ..core import Airlock
from ..exceptions import AirlockError
from ..policy import SecurityPolicy
from ._tool_proxy import already_guarded, guarded_with, mark_guarded, named_tool_proxy

logger = structlog.get_logger("agent-airlock.integrations.pydantic_ai")


SUPPORTED_PYDANTIC_AI_VERSIONS: tuple[str, ...] = (
    "1.88.0",
    "1.89.0",
    "1.89.1",
    "2.31.1",
    "2.43.0",
    "2.63.0",
)
"""PydanticAI versions this adapter has been smoke-tested against.

A user running an unsupported version sees a :class:`UserWarning`
(via ``warnings.warn``) at ``wrap_agent`` time but no hard failure —
the public surface tested is the toolsets walk, which has been stable
since v1.88.0. Update this tuple when a new version is verified.

**2.43.0 was verified by introspection, and it is not fully equivalent
to the 1.x entries.** ``agent.toolsets`` is unchanged (a list of
toolsets, each with a ``tools`` dict of ``Tool`` objects carrying
``.function``), so the walk works. But ``output_validate`` is **gone**
in 2.x, so :meth:`PydanticAIAdapter._maybe_attach_output_validate`
cannot attach the sanitiser and warns instead. Tool-argument validation
is identical; model-output sanitisation is not available.

**Introspection is not verification.** It confirmed the walk on 2.43.0, but
only a real run showed that the replaced ``tool.function`` is never called
(fixed in 0.10.9 by re-pointing ``function_schema.function``). 2.31.1 was
verified by a real ``Agent`` run under ``TestModel``: with a deny-all policy,
no tool body ran.

**2.63.0 and 2.43.0 were verified by real ``TestModel`` runs for 0.10.28**,
under a deny-all policy with an allow-policy control: tools in prefixed,
filtered and renamed toolsets, a ``CombinedToolset``, a ``DynamicToolset``
(``@agent.toolset``), ``run(toolsets=...)``, ``override(tools=...)`` and a
tool registered after ``wrap_agent`` were all refused, and wrapping twice
wrote one audit record per call.
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


def _run_context_params(tool: Any, forward: Callable[..., Any]) -> frozenset[str]:
    """The parameter PydanticAI fills with a ``RunContext``: the first, when ``takes_ctx``.

    It is relaxed to ``Any`` for strict validation. The model never supplies it, and a
    ``RunContext`` carries a model, a tracer and the run's usage, which have no Pydantic
    schema to validate against.
    """
    if not getattr(tool, "takes_ctx", False):
        return frozenset()
    try:
        parameters = inspect.signature(forward).parameters
    except (TypeError, ValueError):
        return frozenset()
    return frozenset(list(parameters)[:1])


def _guard_callable(
    tool: Any,
    forward: Callable[..., Any],
    *,
    name: str,
    policy: SecurityPolicy | None,
) -> Callable[..., Any]:
    """``forward`` behind a new ``Airlock``, re-tagged with the tool's name and contract."""
    # The proxy carries the tool's name, so SecurityPolicy lists match the tool rather
    # than `function`, and the tool's signature, so Airlock validates it.
    proxy = named_tool_proxy(forward, name=name, relaxed_params=_run_context_params(tool, forward))
    airlock = Airlock(policy=policy) if policy is not None else Airlock()
    wrapped: Callable[..., Any] = airlock(proxy)
    mark_guarded(wrapped, policy)
    return wrapped


def _call_path(tool: Any) -> Any:
    """The callable a run invokes for ``tool``: ``function_schema.function`` when it has one.

    PydanticAI runs a tool through ``tool.function_schema.call``, which invokes the function
    captured when the ``Tool`` was built, not ``tool.function``. Replacing only
    ``tool.function`` left real agent runs outside Airlock entirely: on pydantic-ai 2.31.1,
    both a plain and a ``RunContext`` tool ran under a deny-all policy (fixed in 0.10.9).
    """
    schema_function = getattr(getattr(tool, "function_schema", None), "function", None)
    if callable(schema_function):
        return schema_function
    for candidate in ("function", "run"):
        attr = getattr(tool, candidate, None)
        if callable(attr):
            return attr
    return tool


def _describe_toolset(toolset: Any) -> str:
    """How a toolset the walk cannot see into is named in the warning."""
    label = getattr(toolset, "label", None) or getattr(toolset, "id", None)
    kind = type(toolset).__name__
    if isinstance(label, str) and label and label != kind:
        return f"toolset {kind} ({label})"
    return f"toolset {kind}"


def _is_output_toolset(toolset: Any, skip: set[int]) -> bool:
    """Whether ``toolset`` is the run's output toolset, the model's final-answer schema.

    It holds no agent tools (``agent.toolsets`` leaves it out), but an output *function*
    in it (``output_type=[fn]``) runs with arguments the model wrote, so the walk guards
    those (:meth:`PydanticAIAdapter._guard_output_functions`).
    """
    return id(toolset) in skip or (
        type(toolset).__name__ == "OutputToolset"
        and type(toolset).__module__.startswith("pydantic_ai")
    )


@dataclass
class PydanticAIAdapter:
    """Single facade that wraps a ``pydantic_ai.Agent`` with Airlock.

    Attributes:
        attach_output_validate: When ``True`` (default), the adapter
            attaches an ``output_validate`` hook that runs the
            existing :func:`agent_airlock.sanitizer.sanitize_output`
            over structured output before it leaves the model
            boundary. Hook is a v1.88.0+ surface; PydanticAI 2.x
            removed it, and the adapter then warns.
        warn_on_unwrappable: When ``True`` (default), emit a
            :class:`UserWarning` naming every toolset the walk cannot
            see into (an MCP server, an external or deferred toolset),
            at wrap time and, for one first met during a run, then.
            Calls through such a toolset are not validated by
            agent-airlock; silence would read as protection.
    """

    attach_output_validate: bool = True
    warn_on_unwrappable: bool = True

    def wrap_agent(self, agent: Any, *, policy: SecurityPolicy | None = None) -> Any:
        """Wrap a PydanticAI ``Agent`` so every tool routes through Airlock.

        Walks every toolset shape (function, wrapper, combined, dynamic; see the module
        docstring) and, on an agent that builds its run toolset through
        ``_get_toolset`` (pydantic-ai 2.x), re-walks each run's toolset first, so
        toolsets passed to ``run(toolsets=...)`` are guarded too. Idempotent per tool:
        wrapping twice costs one audit record and one rate-limit token per call.

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
        unwrappable: list[tuple[int, str]] = []
        wrapped_count = self._wrap_toolsets_or_tools(agent, policy=policy, report=unwrappable)
        output_toolset = getattr(agent, "_output_toolset", None)
        if output_toolset is not None:
            wrapped_count += self._guard_output_functions(output_toolset, policy=policy)
        run_toolsets_hooked = self._hook_run_toolsets(agent, policy=policy)
        if self.attach_output_validate:
            self._maybe_attach_output_validate(agent)

        logger.info(
            "pydantic_ai_agent_wrapped",
            tool_count=wrapped_count,
            unwrapped_count=len(unwrappable),
            run_toolsets_hooked=run_toolsets_hooked,
            policy_set=policy is not None,
            output_validate_attached=self.attach_output_validate,
        )
        self._warn_unwrappable([description for _, description in unwrappable])
        return agent

    def _wrap_toolsets_or_tools(
        self, agent: Any, *, policy: SecurityPolicy | None, report: list[tuple[int, str]]
    ) -> int:
        """Walk the agent's tool surface and replace callables. Returns count."""
        toolsets = getattr(agent, "toolsets", None)
        if toolsets is not None:
            return self._wrap_toolsets(toolsets, policy=policy, report=report)

        tools = getattr(agent, "tools", None)
        if tools is None:
            raise AirlockError(
                "agent exposes neither `toolsets` nor `tools`; not a PydanticAI shape"
            )
        return self._wrap_tools_collection(tools, policy=policy)

    def _wrap_toolsets(
        self, toolsets: Any, *, policy: SecurityPolicy | None, report: list[tuple[int, str]]
    ) -> int:
        """Walk a list/iterable of toolsets, each down to its function toolsets."""
        seen: set[int] = set()
        return sum(
            self._walk_toolset(toolset, policy=policy, report=report, seen=seen, skip=set())
            for toolset in toolsets
        )

    def _walk_toolset(
        self,
        toolset: Any,
        *,
        policy: SecurityPolicy | None,
        report: list[tuple[int, str]],
        seen: set[int],
        skip: set[int],
    ) -> int:
        """Guard every function tool under ``toolset``; report what has none to guard.

        Recognised by attribute, as ``FunctionToolset.tools``,
        ``WrapperToolset.wrapped``, ``CombinedToolset.toolsets`` and
        ``DynamicToolset.toolset_func`` are named in pydantic-ai 1.88 to 2.63, so test
        stubs of the same shape walk the same way.
        """
        if toolset is None or id(toolset) in seen:
            return 0
        seen.add(id(toolset))
        if _is_output_toolset(toolset, skip):
            return self._guard_output_functions(toolset, policy=policy)

        tools = getattr(toolset, "tools", None)
        if tools is not None:
            return self._wrap_tools_collection(tools, policy=policy)

        wrapped = getattr(toolset, "wrapped", None)
        if wrapped is not None:
            return self._walk_toolset(wrapped, policy=policy, report=report, seen=seen, skip=skip)

        members = getattr(toolset, "toolsets", None)
        if members is not None and not isinstance(members, str | bytes):
            return sum(
                self._walk_toolset(member, policy=policy, report=report, seen=seen, skip=skip)
                for member in members
            )

        factory = getattr(toolset, "toolset_func", None)
        if callable(factory):
            self._guard_factory(toolset, factory, policy=policy)
            built = getattr(toolset, "_toolset", None)  # a per-run copy already evaluated
            return self._walk_toolset(built, policy=policy, report=report, seen=seen, skip=skip)

        report.append((id(toolset), _describe_toolset(toolset)))
        return 0

    def _guard_output_functions(self, toolset: Any, *, policy: SecurityPolicy | None) -> int:
        """Guard the functions an output toolset calls with the model's final answer.

        With ``output_type=[fn]`` the model writes ``fn``'s arguments and PydanticAI runs
        it, through ``processor._function_schema.function``: a tool call by another name.
        That callable is re-pointed to a guarded shim named for the function, so policy
        lists match the function's name. An output type that is a model or a scalar calls
        nothing and is left alone. Until the 0.10.28 review the output toolset was skipped
        whole, and so was the warning that its functions ran unguarded.
        """
        processors = getattr(toolset, "processors", None)
        if not isinstance(processors, Mapping):
            return 0
        count = 0
        for key, processor in processors.items():
            schema = getattr(processor, "_function_schema", None)
            function = getattr(schema, "function", None)
            if schema is None or not callable(function):
                continue
            name = str(getattr(function, "__name__", key))
            if already_guarded(function, policy, tool=name):
                continue
            schema.function = _guard_callable(schema, function, name=name, policy=policy)
            count += 1
        return count

    def _guard_factory(
        self, toolset: Any, factory: Callable[..., Any], *, policy: SecurityPolicy | None
    ) -> None:
        """Re-point a ``DynamicToolset``'s factory so each toolset it builds is walked first.

        A dynamic toolset is built per run (or per run step) by calling its factory with
        the run context; there is nothing static to wrap. Its per-run copies are made from
        the same ``toolset_func`` attribute, so they inherit the re-pointed factory.
        """
        if already_guarded(factory, policy, tool=_describe_toolset(toolset)):
            return
        adapter = self

        def walk_built(built: Any) -> Any:
            report: list[tuple[int, str]] = []
            adapter._walk_toolset(built, policy=policy, report=report, seen=set(), skip=set())
            adapter._warn_unwrappable([description for _, description in report])
            return built

        @functools.wraps(factory)
        def guarded_factory(*args: Any, **kwargs: Any) -> Any:
            built = factory(*args, **kwargs)
            if inspect.isawaitable(built):

                async def walk_when_built() -> Any:
                    return walk_built(await built)

                return walk_when_built()
            return walk_built(built)

        mark_guarded(guarded_factory, policy)
        toolset.toolset_func = guarded_factory

    def _hook_run_toolsets(self, agent: Any, *, policy: SecurityPolicy | None) -> bool:
        """Walk each run's toolset before the run uses it. Returns whether it is hooked.

        pydantic-ai 2.x builds every run's toolset in ``Agent._get_toolset`` (``iter``, so
        ``run`` / ``run_sync`` / ``run_stream``, and realtime sessions), from the agent's
        toolsets, any ``override(tools=..., toolsets=...)`` and the toolsets passed to the
        run. Wrapping that method on this agent instance (only it) walks the run's toolset
        first, so a toolset first seen at run time is guarded before any of its tools can
        be called. A copy of the agent made after the wrap shares the hook, which builds
        the original agent's toolset; wrap the copy itself instead.
        """
        original = getattr(agent, "_get_toolset", None)
        if not callable(original):
            if type(agent).__module__.startswith("pydantic_ai"):
                warnings.warn(
                    "agent-airlock cannot guard toolsets passed at run time on this "
                    "PydanticAI version (the agent has no _get_toolset): tools in "
                    "run(toolsets=...) and override(...) are NOT validated. Register them "
                    "on the agent before wrap_agent.",
                    UserWarning,
                    stacklevel=4,
                )
            return False
        if already_guarded(original, policy, tool="the agent's run toolsets"):
            return True

        adapter = self
        warned: set[int] = set()

        @functools.wraps(original)
        def guarded_get_toolset(*args: Any, **kwargs: Any) -> Any:
            toolset = original(*args, **kwargs)
            skip = {
                id(candidate)
                for candidate in (
                    kwargs.get("output_toolset"),
                    getattr(agent, "_output_toolset", None),
                )
                if candidate is not None
            }
            report: list[tuple[int, str]] = []
            for output in (kwargs.get("output_toolset"), getattr(agent, "_output_toolset", None)):
                if output is not None:
                    adapter._guard_output_functions(output, policy=policy)
            adapter._walk_toolset(toolset, policy=policy, report=report, seen=set(), skip=skip)
            fresh = [(key, description) for key, description in report if key not in warned]
            warned.update(key for key, _ in fresh)
            adapter._warn_unwrappable([description for _, description in fresh])
            return toolset

        mark_guarded(guarded_get_toolset, policy)
        agent._get_toolset = guarded_get_toolset
        return True

    def _warn_unwrappable(self, descriptions: list[str]) -> None:
        """Name every toolset the walk could not see into, unless warnings are off."""
        if not descriptions or not self.warn_on_unwrappable:
            return
        warnings.warn(
            f"agent-airlock did not guard {len(descriptions)} PydanticAI toolset(s): "
            f"{', '.join(descriptions)}. These run tools that have no local Python callable "
            "to wrap (an MCP server, an external or deferred toolset); calls through them "
            "are NOT validated by agent-airlock.",
            UserWarning,
            stacklevel=4,
        )

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
        """Replace ``tool.function`` / ``tool.run`` / ``tool`` with a guarded shim.

        The callable a run invokes, ``tool.function_schema.function``, is guarded too,
        whether or not it is the same object as ``tool.function``. A tool whose call path
        is already guarded is left alone (idempotent per tool).
        """
        if already_guarded(_call_path(tool), policy, tool=name):
            return tool

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

        wrapped = (
            forward
            if guarded_with(forward, policy)
            else _guard_callable(tool, forward, name=name, policy=policy)
        )
        schema: Any = getattr(tool, "function_schema", None)
        schema_function = getattr(schema, "function", None)
        if schema is not None and callable(schema_function):
            # The run path. Re-pointed to the same shim when it holds the tool's function,
            # and guarded on its own when it holds another callable, which is what runs.
            schema.function = (
                wrapped
                if schema_function is forward
                else _guard_callable(tool, schema_function, name=name, policy=policy)
            )

        if target_attr is not None:
            setattr(tool, target_attr, wrapped)  # noqa: B010
            return tool
        return wrapped

    def _maybe_attach_output_validate(self, agent: Any) -> None:
        """Wire ``agent.output_validate`` to the airlock sanitizer (v1.88+).

        When the attribute is absent the hook cannot be attached, and this
        **warns** rather than returning quietly.

        The quiet return was a real defect. PydanticAI **2.x removed
        ``output_validate``** (verified absent on 2.43.0 while ``toolsets``
        still works), so on 2.x the tool walk succeeded, this method found no
        attribute, returned, and the caller was left with
        ``attach_output_validate=True`` and no output sanitisation. Believing
        a sanitiser is attached when it is not is worse than knowing it is
        off, which is the same reasoning the Google ADK adapter applies to
        tool entries it cannot guard.

        The version-drift warning does not cover this: it only fires for real
        ``pydantic_ai.*`` objects outside
        :data:`SUPPORTED_PYDANTIC_AI_VERSIONS`, and it says behaviour is
        best-effort, not that output sanitisation is off.
        """
        if not hasattr(agent, "output_validate"):
            warnings.warn(
                "agent-airlock could not attach output sanitisation: this agent has no "
                "`output_validate` attribute (PydanticAI 2.x removed it). Tool arguments "
                "are still validated, but model output is NOT sanitised by this adapter. "
                "Pass attach_output_validate=False to silence this, or sanitise output "
                "yourself with agent_airlock.sanitizer.sanitize_output.",
                UserWarning,
                stacklevel=4,
            )
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
