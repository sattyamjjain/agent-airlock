"""Google ADK (Agent Development Kit) canonical adapter.

Google renamed Vertex AI to the **Gemini Enterprise Agent Platform** at
Cloud Next '26 (announced 2026-04-22), consolidating Agentspace and
Agent Builder under one umbrella and naming ADK as that platform's
code-first development kit. ADK is therefore the supported way to write
tool-calling agents against Gemini in an enterprise account, and it had
no agent-airlock adapter until this module.

What the adapter actually buys you
----------------------------------
Not just decorator placement. A bare ``@Airlock()`` on an ADK tool that
takes ADK's injected ``tool_context`` **fails at decoration time**::

    from google.adk.tools.tool_context import ToolContext

    @Airlock()                       # <- raises, before any call happens
    def remember(city: str, tool_context: ToolContext) -> dict: ...

    pydantic.errors.PydanticSchemaGenerationError: Unable to generate
    pydantic-core schema for <class 'google.adk.agents.context.Context'>

``Airlock`` validates through ``pydantic.validate_call(strict=True)``,
and ``ToolContext`` (an alias of ``google.adk.agents.context.Context`` in
ADK 2.9.0) is an arbitrary type Pydantic cannot build a schema for.
``tool_context`` is *injected by the ADK runtime*, never supplied by the
model, and ADK itself excludes it from the declaration the model sees
(``FunctionTool._ignore_params == ['tool_context', 'input_stream']``).

So this adapter relaxes exactly those runtime-injected parameters to
``Any`` for the validator, and leaves every model-supplied parameter
under strict validation. See :data:`ADK_INJECTED_PARAMS`.

Relaxing the *annotation* is safe because ADK drops those parameters by
**name**, not by type: ``_ignore_params`` is a list of names, and ADK
never builds a schema for their annotation. Confirmed on 2.9.0 and
asserted in ``TestAgainstRealAdk``, so a future ADK that switched to
type-based detection would fail the suite rather than silently start
leaking ``tool_context`` into the model-visible schema.

The tool contract the model sees is unchanged. Verified against ADK
2.9.0 by comparing ``FunctionTool._get_declaration()`` before and after
the wrap: name, description and ``parameters_json_schema`` compare
equal. That is pinned by ``TestAgainstRealAdk`` in
``tests/integrations/test_google_adk_adapter.py``, which runs wherever
the ``[google-adk]`` extra is installed and skips where it is not — so
the claim is machine-checked rather than asserted in prose, but only on
an install that can actually check it.

Tool shapes handled
-------------------
``LlmAgent.tools`` is typed ``list[Callable | BaseTool | BaseToolset]``
and ADK keeps bare callables bare (it does not wrap them into
``FunctionTool`` at construction). The adapter therefore handles:

* **bare callable** — replaced in the list by the guarded version;
* **``BaseTool`` carrying ``.func``** (``FunctionTool`` and friends) —
  ``.func`` is replaced in place, so ``name``/``description`` computed at
  tool construction survive untouched;
* **``BaseToolset``** — *not* wrapped. ``BaseToolset.get_tools`` is
  ``async`` and returns a freshly built list per call, so there is no
  static callable to rewrite. Left unguarded and **reported**, never
  silently skipped (see :attr:`GoogleADKAdapter.warn_on_unwrappable`);
* **``BaseTool`` without ``.func``** — ADK built-ins such as
  ``GoogleSearchTool`` execute model-side, so there is no local callable
  to guard. Also reported rather than silently skipped.

The ADK package is **not** imported at module load — callers without the
``[google-adk]`` extra still ``import agent_airlock`` cleanly. Stub
agents (any object with a ``tools`` attribute) bypass the SDK import;
that is the test seam, matching ``integrations/pydantic_ai.py``.

Optional dep
------------
``pip install "agent-airlock[google-adk]"`` pulls ``google-adk>=2.0,<3.0``.

Primary sources
---------------
- ADK docs: https://google.github.io/adk-docs/
- ADK source: https://github.com/google/adk-python
- ``google-adk`` 2.9.0 on PyPI, published 2026-09-10 — the release this
  adapter was introspected against: https://pypi.org/project/google-adk/2.9.0/
- Gemini Enterprise Agent Platform (formerly Vertex AI), announced at
  Google Cloud Next '26 on 2026-04-22:
  https://cloud.google.com/products/gemini-enterprise-agent-platform
"""

from __future__ import annotations

import inspect
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .._log import structlog
from ..core import Airlock
from ..exceptions import AirlockError
from ..policy import SecurityPolicy

logger = structlog.get_logger("agent-airlock.integrations.google_adk")


SUPPORTED_GOOGLE_ADK_VERSIONS: tuple[str, ...] = ("2.9.0",)
"""ADK versions this adapter has been introspected and smoke-tested against.

``2.9.0`` (published 2026-09-10) is the release every structural fact in
this module was verified on: ``LlmAgent.tools`` as the tool collection,
``FunctionTool.func`` as the user callable, ``BaseToolset.get_tools``
being async, and ``_ignore_params == ['tool_context', 'input_stream']``.

A user on a different version gets a :class:`UserWarning` at
``wrap_agent`` time and **no hard failure** — the surface relied on is
the ``tools`` list walk. Add to this tuple once a new release is
verified.
"""

ADK_INJECTED_PARAMS: frozenset[str] = frozenset({"tool_context", "input_stream"})
"""Parameters the ADK runtime injects, which the model never supplies.

Mirrors ``google.adk.tools.function_tool.FunctionTool._ignore_params`` in
ADK 2.9.0. These are relaxed to ``Any`` for Airlock's strict validator
because their runtime types (``ToolContext`` / streaming handles) have no
Pydantic schema. Every *model-supplied* parameter stays strictly
validated, which is the argument boundary agent-airlock exists to guard.
"""

_INSTALL_HINT = (
    "google-adk>=2.0,<3.0 is not installed. "
    'Install the extra: pip install "agent-airlock[google-adk]"'
)


class GoogleADKMissingError(AirlockError):
    """Raised when ``wrap_agent`` is called without the extra installed.

    Subclass of :class:`AirlockError` so callers get a clear, actionable
    error instead of a deep ``ImportError`` from inside ADK's package
    layout.
    """


def _relax_injected_params(func: Callable[..., Any]) -> Callable[..., Any]:
    """Return ``func`` with ADK-injected parameters annotated ``Any``.

    Returns ``func`` itself when it takes none of
    :data:`ADK_INJECTED_PARAMS`, so the common case is byte-identical to
    a plain ``@Airlock()`` and costs no extra frame.

    The returned shim keeps the original parameter *names, order and
    defaults* — only the annotations of injected parameters change — so
    ADK still detects its context parameter and still produces the same
    declaration for the model.
    """
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):  # pragma: no cover - builtins/C callables
        return func

    if not any(name in ADK_INJECTED_PARAMS for name in signature.parameters):
        return func

    relaxed_signature = signature.replace(
        parameters=[
            param.replace(annotation=Any) if name in ADK_INJECTED_PARAMS else param
            for name, param in signature.parameters.items()
        ]
    )
    relaxed_annotations = {
        name: (Any if name in ADK_INJECTED_PARAMS else annotation)
        for name, annotation in getattr(func, "__annotations__", {}).items()
    }

    shim: Callable[..., Any]
    if inspect.iscoroutinefunction(func):

        async def _async_shim(*args: Any, **kwargs: Any) -> Any:
            return await func(*args, **kwargs)

        shim = _async_shim
    else:

        def _sync_shim(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        shim = _sync_shim

    _adopt_identity(shim, func, relaxed_signature, relaxed_annotations)
    return shim


def _adopt_identity(
    shim: Any,
    func: Callable[..., Any],
    signature: inspect.Signature,
    annotations: dict[str, Any],
) -> None:
    """Carry onto ``shim`` the identity ADK reads when building a declaration.

    ``functools.wraps`` is deliberately not used: it would set
    ``__wrapped__``, and both ``inspect.signature`` and ADK's declaration
    builder would then follow it back to the un-relaxed annotation that
    :func:`_relax_injected_params` exists to hide.

    ``shim`` is typed ``Any`` on purpose. It is a function object, but the
    caller builds it in one of two branches (sync or async), so a narrower
    type makes it a union and every dunder assignment below needs an
    inline ignore whose *error code* depends on mypy's inference. Taking
    ``Any`` here keeps the suppression out of the codebase entirely.
    """
    shim.__name__ = getattr(func, "__name__", "adk_tool")
    shim.__qualname__ = getattr(func, "__qualname__", shim.__name__)
    shim.__doc__ = func.__doc__
    shim.__module__ = getattr(func, "__module__", shim.__module__)
    shim.__annotations__ = annotations
    shim.__signature__ = signature


def _airlock_guard(
    func: Callable[..., Any], *, policy: SecurityPolicy | None
) -> Callable[..., Any]:
    """Airlock-decorate one ADK tool callable."""
    airlock = Airlock(policy=policy) if policy is not None else Airlock()
    return airlock(_relax_injected_params(func))


@dataclass
class GoogleADKAdapter:
    """Single facade that wraps a ``google.adk.agents.Agent`` with Airlock.

    Attributes:
        warn_on_unwrappable: When ``True`` (default), emit a
            :class:`UserWarning` naming every entry in ``agent.tools``
            the adapter could not guard — toolsets, and built-in tools
            that execute model-side. Silence is the wrong default for a
            deny-by-default layer: a user who believes a toolset is
            guarded when it is not is worse off than one who is told.
    """

    warn_on_unwrappable: bool = True

    def wrap_agent(self, agent: Any, *, policy: SecurityPolicy | None = None) -> Any:
        """Wrap an ADK ``Agent`` so every function tool routes through Airlock.

        Args:
            agent: A ``google.adk.agents.Agent`` (a.k.a. ``LlmAgent``)-shaped
                object. The adapter requires a ``tools`` attribute holding a
                mutable sequence — ADK 2.9.0's public surface. Any object with
                a ``tools`` list works, which is the test seam.
            policy: Optional :class:`SecurityPolicy`. When set, every tool
                callable is wrapped with ``Airlock(policy=policy)``.

        Returns:
            The same agent, mutated in place — every guardable tool callable
            replaced by an Airlock-decorated shim.

        Raises:
            GoogleADKMissingError: ``google-adk`` extra is missing AND the
                agent is a real ADK object (``__module__`` starts with
                ``google.adk``). Stub agents bypass the SDK import.
            AirlockError: The agent exposes no ``tools`` attribute, so it is
                not a recognised ADK shape.
        """
        self._maybe_check_sdk(agent)

        tools = getattr(agent, "tools", None)
        if tools is None:
            raise AirlockError("agent exposes no `tools` attribute; not a Google ADK shape")
        if not isinstance(tools, list):
            raise AirlockError(
                f"unrecognised tools type {type(tools).__name__}; "
                "expected a list (google.adk LlmAgent.tools)"
            )

        wrapped_count = 0
        unwrappable: list[str] = []
        for index, tool in enumerate(tools):
            replacement, skip_reason = self._wrap_one(tool, policy=policy)
            if skip_reason is not None:
                unwrappable.append(skip_reason)
                continue
            tools[index] = replacement
            wrapped_count += 1

        logger.info(
            "google_adk_agent_wrapped",
            tool_count=wrapped_count,
            unwrapped_count=len(unwrappable),
            policy_set=policy is not None,
        )
        if unwrappable and self.warn_on_unwrappable:
            warnings.warn(
                "agent-airlock did not guard "
                f"{len(unwrappable)} of {len(tools)} ADK tool entries: "
                f"{', '.join(unwrappable)}. These have no local callable to wrap; "
                "calls through them are NOT validated by agent-airlock.",
                UserWarning,
                stacklevel=3,
            )
        return agent

    def _wrap_one(self, tool: Any, *, policy: SecurityPolicy | None) -> tuple[Any, str | None]:
        """Guard one ``agent.tools`` entry.

        Returns ``(replacement, None)`` when guarded, or ``(tool, reason)``
        when the entry has no local callable to wrap.
        """
        # 1. BaseTool carrying the user callable (FunctionTool and friends).
        #    Mutating ``.func`` in place keeps the name/description ADK
        #    computed at tool construction.
        func = getattr(tool, "func", None)
        if callable(func):
            tool.func = _airlock_guard(func, policy=policy)
            return tool, None

        # 2. Toolsets build their tools per call, via an async ``get_tools``.
        #    There is no static callable to rewrite.
        if callable(getattr(tool, "get_tools", None)):
            return tool, f"toolset {type(tool).__name__}"

        # 3. Bare callable — ADK keeps these as-is in ``tools``.
        if callable(tool):
            return _airlock_guard(tool, policy=policy), None

        # 4. Built-in model-side tools (e.g. GoogleSearchTool) expose no
        #    local callable at all.
        name = getattr(tool, "name", None) or type(tool).__name__
        return tool, f"tool {name} (no local callable)"

    def _maybe_check_sdk(self, agent: Any) -> None:
        """Raise :class:`GoogleADKMissingError` only for real ADK objects.

        Stubs carrying ``tools`` but no ADK provenance are allowed through —
        the test surface has to run without the optional dep installed.

        Also emits a :class:`UserWarning` when the installed ADK version is
        outside :data:`SUPPORTED_GOOGLE_ADK_VERSIONS`.
        """
        if not type(agent).__module__.startswith("google.adk"):
            return
        try:
            import google.adk as _adk
        except ImportError as exc:
            raise GoogleADKMissingError(_INSTALL_HINT) from exc
        installed = getattr(_adk, "__version__", "unknown")
        if installed not in SUPPORTED_GOOGLE_ADK_VERSIONS:
            warnings.warn(
                f"google-adk {installed} is outside SUPPORTED_GOOGLE_ADK_VERSIONS "
                f"{SUPPORTED_GOOGLE_ADK_VERSIONS}; adapter behaviour is best-effort",
                UserWarning,
                stacklevel=4,
            )


def wrap_agent(
    agent: Any,
    policy: SecurityPolicy | None = None,
    *,
    warn_on_unwrappable: bool = True,
) -> Any:
    """Wrap an ADK agent's tools with Airlock. Module-level convenience.

    Equivalent to ``GoogleADKAdapter(...).wrap_agent(agent, policy=policy)``.

    Args:
        agent: A ``google.adk.agents.Agent``-shaped object with ``tools``.
        policy: Optional :class:`SecurityPolicy` applied to every tool.
        warn_on_unwrappable: Warn about tool entries with no local callable
            (toolsets, model-side built-ins) rather than skipping silently.

    Returns:
        The same agent, mutated in place.
    """
    adapter = GoogleADKAdapter(warn_on_unwrappable=warn_on_unwrappable)
    return adapter.wrap_agent(agent, policy=policy)


__all__ = [
    "ADK_INJECTED_PARAMS",
    "SUPPORTED_GOOGLE_ADK_VERSIONS",
    "GoogleADKAdapter",
    "GoogleADKMissingError",
    "wrap_agent",
]
