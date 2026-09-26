"""Name-retagging proxy for the tool-walking adapters, carrying the tool's call contract.

The walkers in this package (``crewai``, ``pydantic_ai``, ``anthropic_claude_agent_sdk``)
hand ``Airlock`` a proxy re-tagged with the tool's name, so ``SecurityPolicy`` allow and
deny lists match the tool rather than the attribute it lives on (``_run``, ``function``,
``forward``). ``Airlock`` enforces exactly the signature it is handed, so the proxy has to
carry two things the tool has:

* **Its signature and annotations.** The proxy used to be ``(*args, **kwargs)``. Strict
  validation then had no parameter to check, and ghost-argument detection saw a
  ``**kwargs`` that accepts everything, so a wrong-typed argument reached the tool and an
  invented one reached it too.
* **Its async-ness.** ``Airlock`` picks its async wrapper by
  ``asyncio.iscoroutinefunction``. A plain ``def`` proxy around an ``async def`` tool got
  the sync wrapper, which audited success before the tool ran and returned the
  un-awaited coroutine, so the result the framework awaited never passed through output
  sanitisation.

Annotations are resolved with ``get_type_hints(..., include_extras=True)`` for the reason
:func:`agent_airlock.validator.create_argument_validator` gives: under
``from __future__ import annotations`` they are strings, and the proxy does not share the
tool's module globals.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Collection
from typing import Any, get_type_hints

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.integrations._tool_proxy")


def named_tool_proxy(
    forward: Callable[..., Any],
    *,
    name: str,
    relaxed_params: Collection[str] = (),
) -> Callable[..., Any]:
    """Return a proxy named ``name`` that calls ``forward`` and carries its contract.

    Args:
        forward: The tool's own callable — a function, bound method,
            ``functools.partial`` or callable object.
        name: The name ``SecurityPolicy`` lists should match (the tool's name).
        relaxed_params: Parameters the framework injects rather than the model, such as
            a run context. Their runtime types have no Pydantic schema, so they are
            annotated ``Any``; every other parameter keeps its annotation and stays
            strictly validated.

    Returns:
        A proxy that is ``async`` exactly when ``forward`` is, whose ``__signature__``
        and ``__annotations__`` are ``forward``'s with forward references resolved.

    Raises:
        AirlockError: ``forward`` has no readable signature. A proxy without one would
            validate nothing, so wrapping is refused rather than waived.
    """
    signature, annotations = _contract(forward, name=name, relaxed=frozenset(relaxed_params))
    proxy = _async_proxy(forward) if _is_async(forward) else _sync_proxy(forward)
    _adopt_identity(proxy, forward, name=name, signature=signature, annotations=annotations)
    return proxy


def _adopt_identity(
    proxy: Any,
    forward: Callable[..., Any],
    *,
    name: str,
    signature: inspect.Signature,
    annotations: dict[str, Any],
) -> None:
    """Carry the tool's name and contract onto ``proxy``.

    ``proxy`` is typed ``Any`` so the dunder assignments need no inline ignores, as in
    ``google_adk._adopt_identity``. ``__wrapped__`` is deliberately not set: introspection
    that unwraps would then reach ``forward`` and read its un-relaxed annotations.
    """
    proxy.__name__ = name
    proxy.__qualname__ = name
    proxy.__doc__ = getattr(forward, "__doc__", None)
    proxy.__module__ = getattr(_hint_source(forward), "__module__", None) or proxy.__module__
    proxy.__signature__ = signature
    proxy.__annotations__ = annotations


def _contract(
    forward: Callable[..., Any], *, name: str, relaxed: frozenset[str]
) -> tuple[inspect.Signature, dict[str, Any]]:
    """``forward``'s signature and annotations, resolved, with ``relaxed`` ones as ``Any``."""
    try:
        signature = inspect.signature(forward)
    except (TypeError, ValueError) as exc:
        raise AirlockError(
            f"tool {name!r}: cannot read the signature of {forward!r} ({exc}); "
            "refusing to wrap a callable whose arguments cannot be validated"
        ) from exc

    hints = _resolved_hints(forward, name=name)
    parameters = [
        param.replace(
            annotation=Any if param_name in relaxed else hints.get(param_name, param.annotation)
        )
        for param_name, param in signature.parameters.items()
    ]
    signature = signature.replace(
        parameters=parameters,
        return_annotation=hints.get("return", signature.return_annotation),
    )
    annotations = {
        param.name: param.annotation
        for param in parameters
        if param.annotation is not inspect.Parameter.empty
    }
    if signature.return_annotation is not inspect.Signature.empty:
        annotations["return"] = signature.return_annotation
    return signature, annotations


def _resolved_hints(forward: Callable[..., Any], *, name: str) -> dict[str, Any]:
    """``forward``'s annotations with forward references resolved.

    Falls back to the raw annotations when a reference cannot be resolved. Pydantic then
    retries them against the tool's module, which the proxy adopts as its ``__module__``,
    and one that is genuinely unresolvable fails when ``Airlock`` builds its validator —
    at wrap time — instead of letting arguments through unchecked.
    """
    source = _hint_source(forward)
    try:
        return get_type_hints(source, include_extras=True)
    except Exception as exc:  # unresolvable forward reference
        logger.warning(
            "tool_annotations_unresolved",
            tool=name,
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return dict(getattr(source, "__annotations__", None) or {})


def _hint_source(forward: Callable[..., Any]) -> Any:
    """The object whose ``__annotations__`` and module describe ``forward``'s parameters."""
    if isinstance(forward, functools.partial):
        return _hint_source(forward.func)
    if inspect.isfunction(forward) or inspect.ismethod(forward):
        return forward
    return _class_call(forward) or forward


def _is_async(forward: Callable[..., Any]) -> bool:
    """Whether calling ``forward`` returns a coroutine, ``async def __call__`` included."""
    if inspect.iscoroutinefunction(forward):
        return True
    call = _class_call(forward)
    return call is not None and inspect.iscoroutinefunction(call)


def _class_call(forward: Callable[..., Any]) -> Any:
    """The Python-level ``__call__`` of ``forward``'s class, or ``None`` for built-in ones.

    Read with ``getattr_static`` so the function itself comes back, not a bound method.
    """
    call = inspect.getattr_static(type(forward), "__call__", None)
    return call if inspect.isfunction(call) else None


def _sync_proxy(forward: Callable[..., Any]) -> Callable[..., Any]:
    def proxy(*args: Any, **kwargs: Any) -> Any:
        return forward(*args, **kwargs)

    return proxy


def _async_proxy(forward: Callable[..., Any]) -> Callable[..., Any]:
    async def proxy(*args: Any, **kwargs: Any) -> Any:
        return await forward(*args, **kwargs)

    return proxy
