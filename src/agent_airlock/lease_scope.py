"""Bind a tool argument to the capability lease its caller holds (V0.10.29).

``@lease_scoped(arg="path", capability=Capability.WRITE_FILE, engine=engine)`` makes
``@Airlock`` check, before the tool runs (step 4.5), that the call's ``path`` falls within
the target glob of a lease the calling agent holds in ``engine`` for that capability, and
then meters the use with ``engine.check_and_use``. A value the tool's schema accepts is
still refused when it is outside every such lease: the schema says what shape the argument
has, the lease what the agent may touch. Until 0.10.29 nothing tied an argument to a lease
on the ``@Airlock`` path, so a substituted argument reached the effect
(modelcontextprotocol/modelcontextprotocol#3354).

A lease counts for ``capability=Capability.WRITE_FILE`` when its ``capability`` label is
``"write_file"``. The value is matched as written, with :func:`fnmatch.fnmatchcase`, so
``*`` crosses ``/``; a value with a ``..`` segment or a NUL is refused, and symlinks are
the filesystem guard's to resolve (step 3).
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

from .capabilities import _airlock_wrappers_beneath
from .capability_caps import Capability

if TYPE_CHECKING:
    from .capability_caps import CapabilityCapEngine

__all__ = ["LeaseRefusal", "LeaseScope", "check_lease_scopes", "lease_scoped", "lease_scopes"]

F = TypeVar("F", bound=Callable[..., Any])

_SCOPES_ATTR = "__airlock_lease_scopes__"
_SEPARATORS = re.compile(r"[\\/]")


@dataclass(frozen=True)
class LeaseScope:
    """One ``@lease_scoped`` declaration: the argument, its capability, the lease engine."""

    arg: str
    capability: Capability
    engine: CapabilityCapEngine


@dataclass(frozen=True)
class LeaseRefusal:
    """Why a call's argument fell outside its caller's leases, as the model may read it."""

    arg: str
    capability: str
    reason: str


def lease_scoped(
    *, arg: str, capability: Capability, engine: CapabilityCapEngine
) -> Callable[[F], F]:
    """Declare that argument ``arg`` must fall within a lease the calling agent holds.

    Usable above or below ``@Airlock``, and more than once for several arguments.

    Args:
        arg: The parameter whose value is the lease target (a path, a URL, an account).
        capability: The :class:`agent_airlock.capability_caps.Capability` the use is
            metered as, and whose value names the leases that count.
        engine: The :class:`~agent_airlock.capability_caps.CapabilityCapEngine` holding
            the leases and the caps.

    Raises:
        ValueError: ``arg`` is not a parameter name.
        TypeError: ``capability`` is not a ``capability_caps.Capability``, or ``engine``
            has no ``held_leases`` and ``check_and_use``.
    """
    if not isinstance(arg, str) or not arg.isidentifier():
        raise ValueError(f"@lease_scoped(arg=...) must name a parameter, got {arg!r}")
    if not isinstance(capability, Capability):
        raise TypeError(
            "@lease_scoped(capability=...) takes an agent_airlock.capability_caps.Capability, "
            f"got {capability!r}"
        )
    if not all(callable(getattr(engine, name, None)) for name in ("held_leases", "check_and_use")):
        raise TypeError("@lease_scoped(engine=...) takes a CapabilityCapEngine")
    scope = LeaseScope(arg=arg, capability=capability, engine=engine)

    def decorator(func: F) -> F:
        for target in (func, *_airlock_wrappers_beneath(func)):
            existing = getattr(target, _SCOPES_ATTR, ())
            setattr(target, _SCOPES_ATTR, (*existing, scope))
        return func

    return decorator


def lease_scopes(func: Callable[..., Any]) -> tuple[LeaseScope, ...]:
    """Every ``@lease_scoped`` declaration on ``func`` or down its ``__wrapped__`` chain."""
    found: list[LeaseScope] = []
    seen: set[int] = set()
    current: Any = func
    for _ in range(32):  # bounded, like get_required_capabilities
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        declared = getattr(current, _SCOPES_ATTR, ())
        for scope in declared if isinstance(declared, tuple) else ():
            if isinstance(scope, LeaseScope) and scope not in found:
                found.append(scope)
        current = getattr(current, "__wrapped__", None)
    return tuple(found)


def _refuse(scope: LeaseScope, reason: str) -> LeaseRefusal:
    return LeaseRefusal(arg=scope.arg, capability=scope.capability.value, reason=reason)


def _target(
    scope: LeaseScope, arguments: Mapping[str, Any], defaults: Mapping[str, Any]
) -> str | LeaseRefusal:
    """The value ``scope``'s argument takes in this call, its default when not passed."""
    if scope.arg in arguments:
        value = arguments[scope.arg]
    elif scope.arg in defaults:
        value = defaults[scope.arg]
    else:
        return _refuse(scope, "the call passes no value for it")
    if not isinstance(value, str):
        return _refuse(scope, "it is not a string")
    text = str.__str__(value)
    if "\x00" in text or ".." in _SEPARATORS.split(text):
        return _refuse(scope, "it has a '..' segment or a NUL character")
    return text


def _outside(scope: LeaseScope, agent_id: str, target: str) -> LeaseRefusal | None:
    """A refusal when no lease ``agent_id`` holds for the capability covers ``target``."""
    for lease in scope.engine.held_leases(agent_id):
        if lease.capability == scope.capability.value and fnmatch.fnmatchcase(target, lease.target):
            return None
    return _refuse(scope, f"it is outside every {scope.capability.value} lease this agent holds")


def check_lease_scopes(
    scopes: tuple[LeaseScope, ...],
    *,
    agent_id: str | None,
    arguments: Mapping[str, Any],
    defaults: Mapping[str, Any],
) -> LeaseRefusal | None:
    """The first refusal among ``scopes`` for one call, or None when every argument falls
    within a lease its caller holds. Only then is each use metered through the engine,
    whose cap can still refuse it.

    Args:
        scopes: The tool's declarations, from :func:`lease_scopes`.
        agent_id: The calling agent's id; a call with none holds no lease.
        arguments: The call's arguments by name.
        defaults: The tool's parameter defaults, for an argument the call leaves out.
    """
    if not scopes:
        return None
    if not agent_id:
        return _refuse(scopes[0], "the call names no agent, so it holds no lease")
    targets: list[tuple[LeaseScope, str]] = []
    for scope in scopes:
        target = _target(scope, arguments, defaults)
        if isinstance(target, LeaseRefusal):
            return target
        refusal = _outside(scope, agent_id, target)
        if refusal is not None:
            return refusal
        targets.append((scope, target))
    for scope, target in targets:
        decision = scope.engine.check_and_use(agent_id, scope.capability, target)
        if not decision.allowed:
            return _refuse(scope, f"the {scope.capability.value} cap refused it: {decision.reason}")
    return None
