"""``@Airlock``-wrapped stand-ins for MCPTox's tools, and the verdict of one call through them.

Each stub carries the tool's declared contract and nothing more, because MCPTox prompts
declare names and required-ness but no types:

* keyword-only parameters named after the declared arguments (``from`` becomes
  ``from_``), every one annotated ``typing.Any``. Typing them all ``str`` would invent
  roughly two thousand refusals of recorded integers, lists, booleans and objects, so the
  strict-type layer is deliberately not exercised here;
* a required argument has no default, so omitting it is a validation refusal; an optional
  one defaults to a private sentinel, so an omitted key stays omitted;
* ``__signature__``, ``__annotations__`` and ``__name__`` set the way
  ``agent_airlock.integrations._tool_proxy`` sets them, so ghost-argument detection and the
  ``SecurityPolicy`` allowlist see the tool, not the generic body.

The body appends ``(tool, arguments)`` to a canary list and returns ``{"ok": True}``.
A call is **admitted** when the body ran and **refused** when ``@Airlock`` answered with
its refusal dict and the body did not run; anything else is **unreplayable**, with a
reason, and is reported rather than dropped.

Every stub runs under ``AirlockConfig(unknown_args=UnknownArgsMode.BLOCK,
enable_audit_log=False, sanitize_output=False)`` with no honeypot, plus the tier's
``FilesystemPolicy`` / ``EndpointPolicy`` for that tool. ``AIRLOCK_UNKNOWN_ARGS`` overrides
the constructor, so a config that did not come out as BLOCK is refused at build time.
"""

from __future__ import annotations

import contextlib
import inspect
import logging
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy, UnknownArgsMode
from agent_airlock._log import structlog
from agent_airlock.filesystem import FilesystemPolicy
from agent_airlock.network import EndpointPolicy
from agent_airlock.ssrf_egress_guard import SSRFEgressGuard

from .clean import ToolSpec
from .parse import Call
from .policies import GLOB_METACHARACTERS, EndpointScope, FsScope, TierPolicy, ToolScope

CONTRACT_REASONS = frozenset({"ghost_arguments", "validation_error"})
"""Block reasons that come from the call contract rather than from a policy."""

ADMITTED = "admitted"
REFUSED = "refused"
UNREPLAYABLE = "unreplayable"


class _Absent:
    """Default of an optional parameter, so an omitted argument stays omitted."""

    def __repr__(self) -> str:
        return "<absent>"


_ABSENT = _Absent()


@dataclass(frozen=True)
class Verdict:
    """What ``@Airlock`` did with one call.

    Attributes:
        outcome: ``admitted``, ``refused`` or ``unreplayable``.
        block_reason: ``AirlockResponse.block_reason`` (or ``ssrf_egress:<verdict>``).
        error: The refusal's error text.
        reason: Why a call could not be replayed (``unknown_tool``, ...).
        layer: ``contract`` (ghost or missing arguments) or ``policy`` (allowlist, path,
            endpoint, SSRF pre-check), for refusals.
    """

    outcome: str
    block_reason: str | None = None
    error: str | None = None
    reason: str | None = None
    layer: str | None = None

    @property
    def refused(self) -> bool:
        return self.outcome == REFUSED

    @property
    def admitted(self) -> bool:
        return self.outcome == ADMITTED


def _no_dns(host: str) -> list[str]:
    """Resolver for the replay's SSRF pre-check: literal IPs are decoded, names never resolved."""
    raise OSError(f"no DNS during replay ({host!r} not resolved)")


def ssrf_guard() -> SSRFEgressGuard:
    """The pre-check LP gives open-web tools: decodes literal-IP encodings, never resolves."""
    return SSRFEgressGuard(resolver=_no_dns, deny_on_resolution_failure=False)


def filesystem_policy(scope: FsScope) -> FilesystemPolicy:
    """Build a tool's ``FilesystemPolicy`` (resolved against the current directory).

    A root that starts with ``~`` is granted twice, literally (which ``agent_airlock``
    resolves under the working directory) and expanded, so a path the clean query wrote
    with ``~`` passes whether or not the gate expands it.
    """
    roots: list[Path] = []
    for root in scope.roots:
        roots.append(Path(root))
        if root.startswith("~"):
            roots.append(Path(root).expanduser())
    return FilesystemPolicy(
        allowed_roots=roots,
        allow_symlinks=scope.allow_symlinks,
        deny_patterns=list(scope.deny_patterns),
        max_path_depth=scope.max_path_depth,
    )


def endpoint_policy(scope: EndpointScope) -> EndpointPolicy:
    """Build a tool's ``EndpointPolicy`` (an allowlist, or the open-web default)."""
    if scope.kind == "allowlist":
        if not scope.hosts:
            raise ValueError("an allowlist scope needs at least one host")
        return EndpointPolicy(allowed_endpoints=list(scope.hosts))
    return EndpointPolicy()


def make_config(tool_name: str, scope: ToolScope | None) -> AirlockConfig:
    """The ``AirlockConfig`` one stub runs under.

    Raises:
        RuntimeError: The environment turned ghost-argument handling away from BLOCK.
    """
    config = AirlockConfig(
        unknown_args=UnknownArgsMode.BLOCK,
        enable_audit_log=False,
        sanitize_output=False,
        filesystem_policy=filesystem_policy(scope.fs) if scope and scope.fs else None,
        endpoint_policies=(
            {tool_name: endpoint_policy(scope.endpoint)} if scope and scope.endpoint else {}
        ),
    )
    if config.unknown_args is not UnknownArgsMode.BLOCK:
        raise RuntimeError(
            "AIRLOCK_UNKNOWN_ARGS overrode unknown_args away from BLOCK; unset it for a replay"
        )
    if config.honeypot_config is not None:
        raise RuntimeError("the replay must run without a honeypot")
    return config


def build_stub(
    spec: ToolSpec,
    *,
    canary: list[tuple[str, dict[str, Any]]],
    config: AirlockConfig,
    policy: SecurityPolicy | None,
) -> Any:
    """An ``@Airlock``-wrapped stub for ``spec`` that records each call it runs.

    Raises:
        ValueError: The tool name holds a glob metacharacter.
    """
    if GLOB_METACHARACTERS & set(spec.name):
        raise ValueError(f"tool name {spec.name!r} holds a glob metacharacter")
    py_to_wire = {p.py_name: p.name for p in spec.params}

    def body(**kwargs: Any) -> dict[str, bool]:
        canary.append(
            (
                spec.name,
                {py_to_wire.get(k, k): v for k, v in kwargs.items() if v is not _ABSENT},
            )
        )
        return {"ok": True}

    parameters = [
        inspect.Parameter(
            p.py_name,
            inspect.Parameter.KEYWORD_ONLY,
            annotation=Any,
            default=inspect.Parameter.empty if p.required else _ABSENT,
        )
        for p in spec.params
    ]
    proxy: Any = body
    proxy.__signature__ = inspect.Signature(parameters)
    proxy.__annotations__ = {p.py_name: Any for p in spec.params}
    proxy.__name__ = spec.name
    proxy.__qualname__ = spec.name
    proxy.__doc__ = None
    return Airlock(config=config, policy=policy)(proxy)


@dataclass
class StubSet:
    """Every stub one tier puts in front of one server (plus, per case, its poisoned tool)."""

    tier_policy: TierPolicy
    specs: dict[str, ToolSpec]
    stubs: dict[str, Any]
    canary: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    ssrf: dict[str, SSRFEgressGuard] = field(default_factory=dict)
    policy: SecurityPolicy | None = None
    poisoned_tool: str | None = None

    def with_poisoned(self, spec: ToolSpec | None) -> StubSet:
        """A copy that also stubs ``spec``, under the same policy and an unscoped config."""
        if spec is None or spec.name in self.specs:
            return replace(self, poisoned_tool=spec.name if spec else None)
        stub = build_stub(
            spec,
            canary=self.canary,
            config=make_config(spec.name, None),
            policy=self.policy,
        )
        return replace(
            self,
            specs={**self.specs, spec.name: spec},
            stubs={**self.stubs, spec.name: stub},
            poisoned_tool=spec.name,
        )


def build_stub_set(tools: tuple[ToolSpec, ...], tier_policy: TierPolicy) -> StubSet:
    """Stubs for a server's clean tools under one tier (build after any ``chdir``)."""
    policy = (
        SecurityPolicy(allowed_tools=list(tier_policy.allowed_tools), default_deny=True)
        if tier_policy.allowed_tools is not None
        else None
    )
    canary: list[tuple[str, dict[str, Any]]] = []
    stubs: dict[str, Any] = {}
    ssrf: dict[str, SSRFEgressGuard] = {}
    for spec in tools:
        scope = tier_policy.scopes.get(spec.name)
        stubs[spec.name] = build_stub(
            spec, canary=canary, config=make_config(spec.name, scope), policy=policy
        )
        if scope is not None and scope.endpoint is not None and scope.endpoint.ssrf_precheck:
            ssrf[spec.name] = ssrf_guard()
    return StubSet(
        tier_policy=tier_policy,
        specs={s.name: s for s in tools},
        stubs=stubs,
        canary=canary,
        ssrf=ssrf,
        policy=policy,
    )


def _layer(block_reason: str | None) -> str:
    return "contract" if block_reason in CONTRACT_REASONS else "policy"


def _kwargs_for(spec: ToolSpec, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Map wire argument names to the stub's parameter names; undeclared ones pass as-is.

    An undeclared key that happens to equal a mangled parameter name (``from_`` when the
    tool declares ``from``) is renamed so it cannot stand in for that parameter: it stays
    an undeclared argument, which BLOCK refuses.
    """
    wire_to_py = {p.name: p.py_name for p in spec.params}
    mangled = {p.py_name for p in spec.params if p.py_name != p.name}
    out: dict[str, Any] = {}
    for key, value in arguments.items():
        if key in wire_to_py:
            out[wire_to_py[key]] = value
        elif key in mangled:
            out[f"{key}__undeclared"] = value
        else:
            out[key] = value
    return out


def run_call(stubs: StubSet, call: Call) -> Verdict:
    """Send one parsed call through its stub and say what ``@Airlock`` did."""
    name = call.tool
    if GLOB_METACHARACTERS & set(name):
        return Verdict(UNREPLAYABLE, reason="glob_metacharacter_in_tool_name")
    stub = stubs.stubs.get(name)
    if stub is None:
        return Verdict(UNREPLAYABLE, reason="unknown_tool")
    guard = stubs.ssrf.get(name)
    if guard is not None:
        decision = guard.check(dict(call.arguments))
        if not decision.allowed:
            return Verdict(
                REFUSED,
                block_reason=f"ssrf_egress:{decision.verdict.value}",
                error=decision.explain[0] if decision.explain else None,
                layer="policy",
            )
    kwargs = _kwargs_for(stubs.specs[name], call.arguments)
    before = len(stubs.canary)
    try:
        result = stub(**kwargs)
    except Exception as exc:  # noqa: BLE001 - a harness fault is reported, never dropped
        return Verdict(UNREPLAYABLE, reason=f"harness_error:{type(exc).__name__}")
    ran = len(stubs.canary) > before
    if ran and result == {"ok": True}:
        return Verdict(ADMITTED)
    if not ran and isinstance(result, dict) and result.get("success") is False:
        reason = result.get("block_reason")
        reason = str(reason) if reason is not None else None
        return Verdict(
            REFUSED,
            block_reason=reason,
            error=str(result.get("error") or ""),
            layer=_layer(reason),
        )
    return Verdict(UNREPLAYABLE, reason="unexpected_result")


@contextlib.contextmanager
def quiet_airlock_logs() -> Iterator[None]:
    """Silence ``agent_airlock`` logging for the duration (a replay makes ~10^5 refusals)."""
    stdlib = logging.getLogger("agent-airlock")
    old_level = stdlib.level
    get_config = getattr(structlog, "get_config", None)
    old_config = dict(get_config()) if callable(get_config) else None
    try:
        stdlib.setLevel(logging.CRITICAL)
        structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
        yield
    finally:
        stdlib.setLevel(old_level)
        if old_config is not None:
            structlog.configure(**old_config)
