"""Compute agent-airlock's REAL decision on each head-to-head corpus item.

Every decision here runs the shipped airlock code path — no mock, no lookup
table:

- ``transfer`` items (type-confusion / value-constraint / ghost-arg / benign)
  run through a real ``@Airlock``-decorated tool whose signature declares the
  contract (``amount: int`` with ``> 0``, ghost args = BLOCK). A block is a real
  ``AirlockResponse(success=False)``.
- ``read_file`` items run through :class:`~agent_airlock.safe_types.SafePathValidator`.
- ``fetch`` items run through :class:`~agent_airlock.safe_types.SafeURLValidator`.
- ``arg_injection_*`` items run through the shipped in-process guard chain
  (eval-RCE, subprocess-arg, env-interpolation, codegen).
- ``over_privileged`` runs through a deny-by-default least-privilege
  :class:`~agent_airlock.policy.SecurityPolicy`.
"""

from __future__ import annotations

import time
from typing import Annotated, Any

from pydantic import Field

from agent_airlock import (
    Airlock,
    AirlockConfig,
    CodegenDelimiterInjectionGuard,
    EvalRCEGuard,
    MCPServerEnvInterpolationGuard,
    McpSubprocessArgInjectionGuard,
    UnknownArgsMode,
)
from agent_airlock.policy import PolicyViolation, SecurityPolicy
from agent_airlock.safe_types import SafePathValidator, SafeURLValidator

from .corpus import GatewayCall, load_corpus

# Deny-by-default contract config: reject hallucinated arguments outright.
_CONFIG = AirlockConfig(unknown_args=UnknownArgsMode.BLOCK, enable_audit_log=False)

# Common static launchers allow-listed for the subprocess guard (matches the
# blockrate harness so the two benches agree on the injection decision path).
_ALLOWED_LAUNCHERS = frozenset({"uvx", "npx", "node", "python", "python3", "deno"})

_PATH_VALIDATOR = SafePathValidator()
_URL_VALIDATOR = SafeURLValidator(allowed_schemes=["http", "https"])


@Airlock(config=_CONFIG, return_dict=True)
def _transfer(account: str, amount: Annotated[int, Field(gt=0)]) -> dict[str, Any]:
    """A least-privilege money-transfer tool used as the real airlock oracle."""
    return {"ok": True, "account": account, "amount": amount}


def _transfer_blocks(args: dict[str, Any]) -> bool:
    """True iff the real ``@Airlock`` tool refuses these arguments."""
    result: dict[str, Any] = _transfer(**args)
    return not bool(result.get("success", False))


def _path_blocks(args: dict[str, Any]) -> bool:
    try:
        _PATH_VALIDATOR(args["path"])
        return False
    except Exception:
        return True


def _url_blocks(args: dict[str, Any]) -> bool:
    try:
        _URL_VALIDATOR(args["url"])
        return False
    except Exception:
        return True


def _guard_chain_blocks(args: dict[str, Any]) -> bool:
    """True iff any shipped in-process argument guard refuses the args."""
    guards = (
        EvalRCEGuard(),
        McpSubprocessArgInjectionGuard(allowed_commands=set(_ALLOWED_LAUNCHERS)),
        MCPServerEnvInterpolationGuard(),
        CodegenDelimiterInjectionGuard(),
    )
    for guard in guards:
        try:
            if not guard.evaluate(args).allowed:
                return True
        except Exception:
            continue
    return False


def _policy_blocks(call: GatewayCall) -> bool:
    """True iff the deny-by-default least-privilege policy refuses the tool."""
    allow = [call.allowed_tool] if call.allowed_tool else []
    policy = SecurityPolicy(allowed_tools=allow, default_deny=True)
    try:
        policy.check_tool_allowed(call.tool)
        return False
    except PolicyViolation:
        return True


def airlock_blocks(call: GatewayCall) -> bool:
    """Return airlock's real BLOCK (True) / ALLOW (False) decision for one call."""
    if call.tool == "transfer":
        return _transfer_blocks(call.args)
    if call.tool == "read_file":
        return _path_blocks(call.args)
    if call.tool == "fetch":
        return _url_blocks(call.args)
    if call.item_id == "over_privileged":
        return _policy_blocks(call)
    # Remaining items are argument-injection shapes routed to the guard chain.
    return _guard_chain_blocks(call.args)


def run_airlock() -> list[tuple[GatewayCall, bool, float]]:
    """Run airlock over the corpus; return ``(call, blocked, latency_ms)`` rows."""
    rows: list[tuple[GatewayCall, bool, float]] = []
    for call in load_corpus():
        t0 = time.perf_counter()
        blocked = airlock_blocks(call)
        rows.append((call, blocked, (time.perf_counter() - t0) * 1000.0))
    return rows
