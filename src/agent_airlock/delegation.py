"""Delegation: a delegated agent runs under a policy no wider than its parent's (V0.10.29).

A host that hands part of a task to another agent decides what that agent may do. Until
0.10.29 nothing checked that decision: a child given a wider policy than its parent got it,
and nothing tied the child's calls to what the parent was allowed.

* :meth:`SecurityPolicy.narrow` builds a child policy that can only admit less: its
  allowlist intersected with the parent's, the deny list added to, rate limits and the call
  budget lowered. :func:`subset_problems` (behind :meth:`SecurityPolicy.is_subset_of`)
  checks any child against a parent, field by field, and says what it could not prove.
* :meth:`AirlockContext.delegate` refuses a child that is not a subset and otherwise issues
  a :class:`DelegationLease`, a one-use receipt. Entering it starts the child's run under a
  ceiling: every call in that run must also pass the policies of the run's delegation
  chain, its parent's included (core step 2.1). It cannot start a second run.

Raised in openai/codex#36381 (the host proves the child's authority is a monotonic subset
of the parent's, then issues a one-use receipt) and
modelcontextprotocol/modelcontextprotocol#3354 (substituted tool and argument calls still
reached the effect).
"""

from __future__ import annotations

import contextlib
import fnmatch
import functools
import json
import secrets
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import fields as dc_fields
from datetime import datetime
from typing import TYPE_CHECKING, Any

from ._log import structlog
from .amplification import AmplificationBudget
from .context import AirlockContext, get_current_context
from .exceptions import AirlockError
from .nested_runs import _limit, nested_run
from .policy import RateLimit, SecurityPolicy, TimeWindow, pattern_specificity

if TYPE_CHECKING:
    from .capability_caps import CapabilityCapEngine, Lease

logger = structlog.get_logger("agent-airlock.delegation")

__all__ = [
    "DelegationLease",
    "DelegationRefused",
    "ceiling_chain",
    "glob_covers",
    "issue_delegation",
    "narrow_policy",
    "subset_problems",
]

_GLOB_CHARACTERS = frozenset("*?[")


class DelegationRefused(AirlockError):
    """A delegation the host asked for was refused: the child's policy or leases are wider
    than the parent's, or the lease was used already.

    Attributes:
        problems: What made the child wider, one sentence each; empty for a spent lease.
    """

    def __init__(self, message: str, *, problems: Sequence[str] = ()) -> None:
        self.problems = tuple(problems)
        super().__init__(message)


# -- glob coverage ---------------------------------------------------------------------


def glob_covers(outer: str, inner: str) -> bool:
    """Whether every name the glob ``inner`` matches, ``outer`` matches too.

    Sound, not complete: True only when the patterns' shape proves it (equal patterns, an
    ``outer`` of ``*``, a literal ``inner``, or an ``outer`` with one ``*`` whose literal
    head and tail ``inner`` starts and ends with), so a False can be a subset it could not
    prove. Matching is case-sensitive, as :func:`fnmatch.fnmatchcase` is.
    """
    if outer in ("*", inner):
        return True
    if not _GLOB_CHARACTERS.intersection(inner):
        return fnmatch.fnmatchcase(inner, outer)
    # A character class can end in ']' and so look literal: never reasoned about.
    if outer.count("*") != 1 or "?" in outer or "[" in outer or "[" in inner:
        return False
    head, _, tail = outer.partition("*")
    if len(head) + len(tail) > len(inner):
        return False
    fixed = inner[: len(head)] + inner[len(inner) - len(tail) :]
    return inner.startswith(head) and inner.endswith(tail) and "*" not in fixed and "?" not in fixed


def _unique(patterns: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(patterns))


def _admits_every_tool(policy: SecurityPolicy) -> bool:
    return not policy.allowed_tools and not policy.default_deny


def _intersect(parent: SecurityPolicy, requested: Sequence[str]) -> list[str]:
    """The requested patterns the parent's allowlist covers, and the parent's patterns the
    request covers: names both admit, and no others."""
    if _admits_every_tool(parent):
        return _unique(requested)
    allowed = parent.allowed_tools
    kept = [pattern for pattern in requested if any(glob_covers(p, pattern) for p in allowed)]
    kept += [pattern for pattern in allowed if any(glob_covers(r, pattern) for r in requested)]
    return _unique(kept)


# -- subset rules ----------------------------------------------------------------------


@functools.lru_cache(maxsize=256)
def _minutes_of(
    start_hour: int, start_minute: int, end_hour: int, end_minute: int
) -> frozenset[int]:
    window = TimeWindow(start_hour, start_minute, end_hour, end_minute)
    day = datetime(2000, 1, 1)
    return frozenset(
        minute
        for minute in range(24 * 60)
        if window.is_within(day.replace(hour=minute // 60, minute=minute % 60))
    )


def _minutes(window: TimeWindow) -> frozenset[int]:
    """The minutes of the day ``window`` admits, read as ``TimeWindow.is_within`` reads them."""
    return _minutes_of(window.start_hour, window.start_minute, window.end_hour, window.end_minute)


def _caps(pattern: str, parent_values: Mapping[str, Any]) -> list[Any]:
    """The parent's values a child's value for ``pattern`` could stand in for.

    The most specific pattern decides, and among patterns as specific as each other the
    dictionary's order does, which a child may not share. So for a pattern the parent has,
    the values of every parent pattern as specific as it; for one it does not, all of them.
    """
    if pattern not in parent_values:
        return list(parent_values.values())
    key = pattern_specificity(pattern)
    return [value for name, value in parent_values.items() if pattern_specificity(name) == key]


def _allowlist_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    if _admits_every_tool(parent) or (child.default_deny and not child.allowed_tools):
        return None
    if _admits_every_tool(child):
        return "allowed_tools: the child admits every tool and the parent does not"
    wider = [
        pattern
        for pattern in child.allowed_tools
        if not any(glob_covers(allowed, pattern) for allowed in parent.allowed_tools)
    ]
    return f"allowed_tools: {wider} not within the parent's allowlist" if wider else None


def _denylist_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    missing = [
        pattern
        for pattern in parent.denied_tools
        if not any(glob_covers(denied, pattern) for denied in child.denied_tools)
    ]
    return f"denied_tools: the child does not deny {missing}" if missing else None


def _window_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    windows = child._time_windows
    missing = [pattern for pattern in parent._time_windows if pattern not in windows]
    if missing:
        return f"time_restrictions: the child drops {missing}"
    allowed = {pattern: _minutes(window) for pattern, window in parent._time_windows.items()}
    wider = [
        pattern
        for pattern, window in windows.items()
        if not all(_minutes(window) <= cap for cap in _caps(pattern, allowed))
    ]
    return f"time_restrictions: {wider} admit hours the parent does not" if wider else None


def _rate_at_most(limit: RateLimit, cap: RateLimit) -> bool:
    """No more calls at once and no faster: a burst no larger, a refill no quicker."""
    return limit.max_tokens <= cap.max_tokens and (
        limit.max_tokens * cap.refill_period_seconds <= cap.max_tokens * limit.refill_period_seconds
    )


def _rate_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    limits = child._rate_limiters
    missing = [pattern for pattern in parent._rate_limiters if pattern not in limits]
    if missing:
        return f"rate_limits: the child drops {missing}"
    wider = [
        pattern
        for pattern, limit in limits.items()
        if not all(_rate_at_most(limit, cap) for cap in _caps(pattern, parent._rate_limiters))
    ]
    return f"rate_limits: {wider} are not lower than the parent's" if wider else None


def _rate_mode_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    """How the limits apply: every matching pattern's, and one bucket for every agent."""
    if parent.rate_limit_mode == "all" and child.rate_limit_mode != "all":
        return (
            "rate_limit_mode: the child spends only its most specific pattern's token, "
            "where the parent spends one from every pattern that matches"
        )
    if parent.rate_limit_scope == "policy" and child.rate_limit_scope != "policy":
        return (
            "rate_limit_scope: the child gives each agent its own bucket, where the "
            "parent's agents share one"
        )
    return None


def _identity_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    if parent.require_agent_id and not child.require_agent_id:
        return "require_agent_id: the child admits calls that name no agent"
    roles = set(parent.allowed_roles)
    if roles and not (child.allowed_roles and set(child.allowed_roles) <= roles):
        return "allowed_roles: the child admits roles the parent does not"
    return None


def _reauth_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    if not parent.reauth_on_untrusted_reinvocation:
        return None
    if (
        not child.reauth_on_untrusted_reinvocation
        or child.untrusted_reinvocation_threshold > parent.untrusted_reinvocation_threshold
    ):
        return (
            "reauth_on_untrusted_reinvocation: the child asks for re-authorization later "
            "than the parent, or never"
        )
    return None


def _grant_keys(policy: SecurityPolicy) -> set[str]:
    """What each unrevoked standing grant admits, whatever its id."""
    with policy._lock:
        revoked = set(policy._revoked_grants)
    return {
        json.dumps(grant.canonical()[1:])
        for grant in policy.standing_grants
        if grant.grant_id not in revoked
    }


def _escalation_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    missing = [pattern for pattern in parent.escalate_tools if pattern not in child.escalate_tools]
    if missing:
        return f"escalate_tools: the child does not escalate {missing}"
    if child.approver is not None and child.approver is not parent.approver:
        return (
            "approver: the child's is not the parent's, so it could grant what that one would not"
        )
    if child.approver is not None and child.escalation_channel != parent.escalation_channel:
        return "escalation_channel: the child asks somewhere the parent does not"
    if child.approval_ledger is not None and child.approval_ledger is not parent.approval_ledger:
        return "approval_ledger: the child's is not the parent's"
    if _grant_keys(child) - _grant_keys(parent):
        return "standing_grants: the child admits calls no grant of the parent admits"
    return None


def _ratio_within(mine: AmplificationBudget, theirs: AmplificationBudget) -> bool:
    if theirs.max_amplification_ratio is None or theirs.baseline_calls_per_run is None:
        return True
    return (
        mine.max_amplification_ratio is not None
        and mine.baseline_calls_per_run == theirs.baseline_calls_per_run
        and mine.max_amplification_ratio <= theirs.max_amplification_ratio
    )


def _budget_problem(child: SecurityPolicy, parent: SecurityPolicy) -> str | None:
    mine, theirs = child.amplification_budget, parent.amplification_budget
    blocks_all = mine is not None and mine.action == "block" and not mine.is_configured()
    if theirs is None or theirs.action == "warn" or blocks_all:
        return None
    if mine is None or mine.action == "warn" or not theirs.is_configured():
        return "amplification_budget: the child's admits calls the parent's refuses"
    calls = theirs.max_calls_per_run
    if calls is not None and (mine.max_calls_per_run is None or mine.max_calls_per_run > calls):
        return "amplification_budget: the child's max_calls_per_run is above the parent's"
    if not _ratio_within(mine, theirs):
        return "amplification_budget: the child's amplification ratio is looser than the parent's"
    wall = theirs.max_wall_seconds
    if wall is not None and (mine.max_wall_seconds is None or mine.max_wall_seconds > wall):
        return "amplification_budget: the child's max_wall_seconds is above the parent's"
    return None


_RULES: tuple[Callable[[SecurityPolicy, SecurityPolicy], str | None], ...] = (
    _allowlist_problem,
    _denylist_problem,
    _window_problem,
    _rate_problem,
    _rate_mode_problem,
    _identity_problem,
    _reauth_problem,
    _escalation_problem,
    _budget_problem,
)

#: The fields the rules above compare: what a delegation ceiling applies to a call.
_COMPARED = frozenset(
    {
        "allowed_tools",
        "default_deny",
        "denied_tools",
        "time_restrictions",
        "rate_limits",
        "rate_limit_mode",
        "rate_limit_scope",
        "require_agent_id",
        "allowed_roles",
        "reauth_on_untrusted_reinvocation",
        "untrusted_reinvocation_threshold",
        "escalate_tools",
        "approver",
        "escalation_channel",
        "approval_ledger",
        "standing_grants",
        "amplification_budget",
    }
)

#: Fields a ceiling does not apply (the tool's own policy does): a child keeps its parent's.
_CARRIED = (
    "capability_policy",
    "stdio_mode",
    "model_tier_budget",
    "sequence_guard",
    "action_contradiction_gate",
    "deserialization_guard",
    "tool_arg_sink_guard",
    "argument_secret_guard",
    "trace_redaction",
    "data_flow_policy",
    "run_guard",
    "shell_command_policy",
    "effect_guard",
)

#: Fields that cannot widen what a policy admits: a longer wait for the approver admits
#: nothing more.
_IGNORED = frozenset({"escalation_timeout_seconds"})


def _same(child_value: Any, parent_value: Any) -> bool:
    return child_value is parent_value or (
        isinstance(child_value, str) and child_value == parent_value
    )


def subset_problems(child: SecurityPolicy, parent: SecurityPolicy) -> list[str]:
    """What keeps ``child`` from being provably no wider than ``parent``, one sentence
    each; empty when it admits no call ``parent`` refuses.

    The tool lists, identity, time windows, rate limits, escalations, re-authorization and
    call budget are compared by rule. Every other field must be the parent's own object,
    which :meth:`SecurityPolicy.narrow` keeps. A public field this module does not know is
    a problem too, so a field added to ``SecurityPolicy`` later is refused until it is
    compared.
    """
    problems = [problem for rule in _RULES if (problem := rule(child, parent))]
    problems += [
        f"{name}: not the parent's (a delegated policy keeps it unchanged)"
        for name in _CARRIED
        if not _same(getattr(child, name), getattr(parent, name))
    ]
    known = _COMPARED | _IGNORED | set(_CARRIED)
    fields = {spec.name for spec in dc_fields(SecurityPolicy) if not spec.name.startswith("_")}
    problems += [f"{name}: a field delegation does not compare" for name in sorted(fields - known)]
    return problems


def narrow_policy(
    parent: SecurityPolicy,
    *,
    allowed_tools: Sequence[str] | None,
    denied_tools: Sequence[str],
    rate_limits: Mapping[str, str] | None,
    amplification_budget: AmplificationBudget | None,
) -> SecurityPolicy:
    """:meth:`SecurityPolicy.narrow`'s work; see it for the arguments."""
    for name, value in (("allowed_tools", allowed_tools), ("denied_tools", denied_tools)):
        if isinstance(value, str):
            raise TypeError(f"narrow({name}=...) takes a list of patterns, not a string")
    kwargs = parent._public_kwargs()
    if allowed_tools is not None:
        kwargs["allowed_tools"] = _intersect(parent, list(allowed_tools))
    # An allowlist that came out empty must refuse every tool, not admit them all.
    kwargs["default_deny"] = (
        parent.default_deny or bool(parent.allowed_tools) or allowed_tools is not None
    )
    kwargs["denied_tools"] = _unique([*parent.denied_tools, *denied_tools])
    if rate_limits:
        kwargs["rate_limits"] = {**parent.rate_limits, **dict(rate_limits)}
    if amplification_budget is not None:
        kwargs["amplification_budget"] = amplification_budget
    child = SecurityPolicy(**kwargs)
    with parent._lock:
        child._revoked_grants = set(parent._revoked_grants)
    problems = subset_problems(child, parent)
    if problems:
        raise ValueError("narrow() would admit more than the policy does: " + "; ".join(problems))
    return child


# -- the one-use lease -----------------------------------------------------------------


def _lease_covers(held: Lease, wanted: Lease) -> bool:
    """Whether ``held`` confers all of ``wanted``: the same capability, a target glob that
    covers it, no category it lacks, allowlisted egress only if it is."""
    return (
        held.capability == wanted.capability
        and glob_covers(held.target, wanted.target)
        and wanted.categories <= held.categories
        and (held.network_allowlisted or not wanted.network_allowlisted)
    )


def _uncovered(engine: CapabilityCapEngine, holder: str, leases: Sequence[Lease]) -> list[str]:
    held = engine.held_leases(holder)
    return [
        f"lease {lease.lease_id!r}: no lease the parent holds covers "
        f"{lease.capability} on {lease.target!r}"
        for lease in leases
        if not any(_lease_covers(have, lease) for have in held)
    ]


def _engine_problems(
    parent_agent: str | None,
    child_agent: str | None,
    engine: CapabilityCapEngine | None,
    leases: Sequence[Lease],
) -> list[str]:
    if engine is None:
        return ["leases need the engine that holds them: pass engine="] if leases else []
    if not parent_agent:
        return ["an engine meters a delegation by the parent's agent id, and this run has none"]
    if leases and (not child_agent or child_agent == parent_agent):
        return ["leases are held per agent: give the child its own agent_id"]
    return _uncovered(engine, parent_agent, leases)


def _same_chain(first: tuple[SecurityPolicy, ...], second: tuple[SecurityPolicy, ...]) -> bool:
    return len(first) == len(second) and all(a is b for a, b in zip(first, second, strict=True))


class DelegationLease:
    """A one-use lease on a delegated run, issued by :meth:`AirlockContext.delegate`.

    Entering it (``with lease as child:``, or ``async with``) starts the child's run: it
    spends the lease, checks the child is still within its parent, takes one level of the
    run budget (:func:`agent_airlock.nested_runs.nested_run`), meters the parent's
    ``delegate_to_agent`` capability and grants the child's capability leases when an
    engine was given, and makes the child's context current. Every call in that run must
    pass the policies of its delegation chain as well as its tool's own. A second entry is
    refused, and so is an entry from another run.

    Attributes:
        lease_id: The lease's random id, for logs; not a credential.
        agent_id: The child's agent id.
        policy: The child's policy, frozen when the lease was issued.
    """

    def __init__(
        self,
        *,
        parent: AirlockContext[Any],
        chain: tuple[SecurityPolicy, ...],
        policy: SecurityPolicy,
        agent_id: str | None,
        engine: CapabilityCapEngine | None,
        leases: tuple[Lease, ...],
        limits: tuple[int | None, int | None],
    ) -> None:
        self.lease_id = secrets.token_hex(16)
        self.agent_id = agent_id
        self.policy = policy
        self._parent = parent
        self._chain = chain
        self._engine = engine
        self._leases = leases
        self._limits = limits
        self._lock = threading.Lock()
        self._spent = False
        self._stack: contextlib.ExitStack | None = None

    def __repr__(self) -> str:
        return f"DelegationLease(agent_id={self.agent_id!r}, spent={self._spent})"

    @property
    def spent(self) -> bool:
        """Whether the lease was entered; a spent lease starts no run."""
        return self._spent

    def _spend(self) -> None:
        with self._lock:
            spent, self._spent = self._spent, True
        if spent:
            logger.warning("delegation_lease_reused", agent_id=self.agent_id)
            raise DelegationRefused(
                "this delegation lease was used already: issue a new one for another run"
            )

    def _admit(self) -> None:
        """Refuse an entry from another run, or one the parent no longer covers."""
        ambient, parent = get_current_context(), self._parent
        if ambient is not None and not (
            ambient._run_state is parent._run_state
            and _same_chain(ambient._ceiling, parent._ceiling)
        ):
            raise DelegationRefused("this delegation lease was issued in another run")
        problems = subset_problems(self.policy, self._chain[-1])
        problems += _engine_problems(
            self._parent.agent_id, self.agent_id, self._engine, self._leases
        )
        if (
            self._engine is not None
            and self._leases
            and self._engine.held_leases(str(self.agent_id))
        ):
            problems.append(f"agent {self.agent_id!r} already holds leases of its own")
        if problems:
            logger.warning("delegation_refused", agent_id=self.agent_id, problems=problems)
            raise DelegationRefused("delegation refused: " + "; ".join(problems), problems=problems)

    def _meter_and_grant(self, stack: contextlib.ExitStack) -> None:
        engine = self._engine
        if engine is None:
            return
        from .capability_caps import Capability

        decision = engine.check_and_use(
            str(self._parent.agent_id), Capability.DELEGATE_TO_AGENT, self.agent_id or "*"
        )
        if not decision.allowed:
            raise DelegationRefused(
                f"the parent's delegate_to_agent cap refused it: {decision.reason}"
            )
        for lease in self._leases:
            engine.grant_lease(str(self.agent_id), lease)
            stack.callback(engine.revoke_lease, str(self.agent_id), lease.lease_id)

    def _child_context(self) -> AirlockContext[Any]:
        """The child's context: the parent's identity fields and the child's agent id. The
        run's taint, halt latch and untrusted-output counts go on with it, so a halted run
        cannot carry on through a child; the parent's one-shot grants do not."""
        parent = self._parent
        child: AirlockContext[Any] = AirlockContext(
            agent_id=self.agent_id,
            session_id=parent.session_id,
            workspace_id=parent.workspace_id,
            user_id=parent.user_id,
            roles=list(parent.roles),
            metadata=dict(parent.metadata),
        )
        child.untrusted_reinvocation_count = parent.untrusted_reinvocation_count
        child._flow = parent._flow
        child._run_state = parent._run_state
        child._ceiling = (*self._chain, self.policy)
        return child

    def __enter__(self) -> AirlockContext[Any]:
        self._spend()
        stack = contextlib.ExitStack()
        try:
            self._admit()
            max_depth, max_turns = self._limits
            stack.enter_context(nested_run(max_depth=max_depth, max_turns=max_turns))
            self._meter_and_grant(stack)
            child = stack.enter_context(self._child_context())
        except BaseException:
            stack.close()
            raise
        self._stack = stack
        logger.info(
            "delegation_started",
            parent_agent_id=self._parent.agent_id,
            agent_id=self.agent_id,
            depth=len(self._chain),
        )
        return child

    def __exit__(self, *exc_info: Any) -> None:
        stack, self._stack = self._stack, None
        if stack is not None:
            stack.__exit__(*exc_info)

    async def __aenter__(self) -> AirlockContext[Any]:
        return self.__enter__()

    async def __aexit__(self, *exc_info: Any) -> None:
        self.__exit__(*exc_info)


def _parent_chain(
    parent: AirlockContext[Any], parent_policy: SecurityPolicy | None
) -> tuple[SecurityPolicy, ...]:
    """The delegation chain a child of ``parent`` extends: the run's own when it was
    delegated, else the one policy the host says the run is under."""
    chain: tuple[SecurityPolicy, ...] = parent._ceiling
    if chain:
        if parent_policy is not None and parent_policy is not chain[-1]:
            raise ValueError(
                "this run was itself delegated, so its own policy is the parent: leave "
                "parent_policy out"
            )
        return chain
    if parent_policy is None:
        raise DelegationRefused(
            "this run has no policy to narrow: pass parent_policy, the policy it runs under"
        )
    if not isinstance(parent_policy, SecurityPolicy):
        raise TypeError(
            f"parent_policy must be a SecurityPolicy, got {type(parent_policy).__name__}"
        )
    return (parent_policy,)


def issue_delegation(
    parent: AirlockContext[Any],
    child_policy: SecurityPolicy,
    *,
    agent_id: str | None,
    parent_policy: SecurityPolicy | None,
    engine: CapabilityCapEngine | None,
    leases: Sequence[Lease],
    max_depth: int | None,
    max_turns: int | None,
) -> DelegationLease:
    """:meth:`AirlockContext.delegate`'s work; see it for the arguments."""
    if not isinstance(child_policy, SecurityPolicy):
        raise TypeError(f"delegate() takes a SecurityPolicy, got {type(child_policy).__name__}")
    limits = (_limit("max_depth", max_depth), _limit("max_turns", max_turns))
    chain = _parent_chain(parent, parent_policy)
    child_agent = agent_id if agent_id is not None else parent.agent_id
    held = tuple(leases)
    problems = subset_problems(child_policy, chain[-1])
    problems += _engine_problems(parent.agent_id, child_agent, engine, held)
    if problems:
        logger.warning(
            "delegation_refused",
            parent_agent_id=parent.agent_id,
            agent_id=child_agent,
            problems=problems,
        )
        raise DelegationRefused("delegation refused: " + "; ".join(problems), problems=problems)
    lease = DelegationLease(
        parent=parent,
        chain=chain,
        policy=child_policy.freeze(),
        agent_id=child_agent,
        engine=engine,
        leases=held,
        limits=limits,
    )
    logger.info("delegation_lease_issued", parent_agent_id=parent.agent_id, agent_id=child_agent)
    return lease


def ceiling_chain(context: AirlockContext[Any]) -> tuple[SecurityPolicy, ...]:
    """The policies a call in ``context`` must pass besides its tool's own, outermost
    first: its run's delegation chain, and that of the context set around the call, so a
    call that names another agent than its run still meets the ceiling it was made under."""
    chain = list(context._ceiling)
    ambient = get_current_context()
    if ambient is not None and ambient is not context:
        chain += [policy for policy in ambient._ceiling if all(policy is not p for p in chain)]
    return tuple(chain)
