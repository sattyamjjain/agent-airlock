"""OpenAI Agents SDK: approvals from the run's own interruptions, nested budgets, hard and
soft refusals as the SDK's tool-guardrail behaviors (V0.10.29).

Read against openai-agents v0.24.0 (2026-10-15); the SDK is imported only when used.

* :class:`InterruptionApprovals` approves or rejects a paused run's tool calls only from the
  interruptions of the state being resumed (openai/openai-agents-python#5413). An item from
  another run or state is refused, and each call id is approved once. The approval is
  recorded in the policy's ``approval_ledger`` for the arguments the SDK will call the tool
  with, so the resumed call is admitted at step 2 and still spends its rate-limit token.
* :func:`airlock_agent_tool` is the SDK's ``Agent.as_tool`` with each call run as a nested
  run of the run tree's budget (:mod:`agent_airlock.nested_runs`,
  openai/openai-agents-python#5453): it takes a level of depth, and each of its model calls
  takes a turn of what the tree has left, so neither a nested run nor its concurrent
  siblings take more than the root allowed. :func:`airlock_turn_hooks` counts the root
  run's own model calls the same way. A budget that runs out is the calling agent's failed
  tool result; a root's ``hard_stop`` raises out of the run.
* :func:`airlock_tool_input_guardrail` maps Airlock's verdicts to the SDK's tool-guardrail
  behaviors: a halted run (a hard stop, openai/openai-agents-python#5351) is
  ``raise_exception``, which ends the run, and a call the policy refuses is
  ``reject_content``, which tells the model and lets the run go on.
"""

from __future__ import annotations

import importlib
import json
import threading
import time
import typing
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from .._arg_walk import bind_arguments, signature_of
from .._log import structlog
from ..approvals import args_digest
from ..context import AirlockContext, get_current_context
from ..nested_runs import RunBudgetExhausted, current_run_budget, nested_run, spend_turn
from ..policy import PolicyViolation, SecurityPolicy
from ..self_heal import handle_policy_violation, handle_run_budget_exhausted, refusal_text

logger = structlog.get_logger("agent-airlock.integrations.openai_agents")

__all__ = [
    "InterruptionApprovals",
    "airlock_agent_tool",
    "airlock_tool_input_guardrail",
    "airlock_turn_hooks",
]


def _sdk() -> Any:
    """The ``agents`` module (openai-agents), imported on first use.

    Raises:
        ImportError: openai-agents is not installed.
    """
    try:
        return importlib.import_module("agents")
    except ImportError as exc:
        raise ImportError("openai-agents is required: pip install openai-agents") from exc


# --------------------------------------------------------------------------- #
# Approvals from the state being resumed
# --------------------------------------------------------------------------- #


def _call_id(item: Any) -> str | None:
    """The call an approval item names: ``ToolApprovalItem.call_id``, else its raw item's."""
    found = getattr(item, "call_id", None)
    if found is None:
        raw = getattr(item, "raw_item", None)
        found = (
            raw.get("call_id") or raw.get("id")
            if isinstance(raw, dict)
            else getattr(raw, "call_id", None) or getattr(raw, "id", None)
        )
    return found if isinstance(found, str) and found else None


def _identity(item: Any) -> tuple[str | None, str | None, str | None]:
    """What makes an approval item the call it names: call id, tool name, arguments."""
    name = getattr(item, "name", None) or getattr(item, "tool_name", None)
    arguments = getattr(item, "arguments", None)
    return (
        _call_id(item),
        name if isinstance(name, str) else None,
        arguments if isinstance(arguments, str) else None,
    )


def _takes_context(func: Any) -> bool:
    """Whether the SDK hands ``func`` its run context first: ``function_schema``'s rule, a
    first parameter annotated ``RunContextWrapper`` or ``ToolContext``."""
    signature = signature_of(func)
    first = next(iter(signature.parameters.values()), None) if signature is not None else None
    if first is None:
        return False
    try:
        annotation = typing.get_type_hints(func).get(first.name, first.annotation)
    except Exception:  # noqa: BLE001 - an annotation that does not resolve is no context
        return False
    origin = typing.get_origin(annotation) or annotation
    kinds = (_sdk().RunContextWrapper, importlib.import_module("agents.tool_context").ToolContext)
    return any(origin is kind for kind in kinds)


def _approval_digest(item: Any, name: str, arguments: str, parsed: dict[str, Any]) -> str:
    """The digest step 2 works out for the approved call.

    That is its arguments as the SDK will call the tool with them (``prepare_arguments``:
    defaults filled in, models built), bound to the guarded function's signature. Where the
    item's agent has no one function tool of that name, or the SDK cannot prepare them
    without running the tool's own validators, it is the JSON object's digest: a call whose
    arguments the SDK then changes does not match it, and is refused at step 2.
    """
    tools: list[Any] = [
        tool
        for tool in getattr(getattr(item, "agent", None), "tools", None) or ()
        if getattr(tool, "name", None) == name and hasattr(tool, "on_invoke_tool")
    ]
    prepare: Any = getattr(tools[0].on_invoke_tool, "prepare_arguments", None) if tools else None
    func: Any = None
    if len(tools) == 1 and callable(prepare):
        try:
            func = tools[0].__wrapped__
        except AttributeError:  # a tool whose invoker was replaced has no __wrapped__
            func = None
    prepared: Any = prepare(arguments, name) if func is not None else None
    if prepared is None or (parsed and not (prepared.args or prepared.kwargs)):
        return args_digest(parsed)
    leading = (None,) if _takes_context(func) else ()
    bound = bind_arguments(
        signature_of(func), (*leading, *prepared.args), prepared.kwargs, skip_first=bool(leading)
    )
    return args_digest(bound)


def _arguments_object(call_id: str, arguments: str) -> dict[str, Any]:
    """``arguments`` read as the JSON object a function tool is called with.

    Raises:
        ValueError: They are not JSON, or not an object.
    """
    try:
        parsed = json.loads(arguments)
    except ValueError as exc:
        raise ValueError(f"the arguments of call {call_id!r} are not JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"the arguments of call {call_id!r} are not a JSON object")
    return parsed


class InterruptionApprovals:
    """Approve a paused run's tool calls only from the state being resumed, once each.

    The approval admits one call of the tool with exactly the approved arguments within
    ``ttl_seconds``: the resumed run's call, when the ledger is that run's alone.

    Args:
        policy: The policy the tools are guarded with. Its ``approval_ledger`` receives
            each approval, which the resumed call claims at step 2.
        ttl_seconds: How long a recorded approval stays claimable; the resumed run claims it
            as the call runs, so a short life is enough.
        limit: How many approved call ids are remembered against a second approval.

    Raises:
        ValueError: ``policy`` has no ``approval_ledger``.
    """

    def __init__(
        self, policy: SecurityPolicy, *, ttl_seconds: float = 60.0, limit: int = 10_000
    ) -> None:
        if policy.approval_ledger is None:
            raise ValueError(
                "InterruptionApprovals needs a SecurityPolicy with an approval_ledger: the "
                "resumed call is admitted by claiming the approval recorded there"
            )
        self._policy = policy
        self._ttl = ttl_seconds
        self._approved: OrderedDict[str, None] = OrderedDict()
        self._limit = limit
        self._lock = threading.Lock()

    @staticmethod
    def _pending(state: Any, item: Any) -> tuple[Any, str, str, str]:
        """``state``'s own interruption that ``item`` names, with its call id, tool and
        arguments.

        Raises:
            ValueError: ``item`` names no call id, tool or arguments, or not exactly one of
                ``state``'s pending calls.
        """
        identity = _identity(item)
        call_id, name, arguments = identity
        matches: list[Any] = []
        if call_id is not None and name is not None and arguments:
            matches = [c for c in state.get_interruptions() if _identity(c) == identity]
            if len(matches) == 1:
                return matches[0], call_id, name, arguments
        logger.warning("openai_agents_approval_refused", tool=name, call_id=call_id)
        if len(matches) > 1:
            raise ValueError(f"more than one pending call of this state is call {call_id!r}")
        raise ValueError(
            "not an interruption of the state being resumed: approve the items from "
            "this state's get_interruptions() (or the run's interruptions)"
        )

    def _first(self, call_id: str) -> bool:
        with self._lock:
            if call_id in self._approved:
                return False
            self._approved[call_id] = None
            if len(self._approved) > self._limit:
                self._approved.popitem(last=False)
            return True

    def _forget(self, call_id: str) -> None:
        with self._lock:
            self._approved.pop(call_id, None)

    def approve(self, state: Any, item: Any) -> None:
        """Approve ``item`` on ``state`` and record it for Airlock.

        Raises:
            ValueError: ``item`` is not one of ``state``'s interruptions, was approved
                already, or its arguments are not a JSON object.
        """
        pending, call_id, name, arguments = self._pending(state, item)
        digest = _approval_digest(pending, name, arguments, _arguments_object(call_id, arguments))
        if not self._first(call_id):
            logger.warning("openai_agents_approval_replayed", tool=name, call_id=call_id)
            raise ValueError(f"call {call_id!r} was approved already")
        try:
            state.approve(pending)
        except Exception:
            self._forget(call_id)
            raise
        ledger = self._policy.approval_ledger
        if ledger is not None:
            ledger.grant(name, digest, expires_at=time.time() + self._ttl)
        logger.info("openai_agents_approval_recorded", tool=name, call_id=call_id)

    def reject(self, state: Any, item: Any, *, message: str | None = None) -> None:
        """Reject ``item`` on ``state``; the model reads ``message`` when the run resumes.

        Raises:
            ValueError: ``item`` is not one of ``state``'s interruptions.
        """
        pending = self._pending(state, item)[0]
        state.reject(pending, rejection_message=message)


# --------------------------------------------------------------------------- #
# Nested runs inside the run tree's budget
# --------------------------------------------------------------------------- #


def _counting_hooks(sdk: Any, inner: Any = None) -> Any:
    """``RunHooks`` that take a turn of the current run budget before each model call, then
    pass every hook on to ``inner`` (the caller's own hooks), if given."""

    class AirlockTurnHooks(sdk.RunHooks):  # type: ignore[misc]
        async def on_llm_start(self, *args: Any) -> None:
            spend_turn()
            if inner is not None:
                await inner.on_llm_start(*args)

        def __getattribute__(self, name: str) -> Any:
            if inner is not None and name.startswith("on_") and name != "on_llm_start":
                return getattr(inner, name)
            return super().__getattribute__(name)

    return AirlockTurnHooks()


def airlock_turn_hooks(hooks: Any = None) -> Any:
    """``RunHooks`` for the root ``Runner.run(..., hooks=...)``, counting its own turns.

    Each of the run's model calls takes a turn of the run budget current when it is made
    (:func:`agent_airlock.nested_runs.run_budget`), so the root run's turns count against
    the tree's ``max_turns`` beside its nested runs'. A model call the budget has no turn
    left for raises :class:`RunBudgetExhausted` out of the run, ``hard_stop`` or not: a root
    run has no calling agent to hand a failed tool result to. With no budget set, nothing
    is counted.

    Args:
        hooks: Your own ``RunHooks``, each called after the count.

    Raises:
        ImportError: openai-agents is not installed.
    """
    return _counting_hooks(_sdk(), hooks)


def _budget_refusal(name: str, kind: str) -> str:
    return refusal_text(handle_run_budget_exhausted(name, kind=kind).to_dict())


def _exhaustion(sdk: Any, error: BaseException) -> RunBudgetExhausted | None:
    """``error`` as the run budget running out, or None when it is anything else.

    The SDK's ``MaxTurnsExceeded`` counts when the nested run's turns are spent: a run with
    a ``max_turns`` share meets the SDK's cap, set to the share, before the share runs dry.
    """
    if isinstance(error, RunBudgetExhausted):
        return error
    budget = current_run_budget()
    if isinstance(error, sdk.MaxTurnsExceeded) and budget is not None and budget.turns_left == 0:
        return RunBudgetExhausted(
            "the nested run took every turn of its budget",
            kind="turns",
            hard_stop=budget.hard_stop,
        )
    return None


def _failure(sdk: Any, inner: Any) -> Callable[[Any, Exception], Any]:
    """An agent tool's ``failure_error_function``: the budget's own refusals, then ``inner``."""

    def failure(ctx: Any, error: Exception) -> Any:
        exhausted = _exhaustion(sdk, error)
        if exhausted is None:
            if inner is None:
                raise error
            return inner(ctx, error)
        if exhausted.hard_stop:
            if exhausted is error:
                raise error
            raise exhausted from error
        name = str(getattr(ctx, "tool_name", None) or "agent_tool")
        logger.info("openai_agents_nested_run_refused", tool=name, budget=exhausted.kind)
        return _budget_refusal(name, exhausted.kind)

    return failure


class _NestedRunInvoker:
    """An agent tool's ``on_invoke_tool``, each call run as one nested run of the budget."""

    def __init__(self, inner: Any, name: str, limits: tuple[int | None, int | None]) -> None:
        self._inner = inner
        self._name = name
        self._limits = limits

    async def __call__(self, ctx: Any, input: str) -> Any:
        max_depth, max_turns = self._limits
        try:
            with nested_run(max_depth=max_depth, max_turns=max_turns):
                return await self._inner(ctx, input)
        except RunBudgetExhausted as exhausted:
            if exhausted.hard_stop:
                raise
            # The budget had no room as the run started: within it, the tool's failure
            # function answers for the budget.
            logger.info("openai_agents_nested_run_refused", tool=self._name, budget=exhausted.kind)
            return _budget_refusal(self._name, exhausted.kind)

    def __agents_bind_function_tool__(self, tool: Any) -> _NestedRunInvoker:
        """Rebind for a copied tool, as the SDK's own invoker is rebound."""
        bind = getattr(self._inner, "__agents_bind_function_tool__", None)
        inner = bind(tool) if callable(bind) else self._inner
        return _NestedRunInvoker(inner, self._name, self._limits)

    def __getattr__(self, name: str) -> Any:
        # ``prepare_arguments`` and the SDK's markers are the wrapped invoker's. ``_inner``
        # itself is missing only while a copy is being built.
        if name == "_inner":
            raise AttributeError(name)
        return getattr(self._inner, name)


def _checked(name: str, value: int | None) -> int | None:
    if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
        raise ValueError(f"{name} must be a whole number of 0 or more, or None; got {value!r}")
    return value


def airlock_agent_tool(
    agent: Any,
    *,
    max_depth: int | None = None,
    max_turns: int | None = None,
    **options: Any,
) -> Any:
    """``agent.as_tool(**options)`` whose nested runs count against the run tree's budget.

    Each call of the tool is one :func:`agent_airlock.nested_runs.nested_run`: it takes a
    level of depth, and each of its model calls takes a turn of what the tree has left,
    through run hooks set here (yours, ``options["hooks"]``, are still called). The SDK
    gives each nested run its own ``max_turns``, 10 unless set, whatever the parent has
    left. Here a nested run the budget has no depth or turn for, or that spends the turns
    it has, is the calling agent's failed tool result, and a root's ``hard_stop`` raises
    out of the run. The rest (nested approvals, streaming, structured input) is the SDK's.

    Args:
        agent: The ``agents.Agent`` to run as a tool.
        max_depth: How many levels may nest below this run.
        max_turns: The tool's share of the tree's turns for each call, reserved as the
            nested run starts and given back unspent; also the SDK's own cap for the run.
        **options: ``Agent.as_tool``'s arguments. ``failure_error_function`` answers the
            tool's other errors (the SDK's ``default_tool_error_function`` unless given,
            and ``None`` raises them); ``RunConfig.tool_error_formatter`` does not apply.

    Raises:
        ImportError: openai-agents is not installed.
        ValueError: ``max_depth`` or ``max_turns`` is not a whole number of 0 or more.
    """
    sdk = _sdk()
    limits = (_checked("max_depth", max_depth), _checked("max_turns", max_turns))
    if max_turns is not None:
        options["max_turns"] = max_turns
    options["hooks"] = _counting_hooks(sdk, options.get("hooks"))
    options["failure_error_function"] = _failure(
        sdk, options.get("failure_error_function", sdk.default_tool_error_function)
    )
    tool = agent.as_tool(
        options.pop("tool_name", None), options.pop("tool_description", None), **options
    )
    tool.on_invoke_tool = _NestedRunInvoker(tool.on_invoke_tool, str(tool.name), limits)
    return tool


# --------------------------------------------------------------------------- #
# Hard and soft refusals as tool-guardrail behaviors
# --------------------------------------------------------------------------- #


def _guardrail_check(policy: SecurityPolicy | None, data: Any) -> tuple[str, dict[str, Any], str]:
    """``(behavior, output_info, message)`` for one tool call, before it runs."""
    wrapper = getattr(data, "context", None)
    carried = getattr(wrapper, "context", None)
    run = carried if isinstance(carried, AirlockContext) else get_current_context()
    tool = str(getattr(wrapper, "tool_name", "") or "")
    if run is not None and run.halted:
        return "raise_exception", {"airlock": "run_halted", "reason": run.halt_reason}, ""
    if policy is not None:
        try:
            policy.check_tool_allowed(tool)
            policy.check_time_restriction(tool)
        except PolicyViolation as violation:
            refusal = handle_policy_violation(
                tool,
                policy_name="SecurityPolicy",
                reason=violation.message,
                violation_type=violation.violation_type,
            )
            info = {"airlock": "policy_violation", "violation_type": violation.violation_type}
            return "reject_content", info, refusal_text(refusal.to_dict())
    return "allow", {"airlock": "allowed"}, ""


def airlock_tool_input_guardrail(
    policy: SecurityPolicy | None = None, *, name: str = "airlock"
) -> Any:
    """A ``ToolInputGuardrail`` for ``function_tool(tool_input_guardrails=[...])``.

    A call in a run Airlock halted (a ``RunGuard`` hard stop, or ``context.halt()``) gets
    ``raise_exception``: the SDK raises ``ToolInputGuardrailTripwireTriggered`` and the run
    ends. A call the policy refuses by name or time window gets ``reject_content`` with the
    refusal's text, so the model reads it and the run goes on. Anything else is ``allow``,
    and the tool's own ``Airlock`` makes the rest of its checks as it runs. Nothing here
    spends a rate-limit token. The run is the ``AirlockContext`` passed as the run's
    ``context``, or the one set around it.

    Raises:
        ImportError: openai-agents is not installed.
    """
    sdk = _sdk()
    output = sdk.ToolGuardrailFunctionOutput

    def check(data: Any) -> Any:
        behavior, info, message = _guardrail_check(policy, data)
        if behavior == "raise_exception":
            logger.warning("openai_agents_tool_call_stopped", **info)
            return output.raise_exception(output_info=info)
        if behavior == "reject_content":
            return output.reject_content(message, output_info=info)
        return output.allow(output_info=info)

    check.__name__ = name
    factory: Callable[..., Any] = sdk.ToolInputGuardrail
    return factory(guardrail_function=check, name=name)
