"""OpenAI Agents SDK Guardrails bridge for Agent-Airlock.

Provides bridge to convert Airlock policies to OpenAI Agents SDK
guardrails format for seamless integration.

The SDK (``openai-agents``, module ``agents``) is imported only inside
:meth:`AirlockGuardrails.wrap_agent`, through ``importlib``, so this module
imports without it.
"""

from __future__ import annotations

import abc
import datetime
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from agent_airlock.config import AirlockConfig
from agent_airlock.core import Airlock
from agent_airlock.policy import PolicyViolation, SecurityPolicy, TimeWindow
from agent_airlock.sanitizer import SensitiveDataType, detect_sensitive_data

from .._log import structlog

logger = structlog.get_logger("agent-airlock.integrations.openai_guardrails")

T = TypeVar("T")


@dataclass
class GuardrailResult:
    """Result from guardrail check."""

    passed: bool
    message: str | None = None
    violations: list[str] | None = None


class InputGuardrail(abc.ABC):
    """Base class for input guardrails.

    Abstract: a subclass that does not override ``check`` fails at
    construction (``TypeError``), not on first call.
    """

    @abc.abstractmethod
    def check(self, input_data: dict[str, Any]) -> GuardrailResult:
        """Check input data against guardrail.

        Args:
            input_data: The input arguments.

        Returns:
            Guardrail result.
        """
        ...


class OutputGuardrail(abc.ABC):
    """Base class for output guardrails.

    Abstract: a subclass that does not override ``check`` fails at
    construction (``TypeError``), not on first call.
    """

    @abc.abstractmethod
    def check(self, output_data: Any) -> GuardrailResult:
        """Check output data against guardrail.

        Args:
            output_data: The tool output.

        Returns:
            Guardrail result.
        """
        ...


class PIIGuardrail(OutputGuardrail):
    """Guardrail that detects PII in outputs.

    Integrates with Airlock's PII detection to create an
    OpenAI-compatible guardrail.
    """

    def __init__(
        self,
        block_types: list[SensitiveDataType] | None = None,
        action: str = "block",  # "block" or "warn"
    ) -> None:
        """Initialize PII guardrail.

        Args:
            block_types: PII types to detect (all by default).
            action: Action on detection ("block" or "warn").
        """
        self.block_types = block_types
        self.action = action

    def check(self, output_data: Any) -> GuardrailResult:
        """Check output for PII."""
        content = str(output_data)
        detections = detect_sensitive_data(content, self.block_types)

        if detections:
            violation_types = [d["type"] for d in detections]
            return GuardrailResult(
                passed=self.action == "warn",
                message=f"PII detected: {', '.join(violation_types)}",
                violations=violation_types,
            )

        return GuardrailResult(passed=True)


class PolicyGuardrail(InputGuardrail):
    """Guardrail that enforces Airlock SecurityPolicy.

    Converts an Airlock SecurityPolicy to an OpenAI guardrail: ``check`` refuses when the
    tool is not allowed by the policy's allow / deny lists (``default_deny`` included,
    patterns matched like :class:`SecurityPolicy` does, with ``fnmatch``), is outside a
    time window, or is over a rate limit.

    Until 0.10.28 rate limits were never applied (the branch was a ``pass``), a time
    window that could not be parsed allowed the call, and patterns other than a trailing
    ``*`` were compared literally, so ``denied_tools=["*_file"]`` denied nothing.

    Identity, roles, escalation, capabilities and budgets are not checked here: the
    guardrail has no caller identity. They are enforced on the tool itself when it is
    wrapped with ``Airlock`` (``AirlockGuardrails.secure_tool``).
    """

    def __init__(
        self,
        policy: SecurityPolicy,
        tool_name: str,
        *,
        consume_rate_limit: bool = True,
    ) -> None:
        """Initialize policy guardrail.

        Args:
            policy: Airlock security policy.
            tool_name: Name of the tool being guarded.
            consume_rate_limit: Whether a passing ``check`` spends one token of the tool's
                rate limit, as a call would. ``True`` (default) when the guardrail is the
                only check on the tool. ``False`` when the tool is also wrapped with
                ``Airlock`` under the same policy, which spends a token on each call: the
                guardrail then only refuses while the tool's budget is spent, instead of
                charging it twice.
        """
        self.policy = policy
        self.tool_name = tool_name
        self.consume_rate_limit = consume_rate_limit

    def check(self, input_data: dict[str, Any]) -> GuardrailResult:
        """Check if tool execution is allowed by policy."""
        violations: list[str] = []

        try:
            self.policy.check_tool_allowed(self.tool_name)
        except PolicyViolation as exc:
            violations.append(exc.message)

        violations.extend(self._time_violations())
        if not violations:
            # Last, so a call refused for another reason never spends a token.
            violations.extend(self._rate_violations())

        if violations:
            return GuardrailResult(
                passed=False,
                message="Policy violations detected",
                violations=violations,
            )

        return GuardrailResult(passed=True)

    def _matches_pattern(self, tool_name: str, pattern: str) -> bool:
        """Check if tool name matches pattern, as :class:`SecurityPolicy` matches it."""
        return self.policy._matches_pattern(tool_name, pattern)

    def _time_violations(self, now: datetime.datetime | None = None) -> list[str]:
        """The time-window violation for this tool, if any.

        The most specific matching pattern decides, as in
        :meth:`SecurityPolicy.check_time_restriction`. The window is parsed from
        ``time_restrictions`` as configured, so one that cannot be parsed (set after the
        policy was built) is refused rather than read as "no restriction".
        """
        patterns = self.policy._find_matching_patterns(
            self.tool_name, self.policy.time_restrictions
        )
        if not patterns:
            return []
        pattern = patterns[0]
        window_str = self.policy.time_restrictions[pattern]
        try:
            window = TimeWindow.parse(window_str)
        except (TypeError, ValueError):
            return [
                f"Tool '{self.tool_name}' has an unreadable time window {window_str!r} "
                f"(pattern {pattern!r}); refused rather than allowed at any time"
            ]
        if not window.is_within(now):
            return [f"Tool '{self.tool_name}' not allowed at current time (allowed {window_str})"]
        return []

    def _rate_violations(self) -> list[str]:
        """The rate-limit violation for this tool, if any (see ``consume_rate_limit``).

        Uses the policy's own token bucket for the most specific matching pattern, as
        :meth:`SecurityPolicy.check_rate_limit` does, so the guardrail and an ``Airlock``
        on the tool count against the same budget.
        """
        patterns = self.policy._find_matching_patterns(self.tool_name, self.policy.rate_limits)
        if not patterns:
            return []
        pattern = patterns[0]
        limit_str = self.policy.rate_limits[pattern]
        limiter = self.policy._rate_limiters.get(pattern)
        if limiter is None:
            # Set after the policy was built: nothing enforces it, so nothing passes it.
            return [
                f"Tool '{self.tool_name}' has a rate limit {limit_str!r} (pattern {pattern!r}) "
                "that the policy never parsed; refused. Build a new SecurityPolicy with it."
            ]
        # Spend a token as a call would, or (consume_rate_limit=False) only look.
        exhausted = not limiter.acquire() if self.consume_rate_limit else limiter.remaining() < 1
        if exhausted:
            return [f"Rate limit exceeded for tool '{self.tool_name}'. Limit: {limit_str}"]
        return []


def _agents_sdk() -> Any:
    """The OpenAI Agents SDK module (``agents``), imported on first use.

    Raises:
        ImportError: openai-agents is not installed, or ``agents`` is some other package.
    """
    import importlib.util

    if importlib.util.find_spec("agents") is None:
        raise ImportError("openai-agents is required: pip install openai-agents")
    sdk = importlib.import_module("agents")
    missing = [
        name
        for name in ("InputGuardrail", "OutputGuardrail", "GuardrailFunctionOutput")
        if not hasattr(sdk, name)
    ]
    if missing:
        raise ImportError(
            f"the installed `agents` package has no {', '.join(missing)}; "
            "openai-agents is required: pip install openai-agents"
        )
    return sdk


def _sdk_guardrail_kwargs(guardrail_class: Any, **wanted: Any) -> dict[str, Any]:
    """``wanted``, keeping only the fields this SDK version's guardrail class takes."""
    fields = getattr(guardrail_class, "__dataclass_fields__", None)
    if fields is None:
        return wanted
    return {key: value for key, value in wanted.items() if key in fields}


class AirlockGuardrails:
    """Bridge between Airlock and OpenAI Agents SDK guardrails.

    Usage::

        from agents import Agent, function_tool
        from agent_airlock.integrations.openai_guardrails import AirlockGuardrails

        guardrails = AirlockGuardrails(policy=STRICT_POLICY)

        @guardrails.secure_tool
        def my_tool(arg: str) -> str:
            return f"Result: {arg}"

        agent = guardrails.wrap_agent(Agent(name="my_agent", tools=[function_tool(my_tool)]))

    ``wrap_agent`` appends the SDK's own ``InputGuardrail`` / ``OutputGuardrail`` objects.
    ``get_input_guardrails`` / ``get_output_guardrails`` return plain
    ``(ctx, data) -> GuardrailResult`` checkers, which the SDK cannot run on its own.
    """

    def __init__(
        self,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | None = None,
        sandbox: bool = False,
        detect_pii: bool = True,
        pii_action: str = "block",
    ) -> None:
        """Initialize guardrails bridge.

        Args:
            config: Airlock configuration.
            policy: Security policy to enforce.
            sandbox: Whether to use sandbox execution.
            detect_pii: Whether to detect PII in outputs.
            pii_action: Action on PII detection ("block" or "warn").
        """
        self.config = config or AirlockConfig()
        self.policy = policy
        self.sandbox = sandbox
        self.detect_pii = detect_pii
        self.pii_action = pii_action
        self._tools: dict[str, Callable[..., Any]] = {}

    def secure_tool(
        self,
        func: Callable[..., T] | None = None,
        *,
        name: str | None = None,
    ) -> Callable[..., T] | Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator to secure a tool function.

        Can be used with or without arguments:

            @guardrails.secure_tool
            def my_tool(x: int) -> int:
                return x * 2

            @guardrails.secure_tool(name="custom_name")
            def another_tool(x: int) -> int:
                return x + 1
        """

        def decorator(f: Callable[..., T]) -> Callable[..., T]:
            tool_name = name or f.__name__

            # Wrap with Airlock
            secured = Airlock(
                config=self.config,
                policy=self.policy,
                sandbox=self.sandbox,
            )(f)

            self._tools[tool_name] = secured
            # Airlock returns T | dict, but for integration we preserve T signature
            return secured  # type: ignore[return-value]

        if func is not None:
            return decorator(func)
        return decorator

    def _policy_guardrails(self) -> list[PolicyGuardrail]:
        """One policy guardrail per secured tool, charging no rate-limit token itself.

        Each tool is wrapped with ``Airlock`` under the same policy by
        :meth:`secure_tool`, which spends a token on every call; a guardrail that spent
        one too would charge each call twice.
        """
        if not self.policy:
            return []
        return [
            PolicyGuardrail(self.policy, tool_name, consume_rate_limit=False)
            for tool_name in self._tools
        ]

    def get_input_guardrails(self) -> list[Callable[..., Any]]:
        """Get the per-tool policy checks, as plain ``(ctx, data) -> GuardrailResult`` callables.

        Each checks one secured tool against the policy (allow and deny lists, time
        window, rate limit) and belongs before a call of that tool. :meth:`secure_tool`
        already applies the same policy on every call, so :meth:`wrap_agent` does not
        install these: as an SDK input guardrail, which runs once per run, a check for
        one tool would refuse runs that never call it.

        Returns:
            List of guardrail functions.
        """
        guardrails = []

        for policy_guardrail in self._policy_guardrails():

            def create_checker(
                guardrail: PolicyGuardrail,
            ) -> Callable[[Any, dict[str, Any]], GuardrailResult]:
                def checker(ctx: Any, data: dict[str, Any]) -> GuardrailResult:
                    return guardrail.check(data)

                return checker

            guardrails.append(create_checker(policy_guardrail))

        return guardrails

    def get_output_guardrails(self) -> list[Callable[..., Any]]:
        """Get the output checks, as plain ``(ctx, data) -> GuardrailResult`` callables.

        The Agents SDK runs ``OutputGuardrail`` objects, not these: give it
        :meth:`wrap_agent`, which builds them.

        Returns:
            List of guardrail functions.
        """
        guardrails = []

        if self.detect_pii:
            pii_guardrail = PIIGuardrail(action=self.pii_action)

            def pii_checker(ctx: Any, data: Any) -> GuardrailResult:
                return pii_guardrail.check(data)

            guardrails.append(pii_checker)

        return guardrails

    def wrap_agent(self, agent: Any) -> Any:
        """Add Airlock's PII check to an OpenAI Agents SDK ``Agent`` as an SDK guardrail.

        Appends an ``agents.OutputGuardrail`` for PII in the final output (when
        ``detect_pii``); a hit trips it, so ``Runner.run`` raises the SDK's tripwire
        exception. The policy is not a guardrail: :meth:`secure_tool` applies it to every
        call of each tool it wrapped, where the call's name, time and rate budget are
        known. An input guardrail runs once per run, before the model has chosen any
        tool, so in the 0.10.28 review one per tool refused every run while any one tool
        was outside its time window or had spent its rate budget. Until 0.10.28 plain
        functions were appended, which the SDK cannot run: every run failed with
        ``AttributeError`` (``get_name``), and an object without the guardrail lists got
        nothing at all.

        Args:
            agent: OpenAI Agent instance.

        Returns:
            Agent with guardrails configured.

        Raises:
            ImportError: openai-agents is not installed.
            TypeError: ``agent`` has no ``output_guardrails`` list to add to, so the
                check could not be attached.
        """
        sdk = _agents_sdk()
        output_cls = sdk.GuardrailFunctionOutput

        output_guardrails = []
        if self.detect_pii:
            output_guardrails.append(
                sdk.OutputGuardrail(
                    **_sdk_guardrail_kwargs(
                        sdk.OutputGuardrail,
                        guardrail_function=_output_guardrail_function(
                            PIIGuardrail(action=self.pii_action), output_cls
                        ),
                        name="airlock_pii",
                    )
                )
            )

        for attr, additions in (("output_guardrails", output_guardrails),):
            if not additions:
                continue
            if not hasattr(agent, attr):
                raise TypeError(
                    f"{type(agent).__name__} has no `{attr}`; not an openai-agents Agent, "
                    "so Airlock's guardrails could not be attached"
                )
            setattr(agent, attr, list(getattr(agent, attr) or []) + additions)

        logger.info(
            "openai_agent_guardrails_attached",
            output_guardrails=len(output_guardrails),
            secured_tools=len(self._tools),
        )
        return agent


def _output_guardrail_function(
    guardrail: OutputGuardrail, output_cls: Any
) -> Callable[[Any, Any, Any], Any]:
    """An SDK output-guardrail function ``(context, agent, output)`` running ``guardrail``."""

    def airlock_pii_guardrail(context: Any, agent: Any, agent_output: Any) -> Any:
        result = guardrail.check(agent_output)
        return output_cls(output_info=result, tripwire_triggered=not result.passed)

    return airlock_pii_guardrail


def policy_to_guardrails(
    policy: SecurityPolicy,
    tool_names: list[str],
) -> dict[str, list[Any]]:
    """Convert an Airlock SecurityPolicy to guardrail checks.

    The checks are plain ``(ctx, data) -> GuardrailResult`` callables; the Agents SDK
    runs ``InputGuardrail`` / ``OutputGuardrail`` objects, which
    :meth:`AirlockGuardrails.wrap_agent` builds. Each policy check spends one rate-limit
    token when it passes (``PolicyGuardrail(consume_rate_limit=True)``).

    Args:
        policy: Airlock security policy.
        tool_names: List of tool names to create guardrails for.

    Returns:
        Dict with "input" and "output" guardrail lists.
    """
    input_guardrails = []
    output_guardrails = []

    # Create policy guardrails for each tool
    for tool_name in tool_names:
        policy_guardrail = PolicyGuardrail(policy, tool_name)

        def create_input_check(
            guardrail: PolicyGuardrail,
        ) -> Callable[[Any, dict[str, Any]], GuardrailResult]:
            def check(ctx: Any, data: dict[str, Any]) -> GuardrailResult:
                return guardrail.check(data)

            return check

        input_guardrails.append(create_input_check(policy_guardrail))

    # Add PII guardrail for outputs
    pii_guardrail = PIIGuardrail()

    def pii_check(ctx: Any, data: Any) -> GuardrailResult:
        return pii_guardrail.check(data)

    output_guardrails.append(pii_check)

    return {
        "input": input_guardrails,
        "output": output_guardrails,
    }
