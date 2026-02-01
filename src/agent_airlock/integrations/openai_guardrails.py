"""OpenAI Agents SDK Guardrails bridge for Agent-Airlock.

Provides bridge to convert Airlock policies to OpenAI Agents SDK
guardrails format for seamless integration.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar

import structlog

from agent_airlock.config import AirlockConfig
from agent_airlock.core import Airlock
from agent_airlock.policy import SecurityPolicy
from agent_airlock.sanitizer import SensitiveDataType, detect_sensitive_data

if TYPE_CHECKING:
    pass

logger = structlog.get_logger("agent-airlock.integrations.openai_guardrails")

T = TypeVar("T")


@dataclass
class GuardrailResult:
    """Result from guardrail check."""

    passed: bool
    message: str | None = None
    violations: list[str] | None = None


class InputGuardrail:
    """Base class for input guardrails."""

    def check(self, input_data: dict[str, Any]) -> GuardrailResult:
        """Check input data against guardrail.

        Args:
            input_data: The input arguments.

        Returns:
            Guardrail result.
        """
        raise NotImplementedError


class OutputGuardrail:
    """Base class for output guardrails."""

    def check(self, output_data: Any) -> GuardrailResult:
        """Check output data against guardrail.

        Args:
            output_data: The tool output.

        Returns:
            Guardrail result.
        """
        raise NotImplementedError


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

    Converts an Airlock SecurityPolicy to an OpenAI guardrail.
    """

    def __init__(self, policy: SecurityPolicy, tool_name: str) -> None:
        """Initialize policy guardrail.

        Args:
            policy: Airlock security policy.
            tool_name: Name of the tool being guarded.
        """
        self.policy = policy
        self.tool_name = tool_name

    def check(self, input_data: dict[str, Any]) -> GuardrailResult:
        """Check if tool execution is allowed by policy."""
        violations = []

        # Check allowed tools
        if self.policy.allowed_tools:
            allowed = any(
                self._matches_pattern(self.tool_name, pattern)
                for pattern in self.policy.allowed_tools
            )
            if not allowed:
                violations.append(f"Tool '{self.tool_name}' not in allowed list")

        # Check denied tools
        if self.policy.denied_tools:
            denied = any(
                self._matches_pattern(self.tool_name, pattern)
                for pattern in self.policy.denied_tools
            )
            if denied:
                violations.append(f"Tool '{self.tool_name}' is denied")

        # Check rate limits (if implemented)
        if self.policy.rate_limits:
            # Rate limit checking would need state tracking
            pass

        # Check time restrictions
        if self.policy.time_restrictions:
            if not self._check_time_restrictions():
                violations.append(f"Tool '{self.tool_name}' not allowed at current time")

        if violations:
            return GuardrailResult(
                passed=False,
                message="Policy violations detected",
                violations=violations,
            )

        return GuardrailResult(passed=True)

    def _matches_pattern(self, tool_name: str, pattern: str) -> bool:
        """Check if tool name matches pattern."""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return tool_name.startswith(pattern[:-1])
        return tool_name == pattern

    def _check_time_restrictions(self) -> bool:
        """Check time-based restrictions."""

        # Check if current time is within allowed window
        for pattern, window_str in self.policy.time_restrictions.items():
            if self._matches_pattern(self.tool_name, pattern):
                if not self._is_within_time_window(window_str):
                    return False
        return True

    def _is_within_time_window(self, window_str: str) -> bool:
        """Check if current time is within window."""
        import datetime

        try:
            # Parse window like "09:00-17:00"
            start_str, end_str = window_str.split("-")
            start = datetime.datetime.strptime(start_str, "%H:%M").time()
            end = datetime.datetime.strptime(end_str, "%H:%M").time()
            now = datetime.datetime.now().time()

            if start <= end:
                return start <= now <= end
            else:
                # Overnight window
                return now >= start or now <= end
        except (ValueError, AttributeError):
            return True


class AirlockGuardrails:
    """Bridge between Airlock and OpenAI Agents SDK guardrails.

    Usage:
        from agents import Agent
        from agent_airlock.integrations.openai_guardrails import AirlockGuardrails

        guardrails = AirlockGuardrails(policy=STRICT_POLICY)

        @guardrails.secure_tool
        def my_tool(arg: str) -> str:
            return f"Result: {arg}"

        agent = Agent(
            name="my_agent",
            tools=[my_tool],
            input_guardrails=guardrails.get_input_guardrails(),
            output_guardrails=guardrails.get_output_guardrails(),
        )
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
            return secured

        if func is not None:
            return decorator(func)
        return decorator

    def get_input_guardrails(self) -> list[Callable[..., Any]]:
        """Get input guardrails for OpenAI Agent.

        Returns:
            List of guardrail functions.
        """
        guardrails = []

        if self.policy:
            for tool_name in self._tools:
                policy_guardrail = PolicyGuardrail(self.policy, tool_name)

                def create_checker(
                    guardrail: PolicyGuardrail,
                ) -> Callable[[Any, dict[str, Any]], GuardrailResult]:
                    def checker(ctx: Any, data: dict[str, Any]) -> GuardrailResult:
                        return guardrail.check(data)

                    return checker

                guardrails.append(create_checker(policy_guardrail))

        return guardrails

    def get_output_guardrails(self) -> list[Callable[..., Any]]:
        """Get output guardrails for OpenAI Agent.

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
        """Wrap an existing OpenAI Agent with guardrails.

        Args:
            agent: OpenAI Agent instance.

        Returns:
            Agent with guardrails configured.
        """
        import importlib.util

        if importlib.util.find_spec("agents") is None:
            raise ImportError("openai-agents is required: pip install openai-agents")

        # Add guardrails to agent
        input_guardrails = self.get_input_guardrails()
        output_guardrails = self.get_output_guardrails()

        if hasattr(agent, "input_guardrails"):
            agent.input_guardrails = (agent.input_guardrails or []) + input_guardrails
        if hasattr(agent, "output_guardrails"):
            agent.output_guardrails = (agent.output_guardrails or []) + output_guardrails

        return agent


def policy_to_guardrails(
    policy: SecurityPolicy,
    tool_names: list[str],
) -> dict[str, list[Any]]:
    """Convert an Airlock SecurityPolicy to OpenAI guardrails.

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
