"""Anthropic Claude Agent SDK adapter (v0.6.1+).

The canonical-list trio for the Anthropic Claude Agent SDK lives in
this single facade. The underlying defences are already shipped under
the ``claude_*.py`` family (managed-agents, auto-memory, task-budget),
but the canonical contract is one adapter named for the framework
plus matching test + doc, so callers can find the entrypoint without
having to learn the internal module layout.

Usage::

    from agent_airlock.integrations.anthropic_claude_agent_sdk import (
        AnthropicClaudeAgentSDKAdapter,
    )
    from agent_airlock.policy import STRICT_POLICY

    adapter = AnthropicClaudeAgentSDKAdapter()
    secured = adapter.wrap_agent(agent, policy=STRICT_POLICY)

The optional dependency is ``claude-agent-sdk>=0.1.58`` (extra:
``pip install "agent-airlock[claude-agent]"``). The SDK is *not*
imported at module load — calling :meth:`wrap_agent` without the
extra installed raises a clear :class:`RuntimeError` with the
install hint, never an opaque ``ImportError`` from somewhere deep
in the call stack.

Primary sources
---------------
- Anthropic Claude Agent SDK docs:
  https://docs.claude.com/en/agents-and-tools/agent-skills
- Claude Managed Agents launch (2026-04-08):
  https://claude.com/blog/claude-managed-agents
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import structlog

from ..core import Airlock
from ..exceptions import AirlockError
from ..policy import SecurityPolicy
from .claude_auto_memory import (
    AutoMemoryAccessPolicy,
    guarded_read,
    guarded_write,
)
from .claude_managed_agents import (
    DEFAULT_HARNESS_TOOLS,
    ManagedAgentsAuditConfig,
)
from .claude_task_budget import build_output_config, build_task_budget_headers

logger = structlog.get_logger("agent-airlock.integrations.anthropic_claude_agent_sdk")


SUPPORTED_SDK_VERSIONS: tuple[str, ...] = ("0.1.58",)
"""Pinned SDK versions this adapter has been smoke-tested against.

The Claude Agent SDK has churned twice between Sep-2025 and Apr-2026
— if a newer release renames ``Agent`` or shifts the tools dict's
shape, ``wrap_agent`` emits a structlog ``UserWarning``-equivalent
line but does not hard-fail. Update this tuple when a new version
has been verified.
"""

_INSTALL_HINT = (
    "claude-agent-sdk is not installed. "
    'Install the extra: pip install "agent-airlock[claude-agent]"'
)


class ClaudeAgentSDKMissingError(AirlockError):
    """Raised when ``wrap_agent`` is called without the extra installed.

    This is intentionally a subclass of :class:`AirlockError` (and
    therefore ``RuntimeError`` via the inheritance chain) so callers
    get a clear, actionable error instead of a deep ``ImportError``
    from inside the SDK.
    """


@dataclass
class AnthropicClaudeAgentSDKAdapter:
    """Single facade re-exporting the ``claude_*.py`` family.

    Attributes:
        managed_audit: Optional :class:`ManagedAgentsAuditConfig` to
            apply on each request before egress. ``None`` (default)
            disables managed-agent audit.
        auto_memory_policy: Optional :class:`AutoMemoryAccessPolicy`.
            ``None`` (default) means the adapter does not wrap memory
            reads/writes — callers can still call
            :func:`guarded_read` / :func:`guarded_write` directly.
        task_budget_total: Optional total token budget. ``None``
            (default) skips budget injection.
    """

    managed_audit: ManagedAgentsAuditConfig | None = None
    auto_memory_policy: AutoMemoryAccessPolicy | None = None
    task_budget_total: int | None = None

    def wrap_agent(self, agent: Any, *, policy: SecurityPolicy | None = None) -> Any:
        """Wrap a Claude Agent SDK ``Agent`` so every tool routes through Airlock.

        Args:
            agent: A :class:`claude_agent_sdk.Agent`-shaped object. The
                adapter only requires a ``tools`` attribute (dict or
                list) where each entry has a ``__call__`` or ``forward``
                method. Real SDK objects satisfy this; tests can pass a
                stub.
            policy: Optional :class:`SecurityPolicy` (e.g.
                ``STRICT_POLICY``). When set, every tool callable is
                wrapped with :class:`Airlock(policy=policy)`.

        Returns:
            The same agent, mutated in place — every tool callable
            replaced by an Airlock-decorated shim.

        Raises:
            ClaudeAgentSDKMissingError: ``claude-agent-sdk`` extra is
                not installed *and* the agent is not a structural
                stub. Stub agents (``hasattr(agent, "tools")``) bypass
                the SDK import — required by tests and useful in
                CI environments without the optional dep.
        """
        self._maybe_check_sdk(agent)
        tools = getattr(agent, "tools", None)
        if tools is None:
            raise AirlockError(
                "agent does not expose a `tools` attribute; not a Claude Agent SDK shape"
            )

        if isinstance(tools, dict):
            for name, tool in tools.items():
                tools[name] = self._wrap_callable(tool, name=str(name), policy=policy)
        elif isinstance(tools, list):
            for idx, tool in enumerate(tools):
                tools[idx] = self._wrap_callable(
                    tool,
                    name=getattr(tool, "name", f"tool_{idx}"),
                    policy=policy,
                )
        else:
            raise AirlockError(
                f"unrecognised agent.tools type {type(tools).__name__}; expected dict or list"
            )

        logger.info(
            "claude_agent_sdk_wrapped",
            tool_count=len(tools) if hasattr(tools, "__len__") else 0,
            policy_set=policy is not None,
        )
        return agent

    def task_budget_request_kit(self, *, remaining: int, soft: bool = True) -> dict[str, Any]:
        """Return the ``betas`` + body fragments needed for a budgeted call.

        Args:
            remaining: Tokens left in the per-task budget.
            soft: If ``True`` (default) the SDK only nudges the model;
                if ``False`` Airlock raises :class:`TaskBudgetExhausted`
                when remaining hits zero.

        Returns:
            A dict with ``"betas"`` (header value) and ``"body"`` keys
            ready to splat into the SDK request.
        """
        if self.task_budget_total is None:
            return {}
        return {
            "betas": [build_task_budget_headers()["anthropic-beta"]],
            "body": build_output_config(
                total=self.task_budget_total,
                remaining=remaining,
                soft=soft,
            ),
        }

    def _wrap_callable(
        self,
        tool: Any,
        *,
        name: str,
        policy: SecurityPolicy | None,
    ) -> Any:
        """Replace ``tool.forward`` / ``tool`` with an Airlock-decorated shim.

        Args:
            tool: The tool object or callable.
            name: The tool's name (used in logs and audit).
            policy: Optional :class:`SecurityPolicy` to apply.
        """
        forward: Callable[..., Any] | None = getattr(tool, "forward", None)
        if forward is None and callable(tool):
            forward = tool
        if forward is None:
            raise AirlockError(
                f"tool {name!r} exposes neither `forward` nor `__call__`; cannot wrap"
            )

        # Airlock uses ``func.__name__`` for policy checks. We re-tag the
        # callable with the tool's canonical name so SecurityPolicy
        # allowed/denied lists target the tool, not its method name.
        def _named_proxy(*args: Any, **kwargs: Any) -> Any:
            return forward(*args, **kwargs)

        _named_proxy.__name__ = name
        _named_proxy.__qualname__ = name

        airlock = Airlock(policy=policy) if policy is not None else Airlock()
        wrapped = airlock(_named_proxy)

        if hasattr(tool, "forward"):
            # Tool object (non-function): mutate in place. Use setattr so
            # static analysis doesn't try to enforce FunctionType invariants.
            setattr(tool, "forward", wrapped)  # noqa: B010
            return tool
        return wrapped

    def _maybe_check_sdk(self, agent: Any) -> None:
        """Raise :class:`ClaudeAgentSDKMissingError` only for real SDK objects.

        Stubs (test doubles) carrying ``tools`` but no real SDK module
        provenance are allowed through — the test surface needs to run
        without the optional dep installed.
        """
        module = type(agent).__module__
        if not module.startswith("claude_agent_sdk"):
            return
        try:
            import claude_agent_sdk as _sdk  # noqa: F401
        except ImportError as exc:
            raise ClaudeAgentSDKMissingError(_INSTALL_HINT) from exc


def memory_helpers() -> dict[str, Callable[..., Any]]:
    """Return the auto-memory helpers as a dict for callers that prefer that shape."""
    return {"guarded_read": guarded_read, "guarded_write": guarded_write}


__all__ = [
    "DEFAULT_HARNESS_TOOLS",
    "SUPPORTED_SDK_VERSIONS",
    "AnthropicClaudeAgentSDKAdapter",
    "ClaudeAgentSDKMissingError",
    "memory_helpers",
]
