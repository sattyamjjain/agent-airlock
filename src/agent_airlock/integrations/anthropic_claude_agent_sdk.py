"""Anthropic Claude Agent SDK adapter (v0.6.1+).

The canonical-list trio for the Anthropic Claude Agent SDK lives in
this single facade. The underlying defences are already shipped under
the ``claude_*.py`` family (managed-agents, auto-memory, task-budget),
but the canonical contract is one adapter named for the framework
plus matching test + doc, so callers can find the entrypoint without
having to learn the internal module layout.

Usage — guard the tools you serve from an in-process SDK MCP server::

    from claude_agent_sdk import create_sdk_mcp_server, tool

    from agent_airlock.integrations.anthropic_claude_agent_sdk import wrap_tools
    from agent_airlock.policy import SecurityPolicy

    @tool("greet", "Greet a user", {"name": str})
    async def greet(args):
        return {"content": [{"type": "text", "text": f"Hello, {args['name']}!"}]}

    policy = SecurityPolicy(rate_limits={"*": "100/hour"})
    server = create_sdk_mcp_server("tools", tools=wrap_tools([greet], policy=policy))

:meth:`AnthropicClaudeAgentSDKAdapter.wrap_agent` does the same for the entries of any
object's ``tools`` attribute.

The optional dependency is ``claude-agent-sdk>=0.1.58`` (extra:
``pip install "agent-airlock[claude-agent]"``). The SDK is *not*
imported at module load — wrapping an object that comes from the SDK
without the extra installed raises a clear :class:`ClaudeAgentSDKMissingError`
(an :class:`~agent_airlock.exceptions.AirlockError`) with the install
hint, never an opaque ``ImportError`` from somewhere deep in the call
stack.

Primary sources
---------------
- Anthropic Claude Agent SDK docs:
  https://docs.claude.com/en/agents-and-tools/agent-skills
- Claude Managed Agents launch (2026-04-08):
  https://claude.com/blog/claude-managed-agents
"""

from __future__ import annotations

import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .._log import structlog
from ..core import Airlock
from ..exceptions import AirlockError
from ..policy import SecurityPolicy
from ._claude_sdk_tools import guard_sdk_tool, is_sdk_mcp_tool
from ._tool_proxy import named_tool_proxy
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


SUPPORTED_SDK_VERSIONS: tuple[str, ...] = ("0.1.58", "0.1.73", "0.2.152", "0.2.160")
"""Pinned SDK versions this adapter has been smoke-tested against.

Wrapping an object that comes from the SDK on any other version emits
a :class:`UserWarning` (via ``warnings.warn``) but does not hard-fail.
Until 0.10.12 this said so while no comparison was made. Update this
tuple when a new version has been verified.

**0.2.160** is verified end to end: tools returned by :func:`wrap_tools`,
served by ``create_sdk_mcp_server`` and called through an MCP client
session, are refused on a wrong-typed argument, have a ghost argument
stripped, and have their output masked.

v0.1.73 (released 2026-05-04) added ``duration_ms`` to PostToolUse
and PostToolUseFailure hook inputs (tool execution time, excluding
permission prompts and PreToolUse hooks). This adapter forwards the
field into the audit-receipt body when present and remains backward-
compatible with 0.1.58 payloads where ``duration_ms`` is absent.

**0.2.x is now in scope.** This used to read "intentionally out of
scope for this floor — a separate forward-bump candidate", while the
pyproject ceiling of ``<0.2.0`` meant the extra could not install the
line Opus 4.7 requires (v0.2.111+). Verified on **0.2.152**: the
adapter's whole test module passes unchanged, and ``ClaudeSDKClient``,
``tool`` and ``ClaudeAgentOptions`` are all still exported. The ceiling
is now ``<0.3.0``.
"""

_INSTALL_HINT = (
    "claude-agent-sdk is not installed. "
    'Install the extra: pip install "agent-airlock[claude-agent]"'
)


class ClaudeAgentSDKMissingError(AirlockError):
    """Raised when ``wrap_agent`` is called without the extra installed.

    This is intentionally a subclass of :class:`AirlockError` so callers
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
        """Route every entry of ``agent.tools`` through Airlock, in place.

        The SDK has no agent class holding tool callables, so ``agent`` is any
        object with a ``tools`` attribute (dict or list) that you assemble.

        Args:
            agent: The object whose ``tools`` to wrap. Each entry is an
                ``SdkMcpTool`` made by ``claude_agent_sdk.tool`` (replaced by a
                guarded copy, as :func:`wrap_tools` makes), an object with a
                ``forward`` method (whose ``forward`` is replaced), or a
                callable (replaced by its guarded form).
            policy: Optional :class:`SecurityPolicy`. When set, every tool
                is wrapped with :class:`Airlock(policy=policy)`.

        Returns:
            The same agent, its ``tools`` container mutated in place.

        Raises:
            AirlockError: An entry is a tool name, such as the built-in tool
                names in ``ClaudeAgentOptions.tools``, or is not a tool at all.
            ClaudeAgentSDKMissingError: ``agent`` or an entry comes from the
                SDK and the extra is not installed. Stub objects never
                trigger the SDK import, which is what the tests rely on.
        """
        tools = getattr(agent, "tools", None)
        if tools is None:
            raise AirlockError(
                "agent does not expose a `tools` attribute; not a Claude Agent SDK shape"
            )
        entries = list(tools.values()) if isinstance(tools, dict) else tools
        if _from_sdk(agent) or (
            isinstance(entries, list) and any(_from_sdk(tool) for tool in entries)
        ):
            _check_sdk(stacklevel=3)

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
            name: The tool's name (used in logs and audit). An ``SdkMcpTool``
                is guarded under its own ``name``, the one the model calls.
            policy: Optional :class:`SecurityPolicy` to apply.
        """
        if is_sdk_mcp_tool(tool):
            return guard_sdk_tool(tool, policy=policy)
        if isinstance(tool, str):
            raise AirlockError(
                f"{tool!r} is a tool name, not a tool. Claude Code runs its built-in tools "
                "itself, so Airlock cannot wrap them; guard your own SDK tools with "
                "wrap_tools() before passing them to create_sdk_mcp_server()"
            )
        forward: Callable[..., Any] | None = getattr(tool, "forward", None)
        if forward is None and callable(tool):
            forward = tool
        if forward is None:
            raise AirlockError(
                f"tool {name!r} exposes neither `forward` nor `__call__`; cannot wrap"
            )

        # Airlock uses ``func.__name__`` for policy checks, so the proxy carries the
        # tool's canonical name; it also carries the tool's signature, so Airlock
        # validates it, and is async when the tool is.
        airlock = Airlock(policy=policy) if policy is not None else Airlock()
        wrapped = airlock(named_tool_proxy(forward, name=name))

        if hasattr(tool, "forward"):
            # Tool object (non-function): mutate in place. Use setattr so
            # static analysis doesn't try to enforce FunctionType invariants.
            setattr(tool, "forward", wrapped)  # noqa: B010
            return tool
        return wrapped


def wrap_tools(tools: Iterable[Any], *, policy: SecurityPolicy | None = None) -> list[Any]:
    """Return guarded copies of SDK tools, to pass to ``create_sdk_mcp_server``.

    Each handler is fronted by a proxy that takes the tool's ``input_schema`` keys as
    keyword arguments, so ``Airlock`` strips ghost arguments, validates each argument
    strictly and applies ``policy`` before the handler runs, then masks what it returns.
    A refusal reaches the model as an error result (``is_error: True``) with Airlock's
    fix hints. Wrap the tools before building the server: it keeps its own references.

    Args:
        tools: ``SdkMcpTool`` objects made by ``claude_agent_sdk.tool``.
        policy: Optional :class:`SecurityPolicy`; its tool lists match each tool's name.

    Returns:
        New ``SdkMcpTool`` objects in the same order. The originals are unchanged.

    Raises:
        AirlockError: An entry is not an ``SdkMcpTool``, or its ``input_schema`` declares
            a key that is not a Python identifier (see the integration docs).
        ClaudeAgentSDKMissingError: An entry comes from the SDK and the extra is not
            installed.
    """
    tools = list(tools)
    for tool in tools:
        if not is_sdk_mcp_tool(tool):
            raise AirlockError(
                "wrap_tools takes SdkMcpTool objects made by claude_agent_sdk.tool; "
                f"got {type(tool).__name__}"
            )
    if any(_from_sdk(tool) for tool in tools):
        _check_sdk(stacklevel=3)
    guarded = [guard_sdk_tool(tool, policy=policy) for tool in tools]
    logger.info(
        "claude_agent_sdk_tools_wrapped",
        tool_count=len(guarded),
        policy_set=policy is not None,
    )
    return guarded


def _from_sdk(obj: Any) -> bool:
    """Whether ``obj`` is an SDK object; stubs used by the tests never are."""
    return type(obj).__module__.startswith("claude_agent_sdk")


def _check_sdk(*, stacklevel: int) -> None:
    """Import the SDK, and warn when its version is outside ``SUPPORTED_SDK_VERSIONS``.

    Raises:
        ClaudeAgentSDKMissingError: The extra is not installed.
    """
    try:
        import claude_agent_sdk as _sdk
    except ImportError as exc:
        raise ClaudeAgentSDKMissingError(_INSTALL_HINT) from exc
    installed = getattr(_sdk, "__version__", "unknown")
    if installed not in SUPPORTED_SDK_VERSIONS:
        warnings.warn(
            f"claude-agent-sdk {installed} is outside SUPPORTED_SDK_VERSIONS "
            f"{SUPPORTED_SDK_VERSIONS}; adapter behaviour is best-effort",
            UserWarning,
            stacklevel=stacklevel,
        )


def memory_helpers() -> dict[str, Callable[..., Any]]:
    """Return the auto-memory helpers as a dict for callers that prefer that shape."""
    return {"guarded_read": guarded_read, "guarded_write": guarded_write}


def posttooluse_audit_payload(hook_input: dict[str, Any]) -> dict[str, Any]:
    """Map a Claude Agent SDK PostToolUse hook input to an Airlock audit body.

    v0.1.73 of ``claude-agent-sdk`` added ``duration_ms`` to PostToolUse
    and PostToolUseFailure hook inputs (tool execution time, excluding
    permission prompts and PreToolUse hooks). This helper forwards the
    field into the audit-receipt body when present and remains
    backward-compatible with 0.1.58 payloads where the field is absent.

    Args:
        hook_input: The raw hook input dict supplied by the SDK. Must
            contain at least ``"tool_name"``; ``"tool_input"`` and
            ``"duration_ms"`` are passed through when present.

    Returns:
        A dict suitable for inclusion in an Airlock audit receipt:

        - ``tool_name`` (always)
        - ``tool_input`` (when present in input)
        - ``duration_ms`` (only when SDK >= 0.1.73 supplied it)
        - ``sdk_field_durations_present`` (boolean — lets downstream
          observability differentiate "0.1.58 payload" from "0.1.73
          payload that happened to be 0ms")

    Example::

        # SDK 0.1.73+ payload
        body = posttooluse_audit_payload({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "duration_ms": 142,
        })
        # body == {"tool_name": "Bash", "tool_input": {"command": "ls"},
        #          "duration_ms": 142, "sdk_field_durations_present": True}
    """
    body: dict[str, Any] = {"tool_name": hook_input.get("tool_name")}
    if "tool_input" in hook_input:
        body["tool_input"] = hook_input["tool_input"]
    has_duration = "duration_ms" in hook_input
    body["sdk_field_durations_present"] = has_duration
    if has_duration:
        body["duration_ms"] = hook_input["duration_ms"]
    return body


__all__ = [
    "DEFAULT_HARNESS_TOOLS",
    "SUPPORTED_SDK_VERSIONS",
    "AnthropicClaudeAgentSDKAdapter",
    "ClaudeAgentSDKMissingError",
    "memory_helpers",
    "posttooluse_audit_payload",
    "wrap_tools",
]
