"""Claude Managed Agents: an approval gate for the agent toolset (v0.10.25).

Managed Agents runs the agent loop on Anthropic's orchestration layer and the built-in
tools of ``agent_toolset_20260401`` (``bash``, ``read``, ``write``, ``edit``, ``glob``,
``grep``, ``web_fetch``, ``web_search``) in a container the client never touches. A
client sees a built-in tool call *before* it runs in one place only: a tool configured
``always_ask`` makes the server emit an ``agent.tool_use`` event with
``evaluated_permission: "ask"`` and idle with ``stop_reason: requires_action`` until the
client sends ``user.tool_confirmation``. The toolset's default policy is
``always_allow``, so without ``always_ask`` no call ever waits for the client.

:class:`ManagedAgentToolGate` puts Airlock's checks at that confirmation: the kill switch,
a tool allowlist, per-tool input checks (lexical path policy, endpoint policy, an
operator-supplied ``bash`` check) and a :class:`~agent_airlock.policy.SecurityPolicy`.
:func:`build_agent_toolset` builds a toolset whose enabled tools are all ``always_ask``,
and :func:`check_agent_toolset` refuses an agent configuration whose calls would not
reach the gate::

    gate = ManagedAgentToolGate(
        {"read", "glob"},
        path_policy=RemotePathPolicy(allowed_roots=("/workspace",)),
    )
    agent = client.beta.agents.create(name="...", model="...", tools=[gate.agent_toolset()])
    check_agent_toolset(agent.tools, allowed_tools=gate.allowed_tools)

    with client.beta.sessions.events.stream(session_id=session.id) as stream:
        client.beta.sessions.events.send(session_id=session.id, events=[first_message])
        for event in stream:
            if event.type in ("agent.tool_use", "agent.mcp_tool_use"):
                decision = gate.review(event, session_id=session.id)
                if decision.confirmation is not None:
                    client.beta.sessions.events.send(
                        session_id=session.id, events=[decision.confirmation]
                    )
            elif event.type == "session.status_idle" and event.stop_reason.type != "requires_action":
                break

Honest scope:

* Path checks are **lexical**: ``posixpath.normpath`` and ``commonpath`` on the path the
  model wrote, never ``realpath``. The container is remote, so a symlink inside it is
  not seen.
* ``bash`` is **not parsed**. A ``bash`` call is denied unless the operator passes a
  ``command_check``, and what that check accepts is the operator's decision.
* ``grep`` and ``glob`` search or list everything under the directory they name; the
  deny patterns apply to that directory and to a glob's literal parts, not to each file
  grep reads.
* A call the server allows on its own (``always_allow``, or ``auto`` deciding to run it)
  is already running when its event arrives. The gate reviews it for the record and
  reports ``enforced=False`` when it would have refused; the only response left is
  ``user.interrupt``.
* ``deny_message`` reaches the model as the rejected tool's result, so it carries the
  refusal's error and fix hints and never its metadata.

Primary sources:

* Tools and permission policies: https://platform.claude.com/docs/en/managed-agents/tools
* Events: https://platform.claude.com/docs/en/managed-agents/events
"""

from __future__ import annotations

import fnmatch
import posixpath
import warnings
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .._log import structlog
from ..core import PATH_PARAM_NAMES, URL_PARAM_NAMES
from ..exceptions import AirlockError
from ..filesystem import PathValidationError
from ..kill_switch.registry import get as _kill_switch_get
from ..kill_switch.registry import is_frozen as _kill_switch_frozen
from ..network import EndpointPolicy, NetworkBlockedError, validate_endpoint
from ..policy import AgentIdentity, PolicyEscalation, PolicyViolation, SecurityPolicy, ViolationType
from ..self_heal import (
    AirlockResponse,
    BlockReason,
    handle_endpoint_violation,
    handle_path_violation,
    handle_policy_violation,
    handle_rate_limit,
    refusal_text,
)

logger = structlog.get_logger("agent-airlock.integrations.claude_managed_agents")

MANAGED_AGENTS_BETA_HEADER = "managed-agents-2026-04-01"
"""The pinned ``anthropic-beta`` value for Managed Agents.

The Python SDK sends it on ``client.beta.agents``, ``environments`` and ``sessions``
calls; a raw HTTP client must send it itself."""

AGENT_TOOLSET_VERSION = "agent_toolset_20260401"
"""The pinned agent toolset type. A toolset of any other type is refused by
:func:`check_agent_toolset`: its tool names and defaults are unverified."""

AGENT_TOOLSET_TOOLS: tuple[str, ...] = (
    "bash",
    "read",
    "write",
    "edit",
    "glob",
    "grep",
    "web_fetch",
    "web_search",
)
"""The eight built-in tools of ``agent_toolset_20260401``."""

DEFAULT_HARNESS_TOOLS: tuple[str, ...] = AGENT_TOOLSET_TOOLS
"""Kept for compatibility; the same tuple as :data:`AGENT_TOOLSET_TOOLS`.

Until 0.10.25 this named four tools (``read_file``, ``bash``, ``web_browse``,
``code_execute``), three of which the API does not have."""

DEFAULT_REMOTE_DENY_PATTERNS: tuple[str, ...] = (
    "*.env",
    ".env*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "**/.ssh/**",
    "**/.aws/**",
    "**/credentials/**",
    "**/secrets/**",
)
"""Paths a :class:`RemotePathPolicy` refuses by default, matched case-insensitively."""

DENY_MESSAGE_MAX_CHARS = 4000
"""The longest ``deny_message`` a confirmation carries; a longer refusal text is cut."""

_FILE_TOOLS = frozenset({"read", "write", "edit"})
_WRITE_TOOLS = frozenset({"write", "edit"})
_SEARCH_TOOLS = frozenset({"glob", "grep"})
_PATH_TOOLS = _FILE_TOOLS | _SEARCH_TOOLS
_TOOL_USE_EVENTS = ("agent.tool_use", "agent.mcp_tool_use")
_GLOB_METACHARS = frozenset("*?[]{}")
_MAX_PATH_CHARS = 4096
_GATE = "ManagedAgentToolGate"


class ManagedAgentBetaHeaderMissingError(AirlockError):
    """Raised by the deprecated :func:`audit_managed_agent_invocation` when a request
    dict's ``betas`` lacks :data:`MANAGED_AGENTS_BETA_HEADER`."""


class ManagedAgentToolBlocked(AirlockError):
    """Raised by the deprecated :func:`audit_managed_agent_invocation` for a tool name
    outside ``ManagedAgentsAuditConfig.allowed_tools``.

    Attributes:
        tool_name: The tool the request asked for.
        allowed: The intersection set the caller declared.
    """

    def __init__(self, *, tool_name: str, allowed: Iterable[str]) -> None:
        self.tool_name = tool_name
        self.allowed = list(allowed)
        super().__init__(
            f"managed agent requested tool {tool_name!r} which is not in "
            f"the policy-allowed intersection {self.allowed!r}"
        )


class UnknownToolsetVersionError(AirlockError):
    """Raised by the deprecated :func:`audit_managed_agent_invocation` when a request
    dict's ``toolset_version`` is not :data:`AGENT_TOOLSET_VERSION`."""


class ManagedAgentToolsetError(AirlockError):
    """A toolset or gate configuration under which a call could bypass the gate.

    Attributes:
        problems: One line per problem found.
    """

    def __init__(self, message: str, problems: Iterable[str] = ()) -> None:
        self.problems = list(problems)
        detail = "".join(f"\n- {problem}" for problem in self.problems)
        super().__init__(message + detail)


class UnreviewableEventError(AirlockError):
    """:meth:`ManagedAgentToolGate.review` was handed something it cannot answer.

    Only an ``agent.tool_use`` or ``agent.mcp_tool_use`` event with a string ``id`` can
    be confirmed. A custom tool call (``agent.custom_tool_use``) is answered with
    ``user.custom_tool_result``; run that tool through ``@Airlock`` instead.
    """


@dataclass(frozen=True)
class RemotePathPolicy:
    """Lexical POSIX path policy for the tools that run in a Managed Agents container.

    Every check is on the path as written: ``posixpath.normpath`` collapses ``.`` and
    ``..``, and ``posixpath.commonpath`` compares with the roots. Nothing is resolved on
    the local disk, which is not the container's.

    Attributes:
        allowed_roots: Absolute directories (or files) a path must fall within. At least
            one is required; a bare string is read as one root.
        deny_patterns: Glob patterns refused anywhere in a path, case-insensitively,
            matched against the whole path, its name and each component.
        workdir: The directory a relative path is taken from (the container's default
            working directory is ``/workspace``).
        max_path_depth: Most components a normalised path may have.
    """

    allowed_roots: tuple[str, ...]
    deny_patterns: tuple[str, ...] = DEFAULT_REMOTE_DENY_PATTERNS
    workdir: str = "/workspace"
    max_path_depth: int = 32

    def __post_init__(self) -> None:
        roots = _as_tuple(self.allowed_roots)
        if not roots:
            raise ValueError(
                "RemotePathPolicy needs at least one allowed root; to allow no path, "
                "leave the path tools out of the gate's allowed_tools"
            )
        object.__setattr__(self, "allowed_roots", tuple(_absolute_root(root) for root in roots))
        object.__setattr__(self, "deny_patterns", _as_tuple(self.deny_patterns))
        object.__setattr__(self, "workdir", _absolute_root(self.workdir))
        if isinstance(self.max_path_depth, bool) or not isinstance(self.max_path_depth, int):
            raise ValueError("max_path_depth must be an int")
        if self.max_path_depth < 1:
            raise ValueError("max_path_depth must be at least 1")

    def check(self, path: Any) -> str:
        """Return ``path`` normalised and absolute, or refuse it.

        Args:
            path: A path as a tool call's input carries it.

        Returns:
            The normalised absolute path.

        Raises:
            PathValidationError: The path is not a plain string path, names a home or
                variable the gate cannot resolve, is too deep, falls outside every root
                or matches a deny pattern.
        """
        text = _plain_path_text(path)
        if not text.startswith("/"):
            text = posixpath.join(self.workdir, text)
        normalized = posixpath.normpath("/" + text.lstrip("/"))
        depth = len([part for part in normalized.split("/") if part])
        if depth > self.max_path_depth:
            raise PathValidationError(
                f"Path exceeds maximum depth of {self.max_path_depth}",
                str(path),
                "max_depth_exceeded",
                {"depth": depth, "max_depth": self.max_path_depth},
            )
        if not any(_within(normalized, root) for root in self.allowed_roots):
            raise PathValidationError(
                f"Path '{path}' is outside allowed directories",
                str(path),
                "outside_allowed_roots",
                {"allowed_roots": list(self.allowed_roots)},
            )
        if _remote_deny_match(normalized, self.deny_patterns):
            # The pattern is left out: the model is told what it may reach, not what
            # is hidden from it.
            raise PathValidationError("Path matches a denied pattern", str(path), "denied_pattern")
        return normalized


def _as_tuple(value: Any) -> tuple[Any, ...]:
    """A bare string as a one-item tuple, any other iterable as a tuple."""
    return (value,) if isinstance(value, str) else tuple(value)


def _absolute_root(root: Any) -> str:
    if not isinstance(root, str) or not root.startswith("/") or "\x00" in root:
        raise ValueError(f"{root!r} must be an absolute POSIX path")
    return posixpath.normpath("/" + root.lstrip("/"))


def _within(path: str, root: str) -> bool:
    try:
        return posixpath.commonpath([path, root]) == root
    except ValueError:
        return False


def _plain_path_text(path: Any) -> str:
    """``path`` when it is a string the gate can reason about, else a refusal."""
    if not isinstance(path, str) or not path:
        raise PathValidationError("Path must be a non-empty string", repr(path), "invalid_path")
    if "\x00" in path or "\\" in path or len(path) > _MAX_PATH_CHARS or path != path.strip():
        raise PathValidationError(
            "Path has a character or length the gate does not accept", path, "invalid_path"
        )
    if path.startswith("~"):
        raise PathValidationError(
            "A path relative to a home directory cannot be checked remotely",
            path,
            "home_relative",
        )
    if any(part.startswith("$") for part in path.split("/")):
        raise PathValidationError(
            "A path naming a variable cannot be checked", path, "variable_reference"
        )
    return path


def _remote_deny_match(path: str, patterns: Iterable[str]) -> bool:
    lowered = path.lower()
    parts = [part for part in lowered.split("/") if part]
    name = parts[-1] if parts else ""
    for pattern in patterns:
        pat = pattern.lower()
        component = pat.replace("**/", "").replace("/**", "")
        if fnmatch.fnmatchcase(lowered, pat) or fnmatch.fnmatchcase(name, pat):
            return True
        if any(fnmatch.fnmatchcase(part, component) for part in parts):
            return True
    return False


def _tool_names(names: Iterable[str] | str, *, what: str) -> frozenset[str]:
    """Validate built-in tool names.

    Raises:
        ManagedAgentToolsetError: A name is not one of :data:`AGENT_TOOLSET_TOOLS`.
    """
    given = _as_tuple(names)
    unknown = sorted(str(name) for name in given if name not in AGENT_TOOLSET_TOOLS)
    if unknown:
        raise ManagedAgentToolsetError(
            f"{what} names tools agent_toolset_20260401 does not have",
            [f"{name!r} is not one of {', '.join(AGENT_TOOLSET_TOOLS)}" for name in unknown],
        )
    return frozenset(given)


def build_agent_toolset(
    enabled: Iterable[str] | str = (),
    *,
    version: str = AGENT_TOOLSET_VERSION,
) -> dict[str, Any]:
    """An ``agent_toolset_20260401`` entry whose enabled tools all wait for the client.

    Every one of the eight tools is listed, so none falls back to a server default:
    the ones in ``enabled`` are on, the rest off, and each is ``always_ask``.

    Args:
        enabled: The built-in tools to turn on.
        version: The toolset type. Only :data:`AGENT_TOOLSET_VERSION` is accepted.

    Returns:
        A dict for ``client.beta.agents.create(tools=[...])``.

    Raises:
        ManagedAgentToolsetError: An unknown tool name or toolset version.
    """
    if version != AGENT_TOOLSET_VERSION:
        raise ManagedAgentToolsetError(
            f"toolset type {version!r} is not the pinned {AGENT_TOOLSET_VERSION!r}; its "
            "tool names and defaults are unverified"
        )
    names = _tool_names(enabled, what="build_agent_toolset")
    return {
        "type": version,
        "default_config": {"enabled": False, "permission_policy": {"type": "always_ask"}},
        "configs": [
            {"name": tool, "enabled": tool in names, "permission_policy": {"type": "always_ask"}}
            for tool in AGENT_TOOLSET_TOOLS
        ],
    }


def check_agent_toolset(
    tools: Iterable[Any] | Mapping[str, Any],
    *,
    allowed_tools: Iterable[str] | str | None = None,
) -> None:
    """Refuse a tool configuration under which a call would not wait for the gate.

    Reads request dicts or the SDK objects an agent's ``tools`` comes back as, applying
    the API's defaults where a field is absent: a toolset is enabled and ``always_allow``
    unless configured otherwise, an MCP toolset ``always_ask``.

    Args:
        tools: An agent's ``tools`` list (or one toolset entry).
        allowed_tools: The gate's allowed tools. When given, a tool enabled outside it
            is a problem too: every call to it would be refused, so it should be off.

    Raises:
        ManagedAgentToolsetError: With one problem per enabled tool not under
            ``always_ask`` (``auto`` and ``always_allow`` both run calls without the
            client), per toolset of another type, per MCP toolset tool not under
            ``always_ask``, and per entry of a type the gate cannot place.
    """
    allowed = None if allowed_tools is None else _tool_names(allowed_tools, what="allowed_tools")
    entries = [tools] if isinstance(tools, Mapping) else list(tools)
    problems: list[str] = []
    for index, entry in enumerate(entries):
        kind = _field(entry, "type")
        where = f"tools[{index}]"
        if kind == AGENT_TOOLSET_VERSION:
            problems.extend(_agent_toolset_problems(entry, where, allowed))
        elif isinstance(kind, str) and kind.startswith("agent_toolset"):
            problems.append(
                f"{where}: toolset type {kind!r} is not the pinned {AGENT_TOOLSET_VERSION!r}"
            )
        elif kind == "mcp_toolset":
            problems.extend(_mcp_toolset_problems(entry, where))
        elif kind != "custom":
            problems.append(f"{where}: entry type {kind!r} cannot be checked")
    if problems:
        raise ManagedAgentToolsetError(
            "agent tool configuration lets calls run without ManagedAgentToolGate", problems
        )


def _policy_type(policy: Any) -> str | None:
    if isinstance(policy, str):
        return policy
    kind = _field(policy, "type") if policy is not None else None
    return kind if isinstance(kind, str) else None


def _resolved(config: Any, default_enabled: Any, default_policy: str) -> tuple[bool, str]:
    """``(enabled, policy)`` for one tool config over its toolset's defaults.

    Anything but an explicit ``False`` reads as enabled, so an unreadable value fails
    toward a problem report rather than toward silence.
    """
    enabled = _field(config, "enabled") if config is not None else None
    if enabled is None:
        enabled = default_enabled
    policy = _policy_type(_field(config, "permission_policy")) if config is not None else None
    return enabled is not False, policy or default_policy


def _agent_toolset_problems(entry: Any, where: str, allowed: frozenset[str] | None) -> list[str]:
    default = _field(entry, "default_config")
    default_enabled = _field(default, "enabled") if default is not None else None
    default_policy = (
        _policy_type(_field(default, "permission_policy")) if default is not None else None
    ) or "always_allow"
    problems: list[str] = []
    configs: dict[str, Any] = {}
    for config in _field(entry, "configs") or []:
        name = _field(config, "name") or _field(config, "type")
        if name not in AGENT_TOOLSET_TOOLS:
            problems.append(f"{where}: configs names unknown tool {name!r}")
            continue
        configs[name] = config
    for tool in AGENT_TOOLSET_TOOLS:
        enabled, policy = _resolved(
            configs.get(tool), True if default_enabled is None else default_enabled, default_policy
        )
        if not enabled:
            continue
        if policy != "always_ask":
            problems.append(
                f"{where}: {tool} is enabled under {policy!r}, so its calls run without "
                "the client; set permission_policy always_ask"
            )
        if allowed is not None and tool not in allowed:
            problems.append(f"{where}: {tool} is enabled but not in allowed_tools; disable it")
    return problems


def _mcp_toolset_problems(entry: Any, where: str) -> list[str]:
    server = _field(entry, "mcp_server_name")
    default = _field(entry, "default_config")
    default_enabled = _field(default, "enabled") if default is not None else None
    default_policy = (
        _policy_type(_field(default, "permission_policy")) if default is not None else None
    ) or "always_ask"
    problems: list[str] = []
    if default_enabled is not False and default_policy != "always_ask":
        problems.append(
            f"{where}: MCP toolset {server!r} defaults to {default_policy!r}; keep always_ask"
        )
    for config in _field(entry, "configs") or []:
        enabled, policy = _resolved(
            config, True if default_enabled is None else default_enabled, default_policy
        )
        if enabled and policy != "always_ask":
            problems.append(
                f"{where}: MCP tool {_field(config, 'name')!r} on {server!r} is under "
                f"{policy!r}; keep always_ask"
            )
    return problems


def _field(obj: Any, key: str) -> Any:
    """``obj[key]`` for a mapping, ``obj.key`` for an SDK object, None when absent."""
    if isinstance(obj, Mapping):
        return obj.get(key)
    return getattr(obj, key, None)


@dataclass(frozen=True)
class ToolUseDecision:
    """What :meth:`ManagedAgentToolGate.review` decided about one tool-use event.

    Attributes:
        tool_use_id: The event's ``id`` (``sevt_...``), which a confirmation answers.
        tool_name: The tool the event names.
        event_type: ``agent.tool_use`` or ``agent.mcp_tool_use``.
        evaluated_permission: The server's ``allow`` / ``ask`` / ``deny``, or None when
            the event carried none.
        allowed: Whether the gate allows the call.
        checks: The checks run, in order; on a refusal the last one refused.
        refusal: Airlock's refusal (``AirlockResponse.to_dict()``) when not allowed.
        mcp_server_name: The MCP server, for an ``agent.mcp_tool_use`` event.
    """

    tool_use_id: str
    tool_name: str
    event_type: str
    evaluated_permission: str | None
    allowed: bool
    checks: tuple[str, ...] = ()
    refusal: dict[str, Any] | None = field(default=None, hash=False)
    mcp_server_name: str | None = None

    @property
    def needs_confirmation(self) -> bool:
        """Whether the session is waiting for this decision (``evaluated_permission`` ask)."""
        return self.evaluated_permission == "ask"

    @property
    def enforced(self) -> bool:
        """Whether what happens to the call matches this decision.

        True when the decision answers a paused call, or when the server's own
        ``allow``/``deny`` agrees with it. False when the server ran (or denied) the
        call without waiting and the gate disagrees.
        """
        if self.needs_confirmation:
            return True
        if self.evaluated_permission == "deny":
            return not self.allowed
        return self.allowed

    @property
    def deny_message(self) -> str | None:
        """The refusal as the model will read it, or None when allowed."""
        if self.refusal is None:
            return None
        return refusal_text(self.refusal)[:DENY_MESSAGE_MAX_CHARS]

    @property
    def confirmation(self) -> dict[str, Any] | None:
        """The ``user.tool_confirmation`` event to send, or None when nothing is waiting.

        Confirming an event whose ``evaluated_permission`` is not ``ask`` is a 400, so
        there is none for those.
        """
        if not self.needs_confirmation:
            return None
        event: dict[str, Any] = {
            "type": "user.tool_confirmation",
            "tool_use_id": self.tool_use_id,
            "result": "allow" if self.allowed else "deny",
        }
        if not self.allowed:
            event["deny_message"] = self.deny_message
        return event


class ManagedAgentToolGate:
    """Reviews each Managed Agents tool-use event with Airlock's checks.

    Construction is explicit opt-in: a tool is reviewable only when listed, a path tool
    needs a :class:`RemotePathPolicy` and ``web_fetch`` an
    :class:`~agent_airlock.network.EndpointPolicy`. A gate with no tools refuses
    everything.

    Args:
        allowed_tools: Built-in tools the gate may allow.
        path_policy: Paths ``read``, ``glob`` and ``grep`` may touch (and ``write`` /
            ``edit`` when ``write_path_policy`` is unset).
        write_path_policy: Paths ``write`` and ``edit`` may touch.
        endpoint_policy: URLs ``web_fetch`` may fetch (http and https only).
        command_check: Called with a ``bash`` command; returns True to allow it.
            Without one, every ``bash`` call is refused: the gate does not parse shell.
        allowed_mcp_tools: ``(server, tool)`` pairs an ``agent.mcp_tool_use`` may name.
        policy: Checked last, under the built-in tool's name, or
            ``mcp__<server>__<tool>`` for an MCP tool.
        agent: The identity ``policy.check`` sees.

    Raises:
        ManagedAgentToolsetError: An unknown tool name, a path tool without a path
            policy, ``web_fetch`` without an endpoint policy, or a malformed argument.
    """

    def __init__(
        self,
        allowed_tools: Iterable[str] | str = (),
        *,
        path_policy: RemotePathPolicy | None = None,
        write_path_policy: RemotePathPolicy | None = None,
        endpoint_policy: EndpointPolicy | None = None,
        command_check: Callable[[str], bool] | None = None,
        allowed_mcp_tools: Iterable[tuple[str, str]] = (),
        policy: SecurityPolicy | None = None,
        agent: AgentIdentity | None = None,
    ) -> None:
        self.allowed_tools = _tool_names(allowed_tools, what="allowed_tools")
        self.path_policy = path_policy
        self.write_path_policy = write_path_policy
        self.endpoint_policy = endpoint_policy
        self.command_check = command_check
        self.allowed_mcp_tools = frozenset(_mcp_pairs(allowed_mcp_tools))
        self.policy = policy
        self.agent = agent
        problems = self._construction_problems()
        if problems:
            raise ManagedAgentToolsetError("ManagedAgentToolGate is not fully configured", problems)
        if "bash" in self.allowed_tools and command_check is None:
            logger.warning(
                "managed_agent_gate_bash_without_check",
                hint="bash is allowed but no command_check is set; every bash call is refused",
            )

    def _construction_problems(self) -> list[str]:
        problems: list[str] = []
        for name, value in (
            ("path_policy", self.path_policy),
            ("write_path_policy", self.write_path_policy),
        ):
            if value is not None and not isinstance(value, RemotePathPolicy):
                problems.append(f"{name} must be a RemotePathPolicy")
        reads = self.allowed_tools & (_PATH_TOOLS - _WRITE_TOOLS)
        if reads and self.path_policy is None:
            problems.append(f"{', '.join(sorted(reads))} need a path_policy")
        writes = self.allowed_tools & _WRITE_TOOLS
        if writes and self.path_policy is None and self.write_path_policy is None:
            problems.append(f"{', '.join(sorted(writes))} need a path_policy or write_path_policy")
        if self.endpoint_policy is not None and not isinstance(
            self.endpoint_policy, EndpointPolicy
        ):
            problems.append("endpoint_policy must be an EndpointPolicy")
        if "web_fetch" in self.allowed_tools and self.endpoint_policy is None:
            problems.append("web_fetch needs an endpoint_policy")
        if self.command_check is not None and not callable(self.command_check):
            problems.append("command_check must be callable")
        return problems

    def agent_toolset(self, *, version: str = AGENT_TOOLSET_VERSION) -> dict[str, Any]:
        """The toolset entry for this gate: its tools on, all under ``always_ask``."""
        return build_agent_toolset(self.allowed_tools, version=version)

    def review(self, event: Any, *, session_id: str | None = None) -> ToolUseDecision:
        """Decide one ``agent.tool_use`` / ``agent.mcp_tool_use`` event.

        Checks, in order: the kill switch, that the tool is known (an MCP tool, that its
        ``(server, tool)`` pair is allowlisted), that it is in ``allowed_tools``, its
        input, then ``policy``. A check that raises refuses the call; the error is
        logged without the input.

        Args:
            event: The event, as an SDK object or a dict.
            session_id: For the log only.

        Returns:
            The decision; send ``decision.confirmation`` when it is not None.

        Raises:
            UnreviewableEventError: ``event`` is not a tool-use event with a string id.
        """
        event_type = _field(event, "type")
        if event_type not in _TOOL_USE_EVENTS:
            raise UnreviewableEventError(
                f"event type {event_type!r} is not agent.tool_use or agent.mcp_tool_use"
            )
        tool_use_id = _field(event, "id")
        if not isinstance(tool_use_id, str) or not tool_use_id:
            raise UnreviewableEventError("tool-use event has no string id to confirm")
        name = _field(event, "name")
        server = _field(event, "mcp_server_name") if event_type == "agent.mcp_tool_use" else None
        shown = name if isinstance(name, str) else "<unnamed>"
        checks: list[str] = []
        try:
            refusal = self._evaluate(event_type, name, server, _field(event, "input"), checks)
        except Exception as exc:  # noqa: BLE001 - a check that cannot finish refuses
            logger.warning(
                "managed_agent_review_failed",
                tool=shown,
                tool_use_id=tool_use_id,
                session_id=session_id,
                error=type(exc).__name__,
            )
            checks.append("error")
            refusal = _gate_refusal(shown, "the gate could not review this call")
        permission = _field(event, "evaluated_permission")
        decision = ToolUseDecision(
            tool_use_id=tool_use_id,
            tool_name=shown,
            event_type=event_type,
            evaluated_permission=permission if isinstance(permission, str) else None,
            allowed=refusal is None,
            checks=tuple(checks),
            refusal=refusal,
            mcp_server_name=server if isinstance(server, str) else None,
        )
        _log_decision(decision, session_id)
        return decision

    def _evaluate(
        self, event_type: str, name: Any, server: Any, tool_input: Any, checks: list[str]
    ) -> dict[str, Any] | None:
        checks.append("kill_switch")
        if _kill_switch_frozen():
            return _kill_switch_refusal(name if isinstance(name, str) else "<unnamed>")
        checks.append("tool_known")
        if not isinstance(name, str):
            return _gate_refusal("<unnamed>", "the event names no tool")
        if event_type == "agent.mcp_tool_use":
            if not isinstance(server, str) or (server, name) not in self.allowed_mcp_tools:
                return _gate_refusal(name, f"MCP tool {name!r} on server {server!r} is not allowed")
            policy_name = f"mcp__{server}__{name}"
        else:
            if name not in AGENT_TOOLSET_TOOLS:
                return _gate_refusal(name, f"{name!r} is not an agent_toolset_20260401 tool")
            checks.append("allowed_tools")
            if name not in self.allowed_tools:
                return _gate_refusal(name, f"tool {name!r} is not allowed in this session")
            checks.append("input")
            refusal = self._check_input(name, tool_input)
            if refusal is not None:
                return refusal
            policy_name = name
        if self.policy is None:
            return None
        checks.append("policy")
        return self._check_policy(self.policy, policy_name)

    def _check_input(self, name: str, tool_input: Any) -> dict[str, Any] | None:
        if not isinstance(tool_input, Mapping) or not all(isinstance(k, str) for k in tool_input):
            return _gate_refusal(name, "the tool input is not an object with string keys")
        if name in _FILE_TOOLS:
            return self._check_file_tool(name, tool_input)
        if name in _SEARCH_TOOLS:
            return self._check_search_tool(name, tool_input)
        if name == "web_fetch":
            return self._check_web_fetch(tool_input)
        if name == "bash":
            return self._check_bash(tool_input)
        return None  # web_search: its name is all there is to check

    def _check_file_tool(self, name: str, tool_input: Mapping[str, Any]) -> dict[str, Any] | None:
        policy = (
            self.write_path_policy
            if name in _WRITE_TOOLS and self.write_path_policy is not None
            else self.path_policy
        )
        if policy is None:  # pragma: no cover - construction refuses this
            return _gate_refusal(name, "no path policy is configured")
        if "file_path" not in tool_input and "path" not in tool_input:
            return _gate_refusal(name, "the call names no file_path")
        for key, value in tool_input.items():
            if key == "file_path" or key.lower() in PATH_PARAM_NAMES:
                refusal = _path_refusal(name, policy, value)
                if refusal is not None:
                    return refusal
        return None

    def _check_search_tool(self, name: str, tool_input: Mapping[str, Any]) -> dict[str, Any] | None:
        policy = self.path_policy
        if policy is None:  # pragma: no cover - construction refuses this
            return _gate_refusal(name, "no path policy is configured")
        base_value = tool_input.get("path")
        base = policy.workdir if base_value is None else base_value
        refusal = _path_refusal(name, policy, base)
        if refusal is not None or name != "glob":
            return refusal
        pattern = tool_input.get("pattern")
        try:
            base_path = policy.check(base)
            policy.check(_glob_static_path(base_path, pattern))
            if _remote_deny_match(_glob_full_path(base_path, pattern), policy.deny_patterns):
                raise PathValidationError(
                    "Glob pattern targets a denied path", str(pattern), "denied_pattern"
                )
        except PathValidationError as exc:
            return handle_path_violation(
                name, path=exc.path, violation_type=exc.violation_type, details=exc.details
            ).to_dict()
        return None

    def _check_web_fetch(self, tool_input: Mapping[str, Any]) -> dict[str, Any] | None:
        policy = self.endpoint_policy
        if policy is None:  # pragma: no cover - construction refuses this
            return _gate_refusal("web_fetch", "no endpoint policy is configured")
        urls = [
            (key, value)
            for key, value in tool_input.items()
            if key == "url" or key.lower() in URL_PARAM_NAMES
        ]
        if not urls:
            return _gate_refusal("web_fetch", "the call names no url")
        allowed = policy.allowed_endpoints or None
        for _key, url in urls:
            if not isinstance(url, str):
                return _gate_refusal("web_fetch", "the url is not a string")
            hostname, reason = "unknown", ""
            if urlsplit(url).scheme.lower() not in ("http", "https"):
                reason = "scheme_not_allowed"
            else:
                try:
                    validate_endpoint(url, policy)
                except NetworkBlockedError as exc:
                    hostname = str(exc.details.get("hostname", "unknown"))
                    reason = str(exc.details.get("reason", "unknown"))
            if reason:
                return handle_endpoint_violation(
                    "web_fetch",
                    url=url,
                    hostname=hostname,
                    reason=reason,
                    allowed_endpoints=allowed,
                ).to_dict()
        return None

    def _check_bash(self, tool_input: Mapping[str, Any]) -> dict[str, Any] | None:
        if self.command_check is None:
            return _gate_refusal(
                "bash", "bash commands are not parsed, and no command_check allows any"
            )
        command = tool_input.get("command")
        if command is None:
            command = ""
        if not isinstance(command, str):
            return _gate_refusal("bash", "the command is not a string")
        if self.command_check(command) is not True:
            return _gate_refusal("bash", "the command_check refused this command")
        return None

    def _check_policy(self, policy: SecurityPolicy, tool_name: str) -> dict[str, Any] | None:
        try:
            policy.check(tool_name, agent=self.agent)
        except PolicyEscalation:
            return handle_policy_violation(
                tool_name,
                policy_name="SecurityPolicy",
                reason=(
                    f"Tool '{tool_name}' requires human approval, which ManagedAgentToolGate "
                    "does not route; refused"
                ),
            ).to_dict()
        except PolicyViolation as exc:
            if exc.violation_type == ViolationType.RATE_LIMITED.value:
                return handle_rate_limit(
                    tool_name,
                    limit=str(exc.details.get("limit", "unknown")),
                    reset_seconds=int(exc.details.get("reset_seconds", 60)),
                ).to_dict()
            reason = (
                f"Tool '{tool_name}' is denied by policy"
                if exc.violation_type == ViolationType.TOOL_DENIED.value
                else exc.message
            )
            return handle_policy_violation(
                tool_name, policy_name="SecurityPolicy", reason=reason
            ).to_dict()
        return None


def _mcp_pairs(pairs: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    checked: list[tuple[str, str]] = []
    for pair in pairs:
        if (
            not isinstance(pair, tuple)
            or len(pair) != 2
            or not all(isinstance(part, str) and part for part in pair)
        ):
            raise ManagedAgentToolsetError(
                "allowed_mcp_tools takes (server, tool) pairs of strings", [repr(pair)]
            )
        checked.append(pair)
    return checked


def _glob_parts(pattern: Any) -> list[str]:
    """A glob pattern's components, or a refusal of a pattern the gate cannot place."""
    if not isinstance(pattern, str) or not pattern:
        raise PathValidationError(
            "Glob pattern must be a non-empty string", repr(pattern), "invalid_path"
        )
    _plain_path_text(pattern)  # NUL, backslash, ~, $ and length, as for a path
    parts = [part for part in pattern.split("/") if part]
    if ".." in parts:
        raise PathValidationError("Glob pattern climbs out with ..", pattern, "invalid_path")
    return parts


def _glob_static_path(base: str, pattern: Any) -> str:
    """The directory a glob pattern is rooted at: its parts before the first wildcard."""
    parts = _glob_parts(pattern)
    static: list[str] = []
    for part in parts:
        if _GLOB_METACHARS & set(part):
            break
        static.append(part)
    root = "/" if pattern.startswith("/") else base
    return posixpath.join(root, *static) if static else root


def _glob_full_path(base: str, pattern: Any) -> str:
    parts = _glob_parts(pattern)
    return posixpath.join("/" if pattern.startswith("/") else base, *parts)


def _path_refusal(tool: str, policy: RemotePathPolicy, value: Any) -> dict[str, Any] | None:
    try:
        policy.check(value)
    except PathValidationError as exc:
        return handle_path_violation(
            tool, path=exc.path, violation_type=exc.violation_type, details=exc.details
        ).to_dict()
    return None


def _gate_refusal(tool: str, reason: str) -> dict[str, Any]:
    return handle_policy_violation(tool, policy_name=_GATE, reason=reason).to_dict()


def _kill_switch_refusal(tool: str) -> dict[str, Any]:
    listener = _kill_switch_get()
    reason = listener.last_reason if listener else ""
    return AirlockResponse.blocked_response(
        reason=BlockReason.KILL_SWITCH,
        error=(
            f"AIRLOCK_BLOCK: kill switch engaged; '{tool}' refused."
            + (f" Operator reason: {reason}" if reason else "")
        ),
        fix_hints=[
            "An operator has frozen all tool calls for this fleet",
            "This is not a per-call denial: retrying or changing arguments will not help "
            "until the switch is reset",
        ],
        metadata={"function": tool, "operator_reason": reason},
    ).to_dict()


def _log_decision(decision: ToolUseDecision, session_id: str | None) -> None:
    fields = {
        "tool": decision.tool_name,
        "tool_use_id": decision.tool_use_id,
        "session_id": session_id,
        "evaluated_permission": decision.evaluated_permission,
        "allowed": decision.allowed,
        "last_check": decision.checks[-1] if decision.checks else None,
    }
    if not decision.enforced and not decision.allowed:
        logger.warning(
            "managed_agent_tool_not_enforced",
            hint=(
                "the server ran this call without waiting for the gate; send "
                "user.interrupt to stop the session, and configure the tool always_ask"
            ),
            **fields,
        )
    else:
        logger.info("managed_agent_tool_reviewed", **fields)


@dataclass
class ManagedAgentsAuditConfig:
    """Configuration for the deprecated :func:`audit_managed_agent_invocation`.

    Deprecated, removal in v1.0.0: the function it configures checks a request shape
    the Managed Agents API does not have. Use :class:`ManagedAgentToolGate`.

    Attributes:
        allowed_tools: Tool names :func:`audit_managed_agent_invocation` accepts.
        require_beta_header: If True (default), refuse a request dict whose ``betas``
            lacks the pinned beta marker.
        toolset_version: The ``toolset_version`` a request dict must carry, or None to
            skip the check.
        redact_sse_payloads: Stored only. Nothing reads it; call
            :func:`redact_sse_event` on each frame you log.
    """

    allowed_tools: tuple[str, ...] = ()
    require_beta_header: bool = True
    toolset_version: str | None = AGENT_TOOLSET_VERSION
    redact_sse_payloads: bool = True


@dataclass
class ManagedAgentSession:
    """Per-session counter bumped by :func:`audit_managed_agent_invocation`."""

    session_id: str
    invocations: int = field(default=0)


def _emit_otel_span(
    *,
    session_id: str,
    tool_name: str,
    allowed: Iterable[str],
) -> None:
    """Best-effort emit of the ``airlock.managed_agents.invoke`` span.

    Falls through silently if the OTel provider isn't configured — spans are
    observability, not load-bearing for security.
    """
    try:
        from ..observability import end_span, start_span
    except Exception:  # pragma: no cover
        return
    allowed_count = len(list(allowed))
    import contextlib

    with contextlib.suppress(Exception):  # pragma: no cover
        ctx = start_span("airlock.managed_agents.invoke", tool_name)
        ctx.set_attribute("airlock.managed_agents.session_id", session_id)
        ctx.set_attribute("airlock.managed_agents.allowed_count", allowed_count)
        end_span(ctx)


def audit_managed_agent_invocation(
    request: dict[str, Any],
    cfg: ManagedAgentsAuditConfig,
    *,
    session: ManagedAgentSession | None = None,
) -> None:
    """Deprecated, removal in v1.0.0: check a request dict's tool name and markers.

    It reads ``"tool"``, ``"toolset_version"`` and ``"betas"`` keys that no Managed
    Agents request carries, and was written for tool names (``read_file``,
    ``web_browse``, ``code_execute``) the API does not use, so it never gated a real
    call. Review each ``agent.tool_use`` event with :class:`ManagedAgentToolGate`.

    Args:
        request: A dict with ``"tool"`` and, as ``cfg`` requires, ``"toolset_version"``
            and ``"betas"``.
        cfg: The active :class:`ManagedAgentsAuditConfig`.
        session: Optional counter bumped on a clean audit.

    Raises:
        ManagedAgentBetaHeaderMissingError: ``request["betas"]`` lacks the marker.
        UnknownToolsetVersionError: ``request["toolset_version"]`` differs.
        ManagedAgentToolBlocked: ``request["tool"]`` is not in ``cfg.allowed_tools``.
    """
    warnings.warn(
        "audit_managed_agent_invocation is deprecated and will be removed in v1.0.0. It "
        "checks a request shape and tool names the Managed Agents API does not have, so it "
        "never gated a real call; review each agent.tool_use event with ManagedAgentToolGate.",
        FutureWarning,
        stacklevel=2,
    )
    if cfg.require_beta_header:
        betas = request.get("betas") or []
        if MANAGED_AGENTS_BETA_HEADER not in betas:
            raise ManagedAgentBetaHeaderMissingError(
                f"managed-agents request missing beta header {MANAGED_AGENTS_BETA_HEADER!r}"
            )

    if cfg.toolset_version is not None:
        version = request.get("toolset_version")
        if version != cfg.toolset_version:
            raise UnknownToolsetVersionError(
                f"managed-agents request toolset_version={version!r} does "
                f"not match pinned {cfg.toolset_version!r}"
            )

    tool_name = request.get("tool")
    if tool_name is None:
        raise ManagedAgentToolBlocked(tool_name="<missing>", allowed=cfg.allowed_tools)
    if tool_name not in cfg.allowed_tools:
        raise ManagedAgentToolBlocked(tool_name=str(tool_name), allowed=cfg.allowed_tools)

    if session is not None:
        session.invocations += 1

    _emit_otel_span(
        session_id=session.session_id if session else "<no-session>",
        tool_name=str(tool_name),
        allowed=cfg.allowed_tools,
    )


def redact_sse_event(event_data: str) -> str:
    """Run an SSE frame (or any text) through the v0.5.3 log-redaction filter.

    Tool inputs and outputs arrive on the stream as the model wrote them, so a frame you
    log can carry a credential. This applies the regex set ``RedactingLogFilter`` applies
    to ``logging`` records.

    Args:
        event_data: Raw SSE ``data:`` payload.

    Returns:
        The frame with bearer / JWT / API-key shapes redacted.
    """
    from .log_redaction import _load_default_patterns  # noqa: PLC2701

    redacted = event_data
    for pattern in _load_default_patterns():
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


__all__ = [
    "AGENT_TOOLSET_TOOLS",
    "AGENT_TOOLSET_VERSION",
    "DEFAULT_HARNESS_TOOLS",
    "DEFAULT_REMOTE_DENY_PATTERNS",
    "DENY_MESSAGE_MAX_CHARS",
    "MANAGED_AGENTS_BETA_HEADER",
    "ManagedAgentBetaHeaderMissingError",
    "ManagedAgentSession",
    "ManagedAgentToolBlocked",
    "ManagedAgentToolGate",
    "ManagedAgentToolsetError",
    "ManagedAgentsAuditConfig",
    "RemotePathPolicy",
    "ToolUseDecision",
    "UnknownToolsetVersionError",
    "UnreviewableEventError",
    "audit_managed_agent_invocation",
    "build_agent_toolset",
    "check_agent_toolset",
    "redact_sse_event",
]
