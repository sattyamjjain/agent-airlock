"""MCP-bridge subprocess-arg injection guard (v0.8.22+, CVE-2026-42271 anchor).

CVE-2026-42271 (LiteLLM 1.74.2–1.83.6, CVSS 8.7, CWE-78, **CISA KEV
2026-06-09**, actively exploited): the MCP server *preview* endpoints
``POST /mcp-rest/test/connection`` and ``POST /mcp-rest/test/tools/list``
accepted a full MCP server configuration in the request body — including
the stdio-transport ``command``, ``args`` and ``env`` fields — and spawned
that input as a subprocess on the proxy host, with the proxy's full
privileges and **no validation or sandboxing**. Any authenticated user
with even a low-privilege API key could run arbitrary commands; chained
with the Starlette Host-header bypass (CVE-2026-48710) it becomes
unauthenticated RCE. Fixed in LiteLLM 1.83.7.

The exploit class is **not** LiteLLM-specific: whenever a model- or
request-controlled MCP-bridge configuration carrying spawn-shaped fields
(``command`` / ``cmd`` / ``args`` / ``argv`` / ``env``) reaches a
``subprocess`` / ``Popen`` / ``os.system`` / ``exec`` sink, the host is
one crafted payload away from command execution. This guard is the
reusable, CVE-agnostic primitive.

Threat model + posture
----------------------
The configurations this guard inspects are assumed **untrusted** — they
are the model-/request-controlled MCP-bridge args that the CVE class
splices straight into a spawn. The guard is therefore **deny-by-default**:
a spawn-shaped config is refused unless its resolved program is on an
operator-declared ``allowed_commands`` allowlist of explicitly-safe
*static* commands. An empty allowlist (the default) denies every
spawn-shaped config. A config with **no** spawn-shaped fields (a plain
data argument) is allowed — this guard gates the spawn surface only.

It also refuses an ``env`` mapping that carries a known code-loading
variable (``LD_PRELOAD`` / ``PATH`` / ``PYTHONPATH`` / ...), since those
turn even an allowlisted binary into an execution primitive.

Why structural (no spawn)
-------------------------
The guard never spawns anything — it inspects the proposed spawn config
and refuses. It composes *above* the v0.7.6
:class:`agent_airlock.mcp_spec.stdio_command_injection_guard.StdioCommandInjectionGuard`
(which scans an *allowed* argv for shell metachars): this guard decides
*whether the command is allowed to spawn at all*.

Primary sources (retrieved 2026-06-11):
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-42271
  https://thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html
"""

from __future__ import annotations

import enum
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.subprocess_arg_guard")


# Config keys that indicate the value is spawn-shaped (flows into a
# subprocess command line). ``command`` / ``cmd`` carry the program;
# ``args`` / ``argv`` the argument vector; ``env`` the process environment.
_DEFAULT_SPAWN_KEYS: tuple[str, ...] = ("command", "cmd", "args", "argv", "env")

# Environment variables that turn an otherwise-allowlisted binary into a
# code-execution primitive (preload / search-path / interpreter hooks).
_DEFAULT_DANGEROUS_ENV_VARS: frozenset[str] = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "BASH_ENV",
        "ENV",
        "PERL5LIB",
        "RUBYOPT",
    }
)


class McpSubprocessArgVerdict(str, enum.Enum):
    """Stable reason codes for :class:`McpSubprocessArgDecision`."""

    ALLOW = "allow"
    DENY_UNTRUSTED_COMMAND = "deny_untrusted_command"  # command not on the static allowlist
    DENY_UNTRUSTED_ENV = "deny_untrusted_env"  # env carries a code-loading var


@dataclass(frozen=True)
class McpSubprocessArgDecision:
    """Outcome of a single :meth:`McpSubprocessArgInjectionGuard.evaluate` call.

    Mirrors the v0.7.x / v0.8.x guard decision family — every guard
    exposes ``allowed: bool`` so integrators can chain on one
    short-circuit predicate.

    Attributes:
        allowed: True iff the spawn config is safe (no spawn-shaped
            fields, or an allowlisted static command with a clean env).
        verdict: A stable :class:`McpSubprocessArgVerdict` value.
        detail: Free-form human-readable explanation.
        matched_field: The config field that tripped the guard
            (``"command"`` / ``"argv"`` / ``"env.LD_PRELOAD"`` ...), or
            ``None`` when allowed.
        matched_command: The resolved program name that was refused, or
            ``None`` (e.g. for an env-only deny or an allow).
        fix_hints: LLM-actionable remediation hints. Carries the advisory
            / CVE reference when the guard was constructed with one.
    """

    allowed: bool
    verdict: McpSubprocessArgVerdict
    detail: str
    matched_field: str | None = None
    matched_command: str | None = None
    fix_hints: list[str] = field(default_factory=list)


class McpSubprocessArgInjectionError(AirlockError):
    """Raised on a denied spawn config (fail-closed).

    Carries the :class:`McpSubprocessArgDecision` and exposes
    ``fix_hints`` so an upstream airlock layer can route the refusal into
    self-healing retry semantics.

    Attributes:
        decision: The decision that triggered the refusal.
        fix_hints: LLM-actionable remediation hints.
    """

    def __init__(self, decision: McpSubprocessArgDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        super().__init__(decision.detail)


class McpSubprocessArgInjectionGuard:
    """Deny-by-default gate on untrusted MCP-bridge args reaching a spawn sink.

    Refuses any model-/request-controlled MCP server configuration that
    carries spawn-shaped fields (``command`` / ``cmd`` / ``args`` /
    ``argv`` / ``env``) unless the resolved program is on an
    operator-declared allowlist of explicitly-safe *static* commands.
    Blocks the CVE-2026-42271 class, where a preview/config endpoint
    spawns request-controlled ``command`` + ``args`` + ``env`` with no
    validation.

    Args:
        allowed_commands: Program names (basename or absolute path) that
            may be spawned. ``"uvx"`` matches both ``command="uvx"`` and
            ``command="/usr/bin/uvx"``. Empty (default) denies every
            spawn-shaped config.
        spawn_keys: Config keys treated as spawn-shaped. Defaults to
            :data:`_DEFAULT_SPAWN_KEYS`.
        dangerous_env_vars: Environment variable names that are refused
            in an ``env`` mapping. Defaults to
            :data:`_DEFAULT_DANGEROUS_ENV_VARS`.
        advisory: Optional advisory / CVE id (e.g. ``"CVE-2026-42271"``)
            surfaced in every deny ``fix_hints``.
        advisory_url: Optional primary-source URL surfaced alongside.

    Raises:
        TypeError: ``allowed_commands`` is a bare ``str`` (a footgun that
            would be iterated character-by-character).
    """

    def __init__(
        self,
        *,
        allowed_commands: Iterable[str] | None = None,
        spawn_keys: tuple[str, ...] = _DEFAULT_SPAWN_KEYS,
        dangerous_env_vars: frozenset[str] | None = None,
        advisory: str | None = None,
        advisory_url: str | None = None,
    ) -> None:
        if isinstance(allowed_commands, str):
            raise TypeError(
                f"allowed_commands must be an iterable of str, not a bare str: {allowed_commands!r}"
            )
        self._allowed_commands: frozenset[str] = frozenset(allowed_commands or ())
        self._spawn_keys = spawn_keys
        self._dangerous_env_vars = (
            dangerous_env_vars if dangerous_env_vars is not None else _DEFAULT_DANGEROUS_ENV_VARS
        )
        self._advisory = advisory
        self._advisory_url = advisory_url

    def evaluate(self, config: Mapping[str, Any] | None) -> McpSubprocessArgDecision:
        """Decide whether an MCP-bridge spawn config may be spawned.

        Args:
            config: The proposed MCP server / tool configuration. ``None``
                or a mapping with no spawn-shaped fields = nothing to
                spawn = allow.

        Returns:
            :class:`McpSubprocessArgDecision`. ``allowed=False`` maps to a
            refusal at the spawn boundary.
        """
        if not config or not isinstance(config, Mapping):
            return self._allow("no spawn config to inspect")

        has_spawn_field = any(key in config for key in self._spawn_keys)
        if not has_spawn_field:
            # A plain data argument — this guard gates the spawn surface only.
            return self._allow("config carries no spawn-shaped fields")

        # 1) Resolve the program: command / cmd, else argv[0] / args[0].
        program = self._resolve_program(config)
        if program is not None:
            field_name, raw = program
            resolved = self._program_name(raw)
            if not self._is_allowed(raw, resolved):
                return self._deny_command(field_name, raw, resolved)

        # 2) Inspect env for code-loading variables (refused regardless of
        #    whether the command was allowlisted — env turns any binary
        #    into an execution primitive).
        env = config.get("env")
        if isinstance(env, Mapping):
            for var in env:
                if isinstance(var, str) and var.upper() in self._dangerous_env_vars:
                    return self._deny_env(var)

        return self._allow("allowlisted static command with clean env")

    # -- internal helpers --------------------------------------------------

    def _resolve_program(self, config: Mapping[str, Any]) -> tuple[str, str] | None:
        """Return ``(field_name, raw_program_string)`` or None if absent."""
        for key in ("command", "cmd"):
            value = config.get(key)
            if isinstance(value, str) and value.strip():
                return key, value
        for key in ("argv", "args"):
            value = config.get(key)
            if isinstance(value, (list, tuple)) and value and isinstance(value[0], str):
                return f"{key}[0]", value[0]
        return None

    @staticmethod
    def _program_name(raw: str) -> str:
        """Resolve the program basename from a raw command string.

        Splits off any inline arguments (``"/bin/sh -c ..."`` → ``"/bin/sh"``)
        and takes the basename (``"/bin/sh"`` → ``"sh"``).
        """
        first_token = raw.strip().split()[0] if raw.strip() else raw
        return os.path.basename(first_token)

    def _is_allowed(self, raw: str, resolved: str) -> bool:
        """True iff the program matches the allowlist by basename or full token."""
        if not self._allowed_commands:
            return False
        first_token = raw.strip().split()[0] if raw.strip() else raw
        return resolved in self._allowed_commands or first_token in self._allowed_commands

    def _allow(self, reason: str) -> McpSubprocessArgDecision:
        return McpSubprocessArgDecision(
            allowed=True,
            verdict=McpSubprocessArgVerdict.ALLOW,
            detail=reason,
        )

    def _deny_command(self, field_name: str, raw: str, resolved: str) -> McpSubprocessArgDecision:
        logger.warning(
            "mcp_subprocess_arg_blocked",
            verdict=McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND.value,
            field=field_name,
            command=resolved,
            advisory=self._advisory,
        )
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints: list[str] = [
            f"{prefix}MCP-bridge config field {field_name!r} would spawn the "
            f"untrusted command {resolved!r}, which is not on the static "
            f"allowlist. Model-/request-controlled command/args/env must never "
            f"be spawned directly.",
            "Pin the spawn to a fixed, vetted command (and fixed args) declared "
            "by the operator, not derived from request input.",
        ]
        if self._allowed_commands:
            hints.append("Allowed static commands: " + ", ".join(sorted(self._allowed_commands)))
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return McpSubprocessArgDecision(
            allowed=False,
            verdict=McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND,
            detail=(
                f"spawn-shaped field {field_name!r} resolves to non-allowlisted "
                f"command {resolved!r} (raw: {raw!r})"
            ),
            matched_field=field_name,
            matched_command=resolved,
            fix_hints=hints,
        )

    def _deny_env(self, var: str) -> McpSubprocessArgDecision:
        logger.warning(
            "mcp_subprocess_arg_blocked",
            verdict=McpSubprocessArgVerdict.DENY_UNTRUSTED_ENV.value,
            field=f"env.{var}",
            advisory=self._advisory,
        )
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints = [
            f"{prefix}MCP-bridge config sets the code-loading environment "
            f"variable {var!r}, which turns the spawned process into an "
            f"execution primitive (preload / search-path / interpreter hook).",
            "Do not pass request-controlled env into a spawn; pin the process "
            "environment to a fixed, vetted set.",
        ]
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return McpSubprocessArgDecision(
            allowed=False,
            verdict=McpSubprocessArgVerdict.DENY_UNTRUSTED_ENV,
            detail=f"spawn config sets code-loading env var {var!r}",
            matched_field=f"env.{var}",
            matched_command=None,
            fix_hints=hints,
        )


__all__ = [
    "McpSubprocessArgDecision",
    "McpSubprocessArgInjectionError",
    "McpSubprocessArgInjectionGuard",
    "McpSubprocessArgVerdict",
]
