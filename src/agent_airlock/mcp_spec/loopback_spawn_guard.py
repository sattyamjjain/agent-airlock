"""MCP loopback session-spawn exec-resolution guard (v0.8.31+, CVE-2026-53820).

CVE-2026-53820 (OpenClaw < 2026.5.12, exec-denylist bypass, CVSS 6.9, CWE-693
Protection Mechanism Failure): the bundled MCP loopback session-spawn path let
an authenticated caller reach a denylisted/restricted command, because the
**surface** command that was checked against the exec restriction differs from
the **effective** command that actually gets spawned. A name that passes the
surface check resolves — through an alias, a wrapper binary (``env`` / ``sudo``
/ ``timeout`` / ``nice`` / ``nohup`` / ...), or a shell invocation — to a
denied executable, and the restriction is bypassed at the spawn boundary.

This is a protection-mechanism-bypass at the spawn seam, **not** a config-time
check. The fix is to re-resolve the effective program immediately before spawn
and re-check *that* against the policy, deny-by-default.

What it does
------------
:meth:`LoopbackSessionSpawnGuard.check_spawn` takes the spawn command (an argv
list or a shell string), unwraps:

- **aliases** — an operator/bundle-supplied ``name -> argv`` map, and
- **wrapper binaries** — ``env`` / ``sudo`` / ``doas`` / ``nice`` / ``nohup``
  / ``timeout`` / ``setsid`` / ``stdbuf`` / ``xargs`` / ``ionice`` / ``chrt`` /
  ``command``, each of which executes a downstream *named* program,

until it reaches the **effective executable**, then re-checks it: a resolved
program on ``denied_commands`` is refused (the bypassed denylist), and any
resolved program not in ``allowed_commands`` is refused (deny-by-default). The
full unwrap is reported on the decision's ``resolution_chain`` so the
"effective differs from surface" bypass is auditable.

Shells (``sh`` / ``bash`` / ``dash`` / ``zsh``) are treated as **terminal**
effective programs, not unwrapped: ``env X=1 bash -c '<denied>'`` resolves to
``bash``, and ``bash`` is what the policy must allow or deny — exactly the
program a ``-c`` payload would execute under.

Why structural (no spawn)
-------------------------
The guard never spawns anything — it resolves the program *name* and checks it.
It carries no execution surface of its own.

Primary sources (retrieved 2026-06-21):
  https://nvd.nist.gov/vuln/detail/CVE-2026-53820
  https://cwe.mitre.org/data/definitions/693.html
"""

from __future__ import annotations

import enum
import os
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.loopback_spawn_guard")

# Wrapper binaries that exec a downstream *named* program. The effective
# command is the wrapped program, not the wrapper.
DEFAULT_WRAPPER_COMMANDS: frozenset[str] = frozenset(
    {
        "env",
        "sudo",
        "doas",
        "nice",
        "nohup",
        "timeout",
        "setsid",
        "stdbuf",
        "xargs",
        "ionice",
        "chrt",
        "command",
        "proot",
    }
)

# Shells that should be denied by an exec restriction (the canonical bypass
# target: a ``-c`` payload runs arbitrary commands). Treated as terminal — a
# shell IS the effective program, never unwrapped to its script argument.
DEFAULT_DENIED_COMMANDS: frozenset[str] = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh", "ash", "busybox"}
)

_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_MAX_UNWRAP = 16


class LoopbackSpawnVerdict(str, enum.Enum):
    """Stable reason codes for :class:`LoopbackSpawnDecision`."""

    ALLOW = "allow"
    DENY_EMPTY_COMMAND = "deny_empty_command"
    DENY_RESOLVED_DENIED = "deny_resolved_denied"  # effective hits the denylist
    DENY_NOT_ALLOWLISTED = "deny_not_allowlisted"  # effective not in the allow set


@dataclass(frozen=True)
class LoopbackSpawnDecision:
    """Outcome of a single :meth:`LoopbackSessionSpawnGuard.check_spawn` call.

    Mirrors the v0.7.x / v0.8.x guard decision family — exposes
    ``allowed: bool`` for chain-friendly composition.

    Attributes:
        allowed: True iff the resolved effective program is permitted.
        verdict: A stable :class:`LoopbackSpawnVerdict` value.
        detail: Free-form human-readable explanation.
        surface_command: The program name as submitted (``argv[0]``).
        effective_command: The resolved program actually spawned.
        resolution_chain: The unwrap steps from surface to effective — the
            evidence that the effective command differs from the surface one.
        fix_hints: Operator-actionable remediation hints.
    """

    allowed: bool
    verdict: LoopbackSpawnVerdict
    detail: str
    surface_command: str | None = None
    effective_command: str | None = None
    resolution_chain: list[str] = field(default_factory=list)
    fix_hints: list[str] = field(default_factory=list)


class LoopbackSessionSpawnError(AirlockError):
    """Raised on a refused spawn (resolved effective command denied; fail-closed).

    Carries the :class:`LoopbackSpawnDecision` and exposes ``fix_hints`` so an
    upstream airlock layer can surface the refusal.

    Attributes:
        decision: The decision that triggered the refusal.
        fix_hints: Operator-actionable remediation hints.
    """

    def __init__(self, decision: LoopbackSpawnDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        super().__init__(decision.detail)


def _norm(name: str) -> str:
    """Program basename, lowercased (``/usr/bin/Bash`` -> ``bash``)."""
    return os.path.basename(name.strip()).lower()


class LoopbackSessionSpawnGuard:
    """Re-check the resolved effective command at the MCP spawn seam (CVE-2026-53820).

    Args:
        allowed_commands: The allow set (deny-by-default). A resolved effective
            program whose basename is not here is refused. Empty (default)
            denies every spawn.
        aliases: Operator/bundle-supplied ``name -> argv`` expansions applied
            during resolution (the alias-redirection bypass vector). Keys are
            matched on basename.
        denied_commands: Explicit exec denylist (the restriction being
            bypassed). A resolved program here is refused even if also
            allow-listed. Defaults to a shell set
            (:data:`DEFAULT_DENIED_COMMANDS`).
        wrapper_commands: Wrapper binaries unwrapped to their downstream
            program. Defaults to :data:`DEFAULT_WRAPPER_COMMANDS`.
        advisory: Advisory / CVE id surfaced in deny ``fix_hints``.
        advisory_url: Optional primary-source URL surfaced alongside.

    Raises:
        TypeError: ``allowed_commands`` / ``denied_commands`` /
            ``wrapper_commands`` is a bare ``str``.
    """

    def __init__(
        self,
        *,
        allowed_commands: Iterable[str] | None = None,
        aliases: Mapping[str, Sequence[str]] | None = None,
        denied_commands: Iterable[str] | None = None,
        wrapper_commands: Iterable[str] | None = None,
        advisory: str | None = "CVE-2026-53820",
        advisory_url: str | None = None,
    ) -> None:
        for label, value in (
            ("allowed_commands", allowed_commands),
            ("denied_commands", denied_commands),
            ("wrapper_commands", wrapper_commands),
        ):
            if isinstance(value, str):
                raise TypeError(f"{label} must be an iterable of str, not a bare str: {value!r}")
        self._allowed: frozenset[str] = frozenset(_norm(c) for c in (allowed_commands or ()))
        self._denied: frozenset[str] = (
            frozenset(_norm(c) for c in denied_commands)
            if denied_commands is not None
            else DEFAULT_DENIED_COMMANDS
        )
        self._wrappers: frozenset[str] = (
            frozenset(_norm(c) for c in wrapper_commands)
            if wrapper_commands is not None
            else DEFAULT_WRAPPER_COMMANDS
        )
        self._aliases: dict[str, list[str]] = {
            _norm(k): list(v) for k, v in (aliases or {}).items()
        }
        self._advisory = advisory
        self._advisory_url = advisory_url

    def check_spawn(self, command: str | Sequence[str]) -> LoopbackSpawnDecision:
        """Resolve the effective program of a spawn command and re-check it.

        Args:
            command: The spawn command — a shell string (``shlex``-split) or a
                pre-split argv sequence.

        Returns:
            :class:`LoopbackSpawnDecision`. ``allowed=False`` maps to a refusal
            of the spawn at the loopback session boundary.
        """
        argv = self._to_argv(command)
        if not argv or not argv[0].strip():
            return LoopbackSpawnDecision(
                allowed=False,
                verdict=LoopbackSpawnVerdict.DENY_EMPTY_COMMAND,
                detail="empty spawn command",
                resolution_chain=[],
                fix_hints=self._hints("Provide an explicit command to spawn."),
            )

        surface = _norm(argv[0])
        effective, chain = self._resolve_effective(argv)

        if effective in self._denied:
            return self._deny(
                LoopbackSpawnVerdict.DENY_RESOLVED_DENIED,
                surface,
                effective,
                chain,
                f"spawn command {surface!r} resolves to denied executable "
                f"{effective!r} — the exec restriction is bypassed at the "
                "loopback session-spawn seam",
            )
        if effective not in self._allowed:
            return self._deny(
                LoopbackSpawnVerdict.DENY_NOT_ALLOWLISTED,
                surface,
                effective,
                chain,
                f"spawn command {surface!r} resolves to {effective!r}, which is "
                "not in the allow set (deny-by-default)",
            )

        return LoopbackSpawnDecision(
            allowed=True,
            verdict=LoopbackSpawnVerdict.ALLOW,
            detail=f"resolved effective command {effective!r} is allow-listed",
            surface_command=surface,
            effective_command=effective,
            resolution_chain=chain,
        )

    def enforce(self, command: str | Sequence[str]) -> None:
        """Raise :class:`LoopbackSessionSpawnError` on a refused spawn."""
        decision = self.check_spawn(command)
        if not decision.allowed:
            raise LoopbackSessionSpawnError(decision)

    # -- internals --------------------------------------------------------

    def _to_argv(self, command: str | Sequence[str]) -> list[str]:
        if isinstance(command, str):
            try:
                return shlex.split(command)
            except ValueError:
                return command.split()
        return [str(part) for part in command]

    def _resolve_effective(self, argv: list[str]) -> tuple[str, list[str]]:
        """Unwrap aliases + wrappers to the effective program; return (name, chain)."""
        chain: list[str] = [" ".join(argv)]
        seen_aliases: set[str] = set()
        for _ in range(_MAX_UNWRAP):
            prog = _norm(argv[0])
            # 1) alias redirection
            if prog in self._aliases and prog not in seen_aliases:
                seen_aliases.add(prog)
                argv = [*self._aliases[prog], *argv[1:]]
                chain.append(f"alias {prog} -> {' '.join(argv)}")
                continue
            # 2) wrapper binary -> downstream named program
            if prog in self._wrappers:
                downstream = self._downstream_after_wrapper(argv)
                if downstream is None:
                    break  # wrapper with no downstream program; it is effective
                argv = downstream
                chain.append(f"wrapper {prog} -> {' '.join(argv)}")
                continue
            break
        return _norm(argv[0]), chain

    def _downstream_after_wrapper(self, argv: list[str]) -> list[str] | None:
        """Return the argv starting at the wrapper's downstream program.

        Skips options (``-x``), env assignments (``K=V``), and pure-numeric
        wrapper arguments (e.g. ``timeout 5`` / ``nice -n 10``). The first
        remaining token is the downstream program. Conservative: an ambiguous
        token is treated as the program (and then checked), never silently
        dropped — deny-by-default means a wrong guess fails safe.
        """
        for i in range(1, len(argv)):
            tok = argv[i]
            if tok.startswith("-"):
                continue
            if _ENV_ASSIGNMENT.match(tok):
                continue
            if tok.isdigit():
                continue
            return argv[i:]
        return None

    def _deny(
        self,
        verdict: LoopbackSpawnVerdict,
        surface: str,
        effective: str,
        chain: list[str],
        detail: str,
    ) -> LoopbackSpawnDecision:
        logger.warning(
            "loopback_spawn_blocked",
            verdict=verdict.value,
            surface=surface,
            effective=effective,
            advisory=self._advisory,
        )
        return LoopbackSpawnDecision(
            allowed=False,
            verdict=verdict,
            detail=detail,
            surface_command=surface,
            effective_command=effective,
            resolution_chain=chain,
            fix_hints=self._hints(
                f"Surface command {surface!r} resolves to {effective!r} before "
                "spawn. Re-check the resolved program against the exec policy; "
                "add it to allowed_commands only if it is genuinely permitted.",
            ),
        )

    def _hints(self, *extra: str) -> list[str]:
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints = [f"{prefix}{extra[0]}", *extra[1:]] if extra else []
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return hints


__all__ = [
    "DEFAULT_DENIED_COMMANDS",
    "DEFAULT_WRAPPER_COMMANDS",
    "LoopbackSessionSpawnError",
    "LoopbackSessionSpawnGuard",
    "LoopbackSpawnDecision",
    "LoopbackSpawnVerdict",
]
