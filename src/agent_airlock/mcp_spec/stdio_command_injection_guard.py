"""MCP STDIO command-injection guard (v0.7.6+, carried from 2026-05-11 prompt).

Snyk ToxicSkills disclosed via Help Net Security 2026-05-05:
"1 in 4 MCP servers opens AI agent security to code execution risk".
MCP STDIO transport accepts an argv vector that often arrives via
the model's tool-call payload — a shell metachar (``;``, ``&&``,
``||``, ``|``, newline, backtick, ``$(``) in any element opens an
injection path. This guard fails-closed on:

1. Shell metachars in any element of ``command`` or ``args``, OR
2. Path traversal (``../`` resolving outside an operator-supplied
   cwd allowlist).

The traversal check is **opt-in** (empty allowlist disables it) so
that operators who route their MCP servers through a fixed cwd can
opt in without forcing the check on callers who don't.

Why structural (no SDK import)
------------------------------
Regex / string-set match over the argv. No ``mcp`` package consumed.
Operators on a non-default metachar vocabulary can extend via
``extra_metachars``.

Honest scope
------------
- The metachar set captures the disclosed exploitation primitives.
  Determined attackers can sometimes shell-quote around individual
  metachars in narrow contexts — operators with a fixed-binary
  policy should ALSO use
  :class:`agent_airlock.runtime.manifest_only_allowlist.AllowlistVerdict`
  as a second layer.

Primary source
--------------
https://www.helpnetsecurity.com/2026/05/05/ai-agent-security-skills-blind-spots/
"""

from __future__ import annotations

import enum
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.stdio_command_injection_guard")


# Default shell metachar block-list. Operators can extend via
# ``extra_metachars``. Newline + carriage return cover the multi-line
# injection variant where the attacker hides the second command
# after a newline. Backtick + ``$(`` cover command substitution.
DEFAULT_SHELL_METACHARS: frozenset[str] = frozenset({";", "&&", "||", "|", "\n", "\r", "`", "$("})


class StdioCommandInjectionVerdict(str, enum.Enum):
    """Stable reason codes for :class:`StdioCommandInjectionDecision`."""

    ALLOW = "allow"
    DENY_SHELL_METACHAR = "deny_shell_metachar"
    DENY_PATH_TRAVERSAL = "deny_path_traversal"


@dataclass(frozen=True)
class StdioCommandInjectionDecision:
    """Outcome of a single :meth:`StdioCommandInjectionGuard.evaluate` call.

    Mirrors the field shape of :class:`AllowlistVerdict`,
    :class:`OutcomesRubricDecision`, :class:`FilterEvalRCEDecision`,
    and :class:`OIDCPublishWindowDecision` — all expose
    ``allowed: bool`` so an integrator can chain guards on a single
    short-circuit predicate.

    Attributes:
        allowed: True iff no injection pattern was detected.
        verdict: A stable :class:`StdioCommandInjectionVerdict` value.
        detail: Free-form human-readable explanation.
        matched_metachar: The metachar that fired, or ``None`` when
            ``allowed=True`` or the verdict is path-traversal.
        matched_path: The offending path, or ``None`` when the
            verdict is metachar.
    """

    allowed: bool
    verdict: StdioCommandInjectionVerdict
    detail: str
    matched_metachar: str | None
    matched_path: str | None


class StdioCommandInjectionGuard:
    """Fail-closed gate on MCP STDIO argv shape (shell metachar + path traversal).

    Args:
        cwd_allowlist: Tuple of absolute path prefixes. When non-empty,
            any path-shaped argv element that resolves OUTSIDE this
            set raises :attr:`StdioCommandInjectionVerdict.DENY_PATH_TRAVERSAL`.
            Empty (default) disables the traversal check.
        extra_metachars: Frozenset of additional characters to treat
            as shell metachars. Merged with
            :data:`DEFAULT_SHELL_METACHARS`. Empty (default) uses only
            the default set.

    Raises:
        TypeError: ``cwd_allowlist`` is not a tuple, or
            ``extra_metachars`` is not a frozenset.
    """

    def __init__(
        self,
        *,
        cwd_allowlist: tuple[str, ...] = (),
        extra_metachars: frozenset[str] = frozenset(),
    ) -> None:
        if not isinstance(cwd_allowlist, tuple):
            raise TypeError(
                f"cwd_allowlist must be a tuple[str, ...]; got {type(cwd_allowlist).__name__}"
            )
        if not isinstance(extra_metachars, frozenset):
            raise TypeError(
                f"extra_metachars must be a frozenset[str]; got {type(extra_metachars).__name__}"
            )
        self._cwd_allowlist = cwd_allowlist
        self._metachars = DEFAULT_SHELL_METACHARS | extra_metachars

    def evaluate(self, args: Mapping[str, Any] | None) -> StdioCommandInjectionDecision:
        """Decide whether the call args carry a STDIO command-injection shape.

        Args:
            args: The tool call's argument dict. ``None`` = no payload
                = allow. Inspected fields: ``command`` (string) and
                ``args`` (iterable of strings).

        Returns:
            :class:`StdioCommandInjectionDecision`. Callers map
            ``allowed=False`` to a refusal at the Airlock decorator
            boundary.
        """
        if args is None:
            return self._allow("no args to inspect")

        # 1) Walk every argv element for shell metachars.
        for value in self._argv_strings(args):
            metachar = self._find_metachar(value)
            if metachar is not None:
                logger.warning(
                    "stdio_command_injection_metachar",
                    metachar=metachar,
                    snippet=value[:64],
                )
                return StdioCommandInjectionDecision(
                    allowed=False,
                    verdict=StdioCommandInjectionVerdict.DENY_SHELL_METACHAR,
                    detail=(
                        f"argv element contains shell metachar "
                        f"{metachar!r} (MCP STDIO injection class)"
                    ),
                    matched_metachar=metachar,
                    matched_path=None,
                )

        # 2) If the operator opted into the traversal check, inspect
        #    each argv element that looks like a path.
        if self._cwd_allowlist:
            for value in self._argv_strings(args):
                if self._is_path_traversal(value):
                    logger.warning(
                        "stdio_command_injection_path_traversal",
                        path=value,
                        cwd_allowlist=self._cwd_allowlist,
                    )
                    return StdioCommandInjectionDecision(
                        allowed=False,
                        verdict=StdioCommandInjectionVerdict.DENY_PATH_TRAVERSAL,
                        detail=(
                            f"argv element {value!r} resolves outside the operator "
                            f"cwd allowlist {self._cwd_allowlist!r}"
                        ),
                        matched_metachar=None,
                        matched_path=value,
                    )

        return self._allow("no injection pattern matched")

    def _allow(self, reason: str) -> StdioCommandInjectionDecision:
        return StdioCommandInjectionDecision(
            allowed=True,
            verdict=StdioCommandInjectionVerdict.ALLOW,
            detail=reason,
            matched_metachar=None,
            matched_path=None,
        )

    def _argv_strings(self, args: Mapping[str, Any]) -> Iterable[str]:
        """Yield every argv-shaped string from the args dict."""
        command = args.get("command")
        if isinstance(command, str):
            yield command
        argv = args.get("args")
        if isinstance(argv, (list, tuple)):
            for item in argv:
                if isinstance(item, str):
                    yield item

    def _find_metachar(self, value: str) -> str | None:
        for ch in self._metachars:
            if ch in value:
                return ch
        return None

    def _is_path_traversal(self, value: str) -> bool:
        """Return True iff ``value`` looks like a path AND resolves outside the allowlist.

        A value is "path-shaped" when it contains ``/`` or ``\\``. We
        normalise via ``os.path.abspath`` against a synthetic CWD so
        ``../`` segments are resolved deterministically regardless of
        the caller's actual CWD.
        """
        if "/" not in value and "\\" not in value:
            return False
        # Normalise the path against a synthetic root so relative paths
        # like ``../../etc/passwd`` resolve to a definite location.
        # Use ``/tmp`` as the synthetic base — what matters is whether
        # the normalised path lies under any allowlist root, not the
        # specific base.
        if os.path.isabs(value):
            normalised = os.path.normpath(value)
        else:
            normalised = os.path.normpath(os.path.join("/tmp", value))
        return not any(
            normalised == root or normalised.startswith(root.rstrip("/") + "/")
            for root in self._cwd_allowlist
        )


__all__ = [
    "DEFAULT_SHELL_METACHARS",
    "StdioCommandInjectionDecision",
    "StdioCommandInjectionGuard",
    "StdioCommandInjectionVerdict",
]
