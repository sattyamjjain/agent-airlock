"""MCP STDIO command-injection guard (v0.7.6+, carried from 2026-05-11 prompt).

Snyk ToxicSkills disclosed via Help Net Security 2026-05-05:
"1 in 4 MCP servers opens AI agent security to code execution risk".
MCP STDIO transport accepts an argv vector that often arrives via
the model's tool-call payload — a shell metachar (``;``, ``&&``,
``||``, ``|``, newline, backtick, ``$(``) in any element opens an
injection path. This guard fails-closed on:

1. A **stop-parsing token** (``--%``) as any whole element of
   ``command`` or ``args`` — see below, OR
2. Shell metachars in any element of ``command`` or ``args``, OR
3. Path traversal (``../`` resolving outside an operator-supplied
   cwd allowlist).

Stop-parsing tokens (CVE-2026-19591)
------------------------------------
PowerShell's ``--%`` stops the parser: everything after it is handed to
the native command verbatim, without PowerShell's normal quoting,
variable-expansion or metachar rules. An argv-shaped safety scan
therefore **stops describing what will actually execute** the moment the
token appears, so scanning the remaining elements for metachars answers
a question about a command line that PowerShell will not construct.

That is not a hypothetical. In CVE-2026-19591 (CVSS 8.8, CWE-150) the
OpenAI Codex CLI's command-safety parser lowered PowerShell AST elements
into argv-like words and interpreted ``--%`` differently from PowerShell
itself, so a command it classified *safe* ran without approval — a chain
that ends in a rewritten Codex config launching an attacker-controlled
MCP server. Upstream's fix (openai/codex#22643) does not add ``--%`` to
a metachar list; it treats stop-parsing forms as **unsupported** and
routes them to the conservative path. This guard takes the same
position, which is also its own deny-by-default posture: an argv whose
model has been invalidated is refused, not reasoned about.

Matching is on a **whole argv element**, never a substring, because that
is PowerShell's own rule — ``--%`` is only the stop-parsing token when it
stands alone. Substring matching would deny ordinary arguments that
merely contain the characters (``date +--%Y``,
``curl -w '--%{http_code}'``) while adding no security.

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

from .._log import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.stdio_command_injection_guard")


# Default shell metachar block-list. Operators can extend via
# ``extra_metachars``. Newline + carriage return cover the multi-line
# injection variant where the attacker hides the second command
# after a newline. Backtick + ``$(`` cover command substitution.
DEFAULT_SHELL_METACHARS: frozenset[str] = frozenset({";", "&&", "||", "|", "\n", "\r", "`", "$("})

# Tokens that switch the shell out of its normal parsing rules, so that an
# argv-shaped safety scan no longer describes the command that will run.
# Compared by **whole-element equality**, not substring: ``--%`` is only
# PowerShell's stop-parsing token when it stands alone, so substring matching
# would deny benign arguments that merely contain those characters
# (``date +--%Y``) without blocking anything a substring match would catch.
# See the module docstring and CVE-2026-19591.
DEFAULT_STOP_PARSING_TOKENS: frozenset[str] = frozenset({"--%"})


class StdioCommandInjectionVerdict(str, enum.Enum):
    """Stable reason codes for :class:`StdioCommandInjectionDecision`."""

    ALLOW = "allow"
    DENY_SHELL_METACHAR = "deny_shell_metachar"
    DENY_PATH_TRAVERSAL = "deny_path_traversal"
    DENY_STOP_PARSING_TOKEN = "deny_stop_parsing_token"


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
        matched_stop_parsing_token: The stop-parsing token that fired
            (e.g. ``"--%"``), or ``None`` for every other verdict.
            Optional with a default so adding it did not break the
            three existing construction sites or any caller
            constructing this decision positionally.
    """

    allowed: bool
    verdict: StdioCommandInjectionVerdict
    detail: str
    matched_metachar: str | None
    matched_path: str | None
    matched_stop_parsing_token: str | None = None


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
        stop_parsing_tokens: Frozenset of whole argv elements that
            invalidate the argv model and are refused outright.
            Defaults to :data:`DEFAULT_STOP_PARSING_TOKENS` (``--%``).
            Pass ``frozenset()`` to disable the check for a deployment
            that has no PowerShell reachable from its argv.

    Raises:
        TypeError: ``cwd_allowlist`` is not a tuple, or
            ``extra_metachars`` / ``stop_parsing_tokens`` is not a
            frozenset.
    """

    def __init__(
        self,
        *,
        cwd_allowlist: tuple[str, ...] = (),
        extra_metachars: frozenset[str] = frozenset(),
        stop_parsing_tokens: frozenset[str] = DEFAULT_STOP_PARSING_TOKENS,
    ) -> None:
        if not isinstance(cwd_allowlist, tuple):
            raise TypeError(
                f"cwd_allowlist must be a tuple[str, ...]; got {type(cwd_allowlist).__name__}"
            )
        if not isinstance(extra_metachars, frozenset):
            raise TypeError(
                f"extra_metachars must be a frozenset[str]; got {type(extra_metachars).__name__}"
            )
        if not isinstance(stop_parsing_tokens, frozenset):
            raise TypeError(
                "stop_parsing_tokens must be a frozenset[str]; "
                f"got {type(stop_parsing_tokens).__name__}"
            )
        self._cwd_allowlist = cwd_allowlist
        self._metachars = DEFAULT_SHELL_METACHARS | extra_metachars
        self._stop_parsing_tokens = stop_parsing_tokens

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

        # 0) A stop-parsing token is checked FIRST and by whole-element
        #    equality. It has to come first because once the token is present
        #    the rest of the argv is passed to the native command verbatim, so
        #    a metachar verdict over the remaining elements would be answering
        #    a question about a command line the shell will not build. Refuse
        #    rather than reason about it — the same position upstream took in
        #    openai/codex#22643. See CVE-2026-19591.
        for value in self._argv_strings(args):
            if value in self._stop_parsing_tokens:
                logger.warning(
                    "stdio_command_injection_stop_parsing_token",
                    token=value,
                )
                return StdioCommandInjectionDecision(
                    allowed=False,
                    verdict=StdioCommandInjectionVerdict.DENY_STOP_PARSING_TOKEN,
                    detail=(
                        f"argv element {value!r} is a shell stop-parsing token: everything "
                        f"after it is passed to the native command verbatim, so this argv "
                        f"no longer describes what would execute (CVE-2026-19591 class)"
                    ),
                    matched_metachar=None,
                    matched_path=None,
                    matched_stop_parsing_token=value,
                )

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
        # Normalise the path against a synthetic non-existent root so
        # relative paths like ``../../etc/passwd`` resolve to a definite
        # location for prefix-comparison. NO filesystem IO occurs — the
        # base is never created, opened, or listed; it's only used as
        # the leading component for ``os.path.normpath`` resolution of
        # ``..`` segments. The literal string below is therefore not a
        # "tmp directory usage" in the Bandit B108 sense.
        _SYNTHETIC_BASE_FOR_NORMPATH = "/airlock-synthetic-base-for-normpath"  # nosec B108
        if os.path.isabs(value):
            normalised = os.path.normpath(value)
        else:
            normalised = os.path.normpath(os.path.join(_SYNTHETIC_BASE_FOR_NORMPATH, value))
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
