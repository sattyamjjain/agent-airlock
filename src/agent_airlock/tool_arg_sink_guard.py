"""Shell syntax and package specs in a tool's string arguments (v0.10.28).

Nine MCP server CVEs published on 27 and 28 October 2026 share one shape: a string
argument of an ordinary tool, written by the model, reaches a shell or a package installer
on the server. ai-sdlc interpolates ``repo`` into ``gh issue view`` run through
``execSync`` (CVE-2026-117558); esp-mcp hands ``target``, ``port``, ``project_path`` and
``project_name`` to ``asyncio.create_subprocess_shell`` (CVE-2026-117567); hagent puts
``args`` into ``subprocess.run(shell=True)`` (CVE-2026-117573); functype-mcp-server appends
``version`` to ``functype@`` for ``pnpm add`` and then imports what it installed
(CVE-2026-59176). A prompt-injected agent only has to write ``x; id`` or ``file:../evil``
into the argument.

Until 0.10.28 the call path screened shell syntax only in a stdio spawn's argv
(:class:`~agent_airlock.mcp_spec.stdio_command_injection_guard.StdioCommandInjectionGuard`)
and in a ``SafeURL`` argument; the codebase-mcp check (CVE-2026-5023) is called by hand,
for four tool names. A guarded tool whose ``repo: str`` received ``x; id`` passed every
gate. :class:`ToolArgSinkGuard` reads those arguments at step 2.75 of ``@Airlock``, before
the call reaches a server that builds a command line:

- ``shell_args``, or every argument with ``screen_all_str_args`` except ``free_text_args``,
  may not carry shell syntax: the metacharacters of
  :data:`~agent_airlock.mcp_spec.stdio_command_injection_guard.DEFAULT_SHELL_METACHARS`
  plus ``extra_metachars``.
- ``installer_args`` must be a bare version: a PEP 440 version (:data:`PEP440_VERSION`) or
  an npm semver (:data:`NPM_SEMVER`).
- ``dispatch_args`` names arguments that select a function by name, as Agno's PandasTools
  passed ``create_using_function`` to ``getattr(pandas, ...)`` and ``operation`` to
  ``getattr(dataframe, ...)`` (CVE-2026-119050, CWE-470): ``read_pickle`` is a plain
  identifier, with nothing in it for the checks above. Such an argument must hold one
  identifier its allowlist names or, with an empty allowlist, one that
  :data:`DEFAULT_DISPATCH_DENY` does not match. A dotted path passes only when its
  allowlist names it.

The names are the tool's parameter names (or ``**kwargs`` keys); a positional argument is
read under its parameter's name. Everything a shell or installer argument holds is screened
with it: strings nested in lists, tuples, sets and mappings (keys too) and in the tool's own
models, through the walk the other value gates use (:mod:`agent_airlock._arg_walk`). A
dispatch argument is read as itself, one name.

Honest scope
------------
- It screens text, not how a server quotes it. A server that passes argv without a shell is
  not exposed to these characters, and a value refused there was harmless; that is why
  :func:`agent_airlock.policy_presets.tool_arg_sink_defaults` starts in ``warn`` mode and
  why free text (messages, prompts, file bodies) is opted out by name.
- The default set leaves out quotes, bare ``<`` / ``>`` (``pkg>=1.0`` is benign), ``$VAR``
  expansion and globs. A quote that only closes the server's own quoting injects arguments
  rather than commands; mcp-ffmpeg (CVE-2026-117568) took a closing double quote as well as
  ``$()`` and backticks. Add ``'"'`` and ``"'"`` to ``extra_metachars`` for a server known
  to quote its arguments.
- A value starting with ``-`` (option injection, CWE-88) is not shell syntax and passes.
- Only text is read: strings, bytes, and path and URL objects. A number, or an object the
  host passed, carries no text the model wrote.
- A dispatch argument is read at the top level only: a name inside another argument (a
  model's field, a mapping's value) is not, and one argument holds one name, so a list of
  names is refused. :data:`DEFAULT_DISPATCH_DENY` is a backstop: it cannot see what an
  admitted method does with its parameters (``DataFrame.query``, which it admits,
  evaluates an expression string). An allowlist of the names a tool supports is the
  control.

Primary sources
---------------
https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=MCP&pubStartDate=2026-10-26T00:00:00.000&pubEndDate=2026-10-29T23:59:59.999
https://github.com/jordanburke/functype/security/advisories/GHSA-wcjj-9m6g-2fr2
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-119050
https://github.com/agno-agi/agno/issues/8699
"""

from __future__ import annotations

import enum
import fnmatch
import re
from collections.abc import Collection, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from ._arg_walk import (
    MAX_DEPTH,
    ArgumentName,
    ArgumentNestingError,
    ArgumentValue,
    BoundArguments,
    iter_argument_values,
    path_text,
    url_text,
)
from .mcp_spec.stdio_command_injection_guard import DEFAULT_SHELL_METACHARS

ToolArgSinkMode = Literal["deny", "warn"]

#: A PEP 440 version, matched whole: the regular expression of PEP 440's Appendix B (also
#: ``packaging.version.VERSION_PATTERN``), case-insensitive and ASCII-only. ``1.4.4``,
#: ``2.0.0rc1``, ``1!2.0.post1``, ``1.0+local.7``. No specifier operator: ``>=1.0`` is a
#: range, and ``>`` is redirection to a shell.
PEP440_VERSION = re.compile(
    r"""
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?                           # epoch
        (?P<release>[0-9]+(?:\.[0-9]+)*)                  # release segment
        (?P<pre>                                          # pre-release
            [-_\.]?
            (?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))
            [-_\.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?P<post>                                         # post release
            (?:-(?P<post_n1>[0-9]+))
            |
            (?:
                [-_\.]?
                (?P<post_l>post|rev|r)
                [-_\.]?
                (?P<post_n2>[0-9]+)?
            )
        )?
        (?P<dev>                                          # dev release
            [-_\.]?
            (?P<dev_l>dev)
            [-_\.]?
            (?P<dev_n>[0-9]+)?
        )?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?       # local version
    """,
    re.VERBOSE | re.IGNORECASE | re.ASCII,
)

#: An npm semver, matched whole: the regular expression semver.org suggests for SemVer 2.0.0,
#: after an optional ``^``, ``~`` or ``=`` and an optional ``v``. ``1.4.4``, ``^1.30.0``,
#: ``~2.1.0-beta.1``. ``<`` / ``>`` ranges, ``x`` wildcards and dist-tags (``latest``) are
#: not versions: resolve them on the host.
NPM_SEMVER = re.compile(
    r"[\^~=]?v?"
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*)?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?",
    re.ASCII,
)

# A positional argument the call did not bind to a parameter (``_arg_walk.bind_arguments``
# names it by position). Which parameter it is cannot be known, so it is screened.
_UNATTRIBUTED = re.compile(r"arg\[[0-9]+\]")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*:", re.ASCII)
_DRIVE = re.compile(r"[A-Za-z]:[\\/]", re.ASCII)
_PACKAGE_NAME = re.compile(r"[A-Za-z]", re.ASCII)
_WHITESPACE = re.compile(r"\s")

#: The names a ``dispatch_args`` argument may not hold when its allowlist is empty, matched
#: against the case-folded name with :func:`fnmatch.fnmatchcase`: private and dunder names,
#: the pickle family, file readers and writers (pandas' ``read_*`` and ``to_*``), loaders,
#: code evaluation, process spawning, imports and attribute access. A backstop for a tool
#: whose names were never listed, not a contract (CVE-2026-119050).
DEFAULT_DISPATCH_DENY: frozenset[str] = frozenset(
    {
        "_*",
        "*pickle*",
        "read_*",
        "to_*",
        "load",
        "loads",
        "load_*",
        "eval",
        "exec",
        "compile",
        "system",
        "popen",
        "spawn*",
        "open",
        "import_module",
        "__import__",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
        "breakpoint",
    }
)

# A dispatch name is one ASCII identifier, and an allowlist entry an identifier or a dotted
# path of them. Matched with ``fullmatch``: a ``$`` anchor also matches before a trailing
# newline, so ``re.match(r"^[A-Za-z_]\w*$", "head\n")`` succeeds.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)
_DOTTED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", re.ASCII)
_NOT_A_NAME_CHARACTER = re.compile(r"[^A-Za-z0-9_]", re.ASCII)
# A refused name is shown, so a retry knows what was refused; one longer than this is cut.
_SHOWN_NAME_LENGTH = 64
# How many allowed names a refusal lists before it says how many more there are.
_LISTED_NAMES = 20


class ToolArgSinkVerdict(str, enum.Enum):
    """Stable reason codes for :class:`ToolArgSinkDecision`."""

    ALLOW = "allow"
    DENY_SHELL_METACHAR = "deny_shell_metachar"
    DENY_NOT_A_VERSION = "deny_not_a_version"
    DENY_DISPATCH_NAME = "deny_dispatch_name"
    DENY_UNINSPECTABLE = "deny_uninspectable"


@dataclass(frozen=True)
class ToolArgSinkDecision:
    """Outcome of :meth:`ToolArgSinkGuard.evaluate`.

    Attributes:
        allowed: True when nothing was found. A finding is reported in either mode;
            ``@Airlock`` refuses it in ``deny`` mode and logs it in ``warn`` mode.
        verdict: A stable :class:`ToolArgSinkVerdict`.
        detail: What was found and where. It names the argument and the offending token,
            never the whole value.
        argument: Where the finding sits: ``"repo"``, ``"paths[1]"``, ``"config.target"``.
        token: The text that tripped it: a metacharacter (``";"``, ``"$("``); for an
            installer argument the scheme, separator or character that is not a version;
            for a dispatch argument the refused name, or the character that keeps it from
            being one.
        fix_hints: What the caller can send instead.
    """

    allowed: bool
    verdict: ToolArgSinkVerdict
    detail: str
    argument: str | None = None
    token: str | None = None
    fix_hints: tuple[str, ...] = ()


_ALLOW = ToolArgSinkDecision(
    allowed=True, verdict=ToolArgSinkVerdict.ALLOW, detail="no shell syntax or package spec"
)


@dataclass(frozen=True)
class ToolArgSinkGuard:
    """Refuse shell syntax, anything but a version, and callable names a tool must not call.

    Set it on :attr:`agent_airlock.SecurityPolicy.tool_arg_sink_guard`; ``@Airlock`` runs it
    as step 2.75, after the deserialization guard. Name the arguments a server splices into a
    command line, or screen every string argument and name the free-text ones instead, and
    name the arguments a tool turns into a function call::

        SecurityPolicy(tool_arg_sink_guard=ToolArgSinkGuard(shell_args={"repo"}))
        SecurityPolicy(
            tool_arg_sink_guard=ToolArgSinkGuard(
                screen_all_str_args=True,
                free_text_args={"message"},
                installer_args={"version"},
            )
        )
        SecurityPolicy(
            tool_arg_sink_guard=ToolArgSinkGuard(
                dispatch_args={"operation": ("head", "describe")},
            )
        )

    Attributes:
        shell_args: Argument names screened for shell syntax.
        screen_all_str_args: Screen every argument for shell syntax, except
            ``free_text_args``.
        free_text_args: Arguments ``screen_all_str_args`` leaves alone: messages, prompts,
            file bodies. Only meaningful with ``screen_all_str_args``.
        installer_args: Arguments that must be a bare version (:data:`PEP440_VERSION` or
            :data:`NPM_SEMVER`). A URL, a path, ``git+``, ``@``, whitespace, extras
            (``[...]``), a package name and any metacharacter are refused. None (no version
            given) passes.
        extra_metachars: Tokens refused on top of :data:`DEFAULT_SHELL_METACHARS`, such as
            ``'"'`` for a server that wraps arguments in double quotes, or ``">"`` to refuse
            redirection.
        mode: ``"deny"`` refuses a call with a finding (block reason ``tool_arg_sink``);
            ``"warn"`` logs it and runs the call.
        dispatch_args: Arguments that name a function the tool calls, each mapped to the
            names it may hold: ``{"operation": ("head", "describe")}``. The argument must
            hold one identifier (a dotted path only if listed), in its allowlist exactly;
            an empty allowlist admits any identifier :data:`DEFAULT_DISPATCH_DENY` does not
            match. A non-string value, ``None`` included, is refused; an argument the call
            does not pass is not read. Stored as a read-only mapping of frozensets.

    Each name set accepts any collection of strings and is stored as a ``frozenset``.

    Raises:
        TypeError: A name set, or a ``dispatch_args`` allowlist, is a single string or holds
            a non-string; ``dispatch_args`` is not a mapping or has a key that is not a
            string; or ``screen_all_str_args`` is not a bool.
        ValueError: ``mode`` is not ``"deny"`` or ``"warn"``; a name or metacharacter is
            empty; an argument is named both free text and screened, or both a dispatch
            argument and free text or an installer argument; an allowlist entry is not an
            identifier or a dotted path of them; ``free_text_args`` is set without
            ``screen_all_str_args``; or the guard screens nothing.
    """

    shell_args: frozenset[str] = frozenset()
    screen_all_str_args: bool = False
    free_text_args: frozenset[str] = frozenset()
    installer_args: frozenset[str] = frozenset()
    extra_metachars: frozenset[str] = frozenset()
    mode: ToolArgSinkMode = "deny"
    dispatch_args: Mapping[str, Collection[str]] = field(default_factory=dict)
    _ordered: tuple[str, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        for name in ("shell_args", "free_text_args", "installer_args", "extra_metachars"):
            object.__setattr__(self, name, _string_set(getattr(self, name), name))
        object.__setattr__(self, "dispatch_args", _dispatch_names(self.dispatch_args))
        if not isinstance(self.screen_all_str_args, bool):
            raise TypeError(
                f"screen_all_str_args must be a bool; got {type(self.screen_all_str_args).__name__}"
            )
        if self.mode not in ("deny", "warn"):
            raise ValueError(f"mode must be 'deny' or 'warn'; got {self.mode!r}")
        for screened in ("shell_args", "installer_args"):
            both = sorted(self.free_text_args & getattr(self, screened))
            if both:
                raise ValueError(f"{both} named in both free_text_args and {screened}")
        dispatch = frozenset(self.dispatch_args)
        for other in ("free_text_args", "installer_args"):
            both = sorted(dispatch & getattr(self, other))
            if both:
                raise ValueError(f"{both} named in both dispatch_args and {other}")
        if self.free_text_args and not self.screen_all_str_args:
            raise ValueError(
                "free_text_args only exempts arguments from screen_all_str_args: set "
                "screen_all_str_args=True, or drop free_text_args"
            )
        if not (
            self.shell_args or self.installer_args or self.dispatch_args or self.screen_all_str_args
        ):
            raise ValueError(
                "this ToolArgSinkGuard screens nothing: name shell_args, installer_args or "
                "dispatch_args, or set screen_all_str_args=True"
            )
        # Longest first, then alphabetical, as in the stdio guard: "&&" reports before "&",
        # and the token reported does not depend on frozenset iteration order.
        ordered = sorted(self.metachars, key=lambda token: (-len(token), token))
        object.__setattr__(self, "_ordered", tuple(ordered))

    @property
    def metachars(self) -> frozenset[str]:
        """Every token refused as shell syntax: the default set plus ``extra_metachars``."""
        return DEFAULT_SHELL_METACHARS | self.extra_metachars

    def evaluate(self, arguments: Mapping[str, Any] | None) -> ToolArgSinkDecision:
        """Screen a call's arguments and report the first value this guard refuses.

        ``@Airlock`` passes every argument by name (``_arg_walk.bind_arguments``), so a
        positional argument is read under its parameter's name. A ``dispatch_args``
        argument is read first, as one name (CVE-2026-119050). This only reports: the
        caller applies :attr:`mode`.

        Args:
            arguments: The call's arguments by name. None means no arguments.

        Returns:
            The first finding, or an allowing decision. Input the walk cannot read (nested
            deeper than ``_arg_walk.MAX_DEPTH``, self-containing, or not a mapping at all)
            is reported as :attr:`ToolArgSinkVerdict.DENY_UNINSPECTABLE`.
        """
        if arguments is None:
            return _ALLOW
        if not isinstance(arguments, Mapping):
            kind = type(arguments).__name__
            return _refusal(
                ToolArgSinkVerdict.DENY_UNINSPECTABLE,
                f"call arguments are a {kind}, not a mapping; a shape this guard cannot "
                "read is refused, not skipped",
                hints=("Pass the tool's arguments by name",),
            )
        named = getattr(arguments, "named_models", None)
        for name, value in arguments.items():
            key = name.key if isinstance(name, ArgumentName) else str(name)
            if self.screen_all_str_args:
                # A ``**kwargs`` key is text the caller chose, and a server that turns keyword
                # arguments into flags puts it on the command line too. Not echoed back.
                token = self._metachar_in(key)
                if token is not None:
                    return _shell_refusal(None, "an argument name", token, installer=False)
            allowed = self.dispatch_args.get(key)
            if allowed is not None:
                finding = _dispatch_finding(str(name), key, value, allowed)
                if finding is not None:
                    return finding
            installer, shell = self._reads(name, key)
            if not shell:
                continue
            # One argument at a time, so a value is screened by the argument it sits in,
            # not by the nearest mapping key (``config={"repo": ...}`` is read as config).
            argument = BoundArguments({name: value})
            argument.named_models = named
            try:
                for leaf in iter_argument_values(argument):
                    # A mapping key's path spells the key out; name its argument instead.
                    place = (
                        (str(name), f"a mapping key in argument {str(name)!r}")
                        if leaf.is_key
                        else (leaf.path, f"argument {leaf.path!r}")
                    )
                    finding = (
                        self._installer_finding(leaf, *place)
                        if installer
                        else self._finding(leaf, *place)
                    )
                    if finding is not None:
                        return finding
            except ArgumentNestingError as error:
                return _refusal(
                    ToolArgSinkVerdict.DENY_UNINSPECTABLE,
                    f"argument {error.path!r} cannot be screened: {error.reason}",
                    argument=error.path,
                    hints=(
                        f"Argument {error.path!r} is nested too deeply or contains itself; "
                        f"pass plain strings, in containers nested no deeper than "
                        f"{MAX_DEPTH} levels with no self-references",
                    ),
                )
        return _ALLOW

    def _reads(self, name: Any, key: str) -> tuple[bool, bool]:
        """Whether the argument bound as ``name`` is an installer one, and whether it is read."""
        if key in self.installer_args:
            return True, True
        if key in self.shell_args:
            return False, True
        if not isinstance(name, ArgumentName) and _UNATTRIBUTED.fullmatch(key):
            return False, True
        return False, self.screen_all_str_args and key not in self.free_text_args

    def _finding(
        self, leaf: ArgumentValue, argument: str, where: str
    ) -> ToolArgSinkDecision | None:
        text, unreadable = _text_of(leaf, argument, where)
        if unreadable is not None:
            return unreadable
        if text is None:
            return None
        token = self._metachar_in(text)
        if token is None:
            return None
        return _shell_refusal(argument, where, token, installer=False)

    def _installer_finding(
        self, leaf: ArgumentValue, argument: str, where: str
    ) -> ToolArgSinkDecision | None:
        if leaf.value is None:
            return None  # no version given: nothing reaches the installer
        text, unreadable = _text_of(leaf, argument, where)
        if unreadable is not None:
            return unreadable
        if text is None:
            what = f"not a string ({type(leaf.value).__name__})"
            return _version_refusal(argument, where, what, None)
        token = self._metachar_in(text)
        if token is not None:
            return _shell_refusal(argument, where, token, installer=True)
        problem = _version_problem(text)
        if problem is None:
            return None
        return _version_refusal(argument, where, *problem)

    def _metachar_in(self, text: str) -> str | None:
        for token in self._ordered:
            if token in text:
                return token
        return None


def _string_set(value: Any, name: str) -> frozenset[str]:
    """``value`` as a frozenset of non-empty strings; a lone string is refused, not split."""
    if isinstance(value, (str, bytes)):
        raise TypeError(
            f"{name} takes a collection of strings, not one {type(value).__name__}: "
            f"write {name}={{{value!r}}}"
        )
    if not isinstance(value, Iterable):
        raise TypeError(f"{name} must be a collection of strings; got {type(value).__name__}")
    items = frozenset(value)
    for item in items:
        if not isinstance(item, str):
            raise TypeError(f"{name} must hold strings; got a {type(item).__name__}")
        if not item:
            raise ValueError(
                f"{name} holds an empty string"
                + (", which every value contains" if name == "extra_metachars" else "")
            )
    return items


def _text_of(
    leaf: ArgumentValue, argument: str, where: str
) -> tuple[str | None, ToolArgSinkDecision | None]:
    """The text a leaf carries (None for a number or another object), or a refusal.

    A ``str`` subclass is read as the characters it holds, past any ``__str__`` or
    ``__contains__`` it overrides; bytes as Latin-1, which maps every byte to one character
    so no metacharacter is lost; a URL or path object as its text. One whose text cannot be
    read is refused rather than skipped.
    """
    value = leaf.value
    try:
        if isinstance(value, str):
            return str.__str__(value), None
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).decode("latin-1"), None
        text = url_text(value)
        return (text if text is not None else path_text(value)), None
    except Exception as error:  # noqa: BLE001 - an unreadable value is refused, not skipped
        return None, _refusal(
            ToolArgSinkVerdict.DENY_UNINSPECTABLE,
            f"{where} cannot be read as text ({type(error).__name__})",
            argument=argument,
            hints=(f"Pass {where} as a plain string",),
        )


def _version_problem(text: str) -> tuple[str, str | None] | None:
    """Why ``text`` is not a bare version, and the token that shows it; None when it is."""
    if PEP440_VERSION.fullmatch(text) or NPM_SEMVER.fullmatch(text):
        return None
    if not text:
        return "it is empty", None
    if text[:4].lower() == "git+":
        return "a VCS reference", text[:4]
    if _DRIVE.match(text):
        return "a path", text[:3]
    scheme = _SCHEME.match(text)
    if scheme:
        return "a URL or package protocol", scheme.group(0)
    if "@" in text:  # before the separators: ``@scope/pkg`` is a package, not a path
        return "a package@version or scoped package name", "@"
    for separator in ("/", "\\"):
        if separator in text:
            return "a path", separator
    if text[0] in ".~":
        return "a path", text[0]
    space = _WHITESPACE.search(text)
    if space:
        return "whitespace, which separates a second argument or package", space.group(0)
    for bracket in ("[", "]"):
        if bracket in text:
            return "package extras", bracket
    if _PACKAGE_NAME.match(text):
        return "a package name or tag, not a version", None
    return "not a PEP 440 version or an npm semver", None


def _refusal(
    verdict: ToolArgSinkVerdict,
    detail: str,
    *,
    argument: str | None = None,
    token: str | None = None,
    hints: tuple[str, ...],
) -> ToolArgSinkDecision:
    return ToolArgSinkDecision(
        allowed=False,
        verdict=verdict,
        detail=detail,
        argument=argument,
        token=token,
        fix_hints=hints,
    )


def _shell_refusal(
    argument: str | None, where: str, token: str, *, installer: bool
) -> ToolArgSinkDecision:
    hints = (
        f"Remove {token!r} from {where}: it reaches a command line, so shell syntax "
        "(separators, pipes, substitution, line breaks) is refused",
        *(_VERSION_HINTS if installer else ("Send the plain value only",)),
    )
    return _refusal(
        ToolArgSinkVerdict.DENY_SHELL_METACHAR,
        f"{where} carries shell syntax {token!r}",
        argument=argument,
        token=token,
        hints=hints,
    )


def _version_refusal(
    argument: str, where: str, what: str, token: str | None
) -> ToolArgSinkDecision:
    shown = f" ({token!r})" if token is not None else ""
    return _refusal(
        ToolArgSinkVerdict.DENY_NOT_A_VERSION,
        f"{where} is not a bare version: {what}{shown}",
        argument=argument,
        token=token,
        hints=(f"Send {where} as a bare version only", *_VERSION_HINTS),
    )


_VERSION_HINTS = (
    "A bare version looks like 1.4.4, 2.0.0rc1 or ^1.30.0: no URL, path, package name, "
    "'@', extras or whitespace",
)


class _DispatchNames(Mapping[str, frozenset[str]]):
    """``dispatch_args`` as stored: read-only, and hashable, so the frozen guard stays so."""

    def __init__(self, names: Mapping[str, frozenset[str]]) -> None:
        self._names = dict(names)

    def __getitem__(self, key: str) -> frozenset[str]:
        return self._names[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._names)

    def __len__(self) -> int:
        return len(self._names)

    def __hash__(self) -> int:
        return hash(frozenset(self._names.items()))

    def __repr__(self) -> str:
        return repr(self._names)


def _dispatch_names(value: Any) -> _DispatchNames:
    """``dispatch_args`` checked: each argument name mapped to a frozenset of allowed names."""
    if not isinstance(value, Mapping):
        raise TypeError(
            "dispatch_args maps each argument that names a function to the names it may "
            "hold, such as {'operation': ('head', 'describe')}, or {'operation': ()} for the "
            f"default denylist; got a {type(value).__name__}"
        )
    names: dict[str, frozenset[str]] = {}
    for key, allowed in value.items():
        if not isinstance(key, str):
            raise TypeError(f"dispatch_args keys are argument names; got a {type(key).__name__}")
        if not key:
            raise ValueError("dispatch_args holds an empty argument name")
        entries = _string_set(allowed, f"dispatch_args[{key!r}]")
        for entry in sorted(entries):
            if not _DOTTED_NAME.fullmatch(entry):
                raise ValueError(
                    f"dispatch_args[{key!r}] allows {entry!r}, which is not an identifier or "
                    "a dotted path of them"
                )
        names[key] = entries
    return _DispatchNames(names)


def _dispatch_finding(
    argument: str, key: str, value: Any, allowed: Collection[str]
) -> ToolArgSinkDecision | None:
    """Refuse a dispatch argument that does not hold one name the tool may call."""
    where = f"argument {argument!r}"
    if not isinstance(value, str):
        return _dispatch_refusal(
            argument,
            f"{where} is not a string ({type(value).__name__}): it must name one operation",
            None,
            (f"Send {where} as one operation name, a string such as 'head'",),
        )
    # The characters it holds, past any __eq__ or __hash__ a str subclass overrides: those
    # decide frozenset membership, and could claim a name the allowlist does not hold.
    name = str.__str__(value)
    if allowed and name in allowed:
        return None
    shown = _shown(name) if _DOTTED_NAME.fullmatch(name) else None
    add_it = f"If {shown!r} is meant, add it to dispatch_args[{key!r}] in this tool's guard"
    if allowed:
        accepted = f"Choose one of the operations this tool accepts: {_listed(allowed)}"
        if shown is None:
            what, token = _name_problem(name)
            return _dispatch_refusal(
                argument,
                f"{where} is not an operation this tool accepts: {what}",
                token,
                (accepted,),
            )
        return _dispatch_refusal(
            argument,
            f"{where} names {shown!r}, which is not an operation this tool accepts",
            shown,
            (accepted, add_it),
        )
    if shown is None:
        what, token = _name_problem(name)
        return _dispatch_refusal(
            argument,
            f"{where} is not a bare name: {what}",
            token,
            (
                "Send one operation name: letters, digits and underscores, not starting with a digit",
            ),
        )
    if not _IDENTIFIER.fullmatch(name):
        return _dispatch_refusal(
            argument,
            f"{where} names a dotted path, {shown!r}, which only an allowlist can admit",
            shown,
            ("Send a bare operation name, such as 'head'", add_it),
        )
    if not _denied(name):
        return None
    # The pattern that matched is not named: a refusal withholds what it denies (0.10.25).
    return _dispatch_refusal(
        argument,
        f"{where} names {shown!r}, which this tool calls only if its allowlist names it",
        shown,
        (
            "Choose a different operation",
            f"If {shown!r} is meant, list the operations this tool accepts in "
            f"dispatch_args[{key!r}]: an allowlist replaces the default denylist",
        ),
    )


def _name_problem(name: str) -> tuple[str, str | None]:
    """Why ``name`` is not an identifier, and the character that shows it; never the name."""
    if not name:
        return "it is empty", None
    bad = _NOT_A_NAME_CHARACTER.search(name)
    if bad is not None:
        return f"it holds {bad.group()!r}, which a name cannot", bad.group()
    return "it starts with a digit", name[0]


def _shown(name: str) -> str:
    """A refused name as a refusal shows it: whole, unless it is longer than a name needs."""
    if len(name) <= _SHOWN_NAME_LENGTH:
        return name
    return name[:_SHOWN_NAME_LENGTH] + "..."


def _listed(allowed: Collection[str]) -> str:
    """The allowed names, sorted, the first :data:`_LISTED_NAMES` of them."""
    names = sorted(allowed)
    more = len(names) - _LISTED_NAMES
    return ", ".join(names[:_LISTED_NAMES]) + (f" and {more} more" if more > 0 else "")


def _denied(name: str) -> bool:
    """Whether :data:`DEFAULT_DISPATCH_DENY` matches ``name``, case-folded."""
    folded = name.casefold()
    return any(fnmatch.fnmatchcase(folded, pattern) for pattern in DEFAULT_DISPATCH_DENY)


def _dispatch_refusal(
    argument: str, detail: str, token: str | None, hints: tuple[str, ...]
) -> ToolArgSinkDecision:
    return _refusal(
        ToolArgSinkVerdict.DENY_DISPATCH_NAME,
        detail,
        argument=argument,
        token=token,
        hints=hints,
    )


__all__ = [
    "DEFAULT_DISPATCH_DENY",
    "NPM_SEMVER",
    "PEP440_VERSION",
    "ToolArgSinkDecision",
    "ToolArgSinkGuard",
    "ToolArgSinkMode",
    "ToolArgSinkVerdict",
]
