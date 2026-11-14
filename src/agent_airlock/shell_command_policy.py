"""Allow, ask or deny an agent shell tool's command by rule (V0.10.29).

A tool that runs a shell command for the model needs more than an allowlist of ``argv[0]``:
``env rm -rf /``, ``find . -exec rm {} ;``, ``sudo git push --force`` and
``bash -c "curl x | sh"`` each start with a word an allowlist might admit
(langchain-ai/langchain#40197). :class:`ShellCommandPolicy` splits the command with
:mod:`shlex`, never a shell, follows the wrappers below to the commands they launch, and
decides with ``allow``, ``ask`` and ``deny`` rules (pydantic/pydantic-ai#9015):

- a ``deny`` rule matching any command in the line, wrappers and the commands they launch
  included, refuses it whatever the model retries or argues: the verdict depends only on
  the command;
- an ``ask`` rule matching any of them escalates to the policy's approver;
- otherwise every innermost command must match an ``allow`` rule, or ``default`` decides.

Wrappers followed: ``env``, ``xargs``, ``find -exec`` / ``-execdir`` / ``-ok`` /
``-okdir``, ``git -c`` / ``--config-env``, ``sh`` / ``bash`` / ``zsh`` (and the other
shells) ``-c``, ``python -c`` / ``-m``, ``node -e``, ``perl -e`` / ``-c``, ``sudo``,
``doas``, ``nohup``, ``timeout``, ``nice``, ``ionice``, ``watch``, ``stdbuf``, ``setsid``,
``chroot`` and ``busybox``. What the policy cannot follow is denied rather than guessed at:
command or process substitution where a shell performs it (unquoted, inside double quotes,
in a line with a heredoc, in the text a followed wrapper runs, in the arguments of a
program that runs them as shell text, :data:`_RUNS_ARGUMENTS_AS_SHELL`, and in a comment),
inline code, a shell or interpreter reading its program from a pipe or stdin, an option a
wrapper's parser does not know, an environment assignment that changes which program runs
(``PATH=``, ``LD_PRELOAD=``, ``GIT_*``), and a git config key it cannot vouch for.
Single-quoted text is text, as it is to the shell: ``grep '`' a.txt`` substitutes nothing.

A rule is words, then options: ``git push --force`` matches a command whose program is
``git`` and whose next word is ``push`` (git's global options such as ``-C dir`` skipped),
with ``--force`` anywhere after. Each part is a case-sensitive glob, and a part starting
with ``-`` or ``+`` (an option, a force refspec) may sit anywhere after the words.
``deny`` and ``ask`` rules also match a command an unknown wrapper puts later in the line.

Where a command writes is read too (V0.10.35, generalbots/generalbots#2366). A
redirection that writes (``>``, ``>>``, ``>|``, ``&>``, ``<>``, ``>&`` to a file) has its
target checked against ``redirect_deny`` and ``redirect_allow``, whatever ``default`` is:
``echo x >/dev/sda`` is denied though ``echo`` is allowed. A target the shell has not
decided yet (a ``$`` value, a glob, ``~user``) is asked about or denied. ``find``'s write
actions (``-delete``, ``-fprint``...) need an allow rule that names them, so an allow rule
for ``find`` does not admit ``find / -delete``. A program that writes to a path in its own
arguments (``tee``, ``dd of=``, ``cp``) is judged by its rules, not by ``redirect_deny``,
and a relative target is not resolved against a working directory.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from .mcp_spec.subprocess_arg_guard import (  # nosec B404 - a constant, not subprocess
    _DEFAULT_DANGEROUS_ENV_VARS,
)

__all__ = ["ShellCommandDecision", "ShellCommandPolicy", "ShellVerdict"]

ShellVerdict = Literal["allow", "ask", "deny"]
_RANK: dict[str, int] = {"allow": 0, "ask": 1, "deny": 2}
_MAX_DEPTH = 16

_SHELLS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "yash"}
)
_SYSTEM_DIRS = frozenset(
    {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}
    | {"/opt/homebrew/bin"}
)
_SUBSTITUTIONS = ("`", "$(", "<(", ">(")
_SUBSTITUTION = "it uses command or process substitution"
#: Programs that run an argument as shell text, which ``_WRAPPERS`` does not follow to it:
#: a marker anywhere in their words is refused, quoted or not, since the shell that reads
#: the text substitutes it (``eval 'echo `id`'``, ``ssh host 'echo $(id)'``). ``trap`` and
#: ``alias`` store text the shell runs later; ``sg``, ``tmux``, ``screen`` and ``parallel``
#: pass it to ``sh -c`` or type it into a shell.
_RUNS_ARGUMENTS_AS_SHELL = (
    "eval",
    "trap",
    "alias",
    "su",
    "runuser",
    "sg",
    "ssh",
    "script",
    "flock",
    "tmux",
    "screen",
    "parallel",
)


class _Unanalyzable(Exception):
    """A command the policy cannot follow to what it runs; it is denied."""


def _refuse_substitution_in(words: Iterable[str]) -> None:
    """Refuse a substitution marker anywhere in ``words``, quoted or not: for text a shell
    the scanner never sees will read (a heredoc, ``eval``'s arguments)."""
    if any(marker in word for word in words for marker in _SUBSTITUTIONS):
        raise _Unanalyzable(_SUBSTITUTION)


def _refuse_shell_text(argv: list[str]) -> None:
    """Refuse a marker in the words a command no wrapper follows hands to a shell: those
    after a program in :data:`_RUNS_ARGUMENTS_AS_SHELL`, or after a shell named past
    ``argv[0]`` (``docker exec c sh -c '...'``). A shell at ``argv[0]`` that is a leaf runs
    a script file, and its arguments are text."""
    for position, word in enumerate(argv):
        program = _program(word)
        if program in _RUNS_ARGUMENTS_AS_SHELL or (position and program in _SHELLS):
            _refuse_substitution_in(argv[position + 1 :])
            return


def _program(token: str) -> str:
    """The name rules match a program by: a bare name, or a system directory's file. Any
    other path (``./git``) is kept whole, so a rule for ``git`` never admits a file that
    only carries the name."""
    directory, slash, name = token.rpartition("/")
    if not slash:
        return token
    return name if name and directory in _SYSTEM_DIRS else token


def _dangerous_assignment(token: str) -> bool:
    name = token.split("=", 1)[0]
    return name in _DEFAULT_DANGEROUS_ENV_VARS or name.startswith("GIT_") or name == "IFS"


def _is_assignment(token: str) -> bool:
    name, eq, _ = token.partition("=")
    return bool(eq) and name.isidentifier()


# ----------------------------------------------------------------------------------- lines


_OPERATOR_CHARS = "();<>|&"
#: ``$(`` and a backtick start in a word; ``<(`` and ``>(`` in a run of operator characters.
_WORD_MARKERS = tuple(m for m in _SUBSTITUTIONS if m[0] not in _OPERATOR_CHARS)
_OPERATOR_MARKERS = tuple(m for m in _SUBSTITUTIONS if m[0] in _OPERATOR_CHARS)
#: The operators a shell reads in a run of operator characters, longest first, as bash's
#: lexer takes them left to right: ``;>`` is ``;`` then ``>`` (until 0.10.35 the run was
#: one token, read as a redirection, so ``ls ;>x rm -rf /`` was one ``ls`` command), and
#: ``&>`` is one redirection.
_OPERATORS = (
    *("&>>", ";;&", "<<<"),
    *("&&", "||", ";;", ";&", "|&", "<<", ">>", "<&", ">&", "<>", ">|", "&>"),
    *("(", ")", ";", "&", "|", "<", ">"),
)
#: The target of ``>&`` that moves or closes a descriptor (``2>&1``, ``>&2-``, ``>&-``)
#: rather than naming a file.
_DESCRIPTOR = re.compile(r"\d+-?|-")


def _split_operators(run: str) -> list[str]:
    """``run`` (operator characters only) as the operators a shell reads in it."""
    out: list[str] = []
    index = 0
    while index < len(run):
        operator = next(o for o in _OPERATORS if run.startswith(o, index))
        out.append(operator)
        index += len(operator)
    return out


def _writes(operator: str, target: str) -> bool:
    """Whether the redirection ``operator`` with ``target`` writes to a file. ``<``,
    ``<<``, ``<<<`` and ``<&`` only read; ``>&2``, ``2>&1`` and ``>&-`` move or close a
    descriptor."""
    if ">" not in operator:
        return False
    return not (operator == ">&" and _DESCRIPTOR.fullmatch(target))


@dataclass
class _Line:
    """A shell line split into words and operators, as POSIX ``sh`` reads quoting.

    :mod:`shlex` returns a quoted ``';'`` and an operator ``;`` as the same token, so
    ``find -exec rm {} \\;`` could not be told from two commands; this keeps them apart.
    ``expands`` is set when a word holds a ``$`` outside single quotes: its value is not
    known until the shell runs it. A substitution is refused where the shell performs one:
    a backtick or ``$(`` unquoted or inside double quotes (an escaped ``\\``` or ``\\$`` is
    text), ``<(`` or ``>(`` unquoted, and a marker in a comment; inside single quotes it is
    text. ``heredoc`` is set when ``<<`` appears outside quotes: the body is read by the
    shell, which substitutes in it even inside single quotes.
    """

    tokens: list[tuple[str, bool]] = field(default_factory=list)  # (text, is_operator)
    expands: bool = False
    heredoc: bool = False

    @classmethod
    def scan(cls, line: str) -> _Line:
        out = cls()
        word: list[str] = []
        started = False
        index = 0
        while index < len(line):
            char = line[index]
            if (
                char in " \t"
                or char in "\n\r"
                or char in _OPERATOR_CHARS
                or (char == "#" and not started)
            ):
                if started:
                    out.tokens.append(("".join(word), False))
                word, started = [], False
                index = out._separator(line, index)
                continue
            index = out._word_part(line, index, word)
            started = True
        if started:
            out.tokens.append(("".join(word), False))
        return out

    def _separator(self, line: str, index: int) -> int:
        char = line[index]
        if char == "#":  # a comment runs to the end of the line
            end = min(
                (p for p in (line.find("\n", index), line.find("\r", index)) if p != -1),
                default=len(line),
            )
            # Refused as before 0.10.34: a shell that does not read `#` as a comment
            # (interactive zsh) would run it.
            _refuse_substitution_in([line[index:end]])
            return end
        if char in "\n\r":
            self.tokens.append((";", True))
            return index + 1
        if char in _OPERATOR_CHARS:
            end = index
            while end < len(line) and line[end] in _OPERATOR_CHARS:
                end += 1
            run = line[index:end]
            if any(marker in run for marker in _OPERATOR_MARKERS):
                raise _Unanalyzable(_SUBSTITUTION)
            self.heredoc = self.heredoc or "<<" in run
            self.tokens += [(operator, True) for operator in _split_operators(run)]
            return end
        return index + 1

    def _word_part(self, line: str, index: int, word: list[str]) -> int:
        char = line[index]
        if char == "\\":
            if index + 1 >= len(line):
                raise _Unanalyzable("it ends in a backslash")
            if line[index + 1] not in "\n\r":
                word.append(line[index + 1])
            return index + 2
        if char == "'":
            end = line.find("'", index + 1)
            if end == -1:
                raise _Unanalyzable("it has an unclosed quote")
            word.append(line[index + 1 : end])
            return end + 1
        if char == '"':
            return self._double_quoted(line, index + 1, word)
        if any(line.startswith(marker, index) for marker in _WORD_MARKERS):
            raise _Unanalyzable(_SUBSTITUTION)
        if char == "$":
            self.expands = True
        word.append(char)
        return index + 1

    def _double_quoted(self, line: str, index: int, word: list[str]) -> int:
        while index < len(line):
            char = line[index]
            if char == '"':
                return index + 1
            if char == "\\" and index + 1 < len(line) and line[index + 1] in '$`"\\\n':
                if line[index + 1] != "\n":
                    word.append(line[index + 1])
                index += 2
                continue
            if any(line.startswith(marker, index) for marker in _WORD_MARKERS):
                raise _Unanalyzable(_SUBSTITUTION)
            if char == "$":
                self.expands = True
            word.append(char)
            index += 1
        raise _Unanalyzable("it has an unclosed quote")


def _segments(line: str, walk: _Walk | None = None) -> list[list[str]]:
    """The commands of a shell line: split at ``;`` ``&&`` ``||`` ``|`` ``&``, newlines and
    parentheses, with redirections and leading ``NAME=value`` words taken out. Each
    redirection that writes is recorded on ``walk.writes`` with its target, a redirection
    with no command (``ls; >/etc/passwd``) included."""
    scanned = _Line.scan(line)
    if scanned.heredoc:
        # `cat <<EOF` then `'`id`'` runs id: the shell reads the body, not this scanner.
        _refuse_substitution_in([line])
    if walk is not None and scanned.expands:
        walk.expands = True
    segments: list[list[str]] = []
    current: list[str] = []
    writes: list[tuple[str, str]] = []  # this command's (operator, target)
    redirect: str | None = None  # the operator whose target is the next word
    for text, is_operator in scanned.tokens:
        if redirect is not None and not is_operator:
            if _writes(redirect, text):
                writes.append((redirect, text))
            redirect = None
        elif is_operator and ("<" in text or ">" in text):
            if current and current[-1].isdigit():
                current.pop()  # the file descriptor of `2>err`
            redirect = text
        elif is_operator:
            _record_writes(current, writes, walk)
            segments.append(current)
            current, writes, redirect = [], [], None
        else:
            current.append(text)
    _record_writes(current, writes, walk)
    segments.append(current)
    return [_command_words(segment) for segment in segments if segment]


def _record_writes(segment: list[str], writes: list[tuple[str, str]], walk: _Walk | None) -> None:
    """Put one command's writes on ``walk``, each with the command's program."""
    if walk is None or not writes:
        return
    program = next((_program(word) for word in segment if not _is_assignment(word)), "")
    walk.writes += [_Write(operator, target, program) for operator, target in writes]


def _command_words(segment: list[str]) -> list[str]:
    """``segment`` without its leading ``NAME=value`` words, refusing one that changes
    which program runs or how it loads."""
    index = 0
    while index < len(segment) and _is_assignment(segment[index]):
        if _dangerous_assignment(segment[index]):
            raise _Unanalyzable(f"it sets {segment[index].split('=', 1)[0]}")
        index += 1
    return segment[index:]


# --------------------------------------------------------------------------------- writes

#: Where a redirection may not write: devices, system configuration and binaries, cron's
#: spool, and the files a login shell runs. Globs, matched with ``fnmatchcase`` (``*``
#: crosses ``/``) against the target after ``posixpath.normpath``.
_DEFAULT_REDIRECT_DENY: tuple[str, ...] = (
    *("/dev/*", "/etc/*", "/boot/*", "/sys/*", "/proc/*", "/bin/*", "/sbin/*", "/usr/*"),
    *("/lib/*", "/lib64/*", "/var/spool/cron/*"),
    *("~/.ssh/*", "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc"),
)
#: Targets under ``redirect_deny`` a command may still write: the null device and the
#: process's own streams.
_DEFAULT_REDIRECT_ALLOW: tuple[str, ...] = (
    *("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/*"),
)
#: Options with which a program writes or deletes files itself. An allow rule naming the
#: program admits a command carrying one only when the rule's option parts name it
#: (``find -delete``); deny and ask rules are unchanged. To add a program, map the name
#: ``_program`` reads it by to its options; options that launch a command belong in
#: ``_WRAPPERS`` instead (``find -exec``).
_ACTION_OPTIONS: dict[str, frozenset[str]] = {
    "find": frozenset({"-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}),
}
#: Characters that leave a redirection target to the shell: a ``$`` value, a glob, a
#: brace expansion (``/de{v..v}/sda``).
_UNDECIDED_TARGET = frozenset("$*?[{")


@dataclass(frozen=True)
class _Write:
    """A redirection that writes: its operator, target and the command's program."""

    operator: str
    target: str
    program: str


def _undecided(target: str) -> bool:
    """Whether the shell decides ``target`` when it runs: a ``$`` value, a glob, a brace
    expansion, or a tilde form other than ``~/...`` (``~root/x``, ``~+``)."""
    if any(char in _UNDECIDED_TARGET for char in target):
        return True
    return target.startswith("~") and target != "~" and not target.startswith("~/")


def _normalized_target(target: str) -> str:
    """``target`` with ``.`` and ``..`` resolved (``/tmp/../dev/sda`` is ``/dev/sda``) and
    a leading ``//`` read as ``/``, as Linux reads it."""
    path = posixpath.normpath(target)
    return "/" + path.lstrip("/") if path.startswith("//") else path


def _actions(argv: list[str]) -> frozenset[str]:
    """The :data:`_ACTION_OPTIONS` of ``argv``'s program that its words carry."""
    options = _ACTION_OPTIONS.get(_program(argv[0])) if argv else None
    return frozenset(word for word in argv[1:] if word in options) if options else frozenset()


# -------------------------------------------------------------------------------- options


def _words(text: str) -> tuple[str, ...]:
    """A list of option names, written as one line."""
    return tuple(text.split())


def _skip_options(
    args: list[str], with_value: Iterable[str], flags: Iterable[str], *, numbers: bool = False
) -> int:
    """The index of the first argument after the leading options and their values.

    An option outside ``with_value`` and ``flags`` is refused: a parser that guessed at it
    could take the program a wrapper runs for an option's value. ``numbers`` reads ``-10``
    as an option (``nice -10``).
    """
    takes_value, known = set(with_value), set(flags) | set(with_value)
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return index + 1
        if numbers and _is_number_option(arg):
            index += 1
            continue
        if not arg.startswith("-") or arg == "-":
            return index
        name = arg.split("=", 1)[0] if arg.startswith("--") else arg[:2]
        if name not in known:
            raise _Unanalyzable(f"it passes {name}, an option the policy does not know")
        attached = "=" in arg if arg.startswith("--") else len(arg) > 2
        index += 2 if name in takes_value and not attached else 1
    return index


def _is_number_option(arg: str) -> bool:
    return len(arg) > 1 and arg[1:].isdigit()  # `nice -10`, read as its own option


# ------------------------------------------------------------------------------- wrappers

Inner = list[str] | str  # an argv, or a line a shell will run
_Wrapper = Any  # Callable[[list[str]], list[Inner]]


def _rest(argv: list[str], start: int) -> list[Inner]:
    rest = argv[start:]
    return [rest] if rest else []


def _env(argv: list[str]) -> list[Inner]:
    args = argv[1:]
    index = 0
    while index < len(args):
        arg = args[index]
        name = arg.split("=", 1)[0] if arg.startswith("--") else arg[:2]
        if arg == "--":
            index += 1
            break
        if name in ("-S", "--split-string"):
            value, used = _option_value(args, index)
            return [shlex.split(value) + args[index + used :]]
        if not arg.startswith("-") or _is_assignment(arg):
            break
        if name in ("-u", "--unset", "-C", "--chdir"):
            index += _option_value(args, index)[1]
        elif arg in ("-", "-i", "--ignore-environment", "-0", "--null", "-v", "--debug"):
            index += 1
        else:
            raise _Unanalyzable(f"it passes {name}, an option the policy does not know")
    rest = _command_words(args[index:])  # NAME=value words, a dangerous one refused
    return [rest] if rest else []


def _option_value(args: list[str], index: int) -> tuple[str, int]:
    arg = args[index]
    if "=" in arg and arg.startswith("--"):
        return arg.split("=", 1)[1], 1
    if not arg.startswith("--") and len(arg) > 2:
        return arg[2:], 1
    if index + 1 >= len(args):
        raise _Unanalyzable(f"{arg} has no value")
    return args[index + 1], 2


def _simple(
    with_value: tuple[str, ...],
    flags: tuple[str, ...],
    positional: int = 0,
    *,
    numbers: bool = False,
) -> Any:
    """A wrapper whose options come first and whose command follows ``positional`` words."""

    def unwrap(argv: list[str]) -> list[Inner]:
        start = 1 + _skip_options(argv[1:], with_value, flags, numbers=numbers) + positional
        return _rest(argv, start)

    return unwrap


def _xargs(argv: list[str]) -> list[Inner]:
    start = 1 + _skip_options(
        argv[1:],
        with_value=_words(
            "-a --arg-file -d --delimiter -E -I --replace -L --max-lines -n --max-args -P "
            "--max-procs -s --max-chars --process-slot-var --eof"
        ),
        flags=_words(
            "-0 --null -o --open-tty -p --interactive -r --no-run-if-empty -t --verbose -x --exit "
            "--show-limits -e -i -l"
        ),
    )
    return _rest(argv, start) or [["echo"]]  # xargs with no command runs echo


def _find(argv: list[str]) -> list[Inner]:
    inner: list[Inner] = []
    index = 1
    while index < len(argv):
        if argv[index] in ("-exec", "-execdir", "-ok", "-okdir"):
            end = next((i for i in range(index + 1, len(argv)) if argv[i] in (";", "+")), None)
            if end is None:
                raise _Unanalyzable(f"its {argv[index]} has no closing ; or +")
            inner.append(argv[index + 1 : end])
            index = end
        index += 1
    return inner


_SHELL_LONG_FLAGS = frozenset(
    {"--login", "--norc", "--noprofile", "--posix", "--restricted", "--verbose", "--noediting"}
)


def _shell(argv: list[str]) -> list[Inner]:
    """``bash -c LINE`` runs LINE; ``bash script`` is the shell running a file, judged as
    itself; a shell with neither reads its program from stdin or a terminal: refused."""
    args = argv[1:]
    index = 0
    while index < len(args) and args[index].startswith(("-", "+")):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if arg.startswith("--"):
            if arg not in _SHELL_LONG_FLAGS:
                raise _Unanalyzable(f"it passes {arg}, an option the policy does not know")
        elif arg[0] == "-" and "c" in arg[1:]:
            if index + 1 >= len(args):
                raise _Unanalyzable(f"its {arg} has no command")
            return [args[index + 1]]
        elif arg[0] == "-" and ("s" in arg[1:] or "i" in arg[1:]):
            break  # -s and -i read the program from stdin or a terminal
        elif arg[1:] in ("o", "O"):
            index += 1  # -o / +o take an option name
        index += 1
    else:
        if index < len(args):
            return []  # a script file: the shell itself is the command judged
    if index < len(args) and args[index - 1] == "--":
        return []
    raise _Unanalyzable(f"{_program(argv[0])} reads its program from stdin or a terminal")


@dataclass(frozen=True)
class _Interpreter:
    """How one interpreter's command line names its program.

    ``inline`` letters (``python -c``, ``node -e``, ``perl -e``) run code nobody can check;
    ``module`` (``python -m mod``) runs ``mod``, judged as a command; ``values`` letters
    take a value; a first plain word is the script, and the interpreter running it is the
    command judged. With none of those it reads its program from stdin: refused.
    """

    inline: frozenset[str]
    values: frozenset[str] = frozenset()
    long_inline: frozenset[str] = frozenset()
    long_values: frozenset[str] = frozenset()
    module: str | None = None

    def __call__(self, argv: list[str]) -> list[Inner]:
        args = argv[1:]
        index = 0
        while index < len(args):
            arg = args[index]
            if arg == "-":
                break
            if arg == "--":
                if index + 1 < len(args):
                    return []
                break
            if not arg.startswith("-"):
                return []
            step, inner = self._option(args, index)
            if inner is not None:
                return inner
            index += step
        raise _Unanalyzable(f"{_program(argv[0])} reads its program from stdin")

    def _option(self, args: list[str], index: int) -> tuple[int, list[Inner] | None]:
        arg = args[index]
        if arg.startswith("--"):
            name = arg.split("=", 1)[0]
            if name in self.long_inline:
                raise _Unanalyzable(f"it runs inline code ({name})")
            return (2 if name in self.long_values and "=" not in arg else 1), None
        for position, letter in enumerate(arg[1:], start=1):
            if letter in self.inline:
                raise _Unanalyzable(f"it runs inline code (-{letter})")
            if letter == self.module:
                attached = arg[position + 1 :]
                module = attached or (args[index + 1] if index + 1 < len(args) else "")
                if not module:
                    raise _Unanalyzable(f"its -{letter} names no module")
                return 0, [[module, *args[index + (1 if attached else 2) :]]]
            if letter in self.values:
                return (1 if arg[position + 1 :] else 2), None
        return 1, None


_PYTHON = _Interpreter(
    frozenset("c"), frozenset("WX"), module="m", long_values=frozenset({"--check-hash-based-pycs"})
)
_NODE = _Interpreter(
    frozenset("ep"),
    frozenset("r"),
    frozenset({"--eval", "--print"}),
    frozenset(
        {"--require", "--import", "--loader", "--experimental-loader", "--input-type", "--title"}
    ),
)
_PERL = _Interpreter(frozenset("eEc"), frozenset("IMmxilF0CdD"))
_RUBY = _Interpreter(frozenset("e"), frozenset("IrCEFKTWx"))


def _sudo(argv: list[str]) -> list[Inner]:
    args = argv[1:]
    start = 1 + _skip_options(
        args,
        with_value=_words(
            "-C --close-from -D --chdir -g --group -h --host -p --prompt -R --chroot -r --role -t "
            "--type -T --command-timeout -U --other-user -u --user"
        ),
        flags=_words(
            "-A --askpass -b --background -B --bell -E --preserve-env -e --edit -H --set-home -i "
            "--login -K --remove-timestamp -k --reset-timestamp -l --list -n --non-interactive -P "
            "--preserve-groups -S --stdin -s --shell -V --version -v --validate"
        ),
    )
    inner = _rest(argv, start)
    if any(a in ("-i", "-s", "--login", "--shell") for a in args[: start - 1]):
        if not inner:
            raise _Unanalyzable("it opens a root shell")
        # sudo escapes the words for the shell it runs, and how differs between sudo
        # versions and sudo-rs (1.9 leaves `$` alone): a marker in them is refused.
        _refuse_substitution_in(argv[start:])
        return [shlex.join(argv[start:])]
    return inner


def _doas(argv: list[str]) -> list[Inner]:
    if "-s" in argv[1:]:
        raise _Unanalyzable("it opens a root shell")
    inner: list[Inner] = _simple(("-u", "-C"), ("-n", "-L"))(argv)
    return inner


def _chroot(argv: list[str]) -> list[Inner]:
    start = 1 + _skip_options(argv[1:], ("--userspec", "--groups"), ("--skip-chdir",))
    if start + 1 >= len(argv):
        raise _Unanalyzable("it opens a shell in the new root")
    return _rest(argv, start + 1)


def _watch(argv: list[str]) -> list[Inner]:
    args = argv[1:]
    start = 1 + _skip_options(
        args,
        with_value=("-n", "--interval", "-q", "--equexit"),
        flags=_words(
            "-b --beep -c --color -C --no-color -d --differences -e --errexit -g --chgexit -p "
            "--precise -t --no-title -w --no-wrap -x --exec -r --no-rerun"
        ),
    )
    if any(a in ("-x", "--exec") for a in args[: start - 1]):
        return _rest(argv, start)
    return [" ".join(argv[start:])] if argv[start:] else []  # run through `sh -c`


def _busybox(argv: list[str]) -> list[Inner]:
    return _rest(argv, 1)


_WRAPPERS: dict[str, _Wrapper] = {
    "env": _env,
    "xargs": _xargs,
    "find": _find,
    "sudo": _sudo,
    "doas": _doas,
    "nohup": _simple((), ()),
    "timeout": _simple(
        ("-k", "--kill-after", "-s", "--signal"),
        ("--preserve-status", "--foreground", "-v", "--verbose"),
        positional=1,
    ),
    "nice": _simple(("-n", "--adjustment"), (), numbers=True),
    "ionice": _simple(("-c", "--class", "-n", "--classdata"), ("-t", "--ignore")),
    "stdbuf": _simple(("-i", "--input", "-o", "--output", "-e", "--error"), ()),
    "setsid": _simple((), ("-c", "--ctty", "-f", "--fork", "-w", "--wait")),
    "chroot": _chroot,
    "watch": _watch,
    "busybox": _busybox,
    "node": _NODE,
    "nodejs": _NODE,
    "perl": _PERL,
    "ruby": _RUBY,
}


def _wrapper(program: str) -> _Wrapper | None:
    if program in _SHELLS:
        return _shell
    if program == "python" or (
        program.startswith("python") and program[6:].replace(".", "").isdigit()
    ):
        return _PYTHON
    return _WRAPPERS.get(program)


# ------------------------------------------------------------------------------------ git

_GIT_VALUE_OPTIONS = _words(
    "-C --git-dir --work-tree --namespace --super-prefix --list-cmds --attr-source"
)
_GIT_FLAGS = _words(
    "-p --paginate -P --no-pager --bare --no-replace-objects --literal-pathspecs "
    "--glob-pathspecs --noglob-pathspecs --icase-pathspecs --no-optional-locks --no-lazy-fetch "
    "--no-advice --version --help --html-path --man-path --info-path"
)
#: Config keys that are a command git runs (``alias.*`` when it starts with ``!``).
_GIT_COMMAND_KEYS = _words(
    "core.sshcommand core.pager core.editor core.askpass core.fsmonitor sequence.editor "
    "gpg.program gpg.*.program credential.helper diff.external diff.*.textconv diff.*.command "
    "merge.*.driver filter.*.clean filter.*.smudge filter.*.process pager.* web.browser "
    "browser.*.cmd uploadpack.packobjectshook alias.*"
)
#: Config keys that change nothing git runs.
_GIT_SAFE_KEYS = _words(
    "user.name user.email color.* core.quotepath core.autocrlf core.safecrlf init.defaultbranch "
    "advice.* log.* column.* i18n.* pull.rebase push.default gc.auto protocol.version "
    "diff.renames status.* format.*"
)


def _git(argv: list[str]) -> tuple[list[str], list[Inner]]:
    """``git`` with its global options taken out, and the commands its ``-c`` keys run."""
    launched: list[Inner] = []
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        arg = argv[index]
        name = arg.split("=", 1)[0] if arg.startswith("--") else arg[:2]
        if name == "--config-env":
            raise _Unanalyzable("its --config-env reads a value the policy cannot see")
        if name == "--exec-path" and "=" in arg:
            raise _Unanalyzable("its --exec-path changes where git finds its commands")
        if name == "-c":
            value, used = _option_value(argv, index)
            launched += _git_config(value)
            index += used
        elif name in _GIT_VALUE_OPTIONS:
            index += _option_value(argv, index)[1]
        elif arg in (*_GIT_FLAGS, "--exec-path"):
            index += 1
        else:
            raise _Unanalyzable(f"it passes {name}, an option the policy does not know")
    return [argv[0], *argv[index:]], launched


def _git_config(setting: str) -> list[Inner]:
    key, eq, value = setting.partition("=")
    key = key.lower()
    if not eq:
        raise _Unanalyzable(f"its -c {key} has no value")
    if any(fnmatch.fnmatchcase(key, pattern) for pattern in _GIT_COMMAND_KEYS):
        if key.startswith("alias."):
            raise _Unanalyzable("its -c defines an alias, which can stand for any command")
        return [value.removeprefix("!")]
    if any(fnmatch.fnmatchcase(key, pattern) for pattern in _GIT_SAFE_KEYS):
        return []
    raise _Unanalyzable(f"its -c sets {key}, which the policy cannot vouch for")


def _normalized(argv: list[str]) -> tuple[list[str], list[Inner]]:
    """``argv`` as rules read it (git's global options out), and what its settings launch."""
    if argv and _program(argv[0]) == "git":
        return _git(argv)
    return argv, []


# ---------------------------------------------------------------------------------- rules


@dataclass(frozen=True)
class _Rule:
    text: str
    words: tuple[str, ...]
    anywhere: tuple[str, ...]

    @classmethod
    def parse(cls, text: str) -> _Rule:
        try:
            parts = shlex.split(text)
        except ValueError as exc:
            raise ValueError(f"shell rule {text!r} cannot be split into words: {exc}") from exc
        if not parts or parts[0].startswith(("-", "+")):
            raise ValueError(f"shell rule {text!r} must start with a program name")
        cut = next((i for i, part in enumerate(parts) if part.startswith(("-", "+"))), len(parts))
        if any(not part.startswith(("-", "+")) for part in parts[cut:]):
            raise ValueError(f"shell rule {text!r} puts a word after an option")
        return cls(text, tuple(parts[:cut]), tuple(parts[cut:]))

    def names(self, options: Iterable[str]) -> bool:
        """Whether every one of ``options`` matches one of the rule's option parts."""
        return all(
            any(fnmatch.fnmatchcase(option, part) for part in self.anywhere) for option in options
        )

    def matches(self, argv: list[str], *, anywhere: bool) -> bool:
        starts = range(len(argv)) if anywhere else range(min(1, len(argv)))
        return any(self._matches_at(argv, start) for start in starts)

    def matched_program(self, argv: list[str]) -> str | None:
        """The program a match anywhere in ``argv`` starts at, or None for no match."""
        return next(
            (_program(argv[start]) for start in range(len(argv)) if self._matches_at(argv, start)),
            None,
        )

    def _matches_at(self, argv: list[str], start: int) -> bool:
        words, _ = _normalized(argv[start:]) if start else (argv, [])
        if len(words) < len(self.words) or not fnmatch.fnmatchcase(
            _program(words[0]), self.words[0]
        ):
            return False
        if not all(
            fnmatch.fnmatchcase(word, rule)
            for word, rule in zip(words[1:], self.words[1:], strict=False)
        ):
            return False
        rest = words[len(self.words) :]
        return all(any(fnmatch.fnmatchcase(w, part) for w in rest) for part in self.anywhere)


# --------------------------------------------------------------------------------- policy


@dataclass(frozen=True)
class ShellCommandDecision:
    """The policy's verdict on one shell command.

    Attributes:
        verdict: ``allow``, ``ask`` or ``deny``.
        argument: The argument the command came from.
        program: The program the deciding rule (or default) matched, for messages.
        rule: The deciding rule's text, ``default``, or ``unanalyzable``.
        detail: Why, in words safe to show the model (it names no deny rule).
    """

    verdict: ShellVerdict
    argument: str
    program: str
    rule: str
    detail: str


@dataclass(frozen=True)
class ShellCommandPolicy:
    """Allow, ask and deny rules for the commands an agent shell tool runs.

    Attributes:
        allow: Rules whose match lets an innermost command run.
        ask: Rules whose match anywhere in the line escalates to the approver.
        deny: Rules whose match anywhere in the line refuses it.
        default: What an innermost command no allow rule matches gets.
        command_args: The arguments that hold the command: a string is a shell line, a
            list of strings one command's argv.
        tools: Tool-name globs the policy applies to; empty applies it to every tool that
            has one of ``command_args``.
        redirect_deny: Globs of paths a redirection may not write to (``> /dev/sda``,
            ``>> /etc/passwd``), checked after the deny rules and whatever ``default`` is.
            A target the shell decides when it runs (a ``$`` value, a glob, ``~user``) is
            asked about when the policy has an ask rule, else denied. ``()`` turns the
            redirection check off, the unknown-target refusal included.
        redirect_allow: Globs under ``redirect_deny`` a redirection may still write to
            (``/dev/null``, the process's own streams).
    """

    allow: tuple[str, ...] = ()
    ask: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    default: ShellVerdict = "deny"
    command_args: tuple[str, ...] = ("command", "cmd")
    tools: tuple[str, ...] = ()
    redirect_deny: tuple[str, ...] = _DEFAULT_REDIRECT_DENY
    redirect_allow: tuple[str, ...] = _DEFAULT_REDIRECT_ALLOW
    _rules: dict[str, tuple[_Rule, ...]] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Parse the rules and check the settings.

        Raises:
            ValueError: A rule that does not parse, an unknown ``default``, or a name
                collection given as one string.
        """
        for name in (
            *("allow", "ask", "deny", "command_args", "tools"),
            *("redirect_deny", "redirect_allow"),
        ):
            value = getattr(self, name)
            if isinstance(value, str) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"ShellCommandPolicy.{name} takes a tuple of strings")
            object.__setattr__(self, name, tuple(value))
        if self.default not in _RANK:
            raise ValueError("ShellCommandPolicy.default must be allow, ask or deny")
        for kind in ("allow", "ask", "deny"):
            self._rules[kind] = tuple(_Rule.parse(text) for text in getattr(self, kind))

    def applies_to(self, tool_name: str) -> bool:
        return not self.tools or any(fnmatch.fnmatchcase(tool_name, p) for p in self.tools)

    def canonical(self) -> dict[str, object]:
        """The fields a policy digest covers."""
        return {
            "allow": list(self.allow),
            "ask": list(self.ask),
            "deny": list(self.deny),
            "default": self.default,
            "command_args": list(self.command_args),
            "tools": list(self.tools),
            "redirect_deny": list(self.redirect_deny),
            "redirect_allow": list(self.redirect_allow),
        }

    def evaluate(self, arguments: Mapping[str, Any]) -> ShellCommandDecision | None:
        """The verdict on the call's command arguments; None when it carries none."""
        decisions = [
            self.decide(arguments[name], argument=name)
            for name in self.command_args
            if name in arguments and arguments[name] is not None
        ]
        if not decisions:
            return None
        return max(decisions, key=lambda decision: _RANK[decision.verdict])

    def decide(self, command: Any, *, argument: str = "command") -> ShellCommandDecision:
        """The verdict on one command: a shell line, or one command's argv."""
        try:
            return self._judge(_Walk.of(command), argument)
        except _Unanalyzable as why:
            return ShellCommandDecision(
                "deny", argument, "", "unanalyzable", f"the command cannot be checked: {why}"
            )

    def _judge(self, walk: _Walk, argument: str) -> ShellCommandDecision:
        """Deny rules, then where the command writes, then ask rules, then the innermost
        commands (:meth:`_worst`)."""
        for rule in self._rules["deny"]:
            hit = self._first_match(rule, walk)
            if hit is not None:
                return ShellCommandDecision(
                    "deny", argument, hit, rule.text, f"`{hit}` is not permitted"
                )
        redirect = self._redirect(walk, argument)
        if redirect is not None and redirect.verdict == "deny":
            return redirect
        decision: ShellCommandDecision | None = None
        for rule in self._rules["ask"]:
            hit = self._first_match(rule, walk)
            if hit is not None:
                decision = self._worst(walk, argument, ask=(rule, hit))
                break
        if decision is None:
            decision = self._worst(walk, argument, ask=None)
        if redirect is not None and decision.verdict != "deny":
            return redirect  # an undecided target, asked about
        return decision

    @staticmethod
    def _first_match(rule: _Rule, walk: _Walk) -> str | None:
        """The program of the first command in the line ``rule`` matches anywhere in."""
        return next(
            (p for c in walk.everything if (p := rule.matched_program(c)) is not None), None
        )

    def _redirect(self, walk: _Walk, argument: str) -> ShellCommandDecision | None:
        """The verdict the line's writes come to, or None when none is refused or asked
        about: a target ``redirect_deny`` names and ``redirect_allow`` does not is denied;
        a target the shell decides when it runs is asked about with an ask rule in the
        policy, else denied. Nothing is checked when ``redirect_deny`` is empty."""
        if not self.redirect_deny:
            return None
        undecided: _Write | None = None
        for write in walk.writes:
            if _undecided(write.target):
                undecided = undecided or write
                continue
            target = _normalized_target(write.target)
            if any(fnmatch.fnmatchcase(target, glob) for glob in self.redirect_allow):
                continue
            glob = next((g for g in self.redirect_deny if fnmatch.fnmatchcase(target, g)), None)
            if glob is not None:
                return ShellCommandDecision(
                    "deny",
                    argument,
                    write.program,
                    f"redirect {glob}",
                    "the command writes to a path it may not write",
                )
        if undecided is None:
            return None
        return ShellCommandDecision(
            "ask" if self._rules["ask"] else "deny",
            argument,
            undecided.program,
            "redirect (undecided target)",
            "a redirection target is not known until the shell runs it",
        )

    def _worst(
        self, walk: _Walk, argument: str, *, ask: tuple[_Rule, str] | None
    ) -> ShellCommandDecision:
        """The verdict an ask rule (if any) and the innermost commands come to: each is
        allowed by an allow rule, else asked about by an ask rule naming it, else
        ``default``. A line with a ``$`` expansion is admitted by no allow rule: its words
        are not known yet. A command carrying one of its program's
        :data:`_ACTION_OPTIONS` (``find -delete``) is judged here even when it is a
        wrapper, and only an allow rule naming those options admits it."""
        verdict: ShellVerdict = "ask" if ask is not None else "allow"
        rule_text, program = (ask[0].text, ask[1]) if ask is not None else ("", "")
        unnamed: frozenset[str] = frozenset()  # the deciding command's unnamed actions
        acting = [
            command
            for command in walk.everything
            if _actions(command) and all(command is not leaf for leaf in walk.leaves)
        ]
        for leaf in [*walk.leaves, *acting]:
            actions = _actions(leaf)
            named = (
                None
                if walk.expands
                else next(
                    (r for r in self._rules["allow"] if r.matches(leaf, anywhere=False)), None
                )
            )
            allowed = named if named is not None and named.names(actions) else None
            leaf_verdict: ShellVerdict = self.default
            if allowed is not None:
                leaf_verdict = "allow"
            elif any(rule.matches(leaf, anywhere=True) for rule in self._rules["ask"]):
                leaf_verdict = "ask"  # an ask rule names it, so the default does not decide
            if _RANK[leaf_verdict] > _RANK[verdict]:
                verdict, rule_text, program = leaf_verdict, "default", _program(leaf[0])
                unnamed = actions if named is not None and allowed is None else frozenset()
            elif not rule_text and allowed is not None:
                rule_text, program = allowed.text, _program(leaf[0])
        detail = {
            "allow": "the command is permitted",
            "ask": f"`{program}` needs approval",
            "deny": f"`{program}` is not on the list of permitted commands",
        }[verdict]
        if unnamed and verdict != "allow":
            options = ", ".join(f"`{o}`" for o in sorted(unnamed))
            detail += f" ({options} needs an allow rule that names it)"
        if walk.expands and rule_text == "default":
            detail += " (a `$` value is not known until the shell runs it)"
        return ShellCommandDecision(verdict, argument, program, rule_text, detail)


@dataclass
class _Walk:
    """Every command a line runs (wrappers and what they launch), the innermost ones, and
    the redirections that write, from the line and from the lines wrappers run."""

    everything: list[list[str]] = field(default_factory=list)
    leaves: list[list[str]] = field(default_factory=list)
    expands: bool = False
    writes: list[_Write] = field(default_factory=list)

    @classmethod
    def of(cls, command: Any) -> _Walk:
        if isinstance(command, bytes):
            try:
                command = command.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise _Unanalyzable("it is not UTF-8 text") from exc
        walk = cls()
        if isinstance(command, str):
            segments = _segments(command, walk)
        elif isinstance(command, list | tuple) and all(isinstance(a, str) for a in command):
            segments = [list(command)]
        else:
            raise _Unanalyzable(f"it is a {type(command).__name__}, not text or an argv list")
        if not any(segments):
            raise _Unanalyzable("it is empty")
        for segment in segments:
            walk.command(segment, 0)
        return walk

    def command(self, argv: list[str], depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise _Unanalyzable("its wrappers nest too deep")
        argv = _command_words(argv)
        if not argv:
            return
        argv, launched = _normalized(argv)
        self.everything.append(argv)
        wrapper = _wrapper(_program(argv[0]))
        inner = wrapper(argv) if wrapper is not None else []
        if not inner:
            _refuse_shell_text(argv)
            self.leaves.append(argv)
        for item in [*inner, *launched]:
            for segment in _segments(item, self) if isinstance(item, str) else [item]:
                self.command(segment, depth + 1)
