"""The packages an install command names (0.10.37, GHSA-pm3r-rxg9-cj5j, GHSA-v3pr-5www-qwjr).

An agent installs a package through a shell tool far more often than through a
``{"package": ...}`` argument: ``npm i tzero-mcp@12.3.0``, ``npx -y x``, ``pip install x``,
``uvx x``. Until 0.10.37 :class:`~agent_airlock.mcp_spec.oidc_publish_window_guard.
OIDCPublishWindowGuard` read only ``package``, ``version`` and ``url``, so the same install
written as a command reached none of its lists and no release-age check.

:func:`install_specs` reads one command's argv (the guard splits a shell line into argvs
with :class:`~agent_airlock.shell_command_policy.ShellCommandPolicy`'s own scanner first)
and returns an :class:`InstallSpec` per package it installs:

- PyPI: ``pip`` / ``pip3`` / ``pip3.12`` ``install`` (``python -m pip`` reaches here as
  ``pip``), ``uv pip install``, ``uv add``, ``uv tool install``, ``uvx`` / ``uv tool run``
  (the first word, or ``--from``), ``uv run --with``, ``pipx install`` / ``run`` /
  ``inject``. ``--with``, ``--from``, ``--spec`` and ``--preinstall`` name packages too.
- npm: ``npm install`` (and its aliases ``i``, ``add``, ``in`` ...), ``npm exec`` /
  ``npm x`` / ``npx`` (the first word, or each ``-p`` / ``--package``), ``pnpm add`` /
  ``dlx``, ``pnpx``, ``yarn add`` / ``dlx`` / ``global add``, ``bun add`` / ``install X``,
  ``bunx`` / ``bun x``.

An option known to take a value is skipped with it; an unknown option is read as a flag, so
the word after it is judged as a package rather than dropped. What the guard cannot read is
returned with ``uninspectable`` set, and the guard refuses it: a requirements or
constraints file (``-r``, ``-c``), an editable or local install (``-e``, ``.``, ``./x``,
``file:``, a local wheel or tarball), a value the shell decides (``$PKG``), packages a
wrapper adds (``xargs``, ``find -exec``), and shell text an installer runs (``npx -c``,
``pnpm dlx -c``). A URL is passed on as written: the guard reads a registry tarball URL and
leaves any other URL to its rules for one.

Not read: an install with no package words (``npm install``, ``npm ci``, ``pnpm install``,
``uv sync``: the project's own manifest), other installers (``poetry``, ``pdm``,
``pipenv``, ``conda``), and which index an install uses (``--index-url``,
``--registry``): every spec is judged against the public registry's lists and times.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

InstallKind = Literal["npm", "pypi"]


@dataclass(frozen=True)
class InstallSpec:
    """One package an install command names, or why the command cannot be read.

    Attributes:
        kind: The registry it installs from.
        spec: The package spec as written (``tzero-mcp@12.3.0``, ``pkg==1.0``, a URL); for
            an uninspectable install, the word or option that made it so.
        program: The installer and its subcommand (``npm install``, ``uvx``), for messages.
        uninspectable: Why the guard cannot read what it installs, or None.
    """

    kind: InstallKind
    spec: str
    program: str = ""
    uninspectable: str | None = None


@dataclass(frozen=True)
class _Syntax:
    """How one installer's subcommand reads its words.

    ``values``: options that take a value. ``packages``: options whose value is a package
    (``--with``, ``-p``). ``refused``: options that make the install unreadable, mapped to
    why. ``runner``: the first plain word is a package to run and the rest are its own
    arguments; with a package option given it is a command name instead, not judged.
    ``at_pins``: ``name@1.2`` means ``name==1.2`` (uv's tool syntax). ``plain_packages``
    False: plain words are never packages (``uv run``'s are the command it runs).
    """

    values: frozenset[str] = frozenset()
    packages: frozenset[str] = frozenset()
    refused: tuple[tuple[str, str], ...] = ()
    runner: bool = False
    at_pins: bool = False
    plain_packages: bool = True


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


_FROM_FILE = "reads its packages from a file"
_EDITABLE = "installs an editable project from a path or VCS URL"
_SHELL_TEXT = "runs shell text the guard does not read"

_PIP_VALUES = _words(
    "-i --index-url --extra-index-url -f --find-links -t --target --prefix --root --platform "
    "--python-version --implementation --abi --src --upgrade-strategy --no-binary "
    "--only-binary --progress-bar -C --config-settings --global-option --build-option "
    "--install-option --report --root-user-action --python --proxy --retries --timeout --log "
    "--log-file --local-log --cache-dir --exists-action --trusted-host --cert --client-cert "
    "--keyring-provider --use-feature --use-deprecated"
)
_PIP_REFUSED = (
    ("-r", _FROM_FILE),
    ("--requirement", _FROM_FILE),
    ("-c", "reads constraints from a file"),
    ("--constraint", "reads constraints from a file"),
    ("-e", _EDITABLE),
    ("--editable", _EDITABLE),
    ("--group", "installs a dependency group from pyproject.toml"),
)
_UV_VALUES = _PIP_VALUES | _words(
    "-p --directory --project --config-file --color --allow-insecure-host --index "
    "--default-index --index-strategy --resolution --prerelease --exclude-newer "
    "--python-preference --python-platform --link-mode --refresh-package --reinstall-package "
    "--upgrade-package -P --no-binary-package --no-build-package --config-setting "
    "--torch-backend --extra --only-group --no-group --package --script --optional --branch "
    "--tag --rev --bounds --marker -m --frozen-from --env-file"
)
_UV_TOOL_REFUSED = (
    ("--with-requirements", _FROM_FILE),
    ("--with-editable", _EDITABLE),
    ("-e", _EDITABLE),
    ("--editable", _EDITABLE),
)
_NPM_VALUES = _words(
    "--registry --prefix -C -w --workspace --tag --omit --include --install-strategy --cache "
    "--userconfig --globalconfig --loglevel --save-prefix --before --cpu --os --libc "
    "--node-options --script-shell --otp --scope --auth-type --location"
)
_PNPM_VALUES = _words(
    "-C --dir --filter -F --reporter --loglevel --allow-build --store-dir --virtual-store-dir "
    "--registry --save-catalog-name"
)
_YARN_VALUES = _words("--cwd --mode --registry --cache-folder")
_BUN_VALUES = _words("--cwd --registry --cache-dir --backend --network-concurrency --cafile")

_PIP = _Syntax(values=_PIP_VALUES, refused=_PIP_REFUSED)
_UV_PIP = _Syntax(values=_UV_VALUES, refused=_PIP_REFUSED)
_UV_ADD = _Syntax(
    values=_UV_VALUES,
    refused=(
        ("-r", _FROM_FILE),
        ("--requirements", _FROM_FILE),
        ("-e", _EDITABLE),
        ("--editable", _EDITABLE),
    ),
)
_UV_TOOL_INSTALL = _Syntax(
    values=_UV_VALUES,
    packages=_words("--with --from"),
    refused=_UV_TOOL_REFUSED,
    at_pins=True,
)
_UVX = _Syntax(
    values=_UV_VALUES,
    packages=_words("--with --from"),
    refused=_UV_TOOL_REFUSED,
    runner=True,
    at_pins=True,
)
# ``uv run``'s plain words are the command it runs, never a package: only ``--with`` is.
_UV_RUN = _Syntax(
    values=_UV_VALUES,
    packages=_words("--with"),
    refused=_UV_TOOL_REFUSED,
    runner=True,
    plain_packages=False,
)
_PIPX_VALUES = _words("--python --pip-args --suffix --index-url --backend --fetch-python")
_PIPX_INSTALL = _Syntax(
    values=_PIPX_VALUES,
    packages=_words("--spec --preinstall"),
    refused=(("-e", _EDITABLE), ("--editable", _EDITABLE)),
)
_PIPX_RUN = _Syntax(values=_PIPX_VALUES, packages=_words("--spec"), runner=True)
_NPM_INSTALL = _Syntax(values=_NPM_VALUES)
_NPM_EXEC = _Syntax(
    values=_NPM_VALUES,
    packages=_words("-p --package"),
    refused=(("-c", _SHELL_TEXT), ("--call", _SHELL_TEXT)),
    runner=True,
)
_PNPM_ADD = _Syntax(values=_PNPM_VALUES)
_PNPM_DLX = _Syntax(
    values=_PNPM_VALUES,
    packages=_words("--package"),
    refused=(("-c", _SHELL_TEXT), ("--shell-mode", _SHELL_TEXT)),
    runner=True,
)
_YARN_ADD = _Syntax(values=_YARN_VALUES)
_YARN_DLX = _Syntax(values=_YARN_VALUES, packages=_words("-p --package"), runner=True)
_BUN_ADD = _Syntax(values=_BUN_VALUES)
_BUNX = _Syntax(values=_BUN_VALUES, packages=_words("-p --package"), runner=True)

#: npm's spellings of ``install`` (``npm help install`` lists them).
_NPM_INSTALL_ALIASES = _words(
    "install i add in ins inst insta instal isnt isnta isntal isntall install-test it"
)
_PIP_PROGRAM_RE = re.compile(r"pip(?:\d+(?:\.\d+)*)?")


def _program_name(word: str) -> str:
    """The installer a word runs, whatever directory it is in (``/venv/bin/pip`` is pip)."""
    name = posixpath.basename(word.replace("\\", "/"))
    return name[:-4] if name.lower().endswith(".exe") else name


def install_specs(argv: list[str], *, fed: bool = False) -> list[InstallSpec]:
    """The packages one command installs, or an uninspectable marker; ``[]`` for none.

    Args:
        argv: One command's words, wrappers already taken off (``sudo``, ``sh -c``).
        fed: A wrapper adds words to it when it runs (``xargs``, ``find -exec``), so an
            install in it names packages nobody can read.

    Returns:
        One :class:`InstallSpec` per package, in order. An install the guard cannot read is
        one spec with ``uninspectable`` set, and no other spec from that command.
    """
    if not argv:
        return []
    found = _read(argv)
    if found is None:
        return []
    kind, program, syntax, words = found
    if fed:
        return [InstallSpec(kind, argv[0], program, "takes packages from xargs or find -exec")]
    return _specs(kind, program, syntax, words)


_Found = tuple[InstallKind, str, _Syntax, list[str]]


def _read(argv: list[str]) -> _Found | None:
    """The installer, subcommand and syntax ``argv`` runs, with the words after them."""
    program = _program_name(argv[0])
    reader = _READERS.get(program)
    if reader is None and _PIP_PROGRAM_RE.fullmatch(program):
        reader = _pip
    return reader(program, argv[1:]) if reader is not None else None


def _subcommand(args: list[str], values: frozenset[str]) -> tuple[str | None, list[str]]:
    """The first plain word after any leading options (and their values), and the rest."""
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-") or arg == "-":
            return arg, args[index + 1 :]
        index += 2 if _takes_value(arg, values) else 1
    return (args[index], args[index + 1 :]) if index < len(args) else (None, [])


def _takes_value(arg: str, values: frozenset[str]) -> bool:
    """Whether ``arg`` is an option in ``values`` whose value is the next word."""
    if arg.startswith("--"):
        return "=" not in arg and arg in values
    return arg[:2] in values and len(arg) == 2


def _pip(program: str, args: list[str]) -> _Found | None:
    sub, rest = _subcommand(args, _PIP_VALUES)
    return ("pypi", f"{program} install", _PIP, rest) if sub == "install" else None


def _uv(_program: str, args: list[str]) -> _Found | None:
    sub, rest = _subcommand(args, _UV_VALUES)
    if sub == "pip":
        sub2, rest2 = _subcommand(rest, _UV_VALUES)
        return ("pypi", "uv pip install", _UV_PIP, rest2) if sub2 == "install" else None
    if sub == "add":
        return "pypi", "uv add", _UV_ADD, rest
    if sub == "run":
        return "pypi", "uv run", _UV_RUN, rest
    if sub == "tool":
        sub2, rest2 = _subcommand(rest, _UV_VALUES)
        if sub2 == "install":
            return "pypi", "uv tool install", _UV_TOOL_INSTALL, rest2
        if sub2 == "run":
            return "pypi", "uv tool run", _UVX, rest2
    return None


def _uvx(_program: str, args: list[str]) -> _Found | None:
    return "pypi", "uvx", _UVX, args


def _pipx(_program: str, args: list[str]) -> _Found | None:
    sub, rest = _subcommand(args, _PIPX_VALUES)
    if sub == "install":
        return "pypi", "pipx install", _PIPX_INSTALL, rest
    if sub == "run":
        return "pypi", "pipx run", _PIPX_RUN, rest
    if sub == "inject":
        venv, packages = _subcommand(rest, _PIPX_VALUES)  # the first word names the venv
        return ("pypi", "pipx inject", _PIPX_INSTALL, packages) if venv else None
    return None


def _npm(_program: str, args: list[str]) -> _Found | None:
    sub, rest = _subcommand(args, _NPM_VALUES)
    if sub in _NPM_INSTALL_ALIASES:
        return "npm", "npm install", _NPM_INSTALL, rest
    if sub in ("exec", "x"):
        return "npm", "npm exec", _NPM_EXEC, rest
    return None


def _npx(program: str, args: list[str]) -> _Found | None:
    return "npm", program, _NPM_EXEC, args


def _pnpm(_program: str, args: list[str]) -> _Found | None:
    sub, rest = _subcommand(args, _PNPM_VALUES)
    if sub == "add":
        return "npm", "pnpm add", _PNPM_ADD, rest
    if sub == "dlx":
        return "npm", "pnpm dlx", _PNPM_DLX, rest
    return None


def _pnpx(_program: str, args: list[str]) -> _Found | None:
    return "npm", "pnpx", _PNPM_DLX, args


def _yarn(_program: str, args: list[str]) -> _Found | None:
    sub, rest = _subcommand(args, _YARN_VALUES)
    if sub == "global":
        sub, rest = _subcommand(rest, _YARN_VALUES)
    if sub == "add":
        return "npm", "yarn add", _YARN_ADD, rest
    if sub == "dlx":
        return "npm", "yarn dlx", _YARN_DLX, rest
    return None


def _bun(_program: str, args: list[str]) -> _Found | None:
    sub, rest = _subcommand(args, _BUN_VALUES)
    if sub in ("add", "a", "install", "i"):
        return "npm", f"bun {sub}", _BUN_ADD, rest
    if sub == "x":
        return "npm", "bun x", _BUNX, rest
    return None


def _bunx(_program: str, args: list[str]) -> _Found | None:
    return "npm", "bunx", _BUNX, args


_Reader = Callable[[str, list[str]], "_Found | None"]
_READERS: dict[str, _Reader] = {
    "uv": _uv,
    "uvx": _uvx,
    "pipx": _pipx,
    "npm": _npm,
    "npx": _npx,
    "pnpm": _pnpm,
    "pnpx": _pnpx,
    "yarn": _yarn,
    "bun": _bun,
    "bunx": _bunx,
}


def _specs(kind: InstallKind, program: str, syntax: _Syntax, words: list[str]) -> list[InstallSpec]:
    """Every package ``words`` name under ``syntax``, or the one reason they cannot be read."""
    plain: list[str] = []
    named: list[str] = []
    refused = dict(syntax.refused)
    index = 0
    while index < len(words):
        arg = words[index]
        if arg == "--":
            plain += words[index + 1 : index + 2] if syntax.runner else words[index + 1 :]
            break
        if not arg.startswith("-") or arg == "-":
            plain.append(arg)
            if syntax.runner:
                break  # the rest are the run package's own arguments
            index += 1
            continue
        option = _option(arg, words, index, syntax, refused)
        if option.refusal is not None:
            return [InstallSpec(kind, option.name, program, option.refusal)]
        if option.value is not None and option.name in syntax.packages:
            named += _PACKAGE_LIST_RE.split(option.value)
        index += option.used
    runs_a_command = syntax.runner and bool(named)  # the plain word is a command name
    judged = named + ([] if runs_a_command or not syntax.plain_packages else plain)
    out: list[InstallSpec] = []
    for word in judged:
        problem = _unreadable_spec(kind, word)
        if problem is not None:
            return [InstallSpec(kind, word, program, problem)]
        out.append(InstallSpec(kind, _pin(word) if syntax.at_pins else word, program))
    return out


@dataclass(frozen=True)
class _Option:
    name: str
    value: str | None
    used: int
    refusal: str | None = None


def _option(
    arg: str, words: list[str], index: int, syntax: _Syntax, refused: dict[str, str]
) -> _Option:
    """One option at ``words[index]``: its name, its value if it takes one, and how many
    words it uses. Short options may be clustered (``-Ur req.txt`` is ``-U -r req.txt``)."""
    takes = syntax.values | syntax.packages | frozenset(refused)
    following = words[index + 1] if index + 1 < len(words) else None
    if arg.startswith("--"):
        name, eq, attached = arg.partition("=")
        if name in refused:
            return _Option(name, None, 1, f"{name} {refused[name]}")
        if eq:
            return _Option(name, attached, 1)
        if name in takes:
            return _Option(name, following, 2)
        return _Option(name, None, 1)  # an unknown option: read as a flag
    for position in range(1, len(arg)):
        name = "-" + arg[position]
        if name in refused:
            return _Option(name, None, 1, f"{name} {refused[name]}")
        if name in takes:
            attached = arg[position + 1 :]
            return _Option(name, attached, 1) if attached else _Option(name, following, 2)
    return _Option(arg, None, 1)


# uv reads ``--with a,b`` as two packages; a comma inside a range (``a>=1,<2``) is followed
# by an operator, not a name, so it does not split.
_PACKAGE_LIST_RE = re.compile(r",(?=\s*[A-Za-z@])")

_LOCAL_PREFIXES = ("./", "../", "/", "~", "file:", ".\\", "..\\")
_WINDOWS_DRIVE_RE = re.compile(r"[A-Za-z]:[\\/]")
_PYPI_ARCHIVES = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz")
_NPM_ARCHIVES = (".tgz", ".tar.gz", ".tar")


def _unreadable_spec(kind: InstallKind, word: str) -> str | None:
    """Why a package word cannot be judged against a registry, or None when it can."""
    text = word.strip()
    if "$" in text:
        return f"installs {text!r}, a value the shell decides when it runs"
    if "://" in text:
        return None  # a URL: judged as one
    if text in (".", "..") or text.startswith(_LOCAL_PREFIXES) or _WINDOWS_DRIVE_RE.match(text):
        return f"installs from a local path ({text!r})"
    lowered = text.lower()
    if kind == "pypi" and ("/" in text or "\\" in text or lowered.endswith(_PYPI_ARCHIVES)):
        return f"installs from a local path ({text!r})"
    if kind == "npm" and lowered.endswith(_NPM_ARCHIVES):
        return f"installs from a local tarball ({text!r})"
    return None


_AT_PIN_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?)@([^@\s]+)")


def _pin(word: str) -> str:
    """uv's tool syntax as a PEP 508 pin: ``name@1.2`` is ``name==1.2``, ``name@latest`` the
    latest release."""
    match = _AT_PIN_RE.fullmatch(word.strip())
    if match is None:
        return word
    name, version = match.groups()
    return name if version.lower() == "latest" else f"{name}=={version}"


__all__ = ["InstallKind", "InstallSpec", "install_specs"]
