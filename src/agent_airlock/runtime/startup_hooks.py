"""Startup-hook self-check: the code this interpreter ran before any of yours (v0.10.27).

CPython's ``site`` module runs two kinds of hook while the interpreter starts, before the
program's first line and before any ``import agent_airlock``:

- a line of a ``*.pth`` file in a site directory that starts with ``import`` and a space or
  a tab is passed to ``exec()`` (every other line is a directory added to ``sys.path``);
- a module named ``sitecustomize``, then one named ``usercustomize``, is imported when the
  import system can find one.

Either runs in every process that interpreter starts, which is why a compromised package
that drops a ``.pth`` file persists: its line runs before the program it rides in, every
time. :func:`check_startup_hooks` lists them. It walks ``site.getsitepackages()``,
``site.getusersitepackages()`` and every ``sys.path`` entry that is a directory, reports
each ``*.pth`` file holding an executable line, and locates ``sitecustomize`` and
``usercustomize`` with :func:`importlib.util.find_spec`, which finds a module without
running it. Each hook carries its path, its kind and the SHA-256 of its content, and an
allowlist of ``{file name: sha256}`` drops the ones you know; a known name whose content
differs stays a finding. For a ``.pth`` hook that hash covers the ``.pth`` file only, not
the modules its import lines load: a module an allowlisted line imports can change and the
hook stays allowlisted. Allowlist a ``.pth`` only when you trust what it imports, too.

Four kinds of hook every Python install can have are recognised and set apart as benign
(V0.10.36), each by its content and where it sits, never by its file name alone:
``distutils-precedence.pth`` holding exactly a line setuptools has shipped
(:data:`SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES`), virtualenv's ``_virtualenv.pth``, a
setuptools editable install's ``__editable__.*.pth`` whose every executable line calls its
finder, and a ``sitecustomize`` / ``usercustomize`` in the interpreter's own standard-library
directory. Each also needs the module its line imports to resolve to the file beside it, and
no installed distribution's ``RECORD`` may claim any of those files but the one that writes
them: setuptools' hook only setuptools, an editable hook only an editable install, and
virtualenv's or the interpreter's hook none, since neither is installed by pip. So a wheel
that drops ``_virtualenv.pth`` and its own ``_virtualenv.py`` is still a finding. A hook named
in :data:`KNOWN_INCIDENT_HOOKS` carries the advisory it was published in.

What it cannot do: these hooks have already run by the time this module is imported, so
it cannot stop them running or undo what they did. It tells you the interpreter is not
clean. ``AirlockConfig`` runs this check on the first guarded call by default
(``startup_hook_check="warn"`` since V0.10.36): it logs each unknown hook and issues one
``RuntimeWarning`` per process. ``startup_hook_check="deny"`` also refuses each call to a
tool guarded by that config, credential-bearing ones included; a tool guarded by a config
without it still runs, so set it on every config whose tools must not run beside an
unknown hook. Scanning packages when they are installed is not this library's job.

It reports a hook whether or not this interpreter's start-up ran it (``python -S``, a user
site the interpreter does not load, a ``.pth`` file ``site`` skips because it is hidden):
another interpreter on the same machine may run it. Allowlist what is yours.
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import site
import sys
import sysconfig
import threading
import warnings
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from .._log import structlog

logger = structlog.get_logger("agent-airlock.runtime.startup_hooks")

#: A ``.pth`` line ``site`` passes to ``exec()``. Every other line is read as a path.
_EXECUTABLE_PREFIXES = ("import ", "import\t")

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

#: Every line setuptools has written to ``distutils-precedence.pth``, stripped, with the
#: releases that shipped it. Read from ``setup.py`` at every release tag and from every
#: release wheel, 49.0.0 to 84.2.1; they agree. 49.0.0 to 49.2.1 shipped no such file.
SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES: tuple[tuple[str, str], ...] = (
    (
        "49.3.0-49.6.0",
        "import os; enabled = os.environ.get('SETUPTOOLS_USE_DISTUTILS') == 'local'; "
        "enabled and __import__('_distutils_hack').add_shim();",
    ),
    (
        "50.0.0-50.0.3, 60.0.0-60.0.5, 60.2.0-84.2.1",
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
        "enabled = os.environ.get(var, 'local') == 'local'; "
        "enabled and __import__('_distutils_hack').add_shim();",
    ),
    (
        "50.1.0-59.8.0",
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
        "enabled = os.environ.get(var, 'stdlib') == 'local'; "
        "enabled and __import__('_distutils_hack').add_shim();",
    ),
    (
        "60.1.0-60.1.1",
        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; "
        "enabled = os.environ.get(var, 'local') == 'local'; "
        "enabled and __import__('_distutils_hack').ensure_shim();",
    ),
)
_SETUPTOOLS_LINES = frozenset(line for _, line in SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES)

#: Startup-hook file names a published malware advisory documents, to the advisory id. A
#: finding with one of these names carries it and is logged at error level.
KNOWN_INCIDENT_HOOKS: Mapping[str, str] = MappingProxyType(
    {
        # agent-framework 1.26.1 and 1.26.2 on PyPI (OpenSSF MAL-2026-20101).
        "af_runtime_diag.pth": "GHSA-764m-3ppc-5m73",
        "agent_framework_meta.pth": "GHSA-764m-3ppc-5m73",
    }
)

#: The executable line of a setuptools editable install's ``__editable__.*.pth``.
_EDITABLE_LINE = re.compile(r"import (__editable___\w+_finder); \1\.install\(.*\)")


class StartupHookKind(str, Enum):
    """What runs a startup hook: a ``.pth`` line, or a module ``site`` imports by name."""

    PTH = "pth"
    SITECUSTOMIZE = "sitecustomize"
    USERCUSTOMIZE = "usercustomize"


@dataclass(frozen=True)
class StartupHookFinding:
    """One startup hook: where it is, what runs it, and the SHA-256 of its content.

    ``sha256`` is empty when the content could not be read (an unreadable file, a module
    found inside an archive); such a hook matches no allowlist entry. ``recognized`` names
    what a benign hook is (``"setuptools"``, ``"virtualenv"``, ``"editable install"``,
    ``"interpreter"``) and is empty for every other hook.
    """

    path: str
    kind: StartupHookKind
    sha256: str
    recognized: str = ""

    @property
    def name(self) -> str:
        """The file name an allowlist entry is keyed by."""
        return os.path.basename(self.path)

    @property
    def known_incident(self) -> str:
        """The advisory that documents a hook of this file name, or an empty string."""
        return KNOWN_INCIDENT_HOOKS.get(self.name, "")

    def to_dict(self) -> dict[str, str]:
        """The finding as JSON-ready fields; ``known_incident`` and ``recognized`` when set."""
        fields = {"path": self.path, "kind": self.kind.value, "sha256": self.sha256}
        if self.known_incident:
            fields["known_incident"] = self.known_incident
        if self.recognized:
            fields["recognized"] = self.recognized
        return fields


@dataclass(frozen=True)
class StartupHookReport:
    """The startup hooks one walk found, split by an allowlist.

    Attributes:
        findings: Hooks neither an allowlist entry covers nor the benign recogniser
            accepts: an unknown file name, or a known name whose content has another
            SHA-256.
        allowlisted: Hooks whose file name and SHA-256 both match an allowlist entry.
        scanned_dirs: The directories searched for ``.pth`` files, in walk order.
        benign: Hooks every Python install can have (setuptools, virtualenv, a setuptools
            editable install, the interpreter's own customize module); see the module
            docstring. They do not make the report unclean.
    """

    findings: tuple[StartupHookFinding, ...] = ()
    allowlisted: tuple[StartupHookFinding, ...] = ()
    scanned_dirs: tuple[str, ...] = ()
    benign: tuple[StartupHookFinding, ...] = ()

    @property
    def clean(self) -> bool:
        """True when every hook is allowlisted or benign."""
        return not self.findings


def normalize_allowlist(allowlist: Mapping[str, str] | None) -> dict[str, str]:
    """``allowlist`` as ``{file name: lowercase sha256}``.

    Args:
        allowlist: File name (``"x.pth"``, ``"sitecustomize.py"``) to the SHA-256 hex
            digest of the content allowed under that name.

    Returns:
        A new dict; an empty one for ``None``.

    Raises:
        ValueError: For a key that is not a bare file name or a value that is not a
            SHA-256 hex digest. Neither could ever match, so the hook it was meant for would
            stay a finding with nothing to say why.
    """
    if allowlist is None:
        return {}
    if not isinstance(allowlist, Mapping):
        raise ValueError(
            "the startup-hook allowlist maps file names to SHA-256 digests; "
            f"got a {type(allowlist).__name__}"
        )
    normalized: dict[str, str] = {}
    for name, digest in allowlist.items():
        if not isinstance(name, str) or not name or os.path.basename(name) != name:
            raise ValueError(
                f"startup-hook allowlist key {name!r} is not a file name; "
                "entries are keyed by name, such as 'x.pth', not by path"
            )
        value = digest.strip().lower() if isinstance(digest, str) else ""
        if not _SHA256_HEX.fullmatch(value):
            raise ValueError(
                f"startup-hook allowlist entry {name!r} is not a SHA-256 hex digest: {digest!r}"
            )
        normalized[name] = value
    return normalized


def check_startup_hooks(allowlist: Mapping[str, str] | None = None) -> StartupHookReport:
    """Walk the interpreter's site directories now and report its startup hooks.

    Every call walks again. ``@Airlock`` does not call this: it walks once per process,
    on the first call admitted with ``startup_hook_check`` on.

    Args:
        allowlist: ``{file name: sha256}`` of the hooks you know (see
            :func:`normalize_allowlist`).

    Returns:
        A :class:`StartupHookReport`; ``report.clean`` is True when every hook found is
        allowlisted or benign.

    Raises:
        ValueError: For an allowlist entry that could never match.
    """
    allowed = normalize_allowlist(allowlist)
    hooks, scanned = _walk()
    return _split(hooks, scanned, allowed)


def _walk() -> tuple[tuple[StartupHookFinding, ...], tuple[str, ...]]:
    """Every startup hook on disk where this interpreter looks, and the directories read."""
    directories = _directories()
    hooks: list[StartupHookFinding] = []
    for directory in directories:
        hooks.extend(_pth_hooks(directory))
    for name, kind in (
        ("sitecustomize", StartupHookKind.SITECUSTOMIZE),
        ("usercustomize", StartupHookKind.USERCUSTOMIZE),
    ):
        hook = _customize_hook(name, kind)
        if hook is not None:
            hooks.append(hook)
    return _recognize(tuple(hooks), directories), tuple(directories)


def _directories() -> list[str]:
    """The site directories, then each ``sys.path`` directory, each one once."""
    candidates: list[str] = []
    # Both exist on every supported Python; a `site` replaced by an old virtualenv may
    # lack them, and then sys.path is still walked below.
    if hasattr(site, "getsitepackages"):
        candidates.extend(site.getsitepackages())
    if hasattr(site, "getusersitepackages"):
        candidates.append(site.getusersitepackages())
    candidates.extend(
        os.fspath(entry) for entry in sys.path if isinstance(entry, (str, os.PathLike))
    )

    directories: list[str] = []
    seen: set[str] = set()
    for entry in candidates:
        if not isinstance(entry, str) or not entry or not os.path.isdir(entry):
            continue
        key = os.path.normcase(os.path.realpath(entry))
        if key not in seen:
            seen.add(key)
            directories.append(entry)
    return directories


def _pth_hooks(directory: str) -> Iterator[StartupHookFinding]:
    """The ``.pth`` files in ``directory`` that hold an executable line."""
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        # ``site`` cannot list it either, so no .pth file in it ran.
        return
    for name in names:
        path = os.path.join(directory, name)
        if not name.endswith(".pth") or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as handle:
                content = handle.read()
        except OSError:
            # Present but unreadable here: reported, since what it holds is unknown.
            yield StartupHookFinding(path=path, kind=StartupHookKind.PTH, sha256="")
            continue
        if _has_executable_line(content):
            yield StartupHookFinding(
                path=path,
                kind=StartupHookKind.PTH,
                sha256=hashlib.sha256(content).hexdigest(),
            )


def _has_executable_line(content: bytes) -> bool:
    """Whether ``site`` would ``exec()`` a line of this ``.pth`` content.

    Decoded the widest way any supported Python reads it: a UTF-8 byte-order mark is
    dropped (Python 3.13 does), anything undecodable is read byte by byte, and lines are
    split on every boundary ``str.splitlines`` knows, a superset of the universal newlines
    older versions split on. Over-reading here can only add a finding.
    """
    return any(line.startswith(_EXECUTABLE_PREFIXES) for line in _decode(content).splitlines())


def _decode(content: bytes) -> str:
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return content.decode("latin-1")


def _customize_hook(name: str, kind: StartupHookKind) -> StartupHookFinding | None:
    """Where the import system finds module ``name``, without importing it, or None."""
    try:
        spec = importlib.util.find_spec(name)
    except ValueError:
        # Already imported with no __spec__; read where the module came from instead.
        origin = getattr(sys.modules.get(name), "__file__", None)
    except Exception:
        # A finder that raises cannot say there is no such module: reported, not skipped.
        return StartupHookFinding(path=name, kind=kind, sha256="")
    else:
        if spec is None:
            return None
        origin = spec.origin
    if not origin:
        # A namespace package, or a module with no location: importing it runs no file.
        return None
    try:
        with open(origin, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        # Built in, frozen, inside an archive, or unreadable here.
        digest = ""
    return StartupHookFinding(path=origin, kind=kind, sha256=digest)


# --- benign hooks ----------------------------------------------------------------------


@dataclass(frozen=True)
class _Candidate:
    """A hook whose content and place match a benign kind, pending who installed it.

    ``files`` are the hook and the module files its line imports, as :func:`_key` keys;
    ``owners_ok`` is told every installed distribution that claims any of them.
    """

    label: str
    files: frozenset[str]
    owners_ok: Callable[[list[_Distribution]], bool]


@dataclass(frozen=True)
class _Distribution:
    """An installed distribution, as far as recognising a hook needs it."""

    name: str
    editable: bool


def _recognize(
    hooks: tuple[StartupHookFinding, ...], directories: list[str]
) -> tuple[StartupHookFinding, ...]:
    """``hooks`` with ``recognized`` set on each one the benign recogniser accepts."""
    candidates: dict[str, _Candidate] = {}
    for hook in hooks:
        try:
            candidate = _candidate(hook)
        except Exception:
            # Anything unexpected reading it: not recognised, so it stays a finding.
            candidate = None
        if candidate is not None:
            candidates[hook.path] = candidate
    if not candidates:
        return hooks
    try:
        claims = _claimants(
            frozenset().union(*(candidate.files for candidate in candidates.values())),
            directories,
        )
    except Exception:
        # Who installed them cannot be read, so none is recognised: all stay findings.
        return hooks
    recognized: list[StartupHookFinding] = []
    for hook in hooks:
        candidate = candidates.get(hook.path)
        if candidate is not None:
            owners = [owner for path in candidate.files for owner in claims.get(path, ())]
            if candidate.owners_ok(owners):
                hook = dataclasses.replace(hook, recognized=candidate.label)
        recognized.append(hook)
    return tuple(recognized)


def _candidate(hook: StartupHookFinding) -> _Candidate | None:
    """The benign kind ``hook`` matches by content and place, or None."""
    if not hook.sha256:
        return None
    if hook.kind is StartupHookKind.PTH:
        return _pth_candidate(hook.path)
    return _customize_candidate(hook.path)


def _pth_candidate(path: str) -> _Candidate | None:
    directory, name = os.path.split(path)
    with open(path, "rb") as handle:
        text = _decode(handle.read())
    if name == "distutils-precedence.pth":
        if text.strip() not in _SETUPTOOLS_LINES:
            return None
        modules = _module_files("_distutils_hack", directory)
        if modules is None:
            return None
        return _Candidate("setuptools", frozenset({_key(path), *modules}), _only("setuptools"))
    if name == "_virtualenv.pth":
        if text.strip() != "import _virtualenv":
            return None
        modules = _module_files("_virtualenv", directory)
        if modules is None:
            return None
        return _Candidate("virtualenv", frozenset({_key(path), *modules}), _unclaimed)
    if name.startswith("__editable__.") and name.endswith(".pth"):
        lines = [line for line in text.splitlines() if line.startswith(_EXECUTABLE_PREFIXES)]
        matches = [_EDITABLE_LINE.fullmatch(line) for line in lines]
        if not matches or not all(matches):
            return None
        files = {_key(path)}
        for match in matches:
            assert match is not None  # nosec B101 - all(matches) above
            modules = _module_files(match.group(1), directory)
            if modules is None:
                return None
            files.update(modules)
        return _Candidate("editable install", frozenset(files), _all_editable)
    return None


def _customize_candidate(path: str) -> _Candidate | None:
    """A ``sitecustomize`` / ``usercustomize`` the interpreter itself ships.

    It must sit directly in the standard-library directory (Debian and Ubuntu link theirs
    there from ``/etc``, so the directory is resolved, not the file) and no installed
    distribution may claim it: a wheel's ``data`` files can reach that directory in an
    install outside a virtual environment.
    """
    if not os.path.isfile(path):
        return None
    directory = os.path.normcase(os.path.realpath(os.path.dirname(os.path.abspath(path))))
    if directory not in _stdlib_dirs():
        return None
    return _Candidate("interpreter", frozenset({_key(path)}), _unclaimed)


def _stdlib_dirs() -> frozenset[str]:
    """The interpreter's standard-library directories, resolved."""
    paths = sysconfig.get_paths()
    return frozenset(
        os.path.normcase(os.path.realpath(paths[name]))
        for name in ("stdlib", "platstdlib")
        if paths.get(name)
    )


def _module_files(module: str, directory: str) -> list[str] | None:
    """The files of top-level ``module`` when ``sys.path`` resolves it beside ``directory``.

    ``site`` runs the hook's import against ``sys.path``, so a same-named module found
    first elsewhere is what the line would run; then it is not this hook's own module and
    the hook is not recognised. Resolved without importing anything.
    """
    entries = [os.fspath(entry) for entry in sys.path if isinstance(entry, (str, os.PathLike))]
    spec = importlib.machinery.PathFinder.find_spec(module, entries)
    if spec is None or not spec.origin or not os.path.isfile(spec.origin):
        return None
    origin = os.path.abspath(spec.origin)
    home = _key(directory)
    if spec.submodule_search_locations is not None:
        package = os.path.dirname(origin)
        if _key(os.path.dirname(package)) != home:
            return None
        return [
            _key(os.path.join(root, name)) for root, _, names in os.walk(package) for name in names
        ]
    if _key(os.path.dirname(origin)) != home:
        return None
    return [_key(origin)]


def _key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _only(name: str) -> Callable[[list[_Distribution]], bool]:
    def owners_ok(owners: list[_Distribution]) -> bool:
        return all(owner.name == name for owner in owners)

    return owners_ok


def _unclaimed(owners: list[_Distribution]) -> bool:
    return not owners


def _all_editable(owners: list[_Distribution]) -> bool:
    return all(owner.editable for owner in owners)


def _claimants(files: frozenset[str], directories: Iterable[str]) -> dict[str, list[_Distribution]]:
    """Each of ``files`` to the installed distributions whose file list names it.

    Reads every ``*.dist-info/RECORD`` and ``*.egg-info/installed-files.txt`` in the walked
    directories. A file pip installed is in its distribution's list; a file no list names
    was written some other way (virtualenv, a system package, by hand).
    """
    claims: dict[str, list[_Distribution]] = {path: [] for path in files}
    directories = list(directories)
    tokens = _record_tokens(files, directories)
    for directory in directories:
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for entry in entries:
            meta = os.path.join(directory, entry)
            if entry.endswith(".dist-info"):
                listing, base = os.path.join(meta, "RECORD"), directory
            elif entry.endswith(".egg-info"):
                listing, base = os.path.join(meta, "installed-files.txt"), meta
            else:
                continue
            try:
                with open(listing, "rb") as handle:
                    text = handle.read().decode("utf-8", "replace")
            except OSError:
                continue
            if not any(token in text for token in tokens):
                continue
            lines = [line for line in text.splitlines() if any(t in line for t in tokens)]
            try:
                paths = (
                    [row[0] for row in csv.reader(lines) if row]
                    if entry.endswith(".dist-info")
                    else lines
                )
                keys = [_key(os.path.join(base, listed.strip())) for listed in paths]
            except (csv.Error, ValueError, OSError):
                # A list that names one of these files but cannot be read (a NUL byte, an
                # undecodable row) could claim any of them, so each gets an owner no benign
                # kind accepts.
                for owners in claims.values():
                    owners.append(_UNREADABLE)
                continue
            owner: _Distribution | None = None
            for key in keys:
                if key in claims:
                    owner = owner or _distribution(entry, meta)
                    claims[key].append(owner)
    return claims


def _record_tokens(files: frozenset[str], directories: list[str]) -> frozenset[str]:
    """Text a file list's line must hold to name one of ``files``.

    Each file's path below the walked directory that holds it: ``x.pth``, or
    ``_distutils_hack/__pycache__/__init__.cpython-312.pyc``, so the ``__init__.py`` of
    every other package is never resolved. A file in no walked directory is matched by its
    name (``../sitecustomize.py``, a wheel's ``data`` file).
    """
    walked = sorted({_key(directory) for directory in directories}, key=len, reverse=True)
    tokens: set[str] = set()
    for path in files:
        home = next((root for root in walked if path.startswith(root + os.sep)), None)
        relative = os.path.relpath(path, home) if home else os.path.basename(path)
        tokens.add(relative.replace(os.sep, "/"))
        tokens.add(relative.replace(os.sep, "\\"))
    return frozenset(tokens)


_UNREADABLE = _Distribution(name="", editable=False)


def _distribution(entry: str, meta: str) -> _Distribution:
    stem = entry.rsplit(".", 1)[0]
    name = re.sub(r"[-_.]+", "-", stem.split("-", 1)[0]).lower()
    editable = False
    try:
        with open(os.path.join(meta, "direct_url.json"), encoding="utf-8") as handle:
            direct = json.load(handle)
        editable = (
            isinstance(direct, dict)
            and isinstance(direct.get("dir_info"), dict)
            and direct["dir_info"].get("editable") is True
        )
    except (OSError, ValueError):
        pass
    return _Distribution(name=name, editable=editable)


def _split(
    hooks: tuple[StartupHookFinding, ...],
    scanned: tuple[str, ...],
    allowed: Mapping[str, str],
) -> StartupHookReport:
    findings: list[StartupHookFinding] = []
    allowlisted: list[StartupHookFinding] = []
    benign: list[StartupHookFinding] = []
    for hook in hooks:
        if hook.sha256 and allowed.get(hook.name) == hook.sha256:
            allowlisted.append(hook)
        elif hook.recognized:
            benign.append(hook)
        else:
            findings.append(hook)
    return StartupHookReport(
        findings=tuple(findings),
        allowlisted=tuple(allowlisted),
        scanned_dirs=scanned,
        benign=tuple(benign),
    )


# The walk @Airlock reads, done once per process on the first call admitted with the check
# on, the hooks already logged, so each is logged once and not on every call, and whether
# this process has issued its one RuntimeWarning.
_process_lock = threading.Lock()
_process_walk: tuple[tuple[StartupHookFinding, ...], tuple[str, ...]] | None = None
_announced: set[tuple[str, str]] = set()
_warned = False


def process_startup_hook_report(allowlist: Mapping[str, str] | None = None) -> StartupHookReport:
    """This process's report: the walk runs the first time it is asked for, then never again.

    Each caller's allowlist is applied to the one walk, so two configs with different
    allowlists share it.
    """
    global _process_walk
    allowed = normalize_allowlist(allowlist)
    walked = False
    with _process_lock:
        if _process_walk is None:
            _process_walk = _walk()
            walked = True
        hooks, scanned = _process_walk
    if walked:
        for hook in hooks:
            if hook.recognized:
                logger.debug(
                    "airlock_startup_hook_recognized",
                    path=hook.path,
                    kind=hook.kind.value,
                    recognized=hook.recognized,
                )
    return _split(hooks, scanned, allowed)


def announce_startup_hook_findings(report: StartupHookReport, *, mode: str) -> None:
    """Log each finding once per process, and issue one ``RuntimeWarning`` per process.

    The event is ``airlock_startup_hook_found``, at error level for a hook named in
    :data:`KNOWN_INCIDENT_HOOKS` and at warning level otherwise. The ``RuntimeWarning``
    comes with the first findings announced, so a script that configures no logging still
    sees it; under ``-W error`` it is raised instead, from the guarded call.
    """
    global _warned
    with _process_lock:
        fresh = [
            finding
            for finding in report.findings
            if (finding.path, finding.sha256) not in _announced
        ]
        _announced.update((finding.path, finding.sha256) for finding in fresh)
        warn = bool(fresh) and not _warned
        if warn:
            _warned = True
    for finding in fresh:
        fields: dict[str, str] = {
            "path": finding.path,
            "kind": finding.kind.value,
            "sha256": finding.sha256,
            "mode": mode,
            "hint": "remove the hook, or add its file name and sha256 to startup_hook_allowlist",
        }
        if finding.known_incident:
            fields["known_incident"] = finding.known_incident
            logger.error("airlock_startup_hook_found", **fields)
        else:
            logger.warning("airlock_startup_hook_found", **fields)
    if warn:
        warnings.warn(_warning_text(fresh), RuntimeWarning, stacklevel=2)


def _warning_text(findings: list[StartupHookFinding]) -> str:
    names = ", ".join(
        f"{finding.name} (known malicious: {finding.known_incident})"
        if finding.known_incident
        else finding.name
        for finding in findings
    )
    return (
        f"agent-airlock: this Python interpreter ran startup hooks no allowlist covers before "
        f"your program started: {names}. They already ran; Airlock cannot undo them. Remove "
        "them, or add each file name and sha256 to AirlockConfig.startup_hook_allowlist "
        "(startup_hook_check='off' turns the check off)."
    )


def _reset_process_state() -> None:
    """Forget this process's walk, the hooks logged and the warning (test isolation)."""
    global _process_walk, _warned
    with _process_lock:
        _process_walk = None
        _announced.clear()
        _warned = False


__all__ = [
    "KNOWN_INCIDENT_HOOKS",
    "SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES",
    "StartupHookFinding",
    "StartupHookKind",
    "StartupHookReport",
    "announce_startup_hook_findings",
    "check_startup_hooks",
    "normalize_allowlist",
    "process_startup_hook_report",
]
