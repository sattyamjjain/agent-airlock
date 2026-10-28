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
differs stays a finding.

What it cannot do: these hooks have already run by the time this module is imported, so
it cannot stop them running or undo what they did. It tells you the interpreter is not
clean. ``AirlockConfig(startup_hook_check="deny")`` also keeps every ``@Airlock``-guarded
tool, credential-bearing ones included, from running in that process. Scanning packages
when they are installed is not this library's job.

It reports a hook whether or not this interpreter's start-up ran it (``python -S``, a user
site the interpreter does not load, a ``.pth`` file ``site`` skips because it is hidden):
another interpreter on the same machine may run it. Allowlist what is yours.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import site
import sys
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum

from .._log import structlog

logger = structlog.get_logger("agent-airlock.runtime.startup_hooks")

#: A ``.pth`` line ``site`` passes to ``exec()``. Every other line is read as a path.
_EXECUTABLE_PREFIXES = ("import ", "import\t")

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class StartupHookKind(str, Enum):
    """What runs a startup hook: a ``.pth`` line, or a module ``site`` imports by name."""

    PTH = "pth"
    SITECUSTOMIZE = "sitecustomize"
    USERCUSTOMIZE = "usercustomize"


@dataclass(frozen=True)
class StartupHookFinding:
    """One startup hook: where it is, what runs it, and the SHA-256 of its content.

    ``sha256`` is empty when the content could not be read (an unreadable file, a module
    found inside an archive); such a hook matches no allowlist entry.
    """

    path: str
    kind: StartupHookKind
    sha256: str

    @property
    def name(self) -> str:
        """The file name an allowlist entry is keyed by."""
        return os.path.basename(self.path)

    def to_dict(self) -> dict[str, str]:
        """The finding as JSON-ready fields."""
        return {"path": self.path, "kind": self.kind.value, "sha256": self.sha256}


@dataclass(frozen=True)
class StartupHookReport:
    """The startup hooks one walk found, split by an allowlist.

    Attributes:
        findings: Hooks no allowlist entry covers: an unknown file name, or a known name
            whose content has another SHA-256.
        allowlisted: Hooks whose file name and SHA-256 both match an allowlist entry.
        scanned_dirs: The directories searched for ``.pth`` files, in walk order.
    """

    findings: tuple[StartupHookFinding, ...] = ()
    allowlisted: tuple[StartupHookFinding, ...] = ()
    scanned_dirs: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        """True when no hook is outside the allowlist."""
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
        allowlisted.

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
    return tuple(hooks), tuple(directories)


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
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")
    return any(line.startswith(_EXECUTABLE_PREFIXES) for line in text.splitlines())


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


def _split(
    hooks: tuple[StartupHookFinding, ...],
    scanned: tuple[str, ...],
    allowed: Mapping[str, str],
) -> StartupHookReport:
    findings: list[StartupHookFinding] = []
    allowlisted: list[StartupHookFinding] = []
    for hook in hooks:
        if hook.sha256 and allowed.get(hook.name) == hook.sha256:
            allowlisted.append(hook)
        else:
            findings.append(hook)
    return StartupHookReport(
        findings=tuple(findings), allowlisted=tuple(allowlisted), scanned_dirs=scanned
    )


# The walk @Airlock reads, done once per process on the first call admitted with the check
# on, and the hooks already logged, so each is logged once and not on every call.
_process_lock = threading.Lock()
_process_walk: tuple[tuple[StartupHookFinding, ...], tuple[str, ...]] | None = None
_announced: set[tuple[str, str]] = set()


def process_startup_hook_report(allowlist: Mapping[str, str] | None = None) -> StartupHookReport:
    """This process's report: the walk runs the first time it is asked for, then never again.

    Each caller's allowlist is applied to the one walk, so two configs with different
    allowlists share it.
    """
    global _process_walk
    allowed = normalize_allowlist(allowlist)
    with _process_lock:
        if _process_walk is None:
            _process_walk = _walk()
        hooks, scanned = _process_walk
    return _split(hooks, scanned, allowed)


def announce_startup_hook_findings(report: StartupHookReport, *, mode: str) -> None:
    """Log one structured event per finding, the first time each is seen in this process."""
    with _process_lock:
        fresh = [
            finding
            for finding in report.findings
            if (finding.path, finding.sha256) not in _announced
        ]
        _announced.update((finding.path, finding.sha256) for finding in fresh)
    for finding in fresh:
        logger.warning(
            "airlock_startup_hook_found",
            path=finding.path,
            kind=finding.kind.value,
            sha256=finding.sha256,
            mode=mode,
            hint="remove the hook, or add its file name and sha256 to startup_hook_allowlist",
        )


def _reset_process_state() -> None:
    """Forget this process's walk and the hooks logged (test isolation)."""
    global _process_walk
    with _process_lock:
        _process_walk = None
        _announced.clear()


__all__ = [
    "StartupHookFinding",
    "StartupHookKind",
    "StartupHookReport",
    "announce_startup_hook_findings",
    "check_startup_hooks",
    "normalize_allowlist",
    "process_startup_hook_report",
]
