"""Harmless sentinel sinks for the oracle's ground truth.

Every sink here is harmless by construction. The campaign never authors or runs a
working exploit:

- :class:`SinkRecorder` — an in-process list of marker strings. The generic sink
  for pure validators: a "hit" means the guard admitted a value an independent
  reference detector flagged as the forbidden shape.
- :class:`FileCanary` — a canary file under a temp "forbidden root". A hit means
  an admitted path resolved onto that root (would have read/written the canary).
- :class:`LoopbackCanary` — a real ``127.0.0.1`` TCP listener. A hit means an
  admitted egress target resolved to the loopback the listener owns. No external
  host is ever contacted.
- :class:`ReduceCanary` — an object whose ``__reduce__`` only appends a marker to
  an in-process list. A hit means an admitted deserialization payload would have
  driven a ``__reduce__`` sink. Nothing untrusted is ever unpickled.
- :class:`SpawnRecorder` — records argv instead of spawning. A hit means an
  admitted spawn config would have reached a process launcher.

Each canary run points ``AIRLOCK_AUDIT_LOG_PATH`` at a file under its own temp
directory, never the checkout, so an in-process ``@Airlock`` call (mode A) writes
its audit log there and the oracle can read it back to spot a honeypot reply.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

AUDIT_ENV = "AIRLOCK_AUDIT_LOG_PATH"


@contextlib.contextmanager
def canary_env(tmp_root: Path | None = None) -> Iterator[Path]:
    """Point the audit log at a temp file for the duration of a canary run.

    Yields the audit-log path. Restores the previous ``AIRLOCK_AUDIT_LOG_PATH``
    (or unsets it) afterwards. Never writes into the checkout.
    """
    created = False
    if tmp_root is None:
        tmp_root = Path(tempfile.mkdtemp(prefix="airlock-redteam-"))
        created = True
    audit_path = tmp_root / "airlock_audit.jsonl"
    prior = os.environ.get(AUDIT_ENV)
    os.environ[AUDIT_ENV] = str(audit_path)
    try:
        yield audit_path
    finally:
        if prior is None:
            os.environ.pop(AUDIT_ENV, None)
        else:
            os.environ[AUDIT_ENV] = prior
        if created:
            with contextlib.suppress(OSError):
                for child in tmp_root.iterdir():
                    child.unlink()
                tmp_root.rmdir()


def read_audit(audit_path: Path) -> list[dict[str, object]]:
    """Parse the JSON-Lines audit file a canary run wrote, or ``[]``."""
    if not audit_path.exists():
        return []
    records: list[dict[str, object]] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        with contextlib.suppress(json.JSONDecodeError):
            records.append(json.loads(line))
    return records


@dataclass
class SinkRecorder:
    """Generic in-process sink: a list of marker strings."""

    sink: str = "sink"
    hits: list[str] = field(default_factory=list)

    def record(self, marker: str) -> None:
        self.hits.append(f"{self.sink}:{marker}")


@dataclass
class FileCanary:
    """A canary file under a temp forbidden root, with a cleanup contract."""

    root: Path
    canary: Path
    hits: list[str] = field(default_factory=list)

    @classmethod
    @contextlib.contextmanager
    def create(cls) -> Iterator[FileCanary]:
        root = Path(tempfile.mkdtemp(prefix="airlock-forbidden-"))
        canary = root / "canary.secret"
        canary.write_text("sentinel", encoding="utf-8")
        inst = cls(root=root, canary=canary)
        try:
            yield inst
        finally:
            with contextlib.suppress(OSError):
                canary.unlink()
                root.rmdir()

    def touched_by(self, admitted_path: str) -> bool:
        """Whether an admitted path resolves onto the canary (would reach it)."""
        try:
            resolved = Path(os.path.realpath(admitted_path))
        except (OSError, ValueError):
            return False
        hit = resolved == self.canary or self.root in resolved.parents or resolved == self.root
        if hit:
            self.hits.append(f"filesystem:{resolved}")
        return hit


@dataclass
class LoopbackCanary:
    """A bound ``127.0.0.1`` TCP listener; a hit is a connect to its own port."""

    host: str
    port: int
    hits: list[str] = field(default_factory=list)
    _sock: socket.socket | None = None

    @classmethod
    @contextlib.contextmanager
    def create(cls) -> Iterator[LoopbackCanary]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        host, port = sock.getsockname()
        inst = cls(host=host, port=port, _sock=sock)
        try:
            yield inst
        finally:
            with contextlib.suppress(OSError):
                sock.close()

    def connect(self, admitted_host: str, admitted_port: int | None = None) -> bool:
        """Record a hit iff the admitted target is this loopback listener.

        Only ever connects to ``127.0.0.1`` — the sentinel the canary owns.
        """
        if admitted_host not in {"127.0.0.1", "localhost", "::1"}:
            return False
        target_port = admitted_port or self.port
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                self.hits.append(f"egress:127.0.0.1:{target_port}")
                return True
        except OSError:
            return False


_REDUCE_MARKERS: list[str] = []


class ReduceSentinel:
    """An object whose ``__reduce__`` only appends a marker to a module list.

    Pickling it is harmless: the "payload" it produces, if ever unpickled, calls
    :func:`_append_marker`, which appends to :data:`_REDUCE_MARKERS` and nothing
    else. No ``os.system``, no import, no file touch.
    """

    def __init__(self, marker: str = "reduce-sentinel") -> None:
        self.marker = marker

    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (_append_marker, (self.marker,))


def _append_marker(marker: str) -> str:
    _REDUCE_MARKERS.append(marker)
    return marker


@dataclass
class ReduceCanary:
    """Tracks whether a ``__reduce__`` sentinel marker was appended."""

    marker: str = "reduce-sentinel"
    hits: list[str] = field(default_factory=list)

    def payload_bytes(self) -> bytes:
        """A pickle of the benign sentinel (for building admitted candidates)."""
        import pickle  # noqa: S403 - pickling our own harmless sentinel

        return pickle.dumps(ReduceSentinel(self.marker))

    def fire_if_admitted(self, admitted: bool) -> bool:
        """Append a marker iff the guard admitted the deserialization payload.

        Never unpickles untrusted bytes. The sentinel's ``__reduce__`` marker is
        appended directly to stand in for "the sink would have run it".
        """
        if not admitted:
            return False
        before = len(_REDUCE_MARKERS)
        _append_marker(self.marker)
        if len(_REDUCE_MARKERS) > before:
            self.hits.append(f"deserialization:{self.marker}")
            return True
        return False


@dataclass
class SpawnRecorder:
    """Records argv a guard would have handed a process launcher, never spawns."""

    hits: list[str] = field(default_factory=list)
    recorded: list[list[str]] = field(default_factory=list)

    def record(self, argv: list[str]) -> None:
        self.recorded.append(list(argv))
        self.hits.append("spawn:" + " ".join(argv))
