"""Fetch, verify and load MCPTox's ``response_all.json`` from a pinned commit.

The file is downloaded only when the operator passes ``--fetch``, with the standard
library alone, over HTTPS, capped at :data:`MAX_DOWNLOAD_BYTES`. It lands in a temporary
file beside the cache entry, is checked against :data:`MCPTOX_SHA256`, and is renamed
into place only when the digest matches; a mismatch deletes the temporary file and
raises. An existing file (the cache or a ``--data PATH``) is verified the same way on
every load, so every published number is tied to one byte-exact input.

The content is untrusted data: it is parsed with :func:`json.load` and nothing else, and
nothing in it is ever executed. The source repository has no license, so the file is
never committed and nothing in this package quotes its prompt text.

Cases are keyed by ``(server_idx, inst_idx)``, the server's position in the file and the
instance's position on that server: MCPTox's own ``id`` field is not unique.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks._claude.ledger import default_data_dir

MCPTOX_REPO = "https://github.com/zhiqiangwang4/MCPTox-Benchmark"
MCPTOX_COMMIT = "f85189f9ad12504c197c7f920ab818a40657b1fa"
MCPTOX_FILE = "response_all.json"
MCPTOX_URL = (
    "https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/"
    f"{MCPTOX_COMMIT}/{MCPTOX_FILE}"
)
MCPTOX_SHA256 = "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03"
MCPTOX_BYTES = 20_666_873
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
"""Refuse a download larger than this (the pinned file is about 20.7 MB)."""

_CHUNK = 1 << 16


class DataUnavailableError(RuntimeError):
    """The data file is not cached and ``--fetch`` was not passed (or the path is missing)."""


class ChecksumMismatchError(RuntimeError):
    """A downloaded or supplied file does not hash to :data:`MCPTOX_SHA256`."""


def cache_path(root: Path | None = None) -> Path:
    """Where the verified file is cached: ``<data dir>/mcptox/<commit>/response_all.json``."""
    base = root if root is not None else default_data_dir()
    return base / "mcptox" / MCPTOX_COMMIT / MCPTOX_FILE


def sha256_file(path: Path) -> str:
    """Hex sha256 of a file, read in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, expected: str | None = None) -> None:
    """Raise :class:`ChecksumMismatchError` unless ``path`` hashes to ``expected``.

    ``expected`` defaults to :data:`MCPTOX_SHA256`, read at call time.
    """
    expected = expected or MCPTOX_SHA256
    actual = sha256_file(path)
    if actual != expected:
        raise ChecksumMismatchError(
            f"{path} has sha256 {actual}, expected {expected} "
            f"(MCPTox {MCPTOX_COMMIT[:12]} {MCPTOX_FILE})"
        )


def fetch(
    dest: Path | None = None,
    *,
    url: str | None = None,
    expected_sha256: str | None = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    timeout: float = 120.0,
) -> Path:
    """Download ``url`` to ``dest`` (default :func:`cache_path`), verified, atomically.

    ``url`` and ``expected_sha256`` default to the pinned :data:`MCPTOX_URL` and
    :data:`MCPTOX_SHA256`, read at call time.

    Raises:
        ValueError: ``url`` is not HTTPS.
        ChecksumMismatchError: The downloaded bytes do not hash to ``expected_sha256``;
            the temporary file is deleted first.
        RuntimeError: The response is larger than ``max_bytes``.
    """
    url = url or MCPTOX_URL
    expected_sha256 = expected_sha256 or MCPTOX_SHA256
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-HTTPS download: {url!r}")
    target = dest if dest is not None else cache_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".mcptox-", suffix=".part", dir=target.parent)
    tmp = Path(tmp_name)
    digest = hashlib.sha256()
    received = 0
    try:
        with os.fdopen(fd, "wb") as out:
            request = urllib.request.Request(url, headers={"User-Agent": "agent-airlock-bench"})
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                headers = getattr(response, "headers", None)
                declared = headers.get("Content-Length") if headers is not None else None
                if declared is not None and declared.isdigit() and int(declared) > max_bytes:
                    raise RuntimeError(
                        f"{url} declares {declared} bytes, over the {max_bytes}-byte cap"
                    )
                while True:
                    chunk = response.read(_CHUNK)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > max_bytes:
                        raise RuntimeError(f"{url} exceeded the {max_bytes}-byte cap")
                    digest.update(chunk)
                    out.write(chunk)
        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise ChecksumMismatchError(
                f"download from {url} has sha256 {actual}, expected {expected_sha256}"
            )
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return target


def resolve_data_path(data: Path | None = None, *, fetch_missing: bool = False) -> Path:
    """The verified data file: ``data`` if given, else the cache, fetching only on request.

    Raises:
        DataUnavailableError: The file is absent and fetching was not requested.
        ChecksumMismatchError: The file does not hash to :data:`MCPTOX_SHA256`.
    """
    if data is not None:
        if not data.is_file():
            raise DataUnavailableError(f"--data {data} does not exist")
        verify(data)
        return data
    cached = cache_path()
    if cached.is_file():
        verify(cached)
        return cached
    if not fetch_missing:
        raise DataUnavailableError(
            f"MCPTox data not cached at {cached}; pass --fetch to download it from "
            f"{MCPTOX_URL} (about 21 MB, verified by sha256), or --data PATH"
        )
    return fetch(cached)


def load(path: Path) -> dict[str, Any]:
    """Parse the file with :func:`json.load` (and nothing else)."""
    with path.open(encoding="utf-8") as handle:
        doc = json.load(handle)
    if not isinstance(doc, dict) or not isinstance(doc.get("servers"), dict):
        raise ValueError(f"{path} is not an MCPTox response_all.json (no 'servers' object)")
    return doc


def servers(doc: Mapping[str, Any]) -> list[tuple[int, str, Mapping[str, Any]]]:
    """``(server_idx, key, raw server)`` in file order."""
    return [(idx, str(key), raw) for idx, (key, raw) in enumerate(doc["servers"].items())]


@dataclass(frozen=True)
class Case:
    """One malicious instance: the attack side of MCPTox.

    Attributes:
        server_idx: The server's position in the file.
        inst_idx: The instance's position on its server.
        server_key: The server's key in ``servers``.
        paradigm: ``metadata.paradigm`` (``Template-1`` / ``-2`` / ``-3``).
        risk: ``metadata["security risk"]``.
        wrong_data: MCPTox's ``wrong_data`` flag (0 for 1,312 cases, 2 for 36).
        query: The user query (shared by the poisoned and clean arms).
        system: The poisoned system prompt (the clean one plus the poisoned tool).
        poisoned_tool: ``datas[0].poisoned_tool``, literal ``\\n`` normalised.
        data: The raw ``datas[0]`` mapping (responses and labels live here).
    """

    server_idx: int
    inst_idx: int
    server_key: str
    paradigm: str
    risk: str
    wrong_data: int
    query: str
    system: str
    poisoned_tool: str
    data: Mapping[str, Any]

    @property
    def key(self) -> str:
        """``"SS-III"`` (server index, instance index), unique per case."""
        return f"{self.server_idx:02d}-{self.inst_idx:03d}"


def normalise_tool_text(text: str) -> str:
    """Turn the literal two-character ``\\n`` separators some records carry into newlines.

    Only a text with no real line break is rewritten: there the escaped form is the line
    separator. A text that already has real newlines keeps any ``\\n`` it contains, which
    is then part of a value (a regex, a Windows path), not a separator.
    """
    text = text.replace("\r\n", "\n")
    if "\n" in text or "\\n" not in text:
        return text
    return text.replace("\\r\\n", "\n").replace("\\n", "\n")


def iter_cases(doc: Mapping[str, Any]) -> Iterator[Case]:
    """Every malicious instance, in file order.

    Raises:
        ValueError: An instance does not carry exactly one ``datas`` record.
    """
    for server_idx, key, raw in servers(doc):
        for inst_idx, inst in enumerate(raw.get("malicious_instance") or []):
            datas = inst.get("datas") or []
            if len(datas) != 1:
                raise ValueError(f"{key}[{inst_idx}] has {len(datas)} datas records, expected 1")
            record = datas[0]
            metadata = inst.get("metadata") or {}
            poisoned = record.get("poisoned_tool") or inst.get("poisoned_tool") or ""
            yield Case(
                server_idx=server_idx,
                inst_idx=inst_idx,
                server_key=key,
                paradigm=str(metadata.get("paradigm", "unknown")),
                risk=str(metadata.get("security risk", "unknown")),
                wrong_data=int(inst.get("wrong_data") or 0),
                query=str(record.get("query") or ""),
                system=str(record.get("system") or ""),
                poisoned_tool=normalise_tool_text(str(poisoned)),
                data=record,
            )
