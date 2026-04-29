"""Compile cache (deterministic re-runs)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from threading import Lock


def _request_hash(prompt_hash: str, user_text: str, backend: str) -> str:
    h = hashlib.sha256()
    h.update(prompt_hash.encode("utf-8"))
    h.update(b"\x00")
    h.update(backend.encode("utf-8"))
    h.update(b"\x00")
    h.update(user_text.encode("utf-8"))
    return h.hexdigest()


@dataclass
class CompileCache:
    """Pure in-memory cache. Process-local; not crash-durable on purpose.

    Determinism is the goal — durability is a separate feature
    (operators who want durable caching can layer the cache module
    over a SQLite store via ``store=`` in a follow-up).
    """

    _entries: dict[str, str] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock)

    def get(self, prompt_hash: str, user_text: str, backend: str) -> str | None:
        key = _request_hash(prompt_hash, user_text, backend)
        with self._lock:
            return self._entries.get(key)

    def put(self, prompt_hash: str, user_text: str, backend: str, yaml: str) -> None:
        key = _request_hash(prompt_hash, user_text, backend)
        with self._lock:
            self._entries[key] = yaml

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


__all__ = ["CompileCache"]
