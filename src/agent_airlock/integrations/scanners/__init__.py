"""Pluggable IDE-scanner protocol (v0.5.9+).

Defines the minimum contract every IDE scanner integration must
expose so airlock's VS Code policy-lens can mix and match scanners
(airlock's own checks, Cisco IDE Security Scanner, third-party
plug-ins, …) under one UI.

Scanners are registered via :func:`register_scanner`. The
``CiscoIDEScannerBridge`` is the first concrete implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class Finding:
    """One scanner finding, normalised across vendors."""

    scanner_id: str
    rule_id: str
    severity: str
    """One of ``"low" | "medium" | "high" | "critical"``."""
    message: str
    file_path: str
    line: int = 0
    column: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Scanner(Protocol):
    """The minimum surface every scanner must expose."""

    name: str

    def is_configured(self) -> bool:
        """Whether the scanner has the credentials / endpoint it needs."""
        ...

    def scan_file(self, path: Path | str, source: str | None = None) -> list[Finding]:
        """Scan one file and return zero-or-more :class:`Finding`s.

        Args:
            path: Filesystem path of the file being scanned.
            source: Optional pre-loaded source text. When omitted,
                the scanner is free to read the file itself (or no-op
                when not configured).
        """
        ...


_REGISTRY: dict[str, Scanner] = {}


def register_scanner(scanner: Scanner) -> None:
    """Register a scanner under its ``name`` attribute."""
    _REGISTRY[scanner.name] = scanner


def list_scanners() -> tuple[Scanner, ...]:
    """Return every registered scanner sorted by ``name``."""
    return tuple(_REGISTRY[k] for k in sorted(_REGISTRY))


def get_scanner(name: str) -> Scanner | None:
    """Return the scanner registered under ``name``, or ``None``."""
    return _REGISTRY.get(name)


def clear_registry() -> None:
    """Remove every registered scanner — for tests."""
    _REGISTRY.clear()


__all__ = [
    "Finding",
    "Scanner",
    "clear_registry",
    "get_scanner",
    "list_scanners",
    "register_scanner",
]
