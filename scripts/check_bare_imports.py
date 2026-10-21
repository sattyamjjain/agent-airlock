#!/usr/bin/env python3
"""CI guard: every module in ``agent_airlock`` imports with the Pydantic-only core.

The "lazy optional imports" rule says anything from an extra (``e2b``, ``redis``,
``cryptography``, a framework SDK, ...) is imported inside the function that needs it,
behind ``try/except ImportError``. The ``bare-install`` job enforces it by importing the
package root, ``agent_airlock.audit`` and ``policy_presets.list_active()`` in a venv that
holds only Pydantic — which loads about three fifths of the package. The call-path gates
``sequence_guard`` and ``action_contradiction_gate``, all of ``cli/``, most of
``integrations/`` and several ``mcp_spec`` modules are imported lazily by ``core.py`` or
by nothing at all, so a module-level extra import in any of them passed that job.

This walks every module under the package with :func:`pkgutil.walk_packages`, imports
each one, and fails on the first that raises. Run it where only ``pip install -e .`` has
happened; in a dev environment every extra is present and a pass means little.

Exit codes: 0 = every module imported · 1 = at least one raised (each is printed with
its exception) · 2 = the package itself is not importable.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys


def walk(package_name: str = "agent_airlock") -> list[tuple[str, str]]:
    """Import every module under ``package_name``; return ``(module, error)`` pairs."""
    package = importlib.import_module(package_name)
    failures: list[tuple[str, str]] = []
    for info in pkgutil.walk_packages(package.__path__, f"{package_name}."):
        try:
            importlib.import_module(info.name)
        except Exception as exc:  # noqa: BLE001 - any raise is the finding
            failures.append((info.name, f"{type(exc).__name__}: {exc}"))
    return failures


def main(argv: list[str] | None = None) -> int:
    package_name = (argv or sys.argv[1:] or ["agent_airlock"])[0]
    try:
        failures = walk(package_name)
    except ImportError as exc:
        print(f"FAIL: cannot import {package_name}: {exc}")
        return 2
    count = sum(
        1
        for _ in pkgutil.walk_packages(
            importlib.import_module(package_name).__path__, f"{package_name}."
        )
    )
    if failures:
        print(f"FAIL: {len(failures)} of {count} modules under {package_name} did not import:")
        for name, error in failures:
            print(f"  {name}: {error}")
        return 1
    print(f"OK: all {count} modules under {package_name} import with the installed core.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
