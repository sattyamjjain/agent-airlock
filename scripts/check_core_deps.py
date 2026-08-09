#!/usr/bin/env python3
"""CI guard: a bare ``pip install agent-airlock`` must be Pydantic-only.

The zero-core-dependency claim (README, pyproject) says the installed core is Pydantic
and its transitive runtime closure and *nothing else* — structlog and everything else
live behind extras. Commit ``4a404fe`` moved structlog to the ``[logging]`` extra to make
that true, but the only machine check was a **structlog-specific denylist**: it caught
that one name and would wave through any *other* dependency that crept into
``[project.dependencies]``. This turns the sentence into an **exhaustive allowlist gate**.

Rule: after a clean ``pip install -e .`` (no extras) in an isolated environment, every
installed top-level distribution must be in the allowed set:

    allowed = {agent-airlock}
            ∪ closure(pydantic)          # walked dynamically from importlib.metadata
            ∪ {tomli}  (only on <3.11)   # the one conditional core dep in pyproject
            ∪ {pip, setuptools, wheel}   # the venv tooling baseline

Any installed distribution outside that set fails the build. The Pydantic closure is
derived at runtime (not hardcoded) so a Pydantic patch release that renames or adds a
transitive dep does not false-fail this gate; optional-dependency groups (``; extra ==``)
are excluded from the closure so a *new core* dep can never hide behind one of Pydantic's
own extras.

Run it in the clean bare-install environment the CI ``bare-install`` job creates. It is
strict by design: it is meant to run where only ``pip install -e .`` has happened, and it
prints the offending names plus the full allowed set on failure.

Exit codes: 0 = Pydantic-only · 1 = an unexpected distribution is installed.
"""

from __future__ import annotations

import importlib.metadata as md
import re
import sys

# The venv/tooling baseline that a fresh interpreter environment ships with. These are
# not runtime dependencies of agent-airlock; they are the packaging tools pip itself
# relies on and are present in any environment before a single project dep is installed.
BASELINE = {"pip", "setuptools", "wheel"}

# agent-airlock's own conditional core dep. pyproject pins it only for <3.11:
#   "tomli>=2.0;python_version<'3.11'"
SELF = {"agent-airlock"}
if sys.version_info < (3, 11):
    SELF.add("tomli")

_ROOT_DEP = "pydantic"


def _canon(name: str) -> str:
    """PEP 503 canonical distribution name (lowercase, runs of -_. collapse to -)."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _req_dist_name(requirement: str) -> str:
    """Extract the distribution name from a requirement string.

    ``"typing-extensions>=4.6.1"`` -> ``"typing-extensions"``. Avoids a dependency on
    ``packaging`` (which is not guaranteed present on a bare install).
    """
    head = re.split(r"[\s;<>=!~()\[\]]", requirement.strip(), maxsplit=1)[0]
    return _canon(head)


def _closure(root: str) -> set[str]:
    """Transitive runtime-dependency closure of ``root`` via installed metadata.

    Optional-dependency requirements (those carrying an ``extra ==`` marker) are skipped
    so the closure is exactly the *core* runtime deps a bare install pulls.
    """
    seen: set[str] = set()
    stack = [_canon(root)]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        try:
            requirements = md.requires(name) or []
        except md.PackageNotFoundError:
            continue
        for requirement in requirements:
            if "extra ==" in requirement:
                continue  # optional group, not installed on a bare install
            dep = _req_dist_name(requirement)
            if dep and dep not in seen:
                stack.append(dep)
    return seen


def _installed() -> set[str]:
    names: set[str] = set()
    for dist in md.distributions():
        name = dist.metadata["Name"]
        if name:
            names.add(_canon(name))
    return names


def main() -> int:
    allowed = BASELINE | {_canon(n) for n in SELF} | _closure(_ROOT_DEP)
    installed = _installed()
    offenders = sorted(installed - allowed)

    if offenders:
        print(
            "::error::a bare `pip install agent-airlock` pulled dependencies beyond the "
            "Pydantic-only core — the zero-core-dependency claim is false."
        )
        print("\nUnexpected installed distributions:")
        for name in offenders:
            print(f"  - {name}")
        print("\nAllowed (Pydantic transitive closure + conditional tomli + tooling baseline):")
        for name in sorted(allowed):
            print(f"  - {name}")
        print(
            "\nIf this is an intentional new core dependency, it must be justified in "
            "pyproject and this claim (README + docs) updated first."
        )
        return 1

    print("OK: bare install is Pydantic-only.")
    print("Installed:", ", ".join(sorted(installed)))
    print("Allowed:  ", ", ".join(sorted(allowed)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
