"""Single-source-of-truth guard for the package version.

The 0.8.26 release bumped ``pyproject.toml`` but not
``agent_airlock.__version__``, so the published 0.8.26 wheel self-reported
``__version__ == "0.8.25"``. This regression pins the two together: a future
release that bumps one and forgets the other fails CI here instead of shipping
a wheel that lies about its own version.
"""

from __future__ import annotations

import sys
from pathlib import Path

import agent_airlock

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _pyproject_version() -> str:
    with _PYPROJECT.open("rb") as fh:
        return str(tomllib.load(fh)["project"]["version"])


class TestVersionConsistency:
    def test_dunder_version_matches_pyproject(self) -> None:
        assert agent_airlock.__version__ == _pyproject_version(), (
            "agent_airlock.__version__ and pyproject.toml [project].version have "
            "drifted — bump both in lockstep on every release."
        )
