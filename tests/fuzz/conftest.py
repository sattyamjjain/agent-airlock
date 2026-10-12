"""Hypothesis profiles for the property / differential suites.

Two profiles, selected by the ``HYPOTHESIS_PROFILE`` env var (default ``ci``):

- ``ci`` — ``max_examples=50``, ``deadline=None``, ``derandomize=True`` so a CI
  run is deterministic and every test stays well under ~5s. This is what the
  normal test job runs.
- ``deep`` — ``max_examples=5000``, no deadline. Run in waves only
  (``HYPOTHESIS_PROFILE=deep``), not in normal CI.

The suites import ``agent_airlock`` from the worktree; run with
``PYTHONPATH="$PWD/src:$PWD"`` so the worktree's ``src`` is authoritative over any
editable install.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the worktree's src authoritative even under a plain ``pytest`` invocation.
_ROOT = Path(__file__).resolve().parents[2]
for _p in (str(_ROOT / "src"), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from hypothesis import HealthCheck, settings  # noqa: E402

settings.register_profile(
    "ci",
    max_examples=50,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "deep",
    max_examples=5000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
