"""Every ``mcp_spec/*guard*.py`` module is a red-team bypass target (0.10.26).

``benchmarks/adaptive_redteam/adapters/registry.py`` lists the guard modules it drives as
a literal tuple, and ``tests/test_adaptive_redteam_adapters.py`` pins that tuple's length.
Nothing derived the tuple from the directory, so a new guard shipped without an adapter
was never driven by the campaign and nothing said so. This pairs the two.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT / "src"), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from benchmarks.adaptive_redteam.adapters import BYPASS_TARGETS  # noqa: E402

GUARD_DIR = _ROOT / "src" / "agent_airlock" / "mcp_spec"


def test_every_mcp_spec_guard_module_is_a_bypass_target() -> None:
    on_disk = sorted(path.stem for path in GUARD_DIR.glob("*guard*.py"))
    assert on_disk, "no guard modules found; is the checkout intact?"
    missing = sorted(set(on_disk) - set(BYPASS_TARGETS))
    assert not missing, (
        "guard modules with no red-team adapter: "
        f"{missing}; add each to BYPASS_TARGETS and build_registry() in "
        "benchmarks/adaptive_redteam/adapters/registry.py (see benchmarks/CLAUDE.md)"
    )


def test_no_bypass_target_names_a_module_that_is_gone() -> None:
    mcp_spec_targets = [name for name in BYPASS_TARGETS if (GUARD_DIR / f"{name}.py").exists()]
    top_level = _ROOT / "src" / "agent_airlock"
    other_targets = [name for name in BYPASS_TARGETS if name not in mcp_spec_targets]
    stale = [name for name in other_targets if not (top_level / f"{name}.py").exists()]
    assert not stale, f"BYPASS_TARGETS names modules that no longer exist: {stale}"
