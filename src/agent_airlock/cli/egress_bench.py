"""``airlock egress-bench`` — CLI entry for the CVE fixture walker (v0.5.3+).

Wraps ``scripts/egress_bench.py`` as a library-callable function. Exits
the process with the bench's exit code (0 = green, 1 = regression,
2 = harness error).

Usage (module-level)::

    from agent_airlock.cli.egress_bench import egress_bench
    exit_code = egress_bench(fixture_dir=None, output_format="tap")

Primary source (motivating): https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
"""

from __future__ import annotations

import sys
from pathlib import Path


def egress_bench(
    fixture_dir: str | Path | None = None,
    output_format: str = "tap",
) -> int:
    """Run the CVE fixture walker. Returns the process exit code."""
    import importlib.util

    root = Path(__file__).resolve().parent.parent.parent.parent
    script = root / "scripts" / "egress_bench.py"
    spec = importlib.util.spec_from_file_location("_airlock_egress_bench", script)
    if spec is None or spec.loader is None:  # pragma: no cover — dev-path only
        print(f"could not load {script}", file=sys.stderr)
        return 2
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    fixture_path: Path = Path(fixture_dir) if fixture_dir is not None else mod.FIXTURE_DIR
    if not fixture_path.is_dir():
        print(f"fixture dir not found: {fixture_path}", file=sys.stderr)
        return 2

    rows = mod.walk(fixture_path)
    emitters = {"tap": mod._emit_tap, "json": mod._emit_json, "md": mod._emit_md}
    if output_format not in emitters:
        print(f"unknown format: {output_format}", file=sys.stderr)
        return 2
    print(emitters[output_format](rows))
    fail = sum(1 for r in rows if r.status == "fail")
    return 0 if fail == 0 else 1


__all__ = ["egress_bench"]
