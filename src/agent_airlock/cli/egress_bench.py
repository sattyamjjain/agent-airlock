"""``airlock egress-bench`` — CLI entry for the CVE fixture walker (v0.5.3+).

Wraps ``scripts/egress_bench.py`` as a library-callable function. Exits
the process with the bench's exit code (0 = green, 1 = regression,
2 = harness error).

It needs a source checkout: the walker (``scripts/egress_bench.py``) and its
fixtures (``tests/cves/fixtures/``) are not in the wheel. From an installed
package it exits 2 and says so. Until 0.10.24 it raised instead, from a wheel
(``FileNotFoundError``) and in a checkout alike (``AttributeError``, see the
loader below); only ``make egress-bench`` ran the walker.

Usage (module-level)::

    from agent_airlock.cli.egress_bench import egress_bench
    exit_code = egress_bench(fixture_dir=None, output_format="tap")

Primary source (motivating): https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
"""

from __future__ import annotations

import sys
from pathlib import Path

#: The checkout this module sits in when run from source: ``src/agent_airlock/cli/`` → repo root.
_CHECKOUT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _needs_checkout(missing: Path) -> int:
    print(
        "airlock egress-bench needs a source checkout of agent-airlock: "
        f"{missing} is not part of the installed package",
        file=sys.stderr,
    )
    return 2


def egress_bench(
    fixture_dir: str | Path | None = None,
    output_format: str = "tap",
    *,
    source_root: Path | None = None,
) -> int:
    """Run the CVE fixture walker. Returns the process exit code.

    Args:
        fixture_dir: Fixture directory to walk; defaults to the checkout's
            ``tests/cves/fixtures/``.
        output_format: ``tap``, ``json`` or ``md``.
        source_root: The checkout holding ``scripts/egress_bench.py``; defaults to the one
            this module sits in. An installed package has neither the walker nor the
            fixtures, so the call returns 2 rather than raising.

    Returns:
        0 when every fixture is green, 1 on a regression, 2 on a harness error.
    """
    import importlib.util

    root = source_root if source_root is not None else _CHECKOUT_ROOT
    script = root / "scripts" / "egress_bench.py"
    # spec_from_file_location does not check that the file exists; exec_module would raise
    # FileNotFoundError, which is what an installed `airlock egress-bench` did until 0.10.24.
    if not script.is_file():
        return _needs_checkout(script)
    spec = importlib.util.spec_from_file_location("_airlock_egress_bench", script)
    if spec is None or spec.loader is None:  # pragma: no cover — dev-path only
        print(f"could not load {script}", file=sys.stderr)
        return 2
    mod = importlib.util.module_from_spec(spec)
    # Registered before it runs: the walker's dataclasses resolve their string annotations
    # through sys.modules[cls.__module__], and an unregistered module made every call raise
    # AttributeError, in a checkout too, until 0.10.24 (only `make egress-bench`, which runs
    # the script directly, worked).
    sys.modules[spec.name] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise

    if fixture_dir is None:
        fixture_path: Path = mod.FIXTURE_DIR
        if not fixture_path.is_dir():
            return _needs_checkout(fixture_path)
    else:
        fixture_path = Path(fixture_dir)
    if not fixture_path.is_dir():
        print(f"fixture dir not found: {fixture_path}", file=sys.stderr)
        return 2

    try:
        rows = mod.walk(fixture_path)
    except ValueError as exc:  # the walker's FixtureValidationError, and malformed fixtures
        print(f"invalid fixture: {exc}", file=sys.stderr)
        return 2
    emitters = {"tap": mod._emit_tap, "json": mod._emit_json, "md": mod._emit_md}
    if output_format not in emitters:
        print(f"unknown format: {output_format}", file=sys.stderr)
        return 2
    print(emitters[output_format](rows))
    fail = sum(1 for r in rows if r.status == "fail")
    return 0 if fail == 0 else 1


def main(argv: list[str] | None = None) -> int:
    """CLI entry for ``airlock egress-bench`` (and ``python -m agent_airlock.cli.egress_bench``)."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="airlock egress-bench",
        description=(
            "Walk the CVE egress fixtures and report pass/fail (0=green, 1=regression). "
            "Needs a source checkout: the walker and its fixtures are not in the wheel."
        ),
    )
    parser.add_argument(
        "--fixture-dir",
        default=None,
        help="Fixture directory to walk (default: the bundled CVE fixture set).",
    )
    parser.add_argument(
        "--format",
        choices=("tap", "json", "md"),
        default="tap",
        help="Output format (default: tap).",
    )
    args = parser.parse_args(argv)
    return egress_bench(fixture_dir=args.fixture_dir, output_format=args.format)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["egress_bench", "main"]
