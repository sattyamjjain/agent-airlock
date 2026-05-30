#!/usr/bin/env python3
"""Smoke test: pip-install the built wheel + exercise the v0.8.12
behavioral sequence guard end-to-end.

This script runs *outside* the editable source tree:

1. Builds a wheel via ``python -m build --wheel`` into ``dist/``.
2. Creates a throwaway venv under ``.smoke-sequence-venv/``.
3. Installs ``dist/agent_airlock-<version>-py3-none-any.whl`` into
   the venv. **No extras** — the sequence guard is base-install only;
   that's the point.
4. Runs a child Python in the venv that:
   - imports ``SequenceGuard`` from the *installed* package,
   - constructs a declared-DAG guard,
   - drives a permitted transition (admit),
   - drives a disallowed transition (asserts ``SequenceViolation``
     fires with the expected ``from_tool`` / ``to_tool`` / ``mode``).

Exit codes:

  0   smoke passes — the wheel installs cleanly, base-install has zero
      new runtime deps, and the guard behaves identically against the
      installed wheel as it does against the source tree.
  1   smoke assertion failed.
  2   environment problem (build / venv / install failed).

Run from the repo root: ``python3 scripts/smoke_sequence_guard.py``.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess  # noqa: S404 - intentional, smoke driver
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist"
VENV_DIR = REPO_ROOT / ".smoke-sequence-venv"


def _run(cmd: list[str]) -> None:
    print(f"$ {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd)  # noqa: S603 - argv pinned by this script


def build_wheel() -> Path:
    DIST_DIR.mkdir(exist_ok=True)
    for old in DIST_DIR.glob("agent_airlock-*.whl"):
        old.unlink()
    _run([sys.executable, "-m", "build", "--wheel", "--outdir", str(DIST_DIR)])
    wheels = sorted(DIST_DIR.glob("agent_airlock-*.whl"))
    if not wheels:
        print("ERROR: no wheel produced under dist/", file=sys.stderr)
        sys.exit(2)
    return wheels[-1]


def make_venv() -> tuple[Path, Path]:
    if VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    _run([sys.executable, "-m", "venv", str(VENV_DIR)])
    py = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    _run([str(py), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    return VENV_DIR, py


def install_wheel(py: Path, wheel: Path) -> None:
    # Plain install — no extras. The sequence guard must work on base.
    _run([str(py), "-m", "pip", "install", "--quiet", str(wheel)])


CHILD_SMOKE_SCRIPT = textwrap.dedent(
    """\
    import sys

    # Import from the *installed* package, not the source tree.
    from agent_airlock.sequence_guard import (
        ENTRY_SENTINEL,
        SequenceGuard,
        SequenceViolation,
    )


    def main() -> int:
        # 1. Build a declared-DAG guard.
        guard = SequenceGuard(
            mode="declared",
            action="block",
            dag={
                ENTRY_SENTINEL: {"read"},
                "read": {"summarize"},
                "summarize": {"send"},
                "send": set(),
            },
        )

        # 2. Permitted transitions are admitted.
        guard.record_and_check(
            session_key="smoke", tool_name="read", args=("doc-1",), kwargs={}
        )
        guard.record_and_check(
            session_key="smoke", tool_name="summarize", args=(), kwargs={}
        )
        history_after_admit = guard.history("smoke")
        if [t for t, _ in history_after_admit] != ["read", "summarize"]:
            print(
                f"FAIL: trace shape mismatch: {history_after_admit!r}",
                file=sys.stderr,
            )
            return 1

        # 3. Disallowed transition blocks with the expected from/to.
        try:
            guard.record_and_check(
                session_key="smoke",
                tool_name="delete",
                args=(),
                kwargs={},
            )
        except SequenceViolation as exc:
            if exc.from_tool != "summarize":
                print(f"FAIL: from_tool={exc.from_tool!r}", file=sys.stderr)
                return 1
            if exc.to_tool != "delete":
                print(f"FAIL: to_tool={exc.to_tool!r}", file=sys.stderr)
                return 1
            if exc.mode != "declared":
                print(f"FAIL: mode={exc.mode!r}", file=sys.stderr)
                return 1
        else:
            print("FAIL: disallowed transition did not raise", file=sys.stderr)
            return 1

        # 4. The argument-shape hash must never include argument values.
        from agent_airlock.sequence_guard import args_shape_hash
        h1 = args_shape_hash(("secret-token-AAA",), {})
        h2 = args_shape_hash(("totally-different-string-BBB",), {})
        if h1 != h2:
            print(
                f"FAIL: shape hash leaked values: {h1[:12]} vs {h2[:12]}",
                file=sys.stderr,
            )
            return 1

        print(
            f"OK: declared DAG admitted read->summarize, blocked "
            f"summarize->delete (mode='declared')"
        )
        print(f"OK: args_shape_hash is value-invariant ({h1[:16]}...)")
        return 0


    sys.exit(main())
    """
)


def run_child(py: Path) -> int:
    print("$ <venv-python> -c <SMOKE>", flush=True)
    proc = subprocess.run([str(py), "-c", CHILD_SMOKE_SCRIPT], check=False)  # noqa: S603
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-venv",
        action="store_true",
        help="Don't delete .smoke-sequence-venv/ on success.",
    )
    args = parser.parse_args()

    try:
        wheel = build_wheel()
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: wheel build failed: {exc}", file=sys.stderr)
        return 2

    try:
        _venv, py = make_venv()
        install_wheel(py, wheel)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: venv setup failed: {exc}", file=sys.stderr)
        return 2

    rc = run_child(py)
    if rc == 0 and not args.keep_venv:
        shutil.rmtree(VENV_DIR, ignore_errors=True)
    elif rc != 0:
        print(
            f"\nSmoke failed (rc={rc}). Venv left at {VENV_DIR} for triage.",
            file=sys.stderr,
        )
    return rc


if __name__ == "__main__":
    sys.exit(main())
