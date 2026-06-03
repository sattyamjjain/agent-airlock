#!/usr/bin/env python3
"""Smoke test: pip-install the v0.8.15 wheel + exercise the action-time
contradiction gate end-to-end against a simulated "acknowledged
contradiction" trace.

Runs *outside* the editable source tree:

1. Builds a wheel via ``python -m build --wheel`` into ``dist/``.
2. Creates a throwaway venv under ``.smoke-acg-venv/``.
3. Installs ``dist/agent_airlock-<version>-py3-none-any.whl`` into
   the venv. **No extras** — the gate is base-install only.
4. Runs a child Python in the venv that:
   - imports ``ActionContradictionGate`` from the *installed* package,
   - attaches it to a ``SecurityPolicy`` with the ``signal_field``
     detector keyed on ``"evidence_contradiction"``,
   - applies it to a dummy ``send_email`` tool decorated with
     ``@Airlock``,
   - passes a positional context-wrapper carrying
     ``metadata={"evidence_contradiction": True}`` — the simulated
     "acknowledged contradiction" trace,
   - asserts the dummy tool returns a blocked ``AirlockResponse``,
   - re-runs with a non-privileged tool and asserts it is admitted,
   - re-runs the privileged tool with the contradiction signal
     OFF and asserts it is admitted.

Exit codes:

  0   smoke passes.
  1   smoke assertion failed.
  2   environment problem.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess  # noqa: S404 - smoke driver
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist"
VENV_DIR = REPO_ROOT / ".smoke-acg-venv"


def _run(cmd: list[str]) -> None:
    print(f"$ {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd)  # noqa: S603 - argv pinned


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
    _run([str(py), "-m", "pip", "install", "--quiet", str(wheel)])


CHILD_SMOKE_SCRIPT = textwrap.dedent(
    """\
    import sys
    from dataclasses import dataclass, field
    from typing import Any

    # Imports from the *installed* package, not the source tree.
    from agent_airlock import Airlock, SecurityPolicy, __version__
    from agent_airlock.action_contradiction_gate import (
        ActionContradictionGate,
        ActionContradictionViolation,
    )


    @dataclass
    class _Inner:
        agent_id: str
        metadata: dict = field(default_factory=dict)


    @dataclass
    class _Wrapper:
        # RunContextWrapper-style: the seam reads .context off the
        # first positional arg and pulls agent_id + metadata.
        context: _Inner


    def main() -> int:
        if __version__ != "0.8.15":
            print(f"FAIL: __version__={__version__!r}, expected 0.8.15", file=sys.stderr)
            return 1

        policy = SecurityPolicy(
            action_contradiction_gate=ActionContradictionGate(
                signal_field_key="evidence_contradiction",
            ),
        )

        @Airlock(policy=policy)
        def send_email(_ctx: _Wrapper, to: str, body: str) -> str:
            return f"sent to {to}"

        @Airlock(policy=policy)
        def read_kb(_ctx: _Wrapper, query: str) -> str:
            return f"results for {query}"

        # 1. Simulated 'acknowledged contradiction' trace — privileged
        #    sink blocked by default.
        contradicted = _Wrapper(
            context=_Inner(
                agent_id="ag-rag",
                metadata={"evidence_contradiction": True},
            )
        )
        blocked = send_email(contradicted, to="x@x", body="<sensitive>")
        if not isinstance(blocked, dict):
            print(f"FAIL: expected blocked dict, got {type(blocked).__name__}", file=sys.stderr)
            return 1
        if blocked.get("status") != "blocked":
            print(f"FAIL: status={blocked.get('status')!r}", file=sys.stderr)
            return 1
        if "send_email" not in blocked.get("error", ""):
            print(f"FAIL: error did not mention sink: {blocked.get('error')!r}", file=sys.stderr)
            return 1
        print("OK: privileged sink BLOCKED under simulated contradiction trace")

        # 2. Non-privileged tool admitted under the same contradiction state.
        result = read_kb(contradicted, query="alpha")
        if result != "results for alpha":
            print(f"FAIL: non-sink unexpectedly blocked: {result!r}", file=sys.stderr)
            return 1
        print("OK: non-sink ADMITTED under same contradiction state")

        # 3. Clean session — no contradiction → privileged tool admits.
        clean = _Wrapper(
            context=_Inner(
                agent_id="ag-clean",
                metadata={"evidence_contradiction": False},
            )
        )
        result = send_email(clean, to="ok@ok", body="hi")
        if result != "sent to ok@ok":
            print(f"FAIL: clean session blocked: {result!r}", file=sys.stderr)
            return 1
        print("OK: clean session admits the privileged tool")

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
    parser.add_argument("--keep-venv", action="store_true")
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
