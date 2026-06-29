#!/usr/bin/env python3
"""Smoke test: pip-install the v0.8.13 wheel + exercise ``airlock-explain``
end-to-end against a fixture trace and policy.

Runs *outside* the editable source tree:

1. Builds a wheel via ``python -m build --wheel`` into ``dist/``.
2. Creates a throwaway venv under ``.smoke-explain-venv/``.
3. Installs ``dist/agent_airlock-<version>-py3-none-any.whl`` into
   the venv. **No extras** — the new CLI is base-install only.
4. Confirms that ``airlock-explain`` is installed as a console-script
   (proves the new ``[project.scripts]`` block in ``pyproject.toml``
   actually shipped).
5. Writes a fixture policy + audit JSONL trace to disk and runs the
   CLI with ``--format json``. Parses the output and asserts that
   the per-agent ``unused_patterns`` set is exactly the expected
   dead-weight set.

Exit codes:

  0   smoke passes — wheel installs, console-script registers, CLI
      produces the expected diff against the installed wheel.
  1   smoke assertion failed.
  2   environment problem (build / venv / install / shutil.which).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # noqa: S404 - intentional, smoke driver
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist"
VENV_DIR = REPO_ROOT / ".smoke-explain-venv"


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
    _run([str(py), "-m", "pip", "install", "--quiet", str(wheel)])


def write_fixtures(workdir: Path) -> tuple[Path, Path]:
    """Write a deterministic fixture policy + JSONL trace.

    The trace mixes admitted + blocked calls across two agents. The
    smoke assertion is keyed off the deterministic ``unused_patterns``
    sets the diff must produce against this fixture.
    """
    policy = workdir / "policy.toml"
    policy.write_text(
        textwrap.dedent(
            """\
            allowed_tools = ["read_*", "search_*", "write_*", "delete_*"]
            denied_tools  = ["rm_-rf", "drop_database"]
            """
        ),
        encoding="utf-8",
    )
    trace = workdir / "trace.jsonl"
    records = [
        "# Agent-Airlock Audit Log",
        json.dumps({"tool_name": "read_file", "blocked": False, "agent_id": "ag1"}),
        json.dumps({"tool_name": "search_kb", "blocked": False, "agent_id": "ag1"}),
        json.dumps(
            {
                "tool_name": "delete_user",  # blocked — must be ignored
                "blocked": True,
                "agent_id": "ag1",
                "block_reason": "denylisted",
            }
        ),
        json.dumps({"tool_name": "read_file", "blocked": False, "agent_id": "ag2"}),
    ]
    trace.write_text("\n".join(records) + "\n", encoding="utf-8")
    return policy, trace


def run_cli_against_installed_wheel(
    venv_dir: Path, policy: Path, trace: Path
) -> tuple[int, str, str]:
    """Resolve ``airlock-explain`` from the venv bin/ dir and invoke it.

    Does NOT add the venv to PATH — we resolve the absolute path of
    the console-script directly. This proves the console-script
    actually got installed by the wheel, not just that the source tree
    happens to be importable.
    """
    script_name = "airlock-explain.exe" if sys.platform == "win32" else "airlock-explain"
    script_dir = venv_dir / ("Scripts" if sys.platform == "win32" else "bin")
    script_path = script_dir / script_name
    if not script_path.exists():
        print(
            f"FAIL: console-script {script_path} not installed by the wheel",
            file=sys.stderr,
        )
        return 1, "", ""
    print(f"$ {script_path} --unused-scopes --policy {policy} --trace {trace} --format json")
    proc = subprocess.run(  # noqa: S603 - argv pinned
        [
            str(script_path),
            "--unused-scopes",
            "--policy",
            str(policy),
            "--trace",
            str(trace),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def assert_unused_sets(stdout: str) -> int:
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as exc:
        print(f"FAIL: CLI stdout is not valid JSON: {exc}\nstdout={stdout!r}", file=sys.stderr)
        return 1

    expected = {
        "ag1": {"unused": ["delete_*", "write_*"], "used": ["read_*", "search_*"]},
        "ag2": {"unused": ["delete_*", "search_*", "write_*"], "used": ["read_*"]},
    }
    for r in doc:
        agent = r["agent_id"]
        if agent not in expected:
            print(f"FAIL: unexpected agent {agent!r}", file=sys.stderr)
            return 1
        if sorted(r["unused_patterns"]) != expected[agent]["unused"]:
            print(
                f"FAIL: {agent} unused={r['unused_patterns']!r} "
                f"expected={expected[agent]['unused']!r}",
                file=sys.stderr,
            )
            return 1
        if sorted(r["used_patterns"]) != expected[agent]["used"]:
            print(
                f"FAIL: {agent} used={r['used_patterns']!r} expected={expected[agent]['used']!r}",
                file=sys.stderr,
            )
            return 1
    print(f"OK: ag1 unused={expected['ag1']['unused']!r}, used={expected['ag1']['used']!r}")
    print(f"OK: ag2 unused={expected['ag2']['unused']!r}, used={expected['ag2']['used']!r}")
    return 0


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
        venv_dir, py = make_venv()
        install_wheel(py, wheel)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: venv setup failed: {exc}", file=sys.stderr)
        return 2

    fixtures_dir = VENV_DIR.parent / ".smoke-explain-fixtures"
    fixtures_dir.mkdir(exist_ok=True)
    policy, trace = write_fixtures(fixtures_dir)

    rc, stdout, stderr = run_cli_against_installed_wheel(venv_dir, policy, trace)
    if rc != 0:
        print(f"FAIL: CLI returned {rc}\nstderr={stderr!r}", file=sys.stderr)
        return 1
    assert_rc = assert_unused_sets(stdout)
    if assert_rc != 0:
        return assert_rc

    # Read-only contract: the policy file must be byte-identical after the run.
    if (fixtures_dir / "policy.toml").read_bytes() != policy.read_bytes():
        print("FAIL: policy file changed after CLI run", file=sys.stderr)
        return 1
    print("OK: policy file byte-identical after CLI run (read-only contract held)")

    if not args.keep_venv:
        shutil.rmtree(VENV_DIR, ignore_errors=True)
        shutil.rmtree(fixtures_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
