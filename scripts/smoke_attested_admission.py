#!/usr/bin/env python3
"""Smoke test: pip-install the built wheel + exercise the v0.8.10
MCP Attested Tool-Server Admission preset end-to-end.

This script intentionally runs *outside* the editable source tree:

1. Builds a wheel via ``python -m build --wheel`` into ``dist/``.
2. Creates a throwaway venv under ``.smoke-attested-venv/`` (deleted
   at the end if everything passes; left behind on failure for triage).
3. Installs ``dist/agent_airlock-<version>-py3-none-any.whl[attested]``
   into the venv. The ``[attested]`` extra is the surface we care
   about: it must pull in ``cryptography`` and the preset must be
   importable from the installed wheel — not the source tree.
4. Runs a child Python in the venv that:
   - imports ``mcp_attested_admission_defaults`` from the installed
     package,
   - generates an Ed25519 keypair in-process (no key bytes ever
     touch disk),
   - signs a JWS-compact clearance covering one tool name,
   - asserts that a tool *in* the allowlist is admitted,
   - asserts that a tool *not in* the allowlist is denied with
     ``verdict == "block"``,
   - asserts that ENFORCE mode denies a tampered signature.

Exit codes:

  0   all assertions held — the public preset behaves identically
      against the wheel as it does against the source tree.
  1   one or more smoke assertions failed.
  2   environment problem (build failed, venv could not be created,
      install failed).

The script is **session-local**: it does not modify ``PATH`` or any
shared state. Run from the repo root with ``python3
scripts/smoke_attested_admission.py``.
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
VENV_DIR = REPO_ROOT / ".smoke-attested-venv"


def _run(cmd: list[str], *, cwd: Path | None = None) -> None:
    """Run a subprocess; print its argv first so failures are debuggable."""
    print(f"$ {' '.join(cmd)}", flush=True)
    subprocess.check_call(cmd, cwd=cwd)  # noqa: S603 - argv pinned by this script


def build_wheel() -> Path:
    """Build a wheel into ``dist/`` and return its path."""
    DIST_DIR.mkdir(exist_ok=True)
    # Clear any older wheels so we don't accidentally install a stale build.
    for old in DIST_DIR.glob("agent_airlock-*.whl"):
        old.unlink()
    _run([sys.executable, "-m", "build", "--wheel", "--outdir", str(DIST_DIR)])
    wheels = sorted(DIST_DIR.glob("agent_airlock-*.whl"))
    if not wheels:
        print("ERROR: no wheel produced under dist/", file=sys.stderr)
        sys.exit(2)
    return wheels[-1]


def make_venv() -> tuple[Path, Path]:
    """Create a throwaway venv and return (venv_dir, python_path)."""
    if VENV_DIR.exists():
        shutil.rmtree(VENV_DIR)
    _run([sys.executable, "-m", "venv", str(VENV_DIR)])
    py = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    _run([str(py), "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
    return VENV_DIR, py


def install_wheel(py: Path, wheel: Path) -> None:
    """Install the wheel with the [attested] extra."""
    _run(
        [
            str(py),
            "-m",
            "pip",
            "install",
            "--quiet",
            f"{wheel}[attested]",
        ]
    )


CHILD_SMOKE_SCRIPT = textwrap.dedent(
    """\
    import base64
    import json
    import sys
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # The whole point: import from the *installed* package, not the source tree.
    from agent_airlock.mcp_spec.attested_admission import (
        TrustRoot,
        admit_tool,
        verify_clearance,
    )
    from agent_airlock.policy_presets import mcp_attested_admission_defaults


    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


    def sign_clearance(priv: Ed25519PrivateKey, payload: dict) -> bytes:
        header = {"alg": "EdDSA", "typ": "MCP-CLEARANCE"}
        h = b64url(json.dumps(header, separators=(",", ":")).encode())
        p = b64url(json.dumps(payload, separators=(",", ":")).encode())
        sig = priv.sign(f"{h}.{p}".encode("ascii"))
        return f"{h}.{p}.{b64url(sig)}".encode("ascii")


    def main() -> int:
        # 1. Generate keypair in-process. No bytes hit disk.
        priv = Ed25519PrivateKey.generate()
        pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # 2. Build the preset config with the freshly generated trust root.
        cfg = mcp_attested_admission_defaults(
            trust_root=TrustRoot(key_id="smoke-2026", ed25519_pem=pem),
            enforcement_mode="ENFORCE",
            max_clearance_age_days=30,
        )

        # 3. Sign a clearance with exactly one admitted tool.
        now = int(datetime.now(tz=timezone.utc).timestamp())
        blob = sign_clearance(priv, {
            "iss": "https://mcp.smoke.test",
            "sub": "srv-smoke",
            "iat": now,
            "tools": ["read"],
        })

        # 4a. Verify + admit the allowlisted tool.
        clearance = verify_clearance(blob, cfg)
        decision_ok = admit_tool(
            server_id="srv-smoke",
            tool_name="read",
            clearance=clearance,
            cfg=cfg,
        )
        if not decision_ok.admitted:
            print(f"FAIL: allowlisted tool was denied: {decision_ok.reason}",
                  file=sys.stderr)
            return 1
        if decision_ok.verdict.verdict != "allow":
            print(f"FAIL: expected verdict='allow', got "
                  f"{decision_ok.verdict.verdict!r}", file=sys.stderr)
            return 1

        # 4b. Deny a tool that is NOT in the verified allowlist.
        decision_no = admit_tool(
            server_id="srv-smoke",
            tool_name="write",
            clearance=clearance,
            cfg=cfg,
        )
        if decision_no.admitted:
            print("FAIL: non-allowlisted tool was admitted", file=sys.stderr)
            return 1
        if decision_no.verdict.verdict != "block":
            print(f"FAIL: expected verdict='block', got "
                  f"{decision_no.verdict.verdict!r}", file=sys.stderr)
            return 1
        if "tool_not_in_allowlist" not in decision_no.reason:
            print(f"FAIL: expected reason to cite allowlist; got "
                  f"{decision_no.reason!r}", file=sys.stderr)
            return 1

        # 4c. Tampered signature → ENFORCE denies via verify_clearance raising.
        h, p, s = blob.decode().split(".")
        tampered_p = ("A" + p[1:]) if p[0] != "A" else ("B" + p[1:])
        tampered = f"{h}.{tampered_p}.{s}".encode()
        try:
            verify_clearance(tampered, cfg)
        except Exception as exc:
            kind = type(exc).__name__
            if kind not in {"InvalidClearanceSignature", "MalformedClearance"}:
                print(f"FAIL: unexpected verifier exception {kind}: {exc}",
                      file=sys.stderr)
                return 1
        else:
            print("FAIL: tampered clearance did not raise", file=sys.stderr)
            return 1

        # Print the receipt verdict shape so the smoke output is useful
        # to a human eyeballing CI.
        print(f"OK: admit verdict={decision_ok.verdict.verdict!r} "
              f"fingerprint={decision_ok.clearance_fingerprint[:16]}...")
        print(f"OK: deny  verdict={decision_no.verdict.verdict!r} "
              f"reason={decision_no.reason!r}")
        print("OK: tampered signature rejected by verify_clearance")
        return 0


    sys.exit(main())
    """
)


def run_child_smoke(py: Path) -> int:
    """Run the child smoke script under the installed-wheel interpreter."""
    print("$ <venv-python> -c <SMOKE>", flush=True)
    proc = subprocess.run(  # noqa: S603 - argv pinned
        [str(py), "-c", CHILD_SMOKE_SCRIPT],
        check=False,
    )
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-venv",
        action="store_true",
        help="Don't delete .smoke-attested-venv/ on success "
        "(default: deleted on success, kept on failure).",
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

    rc = run_child_smoke(py)
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
