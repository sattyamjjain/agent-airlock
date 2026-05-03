"""End-to-end coverage for ``airlock manifest enforce`` CLI (v0.6.1+).

Exit-code contract:

- 0 — argv allowed by signed manifest
- 2 — argv denied (any deny reason except SIGNING_KEY_MISSING)
- 3 — hard error (signing key missing, manifest unreadable)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock.cli.manifest import main

_KEY = "x" * 64


def _write_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            [
                {
                    "manifest_id": "local-fs",
                    "command": ["python", "-m", "mcp_server_filesystem", "/tmp"],
                    "env_allowlist": ["PATH"],
                    "cwd": None,
                    "signer": "test",
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


class TestManifestCLI:
    """Exit-code regression tests for the airlock manifest enforce CLI."""

    def test_allow_path_exits_zero(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        manifest = _write_manifest(tmp_path)
        rc = main(
            [
                "enforce",
                "--server",
                "local-fs",
                "--manifest",
                str(manifest),
                "--",
                "python",
                "-m",
                "mcp_server_filesystem",
                "/tmp",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "allow" in out

    def test_deny_path_exits_two(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        manifest = _write_manifest(tmp_path)
        rc = main(
            [
                "enforce",
                "--server",
                "local-fs",
                "--manifest",
                str(manifest),
                "--",
                "python",
                "-m",
                "mcp_server_filesystem",
                "/etc",
            ]
        )
        assert rc == 2

    def test_hard_error_exits_three_when_signing_key_missing(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("AIRLOCK_MANIFEST_SIGNING_KEY", raising=False)
        manifest = _write_manifest(tmp_path)
        rc = main(
            [
                "enforce",
                "--server",
                "local-fs",
                "--manifest",
                str(manifest),
                "--",
                "python",
            ]
        )
        assert rc == 3

    def test_missing_argv_after_dashes_is_hard_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        manifest = _write_manifest(tmp_path)
        rc = main(
            [
                "enforce",
                "--server",
                "local-fs",
                "--manifest",
                str(manifest),
            ]
        )
        assert rc == 3

    def test_json_format_emits_parsable_payload(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        manifest = _write_manifest(tmp_path)
        main(
            [
                "--format",
                "json",
                "enforce",
                "--server",
                "local-fs",
                "--manifest",
                str(manifest),
                "--",
                "python",
                "-m",
                "mcp_server_filesystem",
                "/tmp",
            ]
        )
        # structlog emits to stdout in dev mode; pull just the JSON
        # object (the CLI's last printed block) by finding the first
        # opening brace and parsing from there.
        out = capsys.readouterr().out
        json_start = out.find("{")
        assert json_start >= 0, f"no JSON found in output: {out!r}"
        payload = json.loads(out[json_start:])
        assert payload["allowed"] is True
        assert payload["manifest_id"] == "local-fs"
