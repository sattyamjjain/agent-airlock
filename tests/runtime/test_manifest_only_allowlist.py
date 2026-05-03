"""Tests for the v0.6.1 manifest-only runtime allowlist."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock.runtime.manifest_only_allowlist import (
    AllowlistVerdictReason,
    enforce_allowlist,
)

_KEY = "x" * 64  # ≥32 chars satisfies the manifest signing-key floor


def _write_manifest(
    tmp_path: Path,
    *,
    manifest_id: str = "local-fs",
    command: list[str] | None = None,
) -> Path:
    """Write a single-entry signed manifest to a temp file."""
    if command is None:
        command = ["python", "-m", "mcp_server_filesystem", "/tmp"]
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            [
                {
                    "manifest_id": manifest_id,
                    "command": command,
                    "env_allowlist": ["PATH"],
                    "cwd": None,
                    "signer": "test-suite",
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


class TestEnforceAllowlist:
    """Coverage for the runtime allowlist gate."""

    def test_allows_exact_argv_match(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        manifest = _write_manifest(tmp_path)
        verdict = enforce_allowlist(
            server_name="local-fs",
            argv=["python", "-m", "mcp_server_filesystem", "/tmp"],
            manifest_path=manifest,
        )
        assert verdict.allowed is True
        assert verdict.reason == AllowlistVerdictReason.ALLOWED

    def test_denies_unknown_server(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        manifest = _write_manifest(tmp_path)
        verdict = enforce_allowlist(
            server_name="not-registered",
            argv=["python", "-m", "anything"],
            manifest_path=manifest,
        )
        assert verdict.allowed is False
        assert verdict.reason == AllowlistVerdictReason.UNKNOWN_SERVER

    def test_denies_extra_inline_code_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An extra ``--code`` flag is denied even with otherwise-matching argv0."""
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        manifest = _write_manifest(tmp_path)
        verdict = enforce_allowlist(
            server_name="local-fs",
            argv=[
                "python",
                "-m",
                "mcp_server_filesystem",
                "/tmp",
                "--code",
                "print('rce')",
            ],
            manifest_path=manifest,
        )
        assert verdict.allowed is False
        assert verdict.reason == AllowlistVerdictReason.EXTRA_INLINE_FLAG

    def test_denies_argv_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        manifest = _write_manifest(tmp_path)
        verdict = enforce_allowlist(
            server_name="local-fs",
            argv=["python", "-m", "mcp_server_filesystem", "/etc"],
            manifest_path=manifest,
        )
        assert verdict.allowed is False
        assert verdict.reason == AllowlistVerdictReason.ARGV_MISMATCH

    def test_empty_manifest_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AIRLOCK_MANIFEST_SIGNING_KEY", _KEY)
        empty = tmp_path / "empty.json"
        empty.write_text("[]", encoding="utf-8")
        verdict = enforce_allowlist(
            server_name="any",
            argv=["python"],
            manifest_path=empty,
        )
        assert verdict.allowed is False
        assert verdict.reason == AllowlistVerdictReason.EMPTY_MANIFEST

    def test_signing_key_missing_returns_dedicated_reason(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No signing key in env → SIGNING_KEY_MISSING (CLI exit 3, not 2)."""
        monkeypatch.delenv("AIRLOCK_MANIFEST_SIGNING_KEY", raising=False)
        # Manifest file is irrelevant — the key check fires before we even
        # try to load the registry.
        path = tmp_path / "absent.json"
        path.write_text("[]", encoding="utf-8")
        # An empty registry short-circuits before the key check; use a
        # non-empty one that triggers the key load path.
        path.write_text(
            json.dumps(
                [
                    {
                        "manifest_id": "x",
                        "command": ["python"],
                        "env_allowlist": [],
                        "cwd": None,
                        "signer": "t",
                    }
                ]
            ),
            encoding="utf-8",
        )
        verdict = enforce_allowlist(
            server_name="x",
            argv=["python"],
            manifest_path=path,
        )
        assert verdict.allowed is False
        assert verdict.reason == AllowlistVerdictReason.SIGNING_KEY_MISSING
