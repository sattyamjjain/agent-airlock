"""Tests for the wild-payload-corpus MANIFEST.sha256 (Issue #3, v0.6.0+)."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CORPUS_2026_04 = REPO_ROOT / "src" / "agent_airlock" / "corpus" / "wild_payload_corpus" / "2026-04"
MANIFEST = CORPUS_2026_04 / "MANIFEST.sha256"


def _parse_manifest() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, rel = line.partition("  ")
        out[rel.strip()] = digest
    return out


class TestManifestExists:
    def test_manifest_file_exists(self) -> None:
        assert MANIFEST.exists()


class TestManifestCoverage:
    def test_every_yaml_in_corpus_is_listed(self) -> None:
        listed = set(_parse_manifest())
        actual = {str(p.relative_to(CORPUS_2026_04)) for p in CORPUS_2026_04.rglob("*.yaml")}
        missing = actual - listed
        extra = listed - actual
        assert not missing, f"manifest missing entries: {sorted(missing)}"
        assert not extra, f"manifest has stale entries: {sorted(extra)}"

    def test_every_listed_hash_matches(self) -> None:
        for rel, digest in _parse_manifest().items():
            target = CORPUS_2026_04 / rel
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            assert actual == digest, f"{rel}: expected {digest[:12]}, got {actual[:12]}"


class TestVerifyScript:
    def test_verify_script_exits_zero_on_clean_corpus(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/verify_corpus_manifest.py"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_verify_script_detects_drift(self, tmp_path: Path) -> None:
        # Copy the corpus, mutate one file, point the script at the copy.
        import shutil

        copy_root = tmp_path / "2026-04"
        shutil.copytree(CORPUS_2026_04, copy_root)
        target = copy_root / "01.yaml"
        target.write_text(target.read_text(encoding="utf-8") + "# tampered\n", encoding="utf-8")
        # Run the script with the copy as cwd; it picks up the local
        # MANIFEST.sha256.
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "verify_corpus_manifest.py")],
            cwd=copy_root,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "DRIFT" in result.stderr
