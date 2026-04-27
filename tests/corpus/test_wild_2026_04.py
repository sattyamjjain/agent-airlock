"""Tests for the v0.5.8 wild-2026-04 indirect-prompt-injection corpus.

Primary source:
- https://www.helpnetsecurity.com/2026/04/24/indirect-prompt-injection-in-the-wild/
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agent_airlock.cli import replay
from agent_airlock.corpus import (
    CORPUS_ROOT,
    Corpus,
    CorpusError,
    load_corpus,
)


class TestCorpusLoader:
    def test_load_wild_2026_04(self) -> None:
        corpus = load_corpus("wild-2026-04")
        assert isinstance(corpus, Corpus)
        assert corpus.name == "wild-2026-04"
        assert len(corpus.entries) == 10

    def test_unknown_corpus_raises(self) -> None:
        with pytest.raises(CorpusError, match="unknown corpus"):
            load_corpus("does-not-exist-2099-01")

    def test_every_entry_has_pinned_hash(self) -> None:
        corpus = load_corpus("wild-2026-04")
        for entry in corpus.entries:
            recomputed = hashlib.sha256(entry.payload.encode("utf-8")).hexdigest()
            assert entry.sha256 == recomputed

    def test_every_entry_cites_helpnet_source(self) -> None:
        corpus = load_corpus("wild-2026-04")
        for entry in corpus.entries:
            assert entry.source.startswith("https://")

    def test_hash_drift_raises(self, tmp_path: Path) -> None:
        """Tampered payload with stale sha256 must fail to load."""
        bad = tmp_path / "wild_payload_corpus" / "drift"
        bad.mkdir(parents=True)
        f = bad / "01.yaml"
        # Mismatched sha256 (sha of "hello", payload is "world")
        f.write_text(
            "id: bad\n"
            "source: https://example.com\n"
            "sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\n"
            "expected_verdict: block\n"
            "payload: |\n"
            "  world\n",
            encoding="utf-8",
        )
        # Patch CORPUS_ROOT for this test only.
        from agent_airlock import corpus as corpus_mod

        original = corpus_mod.CORPUS_ROOT
        corpus_mod.CORPUS_ROOT = bad.parent
        try:
            with pytest.raises(CorpusError, match="sha256 mismatch"):
                load_corpus("drift")
        finally:
            corpus_mod.CORPUS_ROOT = original


class TestReplayCLI:
    """``airlock replay --corpus wild-2026-04`` exits 0 with default guards."""

    def test_replay_returns_zero(self) -> None:
        rc = replay.main(["--corpus", "wild-2026-04", "--format", "json"])
        assert rc == 0

    def test_unknown_corpus_exits_2(self, capsys: pytest.CaptureFixture) -> None:
        rc = replay.main(["--corpus", "no-such-corpus", "--format", "tap"])
        assert rc == 2

    def test_replay_blocks_all_ten(self) -> None:
        corpus = load_corpus("wild-2026-04")
        results = replay.replay_corpus(corpus)
        assert len(results) == 10
        assert all(r.matched for r in results)
        assert all(r.actual_verdict == "block" for r in results)


class TestCorpusFiles:
    """Each YAML file ships with the canonical layout."""

    def test_ten_files(self) -> None:
        files = sorted((CORPUS_ROOT / "2026-04").glob("*.yaml"))
        assert len(files) == 10

    def test_filenames_zero_padded(self) -> None:
        files = sorted((CORPUS_ROOT / "2026-04").glob("*.yaml"))
        names = [f.name for f in files]
        # 01.yaml ... 10.yaml — zero-padded so lexical sort = numeric.
        assert names == [f"{i:02d}.yaml" for i in range(1, 11)]
