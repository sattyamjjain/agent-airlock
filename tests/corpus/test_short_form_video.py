"""Short-form-video corpus tests + transcript_ingest_guard."""

from __future__ import annotations

import subprocess
import sys

import pytest

from agent_airlock.corpus import list_namespaces, load_corpus
from agent_airlock.mcp_spec.transcript_ingest_guard import (
    SourceKind,
    TranscriptIngestGuard,
)


class TestCorpusEnumeration:
    def test_namespace_appears_in_listing(self) -> None:
        ns = list_namespaces("wild-2026-04")
        assert "short_form_video" in ns

    def test_namespace_filter_returns_five(self) -> None:
        c = load_corpus("wild-2026-04", namespace="short_form_video")
        assert len(c.entries) == 5

    def test_all_short_form_entries_marked_provisional(self) -> None:
        c = load_corpus("wild-2026-04", namespace="short_form_video")
        for e in c.entries:
            assert e.provisional is True
            assert e.namespace == "short_form_video"
            assert e.expected_verdict == "block"


class TestTranscriptIngestGuard:
    @pytest.fixture
    def guard(self) -> TranscriptIngestGuard:
        return TranscriptIngestGuard()

    def test_blocks_on_screen_override(self, guard: TranscriptIngestGuard) -> None:
        c = load_corpus("wild-2026-04", namespace="short_form_video")
        first = c.entries[0]
        result = guard.inspect(first.payload, source_kind=SourceKind.ON_SCREEN_TEXT)
        assert result.verdict == "block"

    def test_blocks_every_short_form_payload(self, guard: TranscriptIngestGuard) -> None:
        c = load_corpus("wild-2026-04", namespace="short_form_video")
        for entry in c.entries:
            result = guard.inspect(entry.payload, source_kind=SourceKind.TRANSCRIPT)
            assert result.verdict == "block", (
                f"{entry.id}: expected block, got {result.verdict} (score={result.risk_score})"
            )

    def test_clean_caption_allows(self, guard: TranscriptIngestGuard) -> None:
        result = guard.inspect(
            "Cute cat compilation for your timeline",
            source_kind=SourceKind.CAPTION,
        )
        assert result.verdict == "allow"

    def test_source_kind_string_accepted(self, guard: TranscriptIngestGuard) -> None:
        result = guard.inspect(
            "Cute cat compilation for your timeline",
            source_kind="caption",
        )
        assert result.source_kind == SourceKind.CAPTION


class TestReplayCLI:
    """``airlock replay --namespace short_form_video`` exits 0 only on full block."""

    def test_replay_short_form_namespace_exits_zero(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_airlock.cli.replay",
                "--corpus",
                "wild-2026-04",
                "--namespace",
                "short_form_video",
                "--format",
                "tap",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"exit={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "ok 5 -" in result.stdout
