"""Tests for the v0.5.8 per-agent baseline + drift scoring.

Primary source:
- https://venturebeat.com/security/rsac-2026-agentic-soc-agent-telemetry-security-gap
"""

from __future__ import annotations

from pathlib import Path

from agent_airlock.baseline import (
    SQLiteBaselineStore,
    build_profile,
    drift_score,
    record_event,
)


def _seed(store: SQLiteBaselineStore, agent: str, base_ts: float) -> None:
    """Seed a deterministic 8-event profile."""
    for i in range(5):
        record_event(
            store,
            agent_id=agent,
            tool_name="read_file",
            egress_host="api.example.com",
            tokens=100,
            latency_ms=50.0,
            now_epoch=base_ts + i,
        )
    for i in range(3):
        record_event(
            store,
            agent_id=agent,
            tool_name="bash",
            egress_host="github.com",
            tokens=200,
            latency_ms=120.0,
            now_epoch=base_ts + 100 + i,
        )


class TestProfileBuild:
    def test_empty_profile(self) -> None:
        store = SQLiteBaselineStore(":memory:")
        profile = build_profile(store, "ghost")
        assert profile.event_count == 0
        assert profile.tool_mix == {}

    def test_profile_aggregates_8_events(self) -> None:
        store = SQLiteBaselineStore(":memory:")
        _seed(store, "agent-1", 1_700_000_000.0)
        profile = build_profile(store, "agent-1", now_epoch=1_700_000_500.0)
        assert profile.event_count == 8
        # Tool mix
        assert profile.tool_mix["read_file"] == 5 / 8
        assert profile.tool_mix["bash"] == 3 / 8
        # Egress
        assert profile.egress_hosts == {
            "api.example.com": 5,
            "github.com": 3,
        }
        # Token stats
        assert 100 < profile.tokens_mean < 200
        # Latency p95 dominated by bash latency
        assert profile.latency_p95 >= 100.0

    def test_window_filtering(self) -> None:
        store = SQLiteBaselineStore(":memory:")
        # Old event (10 days ago) — should be filtered out
        record_event(
            store,
            agent_id="agent-1",
            tool_name="old",
            now_epoch=1_700_000_000.0 - 10 * 86400,
        )
        record_event(
            store,
            agent_id="agent-1",
            tool_name="new",
            now_epoch=1_700_000_000.0,
        )
        profile = build_profile(store, "agent-1", now_epoch=1_700_000_000.0)
        assert profile.event_count == 1
        assert "old" not in profile.tool_mix
        assert "new" in profile.tool_mix


class TestDrift:
    def test_zero_drift(self) -> None:
        store = SQLiteBaselineStore(":memory:")
        _seed(store, "a1", 1_700_000_000.0)
        p1 = build_profile(store, "a1", now_epoch=1_700_000_500.0)
        p2 = build_profile(store, "a1", now_epoch=1_700_000_500.0)
        report = drift_score(p1, p2)
        assert report.overall == 0.0

    def test_tool_mix_drift_detected(self) -> None:
        store = SQLiteBaselineStore(":memory:")
        _seed(store, "a1", 1_700_000_000.0)
        ref = build_profile(store, "a1", now_epoch=1_700_000_500.0)
        # Inject a wildly different mix into a fresh agent's profile.
        store2 = SQLiteBaselineStore(":memory:")
        for i in range(10):
            record_event(
                store2,
                agent_id="a2",
                tool_name="evil_exfil",
                egress_host="attacker.example.com",
                tokens=900,
                latency_ms=800.0,
                now_epoch=1_700_000_000.0 + i,
            )
        cur = build_profile(store2, "a2", now_epoch=1_700_000_500.0)
        report = drift_score(ref, cur)
        # Different tool mix → tool_mix close to 1.0
        assert report.tool_mix > 0.9
        # Different egress hosts → jaccard distance = 1.0
        assert report.egress_hosts == 1.0
        # Big token + latency change → both at saturation
        assert report.tokens > 0.5
        assert report.latency > 0.5
        # Overall drift > 0.7 — clearly flagged.
        assert report.overall > 0.7


class TestStorePersistence:
    def test_events_persist_across_reopen(self, tmp_path: Path) -> None:
        db = tmp_path / "baseline.db"
        first = SQLiteBaselineStore(db)
        record_event(first, agent_id="a1", tool_name="read_file", now_epoch=1.0)
        first.close()

        second = SQLiteBaselineStore(db)
        events = second.events_since("a1", 0.0)
        assert len(events) == 1
        assert events[0].tool_name == "read_file"
        second.close()


class TestCLI:
    """Smoke-test the CLI subcommands."""

    def test_baseline_init_subcommand(self, tmp_path: Path, capsys) -> None:
        from agent_airlock.cli import baseline as bcli

        db = tmp_path / "baseline.db"
        rc = bcli.main(["--db", str(db), "init", "agent-1"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "agent-1" in out

    def test_baseline_show_empty(self, tmp_path: Path, capsys) -> None:
        from agent_airlock.cli import baseline as bcli

        db = tmp_path / "baseline.db"
        rc = bcli.main(["--db", str(db), "--format", "json", "show", "ghost"])
        assert rc == 0
        out = capsys.readouterr().out
        assert '"event_count": 0' in out
