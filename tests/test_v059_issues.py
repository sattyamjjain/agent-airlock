"""Tests for the three v0.5.9 open issues."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from agent_airlock.policy_presets import PresetMeta, list_active


class TestIssue1BaselineThreshold:
    """``airlock baseline diff --threshold`` returns exit 2 on breach."""

    def _make_db_with_drift(self, tmp_path: Path) -> Path:
        from agent_airlock.baseline.store import Event, SQLiteBaselineStore

        db = tmp_path / "baseline.db"
        store = SQLiteBaselineStore(path=db)
        # Reference window — population around 8 days ago so it falls
        # squarely inside the [now-14d, now-7d] reference window the
        # CLI computes from ``now - 7 days``.
        for _ in range(50):
            store.append_event(
                Event(
                    agent_id="agent-x",
                    ts_epoch=time.time() - (8 * 24 * 3600),
                    tool_name="search",
                    egress_host="api.search.example",
                    tokens=100,
                    latency_ms=120.0,
                )
            )
        # Current window: completely different tool / host so TVD /
        # Jaccard both spike well above 0.5.
        for _ in range(50):
            store.append_event(
                Event(
                    agent_id="agent-x",
                    ts_epoch=time.time(),
                    tool_name="exfiltrate",
                    egress_host="evil.example.com",
                    tokens=4000,
                    latency_ms=900.0,
                )
            )
        store.close()
        return db

    def test_below_threshold_exits_zero(self, tmp_path: Path) -> None:
        db = self._make_db_with_drift(tmp_path)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_airlock.cli.baseline",
                "--db",
                str(db),
                "--format",
                "json",
                "diff",
                "agent-x",
                "--threshold",
                "0.99",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

    def test_above_threshold_exits_two(self, tmp_path: Path) -> None:
        db = self._make_db_with_drift(tmp_path)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_airlock.cli.baseline",
                "--db",
                str(db),
                "--format",
                "json",
                "diff",
                "agent-x",
                "--threshold",
                "0.05",
            ],
            capture_output=True,
            text=True,
        )
        # Drift between two disjoint distributions is high; threshold
        # 0.05 must trip exit code 2.
        assert result.returncode == 2, (
            f"exit={result.returncode}; stdout={result.stdout!r}"
        )


class TestIssue2PackListSorted:
    def test_list_sorted_by_pack_id_then_version(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_airlock.cli.pack",
                "--format",
                "json",
                "list",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        keys = [(p["pack_id"], p["version"]) for p in data]
        assert keys == sorted(keys), f"pack list not sorted: {keys}"

    def test_list_idempotent(self) -> None:
        cmd = [
            sys.executable,
            "-m",
            "agent_airlock.cli.pack",
            "--format",
            "json",
            "list",
        ]
        a = subprocess.run(cmd, capture_output=True, text=True)
        b = subprocess.run(cmd, capture_output=True, text=True)
        assert a.stdout == b.stdout


class TestIssue3PolicyPresetsRegistry:
    def test_list_active_returns_preset_meta(self) -> None:
        metas = list_active()
        assert metas, "list_active() must return at least one preset"
        for m in metas:
            assert isinstance(m, PresetMeta)
            assert m.preset_id == m.factory_name
            assert m.preset_id  # non-empty

    def test_list_active_includes_v0_5_9_presets(self) -> None:
        ids = {m.preset_id for m in list_active()}
        # v0.5.9 newcomers must register automatically.
        for required in (
            "mcp_stdio_meta_cve_2026_04",
            "gpt_5_5_spud_agent_defaults",
            "agent_capability_default_caps",
        ):
            assert required in ids, f"{required!r} missing from list_active()"

    def test_list_active_deterministic_order(self) -> None:
        a = [m.preset_id for m in list_active()]
        b = [m.preset_id for m in list_active()]
        assert a == b
        assert a == sorted(a)

    def test_list_active_skips_predicates(self) -> None:
        ids = {m.preset_id for m in list_active()}
        # ``mcpwn_cve_2026_33032_check`` and ``flowise_cve_2025_59528_check``
        # are predicates with required positional args, not preset
        # factories. They must not appear.
        assert "mcpwn_cve_2026_33032_check" not in ids
        assert "flowise_cve_2025_59528_check" not in ids
