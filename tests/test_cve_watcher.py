"""Unit tests for the NVD CVE watcher (scripts/cve_watcher.py).

The watcher files GitHub issues on a cron. Two things therefore have to be
true before it is trusted to run unattended, and both are asserted here:

1. **It does not spam.** Every dedup layer suppresses, the per-run cap holds
   the excess back rather than dropping it, and a deep queue stops new filings
   entirely.
2. **Its relevance filter is not decorative.** NVD's keywordSearch matches
   indexed fields, so "mcp" alone returns NVIDIA nForce chipset CVEs. If the
   corroboration filter regressed, the watcher would open issues for Linux
   kernel bugs.

No network: every test injects a fake fetcher, and the GitHub lookups
short-circuit when no token/owner is supplied.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import (
    already_tracked,
    collect_new_cves,
    extract,
    is_relevant,
)


def _nvd(cve_id: str, description: str, cvss: float | None = 7.0) -> dict[str, Any]:
    """Minimal NVD 2.0 record shaped like the fields `extract` reads."""
    metrics = (
        {"cvssMetricV31": [{"cvssData": {"baseScore": cvss, "baseSeverity": "HIGH"}}]}
        if cvss is not None
        else {}
    )
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-09-01T00:00:00.000",
            "metrics": metrics,
            "descriptions": [{"lang": "en", "value": description}],
        }
    }


class TestIsRelevant:
    @pytest.mark.parametrize(
        "text",
        [
            "A flaw in the Model Context Protocol server allows command injection.",
            "mcp-atlassian permits arbitrary file write via download_path.",
            "Claude Code hooks allow remote code execution.",
            "Flowise CustomMCP node evaluates attacker-controlled JavaScript.",
            "An agentic tool-call loop in OpenClaw bypasses the exec denylist.",
            "Windsurf auto-loads an MCP config with no user consent.",
        ],
    )
    def test_ecosystem_text_is_relevant(self, text: str) -> None:
        assert is_relevant(text) is True

    @pytest.mark.parametrize(
        "text",
        [
            "A buffer overflow in the JPEG decoder of libfoo 1.2.",
            "SQL injection in an unrelated PHP forum.",
            "",
        ],
    )
    def test_unrelated_text_is_not_relevant(self, text: str) -> None:
        assert is_relevant(text) is False

    def test_nvidia_nforce_hardware_is_suppressed(self) -> None:
        """The documented false positive: nForce southbridges are 'MCP' parts.

        NVD returns these for the keyword `mcp`. Filing them would open triage
        issues for Linux kernel CVEs that have nothing to do with the protocol.
        """
        text = (
            "A race condition in the ueagle-atm driver on NVIDIA nForce MCP61 "
            "chipset southbridge hardware allows a local user to crash the kernel."
        )
        assert is_relevant(text) is False

    def test_hardware_words_do_not_suppress_a_real_mcp_cve(self) -> None:
        """Suppression must not fire when a genuine term carried the match."""
        text = (
            "The Model Context Protocol stdio transport in mcp-server-git allows "
            "argument injection. Affected chipset-adjacent builds are unaffected."
        )
        assert is_relevant(text) is True

    def test_bare_claude_attribution_does_not_match(self) -> None:
        """AI-authored-patch credit lines appear in unrelated projects now."""
        text = "Fix a refcount leak in the SCSI midlayer. (This patch was written by Claude.)"
        assert is_relevant(text) is False


class TestAlreadyTracked:
    def test_reads_the_real_ledger(self) -> None:
        """Sanity: the shipped catalog is a non-trivial suppression source."""
        tracked = already_tracked()
        assert len(tracked) > 20
        assert "CVE-2026-30616" in tracked

    def test_reads_ids_from_filenames_and_bodies(self, tmp_path: Path) -> None:
        docs = tmp_path / "index.md"
        docs.write_text("| CVE-2026-11111 | something |\n", encoding="utf-8")
        suite = tmp_path / "cves"
        suite.mkdir()
        (suite / "test_cve_2026_22222_thing.py").write_text("# no id in body\n")
        found = already_tracked((docs, suite))
        assert found == {"CVE-2026-11111", "CVE-2026-22222"}

    def test_missing_paths_are_not_an_error(self, tmp_path: Path) -> None:
        assert already_tracked((tmp_path / "nope.md",)) == set()


class TestCollectNewCves:
    def test_emits_a_genuinely_new_cve(self, tmp_path: Path) -> None:
        new, state = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99001", "MCP stdio command injection.")],
        )
        assert [e["id"] for e in new] == ["CVE-2026-99001"]
        assert state["filed_cves"] == ["CVE-2026-99001"]

    def test_ledger_suppresses(self, tmp_path: Path) -> None:
        ledger = tmp_path / "index.md"
        ledger.write_text("CVE-2026-99002 already covered\n", encoding="utf-8")
        new, _ = collect_new_cves(
            ledger_paths=(ledger,),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99002", "MCP stdio command injection.")],
        )
        assert new == []

    def test_state_file_suppresses(self, tmp_path: Path) -> None:
        state_path = tmp_path / "state.json"
        state_path.write_text(json.dumps({"filed_cves": ["CVE-2026-99003"]}), encoding="utf-8")
        new, _ = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=state_path,
            fetcher=lambda kw: [_nvd("CVE-2026-99003", "MCP stdio command injection.")],
        )
        assert new == []

    def test_irrelevant_description_is_dropped(self, tmp_path: Path) -> None:
        new, _ = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99004", "Heap overflow in a PNG parser.")],
        )
        assert new == []

    def test_duplicate_across_keywords_emitted_once(self, tmp_path: Path) -> None:
        new, _ = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99005", "Anthropic MCP server flaw.")],
        )
        assert len(new) == 1

    def test_corrupt_state_file_is_survivable(self, tmp_path: Path) -> None:
        state_path = tmp_path / "state.json"
        state_path.write_text("{not json", encoding="utf-8")
        new, _ = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=state_path,
            fetcher=lambda kw: [_nvd("CVE-2026-99006", "MCP protocol flaw.")],
        )
        assert [e["id"] for e in new] == ["CVE-2026-99006"]

    def test_state_is_not_written_by_collect(self, tmp_path: Path) -> None:
        """The caller persists, so a dry run leaves no trace."""
        state_path = tmp_path / "state.json"
        collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=state_path,
            fetcher=lambda kw: [_nvd("CVE-2026-99007", "MCP protocol flaw.")],
        )
        assert not state_path.exists()


class TestBackPressure:
    def test_per_run_cap_keeps_the_most_severe(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.cve_watcher as mod

        monkeypatch.setattr(mod, "MAX_NEW_PER_RUN", 2)
        batch = [
            _nvd(f"CVE-2026-990{i}", "MCP stdio command injection.", cvss=float(i))
            for i in (1, 9, 5)
        ]
        new, state = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw, b=batch: b if kw == "mcp" else [],
        )
        assert [e["id"] for e in new] == ["CVE-2026-9909", "CVE-2026-9905"]
        # Held-back CVEs must NOT be recorded as filed, or they are lost.
        assert "CVE-2026-9901" not in state["filed_cves"]

    def test_deep_queue_holds_everything(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import scripts.cve_watcher as mod

        monkeypatch.setattr(mod, "MAX_OPEN_UNTRIAGED", 1)
        monkeypatch.setattr(mod, "open_untriaged_count", lambda owner, token: 5)
        new, state = collect_new_cves(
            ledger_paths=(tmp_path / "empty.md",),
            state_path=tmp_path / "state.json",
            fetcher=lambda kw: [_nvd("CVE-2026-99008", "MCP protocol flaw.")],
        )
        assert new == []
        assert state["filed_cves"] == []


class TestExtract:
    def test_flattens_the_nvd_shape(self) -> None:
        got = extract(_nvd("CVE-2026-99009", "MCP flaw.", cvss=9.8))
        assert got["id"] == "CVE-2026-99009"
        assert got["cvss"] == 9.8
        assert got["severity"] == "HIGH"
        assert got["description"] == "MCP flaw."

    def test_missing_metrics_do_not_raise(self) -> None:
        got = extract(_nvd("CVE-2026-99010", "MCP flaw.", cvss=None))
        assert got["cvss"] is None
        assert got["severity"] is None
