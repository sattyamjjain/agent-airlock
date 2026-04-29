"""Tests for ``airlock studio`` (Feature C — rehearsal sandbox)."""

from __future__ import annotations

import json
import urllib.request
from typing import Any

import pytest

from agent_airlock.studio import StudioApp, StudioState, rehearse_transcript


def _block_destructive(line: str) -> dict[str, Any]:
    if "rm -rf" in line or "drop table" in line.lower():
        return {"verdict": "block", "guard": "stub_destructive", "detail": line}
    return {"verdict": "allow", "guard": "stub_noop"}


@pytest.fixture
def state() -> StudioState:
    return StudioState(verdict_fn=_block_destructive)


class TestRehearseTranscript:
    def test_one_shot_helper(self) -> None:
        lines = rehearse_transcript("ls -la\nrm -rf /tmp/x\necho hi", verdict_fn=_block_destructive)
        assert [ln.verdict for ln in lines] == ["allow", "block", "allow"]
        assert lines[1].guard == "stub_destructive"

    def test_state_remembers_runs(self, state: StudioState) -> None:
        run = state.rehearse("r1", "ls\nrm -rf /tmp\n")
        assert run.transcript_id == "r1"
        assert state.runs["r1"] is run


class TestDiff:
    def test_diff_between_runs(self, state: StudioState) -> None:
        state.rehearse("r1", "ls\nrm -rf /tmp\n")
        # New verdict_fn that allows everything; rerun with same id-suffix.
        state.verdict_fn = lambda line: {"verdict": "allow", "guard": "permissive"}
        state.rehearse("r2", "ls\nrm -rf /tmp\n")
        diff = state.diff("r1", "r2")
        # Only line 2 differs.
        assert len(diff) == 1
        assert diff[0]["line_no"] == 2
        assert diff[0]["before"]["verdict"] == "block"
        assert diff[0]["after"]["verdict"] == "allow"

    def test_diff_missing_run_returns_empty(self, state: StudioState) -> None:
        assert state.diff("nope", "also-nope") == []


class TestHTTPServer:
    def test_healthz(self, state: StudioState) -> None:
        app = StudioApp(state, host="127.0.0.1", port=0)
        httpd, _thread = app.serve_in_thread()
        try:
            port = httpd.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/healthz", timeout=2) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            assert payload == {"status": "ok"}
        finally:
            app.shutdown()

    def test_index_renders_form(self, state: StudioState) -> None:
        app = StudioApp(state, host="127.0.0.1", port=0)
        httpd, _ = app.serve_in_thread()
        try:
            port = httpd.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as r:
                body = r.read().decode("utf-8")
            assert "airlock studio" in body
            assert "<textarea" in body
        finally:
            app.shutdown()

    def test_api_rehearse(self, state: StudioState) -> None:
        app = StudioApp(state, host="127.0.0.1", port=0)
        httpd, _ = app.serve_in_thread()
        try:
            port = httpd.server_address[1]
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/rehearse",
                data=json.dumps(
                    {"transcript_id": "r1", "transcript": "ls\nrm -rf /tmp\necho ok"}
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            verdicts = [ln["verdict"] for ln in payload["lines"]]
            assert verdicts == ["allow", "block", "allow"]
            # Snapshot endpoint reflects the same run.
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/snapshot", timeout=2) as resp:
                snap = json.loads(resp.read().decode("utf-8"))
            assert "r1" in snap["runs"]
        finally:
            app.shutdown()
