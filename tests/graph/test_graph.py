"""Tests for ``airlock graph`` (builder + HTTP server + CLI dump)."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from agent_airlock.graph import build_snapshot
from agent_airlock.graph.server import serve_in_thread


@pytest.fixture
def sample_events() -> list[dict]:
    return [
        {
            "agent_id": "agent-A",
            "tool_name": "fetch_url",
            "mcp_server": "mcp.example",
            "verdict": "allow",
            "envelope_id": "e1",
        },
        {
            "agent_id": "agent-A",
            "tool_name": "fetch_url",
            "mcp_server": "mcp.example",
            "verdict": "allow",
            "envelope_id": "e2",
        },
        {
            "agent_id": "agent-A",
            "tool_name": "delete_file",
            "verdict": "block",
            "envelope_id": "e3",
        },
        {
            "agent_id": "agent-B",
            "tool_name": "fetch_url",
            "verdict": "warn",
            "envelope_id": "e4",
        },
    ]


class TestBuilder:
    def test_node_kinds_and_count(self, sample_events: list[dict]) -> None:
        snap = build_snapshot(sample_events)
        kinds = {n.id: n.kind for n in snap.nodes}
        assert kinds["agent-A"] == "agent"
        assert kinds["fetch_url"] == "tool"
        assert kinds["mcp.example"] == "mcp_server"

    def test_edge_aggregation(self, sample_events: list[dict]) -> None:
        snap = build_snapshot(sample_events)
        # agent-A -> fetch_url 'allow' should aggregate to count=2.
        match = [
            e
            for e in snap.edges
            if e.src == "agent-A" and e.dst == "fetch_url" and e.verdict == "allow"
        ]
        assert len(match) == 1
        assert match[0].count == 2
        assert match[0].last_envelope_id == "e2"

    def test_blocks_kept_separate_from_allows(self, sample_events: list[dict]) -> None:
        snap = build_snapshot(sample_events)
        block_edges = [e for e in snap.edges if e.verdict == "block"]
        assert len(block_edges) == 1
        assert block_edges[0].dst == "delete_file"

    def test_deterministic_order(self, sample_events: list[dict]) -> None:
        a = build_snapshot(sample_events)
        b = build_snapshot(sample_events)
        assert [n.id for n in a.nodes] == [n.id for n in b.nodes]
        assert [(e.src, e.dst, e.verdict) for e in a.edges] == [
            (e.src, e.dst, e.verdict) for e in b.edges
        ]

    def test_missing_fields_skipped(self) -> None:
        snap = build_snapshot([{"agent_id": "x"}, {"tool_name": "y"}])
        assert snap.nodes == ()
        assert snap.edges == ()


class TestSnapshotJSONStable:
    def test_to_dict_round_trip(self, sample_events: list[dict]) -> None:
        snap = build_snapshot(sample_events)
        d = snap.to_dict()
        assert d["version"] == 1
        assert "nodes" in d and "edges" in d
        # Round-trip through JSON.
        reparsed = json.loads(json.dumps(d))
        assert reparsed == d


class TestHTTPServer:
    def test_snapshot_endpoint_returns_json(self, sample_events: list[dict]) -> None:
        httpd, _ = serve_in_thread(in_memory=sample_events, host="127.0.0.1", port=0)
        try:
            port = httpd.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/snapshot", timeout=2) as resp:
                assert resp.status == 200
                payload = json.loads(resp.read().decode("utf-8"))
            assert payload["version"] == 1
            assert any(n["id"] == "agent-A" for n in payload["nodes"])
        finally:
            httpd.shutdown()

    def test_healthz(self) -> None:
        httpd, _ = serve_in_thread(in_memory=[], host="127.0.0.1", port=0)
        try:
            port = httpd.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/healthz", timeout=2) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            assert payload == {"status": "ok"}
        finally:
            httpd.shutdown()

    def test_index_html_served(self) -> None:
        httpd, _ = serve_in_thread(in_memory=[], host="127.0.0.1", port=0)
        try:
            port = httpd.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as resp:
                body = resp.read().decode("utf-8")
            assert "airlock graph" in body
            assert "/graph.js" in body
        finally:
            httpd.shutdown()


class TestJSONLSource:
    def test_jsonl_round_trip(self, tmp_path: Path, sample_events: list[dict]) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text("\n".join(json.dumps(e) for e in sample_events), encoding="utf-8")
        httpd, _ = serve_in_thread(jsonl_path=log, host="127.0.0.1", port=0)
        try:
            port = httpd.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/snapshot", timeout=2) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            ids = {n["id"] for n in payload["nodes"]}
            assert "agent-A" in ids and "fetch_url" in ids
        finally:
            httpd.shutdown()
