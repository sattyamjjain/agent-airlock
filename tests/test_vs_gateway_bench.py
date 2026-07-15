"""Regression tests for the airlock vs native-MCP-gateway head-to-head bench.

Guards the reproduced contract-layer gap:

- airlock BLOCKS every malformed payload in the corpus and passes every benign
  control (0 false-positive) — the core assertion the task requires;
- the recorded gateway fixture aligns 1:1 with the corpus and shows the gateway
  forwarding every malformed payload (the structural gap);
- the joined report yields the dated numbers the README/RESULTS cite.
"""

from __future__ import annotations

from benchmarks.vs_gateway.airlock_runner import airlock_blocks, run_airlock
from benchmarks.vs_gateway.corpus import load_corpus
from benchmarks.vs_gateway.report import build_report


class TestAirlockBlocksMalformedCorpus:
    """airlock must refuse every malformed payload and spare every benign one."""

    def test_all_malformed_blocked(self) -> None:
        malformed = [c for c in load_corpus() if c.expected_block]
        assert malformed, "corpus must contain malformed payloads"
        not_blocked = [c.item_id for c in malformed if not airlock_blocks(c)]
        assert not_blocked == [], f"airlock let malformed payloads through: {not_blocked}"

    def test_no_benign_false_positive(self) -> None:
        benign = [c for c in load_corpus() if not c.expected_block]
        assert benign, "corpus must contain benign controls"
        false_positives = [c.item_id for c in benign if airlock_blocks(c)]
        assert false_positives == [], f"airlock false-positived on benign: {false_positives}"

    def test_expected_corpus_shape(self) -> None:
        corpus = load_corpus()
        assert sum(1 for c in corpus if c.expected_block) == 12
        assert sum(1 for c in corpus if not c.expected_block) == 3


class TestGatewayFixtureAlignment:
    """The recorded gateway measurement must line up with the corpus 1:1."""

    def test_every_corpus_item_has_a_recorded_gateway_decision(self) -> None:
        report = build_report()
        recorded_ids = {r.call.item_id for r in report.rows}
        corpus_ids = {c.item_id for c in load_corpus()}
        assert recorded_ids == corpus_ids

    def test_gateway_forwards_all_malformed(self) -> None:
        report = build_report()
        # The structural gap: the native gateway blocks nothing at the contract layer.
        assert report.gateway_blocked == 0
        assert report.malicious_total == 12


class TestHeadToHeadReport:
    """The joined report must produce the dated numbers the docs cite."""

    def test_reproduced_gap(self) -> None:
        report = build_report()
        assert report.airlock_blocked == 12
        assert report.gateway_blocked == 0
        assert report.airlock_fp == 0
        assert report.gateway_fp == 0

    def test_runner_reports_latency(self) -> None:
        rows = run_airlock()
        assert len(rows) == 15
        assert all(latency >= 0.0 for _call, _blocked, latency in rows)

    def test_fixture_provenance_is_present(self) -> None:
        report = build_report()
        prov = report.provenance
        assert prov.get("gateway_image_version") == "2.0.1"
        assert prov.get("measured_utc_date")
