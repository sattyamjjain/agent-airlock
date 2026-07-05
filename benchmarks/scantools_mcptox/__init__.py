"""scan-tools × MCPTox static contract-coverage bench.

Runs ``airlock scan-tools`` over taxonomy-derived tool-poisoning fixtures
(reconstructed from arXiv:2508.14925) and reports a deterministic, offline
contract-checking coverage number — explicitly not MCPTox's model-in-the-loop
Attack Success Rate, and explicitly differentiated from content-signature
poisoning scanners (MCP-Scan, eSentire MCP-Scanner).

Run with::

    python -m benchmarks.scantools_mcptox
"""

from __future__ import annotations

from .corpus import PoisonCase, load_corpus
from .report import format_report
from .runner import McptoxReport, run_benchmark

__all__ = ["PoisonCase", "load_corpus", "McptoxReport", "run_benchmark", "format_report"]
