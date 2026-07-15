"""Head-to-head: agent-airlock vs a native MCP gateway (contract layer).

Pushes the SAME malformed tool-call corpus through BOTH a live Docker MCP
Gateway (recorded once in ``gateway_measurement.json``; regenerate with
``gateway_harness/``) and agent-airlock (live, every run). Reports the
contract-layer gap: malformed / over-privileged payloads the gateway forwards
that airlock blocks. See ``docs/benchmarks/vs-native-mcp-gateway.md``.
"""

from __future__ import annotations

from .airlock_runner import airlock_blocks, run_airlock
from .corpus import GatewayCall, load_corpus
from .report import HeadToHead, Row, build_report, render

__all__ = [
    "GatewayCall",
    "HeadToHead",
    "Row",
    "airlock_blocks",
    "build_report",
    "load_corpus",
    "render",
    "run_airlock",
]
