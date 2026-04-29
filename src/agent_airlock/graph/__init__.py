"""Live agent-call-graph + policy overlay (v0.5.9+).

Builds a live picture of the agent → tool → MCP-server topology
recorded in airlock's audit log and serves it locally so an operator
can hand a CISO a 30-second visual of what their agents are doing.

The implementation is pure stdlib (``http.server`` + vanilla HTML /
JS / CSS) so it adds zero runtime deps. Live updates come from a 5-
second client poll; a WebSocket transport is queued for v0.5.10.

Reference
---------
* Feature spec: docs/graph.md (shipped 2026-04-28).
"""

from __future__ import annotations

from .builder import GraphEdge, GraphNode, GraphSnapshot, build_snapshot

__all__ = [
    "GraphEdge",
    "GraphNode",
    "GraphSnapshot",
    "build_snapshot",
]
