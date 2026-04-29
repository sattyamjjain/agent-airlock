"""Build a graph snapshot from an audit-event stream.

Snapshot shape (kept JSON-stable so the static UI can ingest it
unchanged across versions):

    {
      "version": 1,
      "generated_at": "<ISO timestamp>",
      "nodes": [{"id": ..., "kind": "agent" | "tool" | "mcp_server", ...}, ...],
      "edges": [
        {"src": ..., "dst": ..., "verdict": "allow" | "warn" | "block",
         "count": <int>, "last_envelope_id": "<id or None>"},
        ...
      ]
    }

The builder is pure: feed it any iterable of audit-event dicts and it
returns the snapshot. The HTTP server (``server.py``) wraps a
JSON-Lines audit file or an in-memory list with this builder.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

NodeKind = Literal["agent", "tool", "mcp_server"]
Verdict = Literal["allow", "warn", "block"]


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: NodeKind
    label: str = ""


@dataclass(frozen=True)
class GraphEdge:
    src: str
    dst: str
    verdict: Verdict
    count: int = 1
    last_envelope_id: str | None = None


@dataclass(frozen=True)
class GraphSnapshot:
    version: int
    generated_at: str
    nodes: tuple[GraphNode, ...] = field(default_factory=tuple)
    edges: tuple[GraphEdge, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }


def build_snapshot(events: Iterable[dict[str, Any]]) -> GraphSnapshot:
    """Aggregate a stream of audit events into a single graph snapshot.

    Recognised event keys:

    * ``"agent_id"`` — source node id (mandatory for an edge).
    * ``"tool_name"`` — destination tool node.
    * ``"mcp_server"`` — optional second hop the tool talks to.
    * ``"verdict"`` — ``"allow"`` / ``"warn"`` / ``"block"`` (default ``"allow"``).
    * ``"envelope_id"`` — most-recent audit envelope id for the edge.

    Edges are aggregated by ``(src, dst, verdict)``: count grows with
    each repeat; ``last_envelope_id`` keeps the most-recent value.
    """
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str, Verdict], GraphEdge] = {}

    def _add_node(node_id: str, kind: NodeKind, label: str = "") -> None:
        if node_id and node_id not in nodes:
            nodes[node_id] = GraphNode(id=node_id, kind=kind, label=label or node_id)

    def _add_edge(src: str, dst: str, verdict: Verdict, env: str | None) -> None:
        key = (src, dst, verdict)
        prev = edges.get(key)
        if prev is None:
            edges[key] = GraphEdge(
                src=src, dst=dst, verdict=verdict, count=1, last_envelope_id=env
            )
        else:
            edges[key] = GraphEdge(
                src=src,
                dst=dst,
                verdict=verdict,
                count=prev.count + 1,
                last_envelope_id=env or prev.last_envelope_id,
            )

    for ev in events:
        agent_id = str(ev.get("agent_id") or "").strip()
        tool_name = str(ev.get("tool_name") or "").strip()
        mcp_server = str(ev.get("mcp_server") or "").strip()
        verdict_raw = str(ev.get("verdict") or "allow").strip()
        verdict: Verdict = (
            verdict_raw  # type: ignore[assignment]
            if verdict_raw in {"allow", "warn", "block"}
            else "allow"
        )
        envelope_id = ev.get("envelope_id")
        envelope_id_str = str(envelope_id) if envelope_id else None

        if not agent_id or not tool_name:
            continue
        _add_node(agent_id, "agent")
        _add_node(tool_name, "tool")
        _add_edge(agent_id, tool_name, verdict, envelope_id_str)

        if mcp_server:
            _add_node(mcp_server, "mcp_server")
            _add_edge(tool_name, mcp_server, verdict, envelope_id_str)

    sorted_nodes = tuple(sorted(nodes.values(), key=lambda n: (n.kind, n.id)))
    sorted_edges = tuple(
        sorted(
            edges.values(),
            key=lambda e: (e.src, e.dst, e.verdict),
        )
    )
    return GraphSnapshot(
        version=1,
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        nodes=sorted_nodes,
        edges=sorted_edges,
    )


__all__ = ["GraphEdge", "GraphNode", "GraphSnapshot", "NodeKind", "Verdict", "build_snapshot"]
