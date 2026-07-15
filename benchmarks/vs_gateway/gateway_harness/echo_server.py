#!/usr/bin/env python3
"""Minimal dependency-free MCP stdio server used ONLY as a receipt oracle.

It declares a handful of typed tools and, on ``tools/call``, echoes back the
exact arguments it received. Its single job in the head-to-head is to prove
whether the Docker MCP Gateway *forwarded* a malformed tool-call payload to the
backend (echo returns the args) or *rejected* it at the gateway (the driver
never sees an echo). It performs NO validation of its own — that is the point:
any validation observed in the head-to-head is the gateway's, not the backend's.
"""

from __future__ import annotations

import json
import sys
from typing import Any

TOOLS: list[dict[str, Any]] = [
    {
        "name": "transfer",
        "description": "Transfer money between accounts.",
        "inputSchema": {
            "type": "object",
            "properties": {"account": {"type": "string"}, "amount": {"type": "integer"}},
            "required": ["account", "amount"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file from the workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "fetch",
        "description": "Fetch a URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "run_python",
        "description": "Run a python snippet.",
        "inputSchema": {
            "type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"],
        },
    },
    {
        "name": "spawn_mcp",
        "description": "Spawn a subprocess MCP server.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "connect_mcp_server",
        "description": "Connect to a remote MCP server URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "render_template",
        "description": "Render a collaboration template.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "run_query",
        "description": "Run a read-only query.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "admin_execute",
        "description": "Execute an arbitrary admin command.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "delete_records",
        "description": "Delete records.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _send(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _result(req_id: Any, result: dict[str, Any]) -> None:
    _send({"jsonrpc": "2.0", "id": req_id, "result": result})


def main() -> None:
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        req_id = msg.get("id")
        if req_id is None:  # notification — nothing to answer
            continue

        if method == "initialize":
            params = msg.get("params", {})
            _result(
                req_id,
                {
                    "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "airlock-echo-oracle", "version": "1.0.0"},
                },
            )
        elif method == "ping":
            _result(req_id, {})
        elif method == "tools/list":
            _result(req_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params", {})
            payload = {
                "received_tool": params.get("name"),
                "received_args": params.get("arguments", {}),
            }
            _result(
                req_id,
                {
                    "content": [{"type": "text", "text": "ECHO " + json.dumps(payload)}],
                    "isError": False,
                },
            )
        else:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )


if __name__ == "__main__":
    main()
