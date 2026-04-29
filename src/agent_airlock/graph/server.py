"""Local HTTP server for ``airlock graph serve``.

Stdlib-only (``http.server``) so the feature ships with no new
runtime dependency. Routes:

* ``GET /``                 — vanilla HTML/JS/CSS bundle
* ``GET /api/snapshot``     — JSON snapshot (drives the 5s poll)
* ``GET /api/healthz``      — liveness probe

The audit event source is pluggable: the constructor takes either a
JSON-Lines file path or an in-memory list. The static web bundle is
served from the ``web/`` directory under this package.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import structlog

from .builder import GraphSnapshot, build_snapshot

logger = structlog.get_logger("agent-airlock.graph.server")

WEB_ROOT: Path = Path(__file__).resolve().parent / "web"


class _SnapshotSource:
    """Read-only view onto the audit event stream."""

    def __init__(
        self,
        *,
        jsonl_path: Path | None = None,
        in_memory: list[dict[str, Any]] | None = None,
    ) -> None:
        if (jsonl_path is None) == (in_memory is None):
            raise ValueError(
                "exactly one of jsonl_path / in_memory must be provided"
            )
        self._jsonl_path = jsonl_path
        self._in_memory = in_memory

    def events(self) -> Iterable[dict[str, Any]]:
        if self._in_memory is not None:
            yield from self._in_memory
            return
        path = self._jsonl_path
        if path is None or not path.exists():
            return
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def make_handler(
    source: _SnapshotSource,
) -> type[BaseHTTPRequestHandler]:
    """Build an HTTP handler closed over a snapshot source."""

    class _Handler(BaseHTTPRequestHandler):
        # Quieter logging — default is one stderr line per request.
        def log_message(self, format: str, *args: Any) -> None:  # noqa: ARG002
            logger.debug("graph_request", line=format % args)

        def do_GET(self) -> None:  # noqa: N802 — http.server contract
            if self.path == "/api/healthz":
                self._json({"status": "ok"})
                return
            if self.path == "/api/snapshot":
                snap = build_snapshot(source.events())
                self._json(snap.to_dict())
                return
            if self.path in ("/", "/index.html"):
                self._serve_file(WEB_ROOT / "index.html", "text/html")
                return
            if self.path == "/graph.js":
                self._serve_file(WEB_ROOT / "graph.js", "application/javascript")
                return
            if self.path == "/style.css":
                self._serve_file(WEB_ROOT / "style.css", "text/css")
                return
            self.send_response(404)
            self.end_headers()

        def _serve_file(self, path: Path, content_type: str) -> None:
            try:
                body = path.read_bytes()
            except OSError:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _Handler


def build_snapshot_for_path(jsonl_path: Path) -> GraphSnapshot:
    """Helper used by ``airlock graph dump``."""
    src = _SnapshotSource(jsonl_path=jsonl_path)
    return build_snapshot(src.events())


def serve(
    *,
    jsonl_path: Path | None = None,
    in_memory: list[dict[str, Any]] | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    """Start an HTTP server bound to ``host:port`` and return it.

    Caller is responsible for ``server.serve_forever()`` on a thread
    or for calling ``server.shutdown()`` from a signal handler.
    """
    source = _SnapshotSource(jsonl_path=jsonl_path, in_memory=in_memory)
    handler = make_handler(source)
    httpd = ThreadingHTTPServer((host, port), handler)
    logger.info("graph_server_started", host=host, port=port)
    return httpd


def serve_in_thread(
    *,
    jsonl_path: Path | None = None,
    in_memory: list[dict[str, Any]] | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Test helper: start the server on a daemon thread, return both."""
    httpd = serve(jsonl_path=jsonl_path, in_memory=in_memory, host=host, port=port)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


__all__ = ["WEB_ROOT", "build_snapshot_for_path", "serve", "serve_in_thread"]
