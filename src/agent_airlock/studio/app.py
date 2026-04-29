"""Stdlib-backed studio app — paste-a-transcript rehearsal sandbox."""

from __future__ import annotations

import html
import json
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

import structlog

logger = structlog.get_logger("agent-airlock.studio.app")

VerdictFn = Callable[[str], dict[str, Any]]
"""Per-line verdict function. Receives one transcript line and returns
a dict like ``{"verdict": "block", "guard": "...", "detail": "..."}``."""


def _default_allow_fn(_line: str) -> dict[str, Any]:
    return {"verdict": "allow", "guard": "noop"}


@dataclass
class TranscriptLine:
    line_no: int
    content: str
    verdict: str = "allow"
    guard: str = ""
    detail: str = ""


@dataclass
class RehearsalRun:
    transcript_id: str
    lines: list[TranscriptLine] = field(default_factory=list)


@dataclass
class StudioState:
    """In-process studio state shared across HTTP requests."""

    bundle_id: str = "default"
    active_presets: list[str] = field(default_factory=list)
    runs: dict[str, RehearsalRun] = field(default_factory=dict)
    verdict_fn: VerdictFn = field(
        default_factory=lambda: _default_allow_fn
    )

    def rehearse(self, transcript_id: str, transcript: str) -> RehearsalRun:
        run = RehearsalRun(transcript_id=transcript_id)
        for idx, raw in enumerate(transcript.splitlines(), start=1):
            verdict = self.verdict_fn(raw)
            run.lines.append(
                TranscriptLine(
                    line_no=idx,
                    content=raw,
                    verdict=str(verdict.get("verdict", "allow")),
                    guard=str(verdict.get("guard", "")),
                    detail=str(verdict.get("detail", "")),
                )
            )
        self.runs[transcript_id] = run
        return run

    def diff(self, a: str, b: str) -> list[dict[str, Any]]:
        """Return a per-line verdict-diff between two prior runs."""
        run_a = self.runs.get(a)
        run_b = self.runs.get(b)
        if run_a is None or run_b is None:
            return []
        out: list[dict[str, Any]] = []
        max_len = max(len(run_a.lines), len(run_b.lines))
        for i in range(max_len):
            la = run_a.lines[i] if i < len(run_a.lines) else None
            lb = run_b.lines[i] if i < len(run_b.lines) else None
            if la is None or lb is None or la.verdict != lb.verdict:
                out.append(
                    {
                        "line_no": i + 1,
                        "before": asdict(la) if la is not None else None,
                        "after": asdict(lb) if lb is not None else None,
                    }
                )
        return out


def rehearse_transcript(
    transcript: str,
    *,
    verdict_fn: VerdictFn,
) -> list[TranscriptLine]:
    """Convenience helper for callers who don't need a long-lived state."""
    state = StudioState(verdict_fn=verdict_fn)
    return state.rehearse("oneshot", transcript).lines


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


_INDEX_HTML = """\
<!doctype html><html><head><meta charset="utf-8"><title>airlock studio</title>
<style>
body{font:14px system-ui,sans-serif;max-width:920px;margin:24px auto;color:#111;}
textarea{width:100%;height:240px;font-family:ui-monospace,monospace;}
.allow{color:#2ca02c}.warn{color:#ff9900}.block{color:#d62728;font-weight:bold}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #e3e3e3;padding:6px;text-align:left;font-family:ui-monospace,monospace;font-size:12px}th{background:#f3f3f3}
</style></head><body>
<h1>airlock studio</h1>
<form method="post" action="/rehearse">
  <label>Transcript ID: <input name="transcript_id" value="run-1"></label>
  <textarea name="transcript" placeholder="Paste an agent transcript, one tool call per line"></textarea>
  <button type="submit">Rehearse</button>
</form>
{rendered_runs}
</body></html>
"""


class StudioApp:
    """Stdlib HTTP server wrapping a :class:`StudioState`."""

    def __init__(
        self,
        state: StudioState,
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
    ) -> None:
        self.state = state
        self.host = host
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None

    # ------------------------------------------------------------------
    # Render helpers
    # ------------------------------------------------------------------

    def render_index(self) -> str:
        if not self.state.runs:
            rendered = "<p><em>No runs yet.</em></p>"
        else:
            rows = []
            for tid, run in self.state.runs.items():
                rows.append(f"<h2>Run {html.escape(tid)}</h2>")
                rows.append(
                    "<table><thead><tr><th>#</th><th>Verdict</th><th>Guard</th><th>Line</th></tr></thead><tbody>"
                )
                for ln in run.lines:
                    rows.append(
                        f'<tr class="{html.escape(ln.verdict)}">'
                        f"<td>{ln.line_no}</td>"
                        f"<td>{html.escape(ln.verdict)}</td>"
                        f"<td>{html.escape(ln.guard)}</td>"
                        f"<td>{html.escape(ln.content)}</td>"
                        f"</tr>"
                    )
                rows.append("</tbody></table>")
            rendered = "\n".join(rows)
        # Plain string substitution — the HTML template contains CSS
        # braces that would conflict with ``str.format``.
        return _INDEX_HTML.replace("{rendered_runs}", rendered)

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def serve(self) -> ThreadingHTTPServer:
        handler = _make_handler(self)
        httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._httpd = httpd
        logger.info("studio_started", host=self.host, port=self.port)
        return httpd

    def serve_in_thread(self) -> tuple[ThreadingHTTPServer, threading.Thread]:
        httpd = self.serve()
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return httpd, thread

    def shutdown(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd = None


def _make_handler(app: StudioApp) -> type[BaseHTTPRequestHandler]:
    class _StudioHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: ARG002
            logger.debug("studio_request", line=format % args)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/healthz":
                self._json({"status": "ok"})
                return
            if self.path == "/api/snapshot":
                self._json(
                    {
                        "bundle_id": app.state.bundle_id,
                        "active_presets": list(app.state.active_presets),
                        "runs": {
                            tid: [asdict(ln) for ln in run.lines]
                            for tid, run in app.state.runs.items()
                        },
                    }
                )
                return
            if self.path in ("/", "/index.html"):
                body = app.render_index().encode("utf-8")
                self._send(200, "text/html; charset=utf-8", body)
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("utf-8")
            if self.path == "/api/rehearse":
                payload = json.loads(raw or "{}")
                tid = str(payload.get("transcript_id", "run"))
                transcript = str(payload.get("transcript", ""))
                run = app.state.rehearse(tid, transcript)
                self._json(
                    {
                        "transcript_id": tid,
                        "lines": [asdict(ln) for ln in run.lines],
                    }
                )
                return
            if self.path == "/rehearse":
                fields = parse_qs(raw)
                tid = (fields.get("transcript_id") or ["run"])[0]
                transcript = (fields.get("transcript") or [""])[0]
                app.state.rehearse(tid, transcript)
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self._send(200, "application/json", body)

    return _StudioHandler


__all__ = [
    "RehearsalRun",
    "StudioApp",
    "StudioState",
    "TranscriptLine",
    "VerdictFn",
    "rehearse_transcript",
]
