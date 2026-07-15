"""Regenerate ``gateway_measurement.json`` from a LIVE Docker MCP Gateway.

Run from the repo root (needs a running Docker daemon + the ``docker mcp``
plugin)::

    docker build -t airlock-bench/echo-mcp:latest \
        benchmarks/vs_gateway/gateway_harness
    python -m benchmarks.vs_gateway.gateway_harness.regen

It spawns ``docker mcp gateway run --transport stdio`` in front of the echo
oracle, pushes the SAME corpus (imported from :mod:`benchmarks.vs_gateway.corpus`
— single source of truth) through it as real ``tools/call`` requests, and
records whether the gateway forwarded each payload (PASS) or rejected it
(BLOCK). The airlock side is never touched here; it is computed live by the
bench. The written file is a faithful recording of this run, not an assumption.
"""

from __future__ import annotations

import datetime
import json
import os
import select
import subprocess
import threading
import time
from typing import Any

from benchmarks.vs_gateway.corpus import load_corpus

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(HERE, "airlock-bench-catalog.yaml")
FIXTURE = os.path.join(os.path.dirname(HERE), "gateway_measurement.json")


class GatewayClient:
    """A tiny newline-delimited JSON-RPC client speaking MCP over the gateway's stdio."""

    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self.proc = proc
        self._id = 0
        self._stash = ""
        self._stderr: list[str] = []
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stderr(self) -> None:
        if self.proc.stderr is None:
            return
        for line in self.proc.stderr:
            self._stderr.append(line.rstrip("\n"))

    def _write(self, obj: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _read_line(self, timeout: float) -> str | None:
        assert self.proc.stdout is not None
        fd = self.proc.stdout.fileno()
        deadline = time.time() + timeout
        buf = ""
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], max(0.0, deadline - time.time()))
            if not ready:
                continue
            chunk = os.read(fd, 65536).decode("utf-8", "replace")
            if not chunk:
                break
            buf += chunk
            if "\n" in buf:
                line, _, rest = buf.partition("\n")
                self._stash = rest
                return line
        return None

    def request(
        self, method: str, params: dict[str, Any] | None = None, timeout: float = 45.0
    ) -> dict[str, Any]:
        self._id += 1
        rid = self._id
        self._write({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._stash:
                line, _, rest = self._stash.partition("\n")
                self._stash = rest
            else:
                line = self._read_line(deadline - time.time())
            if line is None:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == rid:
                return msg
        raise TimeoutError(f"no response to {method} within {timeout}s")

    def notify(self, method: str) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": {}})

    def stderr_tail(self, n: int = 20) -> list[str]:
        return self._stderr[-n:]


def _classify(resp: dict[str, Any]) -> str:
    if "error" in resp:
        return "BLOCK"
    result = resp.get("result", {})
    content = result.get("content", [])
    text = content[0].get("text", "") if content and isinstance(content[0], dict) else ""
    if text.startswith("ECHO "):
        return "PASS"
    return "BLOCK" if result.get("isError") else "PASS"


def _version(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception:  # noqa: BLE001 - provenance best-effort
        return "unknown"


def main() -> int:
    cmd = [
        "docker",
        "mcp",
        "gateway",
        "run",
        "--catalog",
        CATALOG,
        "--servers",
        "echo",
        "--transport",
        "stdio",
        "--log-calls=false",
    ]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    client = GatewayClient(proc)
    try:
        init = client.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "airlock-gwbench", "version": "1.0"},
            },
            timeout=90.0,
        )
        server_info = init.get("result", {}).get("serverInfo", {})
        protocol = init.get("result", {}).get("protocolVersion")
        client.notify("notifications/initialized")
        client.request("tools/list", timeout=60.0)

        records: dict[str, dict[str, str]] = {}
        for call in load_corpus():
            resp = client.request("tools/call", {"name": call.tool, "arguments": call.args})
            decision = _classify(resp)
            records[call.item_id] = {
                "gateway_decision": decision,
                "detail": "backend echoed args (forwarded)"
                if decision == "PASS"
                else "gateway rejected",
            }
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    fixture = {
        "_comment": (
            "RECORDED live measurement of a native Docker MCP Gateway against the "
            "vs_gateway corpus. Regenerate with "
            "benchmarks/vs_gateway/gateway_harness/regen.py (needs Docker). The "
            "shipped bench replays this fixture so it runs without Docker."
        ),
        "provenance": {
            "measured_utc_date": datetime.date.today().isoformat(),
            "gateway_product": server_info.get("name"),
            "gateway_image_version": server_info.get("version"),
            "docker_mcp_cli_version": _version(["docker", "mcp", "version"]),
            "docker_engine_version": _version(
                ["docker", "version", "--format", "{{.Server.Version}}"]
            ),
            "mcp_protocol_version": protocol,
            "transport": "stdio",
            "method": (
                "Each corpus item sent as a real MCP tools/call through the running "
                "gateway to an echo-oracle backend that performs NO validation. "
                "PASS = backend echoed the args (gateway forwarded); BLOCK = gateway "
                "returned a JSON-RPC error before the backend saw the call."
            ),
            "harness": "benchmarks/vs_gateway/gateway_harness/",
        },
        "records": records,
    }
    with open(FIXTURE, "w", encoding="utf-8") as fh:
        json.dump(fixture, fh, indent=2)
        fh.write("\n")
    blocked = sum(
        1
        for k, v in records.items()
        if v["gateway_decision"] == "BLOCK" and not k.startswith("benign")
    )
    print(f"wrote {FIXTURE}: gateway blocked {blocked} malformed payloads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
