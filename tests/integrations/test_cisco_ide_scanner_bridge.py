"""Tests for ``CiscoIDEScannerBridge`` and the generic Scanner protocol."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_airlock.integrations.cisco_ide_scanner_bridge import (
    CiscoIDEScannerBridge,
)
from agent_airlock.integrations.scanners import (
    Scanner,
    clear_registry,
    get_scanner,
    list_scanners,
    register_scanner,
)


@pytest.fixture(autouse=True)
def _reset_registry() -> Any:
    clear_registry()
    yield
    clear_registry()


@pytest.fixture
def tmp_source(tmp_path: Path) -> Path:
    f = tmp_path / "vulnerable.py"
    f.write_text("import os\nos.system(input())\n", encoding="utf-8")
    return f


class TestUnconfigured:
    def test_no_config_means_disabled(self) -> None:
        bridge = CiscoIDEScannerBridge(api_base="", api_key="")
        assert bridge.is_configured() is False

    def test_unconfigured_scan_returns_empty(
        self, tmp_source: Path
    ) -> None:
        bridge = CiscoIDEScannerBridge(api_base="", api_key="")
        assert bridge.scan_file(tmp_source) == []

    def test_unconfigured_does_not_call_http(
        self, tmp_source: Path
    ) -> None:
        calls: list[Any] = []

        def fake_post(*args: Any, **kwargs: Any) -> dict:
            calls.append((args, kwargs))
            return {"findings": []}

        bridge = CiscoIDEScannerBridge(
            api_base="", api_key="", http_post=fake_post
        )
        bridge.scan_file(tmp_source)
        assert calls == []


class TestConfiguredHappyPath:
    """Mocked Cisco endpoint returns 3 findings — bridge surfaces all 3."""

    def test_three_findings_round_trip(self, tmp_source: Path) -> None:
        captured: dict[str, Any] = {}

        def fake_post(url: str, **kwargs: Any) -> dict:
            captured["url"] = url
            captured["headers"] = kwargs.get("headers", {})
            captured["payload"] = kwargs.get("json", {})
            return {
                "findings": [
                    {
                        "rule_id": "CISCO-001",
                        "severity": "high",
                        "message": "os.system on user input",
                        "line": 2,
                        "column": 1,
                        "metadata": {"cwe": "CWE-78"},
                    },
                    {
                        "rule_id": "CISCO-002",
                        "severity": "medium",
                        "message": "missing input sanitisation",
                    },
                    {
                        "rule_id": "CISCO-003",
                        "severity": "low",
                        "message": "untyped argv",
                    },
                ]
            }

        bridge = CiscoIDEScannerBridge(
            api_base="https://scanner.cisco.example",
            api_key="dummy-token",
            http_post=fake_post,
        )
        assert bridge.is_configured()
        findings = bridge.scan_file(tmp_source)
        assert [f.rule_id for f in findings] == [
            "CISCO-001",
            "CISCO-002",
            "CISCO-003",
        ]
        assert findings[0].severity == "high"
        assert findings[0].line == 2
        # Headers carry bearer auth and identify the bridge.
        assert (
            captured["headers"]["Authorization"] == "Bearer dummy-token"
        )
        assert "agent-airlock" in captured["headers"]["User-Agent"]
        # Payload includes filename + source text but never the path.
        assert captured["payload"]["filename"] == "vulnerable.py"
        assert "os.system" in captured["payload"]["source"]


class TestRegistry:
    def test_register_and_lookup(self) -> None:
        bridge = CiscoIDEScannerBridge(
            api_base="https://x", api_key="k"
        )
        register_scanner(bridge)
        assert get_scanner("cisco-ide-scanner") is bridge
        assert bridge in list_scanners()

    def test_satisfies_protocol(self) -> None:
        bridge = CiscoIDEScannerBridge(api_base="x", api_key="k")
        assert isinstance(bridge, Scanner)


class TestNetworkFailureGraceful:
    def test_request_exception_logged_returns_empty(
        self, tmp_source: Path
    ) -> None:
        def boom(*args: Any, **kwargs: Any) -> dict:
            raise ConnectionError("network down")

        bridge = CiscoIDEScannerBridge(
            api_base="https://x",
            api_key="k",
            http_post=boom,
        )
        # Must not raise — surfaces empty findings instead.
        assert bridge.scan_file(tmp_source) == []
