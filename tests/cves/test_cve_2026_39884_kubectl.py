"""Tests for CVE-2026-39884 flux159/mcp-server-kubernetes argv injection (v0.5.6+).

Primary source (cited per v0.5.1+ convention):
- <https://www.sentinelone.com/vulnerability-database/cve-2026-39884/> (2026-04-14, fixed in 3.5.0)
- <https://nvd.nist.gov/vuln/detail/CVE-2026-39884>
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock import ArgvStringConcatenationError
from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.argv_guard import enforce_argv_array
from agent_airlock.policy_presets import (
    flux159_mcp_kubernetes_cve_2026_39884_defaults,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cve_2026_39884_kubectl_argv.json"


class TestArgvGuard:
    """The :func:`enforce_argv_array` primitive on its own."""

    def test_clean_argv_passes(self) -> None:
        enforce_argv_array(["kubectl", "port-forward", "pod/foo", "8080:80"])

    def test_space_injected_flag_blocked(self) -> None:
        with pytest.raises(ArgvStringConcatenationError) as exc:
            enforce_argv_array(["8080 --kubeconfig=/etc/shadow"])
        assert exc.value.argv_index == 0
        assert "kubeconfig" in exc.value.offending_value

    def test_field_name_propagated_to_error(self) -> None:
        with pytest.raises(ArgvStringConcatenationError) as exc:
            enforce_argv_array(
                ["8080 --kubeconfig=evil"],
                field_names=["localPort"],
            )
        assert exc.value.field_name == "localPort"


class TestPresetBlocksAttacks:
    """Each fixture payload must be blocked by the preset."""

    @pytest.mark.parametrize(
        "field,value",
        [
            ("localPort", "8080 --kubeconfig=/etc/shadow"),
            ("namespace", "default --as=system:admin"),
            ("resourceType", "pod -n kube-system"),
            ("targetPort", "443 --kubeconfig=evil.yaml"),
        ],
    )
    def test_fixture_attack_is_blocked(self, field: str, value: str) -> None:
        cfg = flux159_mcp_kubernetes_cve_2026_39884_defaults()
        with pytest.raises(ArgvStringConcatenationError):
            cfg["check"]("port_forward", {field: value})

    def test_clean_port_forward_passes(self) -> None:
        cfg = flux159_mcp_kubernetes_cve_2026_39884_defaults()
        cfg["check"](
            "port_forward",
            {"namespace": "default", "localPort": "8080", "targetPort": "80"},
        )


class TestPresetScope:
    """The preset only triggers on port_forward-shaped tool names."""

    def test_unrelated_tool_unaffected(self) -> None:
        cfg = flux159_mcp_kubernetes_cve_2026_39884_defaults()
        # readPod gets the same dirty fields but is not in scope —
        # the preset is per-tool-name, not global.
        cfg["check"](
            "readPod",
            {"namespace": "default --as=system:admin"},
        )


class TestPresetRoundTrip:
    """The exported preset has the expected shape."""

    def test_preset_keys(self) -> None:
        cfg = flux159_mcp_kubernetes_cve_2026_39884_defaults()
        assert callable(cfg["check"])
        assert isinstance(cfg["tool_name_pattern"], str)
        assert isinstance(cfg["injection_prone_fields"], tuple)
        assert "namespace" in cfg["injection_prone_fields"]
        assert cfg["source"].startswith("https://")


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(ArgvStringConcatenationError, AirlockError)


class TestFixture:
    def test_fixture_parses_and_disclosed_at(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert data["cve"] == "CVE-2026-39884"
        assert data["disclosed_at"] == "2026-04-14"
        assert data["airlock_preset"] == "flux159_mcp_kubernetes_cve_2026_39884_defaults"
        assert len(data["payloads"]) == 4
        for p in data["payloads"]:
            assert p["disclosed_at"]
            assert p["expected"] == "blocked"
