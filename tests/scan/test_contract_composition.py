"""Contract-checker integration tests for JSON Schema 2020-12 composition.

Exercises the new violation codes wired into ``scan_tool`` — SCAN009 (external
``$ref``), SCAN010 (composition ambiguity, deny-by-default), SCAN011 (unsupported
keyword denied) — plus the composition-aware surface / type checks and the
``mcp_schema_2020_12_contract_defaults`` preset.
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.schema_ref_guard import SchemaRefError
from agent_airlock.policy import SecurityPolicy
from agent_airlock.policy_presets import (
    MCP_SCHEMA_2020_12_CONTRACT,
    mcp_schema_2020_12_contract_defaults,
)
from agent_airlock.scan.contract import Grade, scan_tool


def _policy(*allowed: str) -> SecurityPolicy:
    return SecurityPolicy(allowed_tools=list(allowed) or ["t"], default_deny=True)


def _tool(schema: dict, name: str = "t") -> dict:
    return {"name": name, "description": "Does a well-scoped thing.", "inputSchema": schema}


def _codes(result) -> set[str]:
    return {v.code for v in result.violations}


class TestExternalRefFails:
    def test_https_ref_is_scan009_fail(self) -> None:
        r = scan_tool(
            _tool({"type": "object", "properties": {"x": {"$ref": "https://evil/x#/a"}}}),
            _policy("t"),
        )
        assert "SCAN009" in _codes(r)
        assert r.grade is Grade.FAIL

    def test_file_ref_is_scan009_fail(self) -> None:
        r = scan_tool(
            _tool(
                {"type": "object", "additionalProperties": False, "allOf": [{"$ref": "file:///x"}]}
            ),
            _policy("t"),
        )
        assert "SCAN009" in _codes(r)
        assert r.grade is Grade.FAIL

    def test_relative_ref_is_scan009_fail(self) -> None:
        r = scan_tool(_tool({"$ref": "../other.json#/x"}), _policy("t"))
        assert "SCAN009" in _codes(r)


class TestAmbiguityFails:
    def test_oneof_ambiguous_is_scan010_fail(self) -> None:
        schema = {
            "oneOf": [
                {"type": "object", "properties": {"x": {}}, "additionalProperties": False},
                {"type": "object", "properties": {"y": {}}, "additionalProperties": False},
            ]
        }
        r = scan_tool(_tool(schema), _policy("t"))
        assert "SCAN010" in _codes(r)
        assert r.grade is Grade.FAIL

    def test_allof_footgun_is_scan010_fail(self) -> None:
        schema = {
            "allOf": [
                {"type": "object", "properties": {"x": {}}, "additionalProperties": False},
                {"type": "object", "properties": {"y": {}}},
            ]
        }
        assert "SCAN010" in _codes(scan_tool(_tool(schema), _policy("t")))


class TestUnsupportedFails:
    def test_pattern_properties_is_scan011_fail(self) -> None:
        r = scan_tool(
            _tool({"type": "object", "patternProperties": {"^x": {"type": "string"}}}),
            _policy("t"),
        )
        assert "SCAN011" in _codes(r)
        assert r.grade is Grade.FAIL


class TestClosedCompositionPasses:
    def test_oneof_consistent_closed_has_no_surface_violation(self) -> None:
        schema = {
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"x": {"type": "integer"}},
                    "additionalProperties": False,
                },
                {
                    "type": "object",
                    "properties": {"x": {"type": "integer"}},
                    "additionalProperties": False,
                },
            ]
        }
        codes = _codes(scan_tool(_tool(schema), _policy("t")))
        assert codes.isdisjoint({"SCAN003", "SCAN004", "SCAN009", "SCAN010", "SCAN011"})

    def test_local_defs_ref_closed_passes(self) -> None:
        schema = {
            "$defs": {
                "Foo": {
                    "type": "object",
                    "properties": {"a": {"type": "integer"}},
                    "additionalProperties": False,
                }
            },
            "$ref": "#/$defs/Foo",
        }
        r = scan_tool(_tool(schema), _policy("t"))
        assert r.grade is Grade.PASS

    def test_sensitive_arg_inside_oneof_branch_warns(self) -> None:
        # A sensitive unconstrained string declared inside a branch is still caught.
        schema = {
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "additionalProperties": False,
                },
                {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "additionalProperties": False,
                },
            ]
        }
        assert "SCAN005" in _codes(scan_tool(_tool(schema), _policy("t")))


class TestSchemaContractPreset:
    def test_preset_shape(self) -> None:
        p = mcp_schema_2020_12_contract_defaults()
        assert p["preset_id"] == "mcp_schema_2020_12_contract"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-2106"
        assert callable(p["check_tool_schema"])
        assert callable(p["analyze"])

    def test_constant_denies_external_ref(self) -> None:
        with pytest.raises(SchemaRefError):
            MCP_SCHEMA_2020_12_CONTRACT["check_tool_schema"](
                {"properties": {"x": {"$ref": "https://evil/x"}}}
            )

    def test_constant_allows_local_ref(self) -> None:
        MCP_SCHEMA_2020_12_CONTRACT["check_tool_schema"](
            {"$defs": {"Foo": {"type": "object"}}, "$ref": "#/$defs/Foo"}
        )

    def test_analyze_reports_closed(self) -> None:
        a = MCP_SCHEMA_2020_12_CONTRACT["analyze"](
            {"type": "object", "properties": {"x": {}}, "additionalProperties": False}
        )
        assert a.is_closed

    def test_allow_internal_hosts_configures_ssrf(self) -> None:
        p = mcp_schema_2020_12_contract_defaults(allow_internal_hosts=["10.0.0.5"])
        # Still denies the ref (external contract), but the composed SSRF guard
        # carries the allow-list.
        d = p["ref_guard"].check_ref("http://10.0.0.5/s.json")
        assert not d.allowed  # external ref is denied regardless of host allow-list
