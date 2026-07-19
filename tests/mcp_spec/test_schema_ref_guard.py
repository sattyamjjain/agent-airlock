"""Tests for the SEP-2106 external-``$ref`` dereference guard.

Covers per-ref classification (local allow; http / https / file / relative-escape
/ non-local-scheme deny), whole-schema scanning (a ref buried in a ``oneOf`` branch
or a property is caught), the raise path, and the composed SSRF classification.
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.schema_ref_guard import (
    SchemaRefError,
    SchemaRefGuard,
    SchemaRefVerdict,
)
from agent_airlock.ssrf_egress_guard import SSRFEgressGuard, SSRFEgressVerdict


@pytest.fixture
def guard() -> SchemaRefGuard:
    return SchemaRefGuard()


class TestCheckRefAllowsLocal:
    def test_defs_pointer_allowed(self, guard: SchemaRefGuard) -> None:
        d = guard.check_ref("#/$defs/Foo")
        assert d.allowed
        assert d.verdict is SchemaRefVerdict.ALLOW_LOCAL

    def test_definitions_pointer_allowed(self, guard: SchemaRefGuard) -> None:
        assert guard.check_ref("#/definitions/Bar").allowed

    def test_bare_fragment_allowed(self, guard: SchemaRefGuard) -> None:
        assert guard.check_ref("#").allowed


class TestCheckRefDeniesExternal:
    def test_https_denied(self, guard: SchemaRefGuard) -> None:
        d = guard.check_ref("https://evil.example/s.json#/a")
        assert not d.allowed
        assert d.verdict is SchemaRefVerdict.DENY_EXTERNAL_HTTP
        assert d.ssrf is not None  # SSRF classification enrichment present
        assert d.fix_hints

    def test_http_denied(self, guard: SchemaRefGuard) -> None:
        d = guard.check_ref("http://example.com/s.json")
        assert not d.allowed
        assert d.verdict is SchemaRefVerdict.DENY_EXTERNAL_HTTP

    def test_file_denied(self, guard: SchemaRefGuard) -> None:
        d = guard.check_ref("file:///etc/passwd")
        assert not d.allowed
        assert d.verdict is SchemaRefVerdict.DENY_EXTERNAL_FILE

    def test_relative_parent_escape_denied(self, guard: SchemaRefGuard) -> None:
        d = guard.check_ref("../other.json#/x")
        assert not d.allowed
        assert d.verdict is SchemaRefVerdict.DENY_RELATIVE_ESCAPE

    def test_relative_sibling_denied(self, guard: SchemaRefGuard) -> None:
        assert guard.check_ref("other.json").verdict is SchemaRefVerdict.DENY_RELATIVE_ESCAPE

    def test_absolute_path_denied(self, guard: SchemaRefGuard) -> None:
        assert (
            guard.check_ref("/abs/schema.json#/y").verdict is SchemaRefVerdict.DENY_RELATIVE_ESCAPE
        )

    def test_other_scheme_denied(self, guard: SchemaRefGuard) -> None:
        assert guard.check_ref("ftp://h/x").verdict is SchemaRefVerdict.DENY_NON_LOCAL


class TestScanSchema:
    def test_ref_buried_in_oneof_is_caught(self, guard: SchemaRefGuard) -> None:
        schema = {
            "oneOf": [
                {"type": "object", "properties": {"x": {"$ref": "https://evil/x#/a"}}},
                {"$ref": "#/$defs/Ok"},
            ],
            "$defs": {"Ok": {"type": "object"}},
        }
        decisions = guard.scan_schema(schema)
        denied = [d for d in decisions if not d.allowed]
        allowed = [d for d in decisions if d.allowed]
        assert len(denied) == 1
        assert denied[0].ref == "https://evil/x#/a"
        assert allowed and allowed[0].ref == "#/$defs/Ok"

    def test_validate_raises_on_external(self, guard: SchemaRefGuard) -> None:
        with pytest.raises(SchemaRefError) as exc:
            guard.validate({"properties": {"x": {"$ref": "https://evil/x"}}})
        assert exc.value.decision.verdict is SchemaRefVerdict.DENY_EXTERNAL_HTTP
        assert exc.value.fix_hints

    def test_validate_passes_local_only(self, guard: SchemaRefGuard) -> None:
        schema = {"$defs": {"Foo": {"type": "object"}}, "$ref": "#/$defs/Foo"}
        guard.validate(schema)  # must not raise


class TestSSRFComposition:
    def test_metadata_ref_carries_ssrf_verdict(self, guard: SchemaRefGuard) -> None:
        d = guard.check_ref("http://169.254.169.254/latest/meta-data/#/x")
        assert not d.allowed
        assert d.ssrf is not None
        assert d.ssrf.verdict is SSRFEgressVerdict.DENY_METADATA

    def test_custom_ssrf_guard_is_used(self) -> None:
        custom = SSRFEgressGuard(deny_on_resolution_failure=False)
        g = SchemaRefGuard(ssrf_guard=custom)
        assert g.check_ref("https://public.example/s.json").ssrf is not None
