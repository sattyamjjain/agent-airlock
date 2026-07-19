"""Tests for the JSON Schema 2020-12 composition analyzer (deny-by-default).

Covers every composition keyword the analyzer models (``oneOf`` / ``anyOf`` /
``allOf`` / ``not`` / ``if``-``then``-``else`` / ``$ref`` / ``$defs`` /
``prefixItems``), the ambiguity path (a branch permits a shape a sibling forbids),
schema-level ghost-argument stripping under ``oneOf`` with a per-branch report,
external-``$ref`` surfacing, and the unsupported-keyword deny.
"""

from __future__ import annotations

from agent_airlock.scan.schema import (
    SurfaceState,
    analyze_schema,
    is_local_ref,
    iter_property_schemas,
    strip_ghost_args_under_composition,
)

CLOSED_X = {
    "type": "object",
    "properties": {"x": {"type": "integer"}},
    "additionalProperties": False,
}
CLOSED_Y = {
    "type": "object",
    "properties": {"y": {"type": "integer"}},
    "additionalProperties": False,
}
OPEN_X = {"type": "object", "properties": {"x": {"type": "integer"}}}


class TestFlatSurface:
    def test_flat_closed(self) -> None:
        a = analyze_schema(CLOSED_X)
        assert a.surface is SurfaceState.CLOSED
        assert a.is_closed
        assert a.permitted_props == frozenset({"x"})

    def test_flat_open(self) -> None:
        a = analyze_schema(OPEN_X)
        assert a.surface is SurfaceState.OPEN
        assert not a.is_closed

    def test_boolean_true_schema_is_open(self) -> None:
        assert analyze_schema(True).surface is SurfaceState.OPEN

    def test_boolean_false_schema_is_closed(self) -> None:
        assert analyze_schema(False).surface is SurfaceState.CLOSED


class TestOneOfAnyOf:
    def test_oneof_consistent_closed_is_closed(self) -> None:
        a = analyze_schema({"oneOf": [CLOSED_X, dict(CLOSED_X)]})
        assert a.surface is SurfaceState.CLOSED
        assert a.is_closed
        assert a.permitted_props == frozenset({"x"})

    def test_oneof_ambiguous_branches_deny(self) -> None:
        a = analyze_schema({"oneOf": [CLOSED_X, CLOSED_Y]})
        assert a.surface is SurfaceState.AMBIGUOUS
        assert a.is_ambiguous
        assert not a.is_closed
        assert a.permitted_props == frozenset({"x", "y"})
        # The ambiguity names the specific disagreement.
        joined = " ".join(a.ambiguities)
        assert "'x'" in joined and "'y'" in joined

    def test_anyof_ambiguous_branches_deny(self) -> None:
        a = analyze_schema({"anyOf": [CLOSED_X, CLOSED_Y]})
        assert a.surface is SurfaceState.AMBIGUOUS
        assert a.ambiguities

    def test_oneof_open_branch_makes_it_not_closed(self) -> None:
        a = analyze_schema({"oneOf": [CLOSED_X, OPEN_X]})
        # One closed, one open over the same prop → shapes differ → ambiguous.
        assert a.surface is SurfaceState.AMBIGUOUS


class TestAllOf:
    def test_allof_closed_covering_is_closed(self) -> None:
        a = analyze_schema(
            {
                "allOf": [
                    {
                        "type": "object",
                        "properties": {"x": {}, "y": {}},
                        "additionalProperties": False,
                    },
                    {"type": "object", "properties": {"y": {}}},
                ]
            }
        )
        assert a.surface is SurfaceState.CLOSED
        assert a.permitted_props == frozenset({"x", "y"})

    def test_allof_footgun_closed_rejects_sibling_prop(self) -> None:
        a = analyze_schema({"allOf": [CLOSED_X, {"type": "object", "properties": {"y": {}}}]})
        # The closed branch rejects 'y' that the sibling declares → ambiguity.
        assert a.surface is SurfaceState.AMBIGUOUS
        assert any("reject" in m for m in a.ambiguities)


class TestNot:
    def test_not_is_not_statically_decidable(self) -> None:
        a = analyze_schema({"not": {"type": "object", "properties": {"x": {}}}})
        assert a.surface is SurfaceState.AMBIGUOUS
        assert any("not" in m for m in a.ambiguities)

    def test_not_still_surfaces_nested_external_ref(self) -> None:
        a = analyze_schema({"not": {"$ref": "https://evil.example/s.json#/a"}})
        assert "https://evil.example/s.json#/a" in a.external_refs


class TestIfThenElse:
    def test_if_then_else_consistent_closed(self) -> None:
        a = analyze_schema(
            {
                "if": {"properties": {"kind": {"const": "a"}}},
                "then": CLOSED_X,
                "else": dict(CLOSED_X),
            }
        )
        assert a.surface is SurfaceState.CLOSED

    def test_if_then_else_divergent_is_ambiguous(self) -> None:
        a = analyze_schema({"if": {}, "then": CLOSED_X, "else": CLOSED_Y})
        assert a.surface is SurfaceState.AMBIGUOUS

    def test_missing_else_leaves_surface_open(self) -> None:
        # No else branch → else is 'true' (permits anything) → not closed.
        a = analyze_schema({"if": {}, "then": CLOSED_X})
        assert a.surface is not SurfaceState.CLOSED


class TestRefAndDefs:
    def test_local_defs_ref_resolves_and_is_closed(self) -> None:
        schema = {
            "$defs": {
                "Foo": {"type": "object", "properties": {"a": {}}, "additionalProperties": False}
            },
            "$ref": "#/$defs/Foo",
        }
        a = analyze_schema(schema)
        assert a.surface is SurfaceState.CLOSED
        assert a.permitted_props == frozenset({"a"})
        assert not a.external_refs

    def test_external_https_ref_surfaced_and_not_closed(self) -> None:
        a = analyze_schema({"$ref": "https://evil.example/s.json#/x"})
        assert "https://evil.example/s.json#/x" in a.external_refs
        assert not a.is_closed

    def test_external_file_ref_surfaced(self) -> None:
        a = analyze_schema({"$ref": "file:///etc/passwd"})
        assert "file:///etc/passwd" in a.external_refs

    def test_relative_ref_surfaced(self) -> None:
        a = analyze_schema({"$ref": "../other.json#/x"})
        assert "../other.json#/x" in a.external_refs

    def test_unresolvable_local_ref_is_unsupported_denied(self) -> None:
        a = analyze_schema({"$ref": "#/$defs/DoesNotExist"})
        assert a.unsupported
        assert not a.is_closed

    def test_ref_cycle_is_bounded(self) -> None:
        schema = {"$defs": {"A": {"$ref": "#/$defs/A"}}, "$ref": "#/$defs/A"}
        # Must terminate (no infinite recursion) and not crash.
        a = analyze_schema(schema)
        assert a is not None


class TestPrefixItems:
    def test_prefixitems_closed_tail(self) -> None:
        a = analyze_schema({"type": "array", "prefixItems": [{"type": "string"}], "items": False})
        assert a.array_tail is SurfaceState.CLOSED

    def test_prefixitems_open_tail(self) -> None:
        a = analyze_schema({"type": "array", "prefixItems": [{"type": "string"}]})
        assert a.array_tail is SurfaceState.OPEN

    def test_non_array_has_no_array_tail(self) -> None:
        assert analyze_schema(CLOSED_X).array_tail is None


class TestUnsupportedDenied:
    def test_pattern_properties_denied(self) -> None:
        a = analyze_schema({"type": "object", "patternProperties": {"^x": {"type": "string"}}})
        assert a.unsupported
        assert not a.is_closed

    def test_unevaluated_properties_denied(self) -> None:
        a = analyze_schema({"type": "object", "unevaluatedProperties": False})
        assert a.unsupported


class TestGhostStripUnderComposition:
    def test_strip_arg_permitted_by_no_branch(self) -> None:
        schema = {"oneOf": [CLOSED_X, CLOSED_Y]}
        r = strip_ghost_args_under_composition(schema, ["x", "z"])
        assert r.kept == ("x",)
        assert r.stripped == ("z",)

    def test_per_branch_report(self) -> None:
        schema = {"oneOf": [CLOSED_X, CLOSED_Y]}
        r = strip_ghost_args_under_composition(schema, ["x", "y", "z"])
        assert len(r.per_branch) == 2
        branch0 = r.per_branch[0]
        assert branch0.kind == "oneOf"
        assert "x" in branch0.permitted
        assert "z" in branch0.stripped
        branch1 = r.per_branch[1]
        assert "y" in branch1.permitted

    def test_root_branch_report_when_no_composition(self) -> None:
        r = strip_ghost_args_under_composition(CLOSED_X, ["x", "ghost"])
        assert r.kept == ("x",)
        assert r.stripped == ("ghost",)
        assert len(r.per_branch) == 1
        assert r.per_branch[0].kind == "root"


class TestIterPropertySchemas:
    def test_gathers_across_branches(self) -> None:
        schema = {"oneOf": [CLOSED_X, CLOSED_Y]}
        names = {name for name, _ in iter_property_schemas(schema)}
        assert names == {"x", "y"}

    def test_gathers_through_local_ref(self) -> None:
        schema = {
            "$defs": {"Foo": {"properties": {"a": {"type": "integer"}}}},
            "$ref": "#/$defs/Foo",
        }
        names = {name for name, _ in iter_property_schemas(schema)}
        assert names == {"a"}


class TestIsLocalRef:
    def test_local(self) -> None:
        assert is_local_ref("#/$defs/Foo")
        assert is_local_ref("#")

    def test_external(self) -> None:
        assert not is_local_ref("https://x/y#/a")
        assert not is_local_ref("other.json")
        assert not is_local_ref("file:///x")
