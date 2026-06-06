"""Tests for the v0.8.18 DescriptionManifestGuard primitive.

Runtime description-vs-manifest consistency validation. Anchored on the
DCIChecker study (arXiv:2606.04769), which measured **Description-Code
Inconsistency** at 9.93% of 19,200 tool description/implementation pairs
across 2,214 MCP servers — the model-facing description does not match
the tool's actual registered contract roughly 1 call in 10.

This guard operates one layer above ghost-arg stripping + Pydantic
type-validation: those govern the observed *call payload*; this guard
asserts the *declared contract itself is internally honest* before the
tool is admitted. It does not replace them.

Three core cases (the brief's a/b/c):

- (a) description matches manifest → allow.
- (b) description claims an argument the manifest never declares → block.
- (c) description understates a side effect present in the manifest →
  block + structured violation.

Three drift modes (parity with OpenAPIDriftGuard):

- ``strict`` (default): inconsistency → deny.
- ``warn``: inconsistency → allow but log structured warning.
- ``shadow``: inconsistency → allow, record divergences, no log.

Primary source
--------------
https://arxiv.org/abs/2606.04769
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.description_manifest_guard import (
    DescriptionManifestDecision,
    DescriptionManifestDivergenceKind,
    DescriptionManifestGuard,
    DescriptionManifestVerdict,
    DescriptionManifestViolation,
    ToolDescription,
    ToolManifest,
    vaccinate_description_manifest,
)

# ----------------------------------------------------------------------
# Shared fixtures
# ----------------------------------------------------------------------


def _read_file_manifest() -> ToolManifest:
    """Authoritative contract for a ``read_file`` tool.

    Declares one argument (``path``) and two real side effects:
    ``filesystem_read`` and ``network_egress`` (it phones home).
    """
    return ToolManifest(
        name="read_file",
        declared_args={"path"},
        side_effects={"filesystem_read", "network_egress"},
    )


def _guard(drift_mode: str = "strict") -> DescriptionManifestGuard:
    return DescriptionManifestGuard(manifests=[_read_file_manifest()], drift_mode=drift_mode)


# ----------------------------------------------------------------------
# (a) description matches manifest → allow
# ----------------------------------------------------------------------


class TestConsistentDescriptionAllows:
    """An honest description that matches the manifest is admitted."""

    def test_exact_match_allows(self) -> None:
        decision = _guard().evaluate(
            ToolDescription(
                name="read_file",
                described_args={"path"},
                described_side_effects={"filesystem_read", "network_egress"},
            )
        )
        assert decision.allowed is True
        assert decision.verdict is DescriptionManifestVerdict.ALLOW
        assert decision.divergences == ()

    def test_manifest_arg_omitted_from_description_is_not_a_block(self) -> None:
        """Terse-but-honest: description omits a manifest arg → still allowed.

        Benign under-documentation of an input is governed by the
        ghost-arg / Pydantic layer at call time, not by this semantic
        guard (a deliberate scope decision).
        """
        manifest = ToolManifest(name="t", declared_args={"a", "b"}, side_effects=set())
        guard = DescriptionManifestGuard(manifests=[manifest])
        decision = guard.evaluate(ToolDescription(name="t", described_args={"a"}))
        assert decision.allowed is True
        assert decision.verdict is DescriptionManifestVerdict.ALLOW


# ----------------------------------------------------------------------
# (b) described arg not in manifest → block
# ----------------------------------------------------------------------


class TestDescribedArgNotInManifestBlocks:
    """Description advertises an argument the tool never declares → deny."""

    def test_strict_mode_blocks_with_violation_kind(self) -> None:
        decision = _guard().evaluate(
            ToolDescription(
                name="read_file",
                described_args={"path", "exfil_url"},
                described_side_effects={"filesystem_read", "network_egress"},
            )
        )
        assert decision.allowed is False
        assert decision.verdict is DescriptionManifestVerdict.DENY_INCONSISTENT
        kinds = {d.kind for d in decision.divergences}
        assert DescriptionManifestDivergenceKind.DESCRIBED_ARG_NOT_IN_MANIFEST in kinds
        offending = {
            d.item
            for d in decision.divergences
            if d.kind is DescriptionManifestDivergenceKind.DESCRIBED_ARG_NOT_IN_MANIFEST
        }
        assert offending == {"exfil_url"}

    def test_fix_hint_names_the_ghost_argument(self) -> None:
        decision = _guard().evaluate(
            ToolDescription(name="read_file", described_args={"path", "exfil_url"})
        )
        hints = decision.fix_hints()
        assert any("exfil_url" in h for h in hints)

    def test_warn_mode_allows_but_records(self) -> None:
        decision = _guard("warn").evaluate(
            ToolDescription(name="read_file", described_args={"path", "exfil_url"})
        )
        assert decision.allowed is True
        assert decision.verdict is DescriptionManifestVerdict.ALLOW_WARN
        assert decision.divergences  # still surfaced


# ----------------------------------------------------------------------
# (c) description understates a side effect present in manifest → block
# ----------------------------------------------------------------------


class TestUnderstatedSideEffectBlocks:
    """Tool-poisoning shape: manifest has a side effect the description hides."""

    def test_strict_mode_blocks_undisclosed_effect(self) -> None:
        decision = _guard().evaluate(
            ToolDescription(
                name="read_file",
                described_args={"path"},
                # Discloses only filesystem_read; HIDES network_egress.
                described_side_effects={"filesystem_read"},
            )
        )
        assert decision.allowed is False
        assert decision.verdict is DescriptionManifestVerdict.DENY_INCONSISTENT
        undisclosed = {
            d.item
            for d in decision.divergences
            if d.kind is DescriptionManifestDivergenceKind.UNDISCLOSED_SIDE_EFFECT
        }
        assert undisclosed == {"network_egress"}

    def test_violation_fix_hint_flags_tool_poisoning(self) -> None:
        decision = _guard().evaluate(
            ToolDescription(
                name="read_file",
                described_args={"path"},
                described_side_effects={"filesystem_read"},
            )
        )
        hints = decision.fix_hints()
        assert any("network_egress" in h for h in hints)
        assert any("poison" in h.lower() or "disclose" in h.lower() for h in hints)

    def test_shadow_mode_allows_but_records(self) -> None:
        decision = _guard("shadow").evaluate(
            ToolDescription(
                name="read_file",
                described_args={"path"},
                described_side_effects={"filesystem_read"},
            )
        )
        assert decision.allowed is True
        assert decision.verdict is DescriptionManifestVerdict.ALLOW_SHADOW
        assert decision.divergences


# ----------------------------------------------------------------------
# Over-claimed capability (declared capability absent from manifest)
# ----------------------------------------------------------------------


class TestOverclaimedCapabilityBlocks:
    """Description advertises a capability the manifest does not have → deny."""

    def test_strict_mode_blocks_overclaim(self) -> None:
        decision = _guard().evaluate(
            ToolDescription(
                name="read_file",
                described_args={"path"},
                # Adds a capability the manifest never declares.
                described_side_effects={"filesystem_read", "network_egress", "filesystem_write"},
            )
        )
        assert decision.allowed is False
        overclaimed = {
            d.item
            for d in decision.divergences
            if d.kind is DescriptionManifestDivergenceKind.OVERCLAIMED_CAPABILITY
        }
        assert overclaimed == {"filesystem_write"}


# ----------------------------------------------------------------------
# Unknown tool
# ----------------------------------------------------------------------


class TestUnknownTool:
    """A description with no registered manifest fails closed in strict."""

    def test_strict_mode_unknown_tool_denies(self) -> None:
        decision = _guard().evaluate(ToolDescription(name="unregistered", described_args={"x"}))
        assert decision.allowed is False
        assert decision.verdict is DescriptionManifestVerdict.DENY_UNKNOWN_TOOL

    def test_warn_mode_unknown_tool_allows(self) -> None:
        decision = _guard("warn").evaluate(ToolDescription(name="unregistered"))
        assert decision.allowed is True
        assert decision.verdict is DescriptionManifestVerdict.ALLOW_WARN


# ----------------------------------------------------------------------
# Construction + input validation
# ----------------------------------------------------------------------


class TestConstructionValidation:
    """Guard / manifest / description construction guards."""

    def test_unknown_drift_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="drift_mode"):
            DescriptionManifestGuard(manifests=[], drift_mode="loose")

    def test_duplicate_manifest_name_raises(self) -> None:
        with pytest.raises(ValueError, match="duplicate"):
            DescriptionManifestGuard(
                manifests=[ToolManifest(name="t"), ToolManifest(name="t")],
            )

    def test_non_manifest_in_registry_raises(self) -> None:
        with pytest.raises(TypeError, match="ToolManifest"):
            DescriptionManifestGuard(manifests=[{"name": "t"}])  # type: ignore[list-item]

    def test_evaluate_non_description_raises(self) -> None:
        with pytest.raises(TypeError, match="ToolDescription"):
            _guard().evaluate({"name": "read_file"})  # type: ignore[arg-type]

    def test_bare_str_args_rejected(self) -> None:
        """A bare str for an arg set is a footgun (iterates per-char) → TypeError."""
        with pytest.raises(TypeError, match="bare str"):
            ToolManifest(name="t", declared_args="path")  # type: ignore[arg-type]

    def test_empty_manifest_name_raises(self) -> None:
        with pytest.raises(TypeError, match="non-empty"):
            ToolManifest(name="")

    def test_non_str_arg_element_raises(self) -> None:
        with pytest.raises(TypeError, match="elements must be str"):
            ToolManifest(name="t", declared_args={1, 2})  # type: ignore[arg-type]


# ----------------------------------------------------------------------
# Decision / dataclass shape
# ----------------------------------------------------------------------


class TestDecisionShape:
    """Decision objects are frozen and expose the chainable ``allowed`` bool."""

    def test_decision_is_frozen(self) -> None:
        decision = _guard().evaluate(ToolDescription(name="read_file", described_args={"path"}))
        with pytest.raises((AttributeError, TypeError)):
            decision.allowed = False  # type: ignore[misc]

    def test_manifest_and_description_normalise_to_frozenset(self) -> None:
        m = ToolManifest(name="t", declared_args=["a", "a", "b"])
        assert m.declared_args == frozenset({"a", "b"})
        d = ToolDescription(name="t", described_args=("x", "x"))
        assert d.described_args == frozenset({"x"})

    def test_decision_exposes_allowed_bool(self) -> None:
        decision = _guard().evaluate(ToolDescription(name="read_file", described_args={"path"}))
        assert isinstance(decision, DescriptionManifestDecision)
        assert isinstance(decision.allowed, bool)


# ----------------------------------------------------------------------
# vaccinate_description_manifest — the wrap seam (fail-closed before execute)
# ----------------------------------------------------------------------


class TestVaccinateDescriptionManifest:
    """The decorator factory enforces consistency at the wrap seam."""

    def test_consistent_description_passes_call_through(self) -> None:
        vaccine = vaccinate_description_manifest([_read_file_manifest()])

        @vaccine(
            ToolDescription(
                name="read_file",
                described_args={"path"},
                described_side_effects={"filesystem_read", "network_egress"},
            )
        )
        def read_file(*, path: str) -> str:
            return f"contents of {path}"

        assert read_file(path="/etc/hosts") == "contents of /etc/hosts"

    def test_inconsistent_description_raises_before_execute(self) -> None:
        vaccine = vaccinate_description_manifest([_read_file_manifest()], drift_mode="strict")
        executed: list[str] = []

        @vaccine(ToolDescription(name="read_file", described_args={"path", "exfil_url"}))
        def read_file(*, path: str = "", exfil_url: str = "") -> str:
            executed.append(path)
            return "ran"

        with pytest.raises(DescriptionManifestViolation) as exc:
            read_file(path="/etc/hosts", exfil_url="http://evil")
        # Fail-closed: the underlying tool body never ran.
        assert executed == []
        # The violation carries the decision + fix_hints for self-heal.
        assert exc.value.decision.verdict is DescriptionManifestVerdict.DENY_INCONSISTENT
        assert any("exfil_url" in h for h in exc.value.fix_hints)

    def test_warn_mode_does_not_block_call(self) -> None:
        vaccine = vaccinate_description_manifest([_read_file_manifest()], drift_mode="warn")

        @vaccine(ToolDescription(name="read_file", described_args={"path", "exfil_url"}))
        def read_file(*, path: str = "", exfil_url: str = "") -> str:
            return "ran"

        assert read_file(path="/x") == "ran"

    def test_wraps_preserves_name(self) -> None:
        vaccine = vaccinate_description_manifest([_read_file_manifest()])

        @vaccine(ToolDescription(name="read_file", described_args={"path"}))
        def read_file(*, path: str) -> str:
            return path

        assert read_file.__name__ == "read_file"


# ----------------------------------------------------------------------
# Preset wiring
# ----------------------------------------------------------------------


class TestPresetWiring:
    """The policy_presets factory wires the guard with canonical metadata."""

    def test_preset_canonical_keys(self) -> None:
        from agent_airlock.policy_presets import mcp_description_manifest_guard_defaults

        preset = mcp_description_manifest_guard_defaults(manifests=[_read_file_manifest()])
        assert preset["preset_id"] == "mcp_description_manifest_guard"
        assert preset["default_action"] == "deny"
        assert preset["owasp"] == "MCP03"
        assert preset["advisory_url"] == "https://arxiv.org/abs/2606.04769"
        assert isinstance(preset["guard"], DescriptionManifestGuard)

    def test_preset_check_raises_on_inconsistency(self) -> None:
        from agent_airlock.policy_presets import mcp_description_manifest_guard_defaults

        preset = mcp_description_manifest_guard_defaults(manifests=[_read_file_manifest()])
        # Consistent → returns None.
        assert (
            preset["check"](
                ToolDescription(
                    name="read_file",
                    described_args={"path"},
                    described_side_effects={"filesystem_read", "network_egress"},
                )
            )
            is None
        )
        # Inconsistent → raises.
        with pytest.raises(DescriptionManifestViolation):
            preset["check"](ToolDescription(name="read_file", described_args={"path", "ghost"}))

    def test_preset_warn_mode_action_is_allow(self) -> None:
        from agent_airlock.policy_presets import mcp_description_manifest_guard_defaults

        preset = mcp_description_manifest_guard_defaults(
            manifests=[_read_file_manifest()], drift_mode="warn"
        )
        assert preset["default_action"] == "allow"

    def test_preset_rejects_bad_drift_mode(self) -> None:
        from agent_airlock.policy_presets import mcp_description_manifest_guard_defaults

        with pytest.raises(ValueError, match="drift_mode"):
            mcp_description_manifest_guard_defaults(manifests=[], drift_mode="nope")

    def test_preset_discoverable_via_list_active(self) -> None:
        from agent_airlock.policy_presets import list_active

        names = {m.preset_id for m in list_active()}
        assert "mcp_description_manifest_guard_defaults" in names
