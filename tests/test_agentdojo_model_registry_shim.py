"""The AgentDojo model-registry shim registers current ids across all three tables.

These need ``agentdojo`` installed (a bench-only extra) but **no API key and no network**:
they assert the shim makes a current Claude id resolvable through agentdojo's interface —
enum membership, provider map, and the attack self-name map — which is what the paid
model-in-the-loop run relies on. Skipped when the extra is absent, so the default gate
stays zero-dep.
"""

from __future__ import annotations

import pytest

pytest.importorskip("agentdojo", reason="agentdojo is a bench-only extra")

from agentdojo.attacks.base_attacks import get_model_name_from_pipeline  # noqa: E402
from agentdojo.models import MODEL_NAMES, MODEL_PROVIDERS, ModelsEnum  # noqa: E402
from benchmarks.agentdojo.model_registry_shim import (  # noqa: E402
    DEFAULT_CURRENT_CLAUDE,
    ensure_registered,
    register_current_models,
    register_model,
)


class _Pipeline:
    """Minimal stand-in whose ``.name`` mirrors run.py's ``f"{model_id}-{arm}"``."""

    def __init__(self, name: str) -> None:
        self.name = name


class TestModelRegistryShim:
    def test_current_claude_id_is_unknown_to_agentdojo_then_registered(self) -> None:
        model_id = "claude-opus-5"
        # Baseline: unmaintained agentdojo does not know a current Claude id.
        assert model_id not in {m.value for m in ModelsEnum}

        member = register_model(model_id)

        # 1. enum membership — the pipeline does ModelsEnum(config.llm).
        assert ModelsEnum(model_id) is member
        assert member.value == model_id
        assert model_id in {m.value for m in ModelsEnum}
        # 2. provider map — the pipeline does MODEL_PROVIDERS[ModelsEnum(llm)].
        assert MODEL_PROVIDERS[ModelsEnum(model_id)] == "anthropic"
        # 3. attack self-name map — read by the tool_knowledge attack.
        assert MODEL_NAMES[model_id] == "Claude"

    def test_attack_resolves_self_name_from_pipeline_name(self) -> None:
        model_id = "claude-sonnet-5"
        register_model(model_id)
        # get_model_name_from_pipeline matches `full_name in pipeline.name`; without the
        # MODEL_NAMES entry this would raise or return a wrong name — the meaningless-number
        # failure mode an enum-only patch leaves behind.
        assert get_model_name_from_pipeline(_Pipeline(f"{model_id}-airlock")) == "Claude"

    def test_register_model_is_idempotent(self) -> None:
        first = register_model("claude-haiku-4-5-20251001")
        second = register_model("claude-haiku-4-5-20251001")
        assert first is second

    def test_provider_and_self_name_inferred_for_non_claude_ids(self) -> None:
        register_model("gpt-4o-2024-08-06")
        assert MODEL_PROVIDERS[ModelsEnum("gpt-4o-2024-08-06")] == "openai"
        assert MODEL_NAMES["gpt-4o-2024-08-06"] == "GPT-4"

    def test_ensure_registered_adds_unknown_claude_model_only(self) -> None:
        # A known id (already in the enum) is skipped; an unknown claude id is added.
        added = ensure_registered(["gpt-4o-mini-2024-07-18", "claude-4-5-probe-20260801"])
        assert added == ["claude-4-5-probe-20260801"]
        assert "claude-4-5-probe-20260801" in {m.value for m in ModelsEnum}

    def test_ensure_registered_honours_explicit_extra(self) -> None:
        added = ensure_registered([], extra=["some-vendor-model-x1"])
        assert "some-vendor-model-x1" in added
        assert "some-vendor-model-x1" in {m.value for m in ModelsEnum}

    def test_register_current_models_registers_defaults(self) -> None:
        register_current_models()
        known = {m.value for m in ModelsEnum}
        for model_id in DEFAULT_CURRENT_CLAUDE:
            assert model_id in known
            assert MODEL_NAMES[model_id] == "Claude"
