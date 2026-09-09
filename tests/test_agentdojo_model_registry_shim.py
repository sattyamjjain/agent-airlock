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

    def test_together_slug_routes_to_together_not_anthropic(self) -> None:
        """The regression this class was missing.

        Before the ``"/"`` branch in ``_infer``, every Together id fell through to the
        Anthropic default: the run would be built against ``anthropic.Anthropic()``
        instead of Together's OpenAI-compatible endpoint, and the attack would address a
        Llama model as "Claude". Both are silent, and the resulting ASR would have been
        meaningless rather than merely wrong — which is the failure this shim exists to
        prevent for Claude ids in the first place.
        """
        mid = "meta-llama/Llama-3.3-70B-Instruct-Turbo"
        member = register_model(mid)
        assert MODEL_PROVIDERS[member] == "together"
        assert MODEL_NAMES[mid] != "Claude"

    @pytest.mark.parametrize(
        ("model_id", "expected_name"),
        [
            ("mistralai/Mixtral-8x7B-Instruct-v0.1", "Mixtral"),
            ("Qwen/Qwen2.5-72B-Instruct-Turbo", "Qwen"),
            ("deepseek-ai/DeepSeek-V3", "DeepSeek"),
            ("meta-llama/Llama-3.3-70B-Instruct-Turbo", "AI assistant"),
            ("some-lab/Unrecognised-Model-v1", "AI assistant"),
        ],
    )
    def test_together_self_names(self, model_id: str, expected_name: str) -> None:
        # The self-name is what the attack addresses the model by. Mixtral and the
        # Llama fallback reproduce agentdojo 0.1.35's own entries rather than
        # second-guessing them.
        register_model(model_id)
        assert MODEL_PROVIDERS[ModelsEnum(model_id)] == "together"
        assert MODEL_NAMES[model_id] == expected_name

    def test_ensure_registered_auto_adds_a_together_slug(self) -> None:
        # `--model <together id>` used to register nothing at all, so ModelsEnum(...)
        # raised and the arm could not run without --register-model.
        added = ensure_registered(["togethercomputer/probe-model-x1"])
        assert added == ["togethercomputer/probe-model-x1"]
        assert MODEL_PROVIDERS[ModelsEnum("togethercomputer/probe-model-x1")] == "together"

    def test_an_unclassifiable_bare_id_is_still_not_auto_registered(self) -> None:
        # Negative control for the widened auto-registration: a bare id that is neither
        # a Claude id nor a slug must still require an explicit --register-model, so a
        # typo fails loudly instead of being invented as a new model.
        assert ensure_registered(["gpt-4o-typo-that-does-not-exist"]) == []

    def test_together_prompting_can_be_forced_for_models_without_native_tools(self) -> None:
        # Not inferable from the id, so it is passed explicitly. Pinned because the
        # docstring promises this escape hatch.
        mid = "meta-llama/Llama-3-8b-chat-hf"
        member = register_model(mid, provider="together-prompting")
        assert MODEL_PROVIDERS[member] == "together-prompting"

    def test_register_current_models_registers_defaults(self) -> None:
        register_current_models()
        known = {m.value for m in ModelsEnum}
        for model_id in DEFAULT_CURRENT_CLAUDE:
            assert model_id in known
            assert MODEL_NAMES[model_id] == "Claude"
