"""The AgentDojo shim's model routing, pinned without the ``agentdojo`` extra.

The Together-routing regressions from #168 live in
``test_agentdojo_model_registry_shim.py``, which ``importorskip``s ``agentdojo``: a
bench-only extra that no CI job installs, so those tests have never run in CI. The
decision they depend on is ``_infer`` / ``_is_auto_registerable``, which is plain string
logic and imports nothing from ``agentdojo``, so it is pinned here where CI runs it. The
registration into agentdojo's own tables stays covered by the skipped module.
"""

from __future__ import annotations

import pytest
from benchmarks.agentdojo.model_registry_shim import _infer, _is_auto_registerable


class TestTogetherSlugsRouteToTogether:
    def test_a_llama_slug_is_not_routed_to_anthropic(self) -> None:
        # Before the "/" branch in _infer, every Together id fell through to the
        # Anthropic default: the run was built against anthropic.Anthropic() and the
        # attack addressed a Llama model as "Claude".
        provider, self_name = _infer("meta-llama/Llama-3.3-70B-Instruct-Turbo")

        assert provider == "together"
        assert self_name != "Claude"

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
        assert _infer(model_id) == ("together", expected_name)


class TestPrefixRouting:
    @pytest.mark.parametrize(
        ("model_id", "expected"),
        [
            ("claude-sonnet-5", ("anthropic", "Claude")),
            ("gpt-4o-mini-2024-07-18", ("openai", "GPT-4")),
            ("gemini-2.5-pro", ("google", "AI model developed by Google")),
            ("command-r-plus", ("cohere", "Command R")),
        ],
    )
    def test_each_prefix_routes_to_its_provider(
        self, model_id: str, expected: tuple[str, str]
    ) -> None:
        assert _infer(model_id) == expected


class TestAutoRegistration:
    def test_a_together_slug_is_auto_registered(self) -> None:
        # `--model <together id>` used to register nothing, so the arm could not run.
        assert _is_auto_registerable("togethercomputer/probe-model-x1")

    def test_an_unclassifiable_bare_id_is_not(self) -> None:
        # Negative control: a typo must fail loudly, not be invented as a new model.
        assert not _is_auto_registerable("gpt-4o-typo-that-does-not-exist")
