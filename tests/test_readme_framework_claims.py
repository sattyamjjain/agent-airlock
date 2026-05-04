"""Regression test for the README framework-compatibility claim (v0.6.1+).

The 2026-05-02 audit caught a claim-vs-code drift: the README advertised
"10 framework integrations" while the `src/agent_airlock/integrations/`
directory only carried 5 first-party adapters. The split is now
explicit (adapter-shipped vs example-only). This test fails the build
when either side drifts.

Definition: an "adapter-shipped" framework integration is one that has
both a dedicated module under ``src/agent_airlock/integrations/`` (or
``src/agent_airlock/mcp.py`` for the FastMCP case) AND a row in the
README's adapter-shipped paragraph naming that module.

An "example-only" framework integration is one where the user can
apply ``@Airlock()`` directly without any adapter glue — there is a
copy-paste-able file under ``examples/`` and a row in the README's
example-only paragraph.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_README = _REPO / "README.md"


# Modules under src/agent_airlock that the README's adapter-shipped
# paragraph must reference. Update both this set and the README in the
# same PR when you add a new framework adapter.
_ADAPTER_SHIPPED_MODULES: tuple[str, ...] = (
    "integrations/langchain.py",
    "integrations/langgraph_toolnode_compat.py",
    "integrations/openai_guardrails.py",
    "integrations/anthropic.py",
    "integrations/anthropic_claude_agent_sdk.py",
    "integrations/smolagents_wrapper.py",
    "integrations/gemini3_tool_shape_adapter.py",
    "integrations/gpt5_5_tool_shape_adapter.py",
    "integrations/pydantic_ai.py",
    "mcp.py",
)


# Frameworks whose only integration path is `examples/<name>_integration.py`.
_EXAMPLE_ONLY_FRAMEWORKS: tuple[str, ...] = (
    "CrewAI",
    "AutoGen",
    "LlamaIndex",
)


def _readme_text() -> str:
    return _README.read_text(encoding="utf-8")


class TestReadmeFrameworkClaims:
    """Lock the public claim against the directory listing."""

    @pytest.mark.parametrize("module_rel", _ADAPTER_SHIPPED_MODULES)
    def test_adapter_module_exists(self, module_rel: str) -> None:
        path = _REPO / "src" / "agent_airlock" / module_rel
        assert path.exists(), f"adapter module {module_rel} declared in README but absent on disk"

    @pytest.mark.parametrize("module_rel", _ADAPTER_SHIPPED_MODULES)
    def test_readme_references_each_adapter_module(self, module_rel: str) -> None:
        text = _readme_text()
        # The README references each adapter module by relative path.
        # We accept either the bare filename or the module path as the
        # match — both shapes are stable references.
        filename = Path(module_rel).name
        assert filename in text, (
            f"README must mention adapter module {filename!r} to match the on-disk file"
        )

    @pytest.mark.parametrize("framework", _EXAMPLE_ONLY_FRAMEWORKS)
    def test_example_only_framework_has_example_file(self, framework: str) -> None:
        # Map framework name to the example file convention used in the repo.
        slug = framework.lower().replace(".", "")
        # smolagents in examples uses "smolagents_integration" — the four
        # example-only frameworks all follow `<lower-name>_integration.py`.
        expected = _REPO / "examples" / f"{slug}_integration.py"
        assert expected.exists(), (
            f"example-only framework {framework!r} must ship examples/{slug}_integration.py"
        )

    def test_split_prose_present_in_readme(self) -> None:
        """README must explicitly call out adapter-shipped vs example-only."""
        text = _readme_text()
        adapter_count = len(_ADAPTER_SHIPPED_MODULES)
        example_count = len(_EXAMPLE_ONLY_FRAMEWORKS)
        assert f"Adapter-shipped ({adapter_count})" in text, (
            f"README must say 'Adapter-shipped ({adapter_count})' to match the on-disk module set"
        )
        assert f"Example-only ({example_count})" in text, (
            f"README must say 'Example-only ({example_count})' to match the example frameworks"
        )

    def test_pydantic_ai_promoted_to_adapter_shipped(self) -> None:
        """v0.7.1 ADD-1 — PydanticAI must show as adapter-shipped, not example-only."""
        text = _readme_text()
        # Adapter-shipped paragraph should mention pydantic_ai
        assert "integrations/pydantic_ai.py" in text, (
            "README must reference integrations/pydantic_ai.py in the adapter-shipped paragraph"
        )
        # Example-only paragraph should NOT list PydanticAI any more.
        # The example-only prose lists frameworks comma-separated; we
        # check that the canonical example-only paragraph does not lead
        # with "PydanticAI, CrewAI" (the v0.6.1 string).
        assert "**Example-only (4):** PydanticAI, CrewAI" not in text, (
            "README still has the v0.6.1 example-only string with PydanticAI in it"
        )

    def test_no_stale_ten_framework_claim(self) -> None:
        """The legacy '| 10 |' claim is gone."""
        text = _readme_text()
        # The old broken claim was an exact pipe-cell. Anything else
        # mentioning "10" is fine.
        assert "Framework integrations** | 10 |" not in text, (
            "README still carries the stale '10' framework-integrations claim"
        )
