"""Tests for ``policy_compiler`` (compile + explain)."""

from __future__ import annotations

import pytest

from agent_airlock.policy_compiler import (
    PROMPT_HASH,
    CompileCache,
    PolicyChain,
    PolicyCompiler,
    PolicyRule,
    explain_preset,
    register_llm_backend,
)
from agent_airlock.policy_compiler.compiler import (
    _REGISTRY,
    PolicyCompileError,
)


def _stub_backend(system_prompt: str, user_text: str) -> str:
    """Deterministic test backend — encodes user_text length into the policy id."""
    return (
        f"policy_id: stub_p\n"
        f"description: stubbed for {user_text[:20]}\n"
        "rules:\n"
        "  - rule_id: refuse_public_bind\n"
        "    condition: bind_address_public\n"
        "    action: block\n"
    )


@pytest.fixture(autouse=True)
def _register() -> object:
    register_llm_backend("stub", _stub_backend)
    yield
    _REGISTRY.pop("stub", None)


class TestPromptHash:
    def test_hash_is_64_hex_chars(self) -> None:
        assert len(PROMPT_HASH) == 64
        assert all(c in "0123456789abcdef" for c in PROMPT_HASH)

    def test_hash_stable_within_session(self) -> None:
        from agent_airlock.policy_compiler.prompt import PROMPT_HASH as h2

        assert h2 == PROMPT_HASH


class TestCompile:
    def test_compile_round_trip(self) -> None:
        c = PolicyCompiler(backend="stub")
        compiled = c.compile("block 0.0.0.0 binds without auth")
        assert compiled.chain.policy_id == "stub_p"
        assert len(compiled.chain.rules) == 1
        rule = compiled.chain.rules[0]
        assert rule.condition == "bind_address_public"
        assert rule.action == "block"

    def test_chain_to_yaml_round_trip(self) -> None:
        chain = PolicyChain(
            policy_id="x",
            description="d",
            rules=(
                PolicyRule(
                    rule_id="r1",
                    condition="parallel_tool_calls_above",
                    action="block",
                    threshold=8,
                ),
            ),
        )
        rendered = chain.to_yaml()
        assert "threshold: 8" in rendered
        assert rendered.endswith("\n")

    def test_unknown_backend_raises(self) -> None:
        c = PolicyCompiler(backend="not-registered")
        with pytest.raises(PolicyCompileError):
            c.compile("anything")


class TestCacheDeterminism:
    def test_two_compiles_share_cache(self) -> None:
        cache = CompileCache()
        c = PolicyCompiler(backend="stub", cache=cache)
        a = c.compile("alpha")
        b = c.compile("alpha")
        assert a.yaml == b.yaml
        assert len(cache) == 1

    def test_different_text_different_entries(self) -> None:
        cache = CompileCache()
        c = PolicyCompiler(backend="stub", cache=cache)
        c.compile("alpha")
        c.compile("beta")
        assert len(cache) == 2


class TestExplain:
    def test_explain_compiled_chain(self) -> None:
        compiled = PolicyCompiler(backend="stub").compile("block public binds")
        # Convert to a preset-shaped dict that the explainer accepts.
        preset = {
            "policy_id": compiled.chain.policy_id,
            "description": compiled.chain.description,
            "rules": [
                {"rule_id": r.rule_id, "condition": r.condition, "action": r.action}
                for r in compiled.chain.rules
            ],
        }
        out = explain_preset(preset)
        assert "BLOCK when the MCP server binds to a public address" in out

    def test_explain_legacy_dict(self) -> None:
        out = explain_preset({"preset_id": "legacy", "default_action": "block"})
        assert "Preset: legacy" in out
        assert "default_action: block" in out


class TestParserRejectsBadYAML:
    def test_missing_policy_id(self) -> None:
        register_llm_backend(
            "broken",
            lambda *_args: (
                "description: x\nrules:\n  - rule_id: r\n    condition: x\n    action: block\n"
            ),
        )
        c2 = PolicyCompiler(backend="broken")
        with pytest.raises(PolicyCompileError, match="policy_id"):
            c2.compile("anything")
        _REGISTRY.pop("broken", None)


class TestTheStubBackendAnnouncesItself:
    """`airlock policy compile` must not pass off a keyword match as a compilation.

    The CLI defaults to ``--backend stub``, which is a keyword matcher over a
    handful of fixed phrases, not a model. Anything it does not recognise falls
    through to a catch-all rule whose body is unrelated to the request:

        $ airlock policy compile "block any tool that deletes records"
        rules:
          - rule_id: catch_all
            condition: missing_auth_header     # <- nothing to do with deletes
            action: warn

    That output is valid YAML and looks authoritative, so printing it with no
    provenance invites a user to deploy a policy that does not say what they
    asked for. The notice goes to **stderr** so redirecting stdout to a file
    still produces a clean policy.
    """

    @pytest.fixture(autouse=True)
    def _use_the_real_cli_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """`_REGISTRY` is module-global, so a sibling test's stub can win.

        ``_ensure_default_backend`` only fills an empty ``"stub"`` slot, so a
        test that registered its own backend earlier in the session silently
        changes what the CLI does here. Clearing the slot makes this class
        exercise the shipped default regardless of test order.
        """
        from agent_airlock.policy_compiler.compiler import _REGISTRY

        monkeypatch.delitem(_REGISTRY, "stub", raising=False)

    def _run(self, text: str, capsys: pytest.CaptureFixture[str]) -> tuple[str, str]:
        from agent_airlock.cli.policy import main

        assert main(["compile", text]) == 0
        captured = capsys.readouterr()
        return captured.out, captured.err

    def test_unmatched_text_warns_that_it_is_a_placeholder(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out, err = self._run("block any tool that deletes records", capsys)
        assert "rule_id: catch_all" in out
        assert "NOT a translation" in err
        assert "register_llm_backend" in err

    def test_matched_text_still_names_the_matcher(self, capsys: pytest.CaptureFixture[str]) -> None:
        out, err = self._run("block any MCP server bound to 0.0.0.0 without auth", capsys)
        assert "refuse_public_bind" in out
        assert "keyword matcher" in err
        assert "NOT a translation" not in err, "a real match must not raise the loud warning"

    def test_the_notice_never_contaminates_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        """`compile ... > policy.yaml` has to yield a loadable file."""
        out, _ = self._run("block any tool that deletes records", capsys)
        assert "warning:" not in out
        assert "note:" not in out
        assert out.startswith("policy_id:")
