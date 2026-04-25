"""Tests for the Claude Managed Agents audit hook (v0.5.6+).

Primary sources (cited per v0.5.1+ convention):
- Launch blog (2026-04-08): <https://claude.com/blog/claude-managed-agents>
- API overview: <https://platform.claude.com/docs/en/managed-agents/overview>
"""

from __future__ import annotations

import pytest

from agent_airlock import (
    ManagedAgentBetaHeaderMissingError,
    ManagedAgentToolBlocked,
    UnknownToolsetVersionError,
)
from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.claude_managed_agents import (
    AGENT_TOOLSET_VERSION,
    DEFAULT_HARNESS_TOOLS,
    MANAGED_AGENTS_BETA_HEADER,
    ManagedAgentsAuditConfig,
    ManagedAgentSession,
    audit_managed_agent_invocation,
    redact_sse_event,
)
from agent_airlock.policy_presets import claude_managed_agents_safe_defaults


def _ok_request(tool: str = "read_file") -> dict:
    return {
        "tool": tool,
        "betas": [MANAGED_AGENTS_BETA_HEADER],
        "toolset_version": AGENT_TOOLSET_VERSION,
    }


class TestToolIntersection:
    """Unknown tools and disallowed tools both trigger ManagedAgentToolBlocked."""

    def test_disallowed_tool_blocks(self) -> None:
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file",))
        with pytest.raises(ManagedAgentToolBlocked) as exc:
            audit_managed_agent_invocation(_ok_request("bash"), cfg)
        assert exc.value.tool_name == "bash"
        assert "read_file" in exc.value.allowed

    def test_allowed_tool_passes(self) -> None:
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file", "web_browse"))
        audit_managed_agent_invocation(_ok_request("read_file"), cfg)

    def test_missing_tool_field_blocks(self) -> None:
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file",))
        request = _ok_request()
        del request["tool"]
        with pytest.raises(ManagedAgentToolBlocked) as exc:
            audit_managed_agent_invocation(request, cfg)
        assert exc.value.tool_name == "<missing>"


class TestBetaHeaderEnforcement:
    """The pinned beta header must be present on every request."""

    def test_missing_beta_header_blocks(self) -> None:
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file",))
        request = _ok_request("read_file")
        request["betas"] = []
        with pytest.raises(ManagedAgentBetaHeaderMissingError):
            audit_managed_agent_invocation(request, cfg)

    def test_beta_header_check_can_be_disabled(self) -> None:
        """For local-dev shimming — but never in production."""
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file",), require_beta_header=False)
        request = _ok_request("read_file")
        request["betas"] = []
        audit_managed_agent_invocation(request, cfg)


class TestToolsetVersion:
    def test_unknown_toolset_version_blocks(self) -> None:
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file",))
        request = _ok_request("read_file")
        request["toolset_version"] = "agent_toolset_99999999"
        with pytest.raises(UnknownToolsetVersionError):
            audit_managed_agent_invocation(request, cfg)

    def test_toolset_version_check_can_be_disabled(self) -> None:
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file",), toolset_version=None)
        request = _ok_request("read_file")
        request["toolset_version"] = "agent_toolset_made_up"
        audit_managed_agent_invocation(request, cfg)


class TestSessionComposition:
    """The session counter composes with the v0.5.1 task-budget adapter."""

    def test_session_counter_increments_on_clean_audit(self) -> None:
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file",))
        session = ManagedAgentSession(session_id="s-1")
        audit_managed_agent_invocation(_ok_request("read_file"), cfg, session=session)
        audit_managed_agent_invocation(_ok_request("read_file"), cfg, session=session)
        assert session.invocations == 2

    def test_session_counter_unchanged_on_block(self) -> None:
        cfg = ManagedAgentsAuditConfig(allowed_tools=("read_file",))
        session = ManagedAgentSession(session_id="s-fail")
        with pytest.raises(ManagedAgentToolBlocked):
            audit_managed_agent_invocation(_ok_request("bash"), cfg, session=session)
        assert session.invocations == 0


class TestSSERedaction:
    """SSE frames carrying secret-shaped values get redacted."""

    def test_bearer_token_redacted(self) -> None:
        frame = 'data: {"output": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"}'
        out = redact_sse_event(frame)
        assert "[REDACTED]" in out
        assert "eyJhbGciOiJIUzI1NiJ9.payload.signature" not in out

    def test_clean_frame_unchanged(self) -> None:
        frame = 'data: {"output": "Hello world"}'
        assert redact_sse_event(frame) == frame


class TestPreset:
    """``claude_managed_agents_safe_defaults`` shape + opt-in semantics."""

    def test_preset_returns_safe_defaults(self) -> None:
        cfg = claude_managed_agents_safe_defaults()
        audit = cfg["audit_config"]
        assert isinstance(audit, ManagedAgentsAuditConfig)
        assert audit.allowed_tools == ()  # empty until caller opts in
        assert audit.require_beta_header is True
        assert audit.toolset_version == AGENT_TOOLSET_VERSION
        assert audit.redact_sse_payloads is True
        assert cfg["beta_header"] == MANAGED_AGENTS_BETA_HEADER
        assert cfg["harness_tools"] == DEFAULT_HARNESS_TOOLS

    def test_preset_blocks_all_tools_until_opt_in(self) -> None:
        cfg = claude_managed_agents_safe_defaults()
        with pytest.raises(ManagedAgentToolBlocked):
            audit_managed_agent_invocation(_ok_request("read_file"), cfg["audit_config"])


class TestErrorHierarchy:
    @pytest.mark.parametrize(
        "err",
        [
            ManagedAgentBetaHeaderMissingError,
            ManagedAgentToolBlocked,
            UnknownToolsetVersionError,
        ],
    )
    def test_subclasses_airlock_error(self, err: type[Exception]) -> None:
        assert issubclass(err, AirlockError)
