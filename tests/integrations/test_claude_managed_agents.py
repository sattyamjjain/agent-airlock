"""Tests for the Claude Managed Agents approval gate (v0.10.25).

Events are built in the shapes the Managed Agents docs and the Python SDK (anthropic
1.13.0, ``BetaManagedAgentsAgentToolUseEvent``) define, both as dicts and as attribute
objects standing in for SDK models::

    {"type": "agent.tool_use", "id": "sevt_...", "name": "read",
     "input": {"file_path": "..."}, "evaluated_permission": "ask",
     "evaluation": {"type": "always_ask"}}

Built-in tool input keys follow the SDK's ``agent_toolset20260401`` input types: ``read``
and ``write`` and ``edit`` take ``file_path``; ``glob`` and ``grep`` take ``pattern`` and an
optional ``path``; ``bash`` takes ``command``. Until 0.10.25 this module checked a request
dict with a ``"tool"`` key for tools named ``read_file``, ``web_browse`` and
``code_execute``, none of which the API has, so no real call was ever gated.

Primary sources:
- https://platform.claude.com/docs/en/managed-agents/tools
- https://platform.claude.com/docs/en/managed-agents/events
"""

from __future__ import annotations

import copy
import dataclasses
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

import agent_airlock
from agent_airlock import refusal_text
from agent_airlock.exceptions import AirlockError
from agent_airlock.filesystem import PathValidationError
from agent_airlock.integrations.claude_managed_agents import (
    AGENT_TOOLSET_TOOLS,
    AGENT_TOOLSET_VERSION,
    DEFAULT_HARNESS_TOOLS,
    DEFAULT_REMOTE_DENY_PATTERNS,
    DENY_MESSAGE_MAX_CHARS,
    MANAGED_AGENTS_BETA_HEADER,
    ManagedAgentBetaHeaderMissingError,
    ManagedAgentsAuditConfig,
    ManagedAgentSession,
    ManagedAgentToolBlocked,
    ManagedAgentToolGate,
    ManagedAgentToolsetError,
    RemotePathPolicy,
    ToolUseDecision,
    UnknownToolsetVersionError,
    UnreviewableEventError,
    audit_managed_agent_invocation,
    build_agent_toolset,
    check_agent_toolset,
    redact_sse_event,
)
from agent_airlock.kill_switch import (
    HMACBroadcastSigner,
    InMemoryTransport,
    KillSwitchBroadcast,
    KillSwitchListener,
    registry,
)
from agent_airlock.network import EndpointPolicy
from agent_airlock.policy import SecurityPolicy
from agent_airlock.policy_presets import claude_managed_agents_safe_defaults
from agent_airlock.sandbox_backend import ManagedSandboxBackend

WORKSPACE = RemotePathPolicy(allowed_roots=("/workspace",))


def _event(
    name: str = "read",
    tool_input: Any = None,
    *,
    permission: str | None = "ask",
    event_type: str = "agent.tool_use",
    event_id: str = "sevt_01",
    server: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "type": event_type,
        "id": event_id,
        "name": name,
        "input": {"file_path": "/workspace/notes.txt"} if tool_input is None else tool_input,
        "processed_at": "2026-10-12T00:00:00Z",
    }
    if permission is not None:
        event["evaluated_permission"] = permission
        event["evaluation"] = {"type": "always_ask" if permission == "ask" else "always_allow"}
    if server is not None:
        event["mcp_server_name"] = server
    return event


def _as_object(value: Any) -> Any:
    """The event as attribute access, the way SDK models expose it.

    ``input`` stays a dict, as it is on the SDK model (``Dict[str, object]``).
    """
    if isinstance(value, dict):
        return SimpleNamespace(
            **{key: item if key == "input" else _as_object(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return [_as_object(item) for item in value]
    return value


SHAPES: list[Callable[[dict[str, Any]], Any]] = [lambda e: e, _as_object]


@pytest.fixture(autouse=True)
def _no_leaked_switch() -> Any:
    registry.clear()
    yield
    registry.clear()


class TestConstants:
    def test_the_toolset_has_exactly_the_eight_documented_tools(self) -> None:
        assert AGENT_TOOLSET_TOOLS == (
            "bash",
            "read",
            "write",
            "edit",
            "glob",
            "grep",
            "web_fetch",
            "web_search",
        )

    def test_default_harness_tools_aliases_the_real_names(self) -> None:
        assert DEFAULT_HARNESS_TOOLS is AGENT_TOOLSET_TOOLS
        for invented in ("read_file", "web_browse", "code_execute"):
            assert invented not in DEFAULT_HARNESS_TOOLS

    def test_pins(self) -> None:
        assert MANAGED_AGENTS_BETA_HEADER == "managed-agents-2026-04-01"
        assert AGENT_TOOLSET_VERSION == "agent_toolset_20260401"
        assert DENY_MESSAGE_MAX_CHARS == 4000

    def test_default_deny_patterns_cover_credentials(self) -> None:
        for pattern in ("*.env", ".env*", "*.pem", "*.key", "**/.ssh/**", "**/.aws/**"):
            assert pattern in DEFAULT_REMOTE_DENY_PATTERNS


class TestBuildAgentToolset:
    def test_every_tool_is_listed_and_every_one_waits_for_the_client(self) -> None:
        toolset = build_agent_toolset({"read", "glob"})
        assert toolset["type"] == AGENT_TOOLSET_VERSION
        assert toolset["default_config"] == {
            "enabled": False,
            "permission_policy": {"type": "always_ask"},
        }
        assert [c["name"] for c in toolset["configs"]] == list(AGENT_TOOLSET_TOOLS)
        assert {c["name"] for c in toolset["configs"] if c["enabled"]} == {"read", "glob"}
        assert {c["permission_policy"]["type"] for c in toolset["configs"]} == {"always_ask"}

    def test_nothing_enabled(self) -> None:
        assert not any(c["enabled"] for c in build_agent_toolset()["configs"])

    def test_a_single_name_as_a_string(self) -> None:
        assert [c["name"] for c in build_agent_toolset("bash")["configs"] if c["enabled"]] == [
            "bash"
        ]

    def test_an_unknown_tool_is_refused(self) -> None:
        with pytest.raises(ManagedAgentToolsetError) as exc:
            build_agent_toolset({"read_file"})
        assert exc.value.problems and "read_file" in exc.value.problems[0]

    def test_an_unpinned_version_is_refused(self) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="not the pinned"):
            build_agent_toolset({"read"}, version="agent_toolset_20270101")

    def test_each_call_returns_fresh_dicts(self) -> None:
        first = build_agent_toolset({"read"})
        first["configs"][0]["permission_policy"]["type"] = "always_allow"
        assert build_agent_toolset({"read"})["configs"][0]["permission_policy"]["type"] == (
            "always_ask"
        )

    def test_it_passes_its_own_check(self) -> None:
        check_agent_toolset([build_agent_toolset({"read", "web_fetch"})])


class TestCheckAgentToolset:
    def test_a_bare_toolset_enables_everything_under_always_allow(self) -> None:
        with pytest.raises(ManagedAgentToolsetError) as exc:
            check_agent_toolset([{"type": AGENT_TOOLSET_VERSION}])
        assert len(exc.value.problems) == len(AGENT_TOOLSET_TOOLS)
        assert all("'always_allow'" in problem for problem in exc.value.problems)

    def test_auto_bypasses_the_gate_too(self) -> None:
        toolset = {
            "type": AGENT_TOOLSET_VERSION,
            "default_config": {"enabled": True, "permission_policy": {"type": "auto"}},
            "configs": [
                {"name": "bash", "permission_policy": {"type": "always_ask"}},
                {"name": "web_fetch", "enabled": False},
                {"name": "web_search", "enabled": False},
            ],
        }
        with pytest.raises(ManagedAgentToolsetError) as exc:
            check_agent_toolset([toolset])
        flagged = {problem.split(": ")[1].split()[0] for problem in exc.value.problems}
        assert flagged == {"read", "write", "edit", "glob", "grep"}

    def test_opt_in_tools_under_always_ask_pass(self) -> None:
        check_agent_toolset(
            [
                {
                    "type": AGENT_TOOLSET_VERSION,
                    "default_config": {"enabled": False},
                    "configs": [
                        {
                            "name": "read",
                            "enabled": True,
                            "permission_policy": {"type": "always_ask"},
                        }
                    ],
                }
            ]
        )

    def test_an_enabled_tool_outside_allowed_tools_is_a_problem(self) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="not in allowed_tools"):
            check_agent_toolset([build_agent_toolset({"read", "glob"})], allowed_tools={"read"})

    def test_an_unpinned_toolset_type(self) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="agent_toolset_20250101"):
            check_agent_toolset([{"type": "agent_toolset_20250101"}])

    def test_an_mcp_toolset_defaults_to_always_ask(self) -> None:
        check_agent_toolset([{"type": "mcp_toolset", "mcp_server_name": "github"}])

    @pytest.mark.parametrize(
        "toolset",
        [
            {
                "type": "mcp_toolset",
                "mcp_server_name": "github",
                "default_config": {"permission_policy": {"type": "auto"}},
            },
            {
                "type": "mcp_toolset",
                "mcp_server_name": "github",
                "configs": [{"name": "merge_pr", "permission_policy": {"type": "always_allow"}}],
            },
        ],
    )
    def test_an_mcp_toolset_that_runs_calls_on_its_own(self, toolset: dict[str, Any]) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="always_ask"):
            check_agent_toolset([toolset])

    def test_custom_tools_are_the_clients_to_run(self) -> None:
        check_agent_toolset([{"type": "custom", "name": "run_tests", "input_schema": {}}])

    def test_an_entry_it_cannot_place_is_a_problem(self) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="cannot be checked"):
            check_agent_toolset([{"type": "computer_toolset_20260801"}])

    def test_the_server_echo_shape(self) -> None:
        """``agent.tools`` comes back with resolved defaults and typed configs."""
        echo = _as_object(
            {
                "type": AGENT_TOOLSET_VERSION,
                "default_config": {"enabled": False, "permission_policy": {"type": "always_ask"}},
                "configs": [
                    {
                        "name": tool,
                        "type": tool,
                        "enabled": tool == "read",
                        "permission_policy": {"type": "always_ask"},
                    }
                    for tool in AGENT_TOOLSET_TOOLS
                ],
            }
        )
        check_agent_toolset([echo], allowed_tools={"read"})

    def test_an_echo_that_drifted_to_always_allow_is_caught(self) -> None:
        echo = _as_object(build_agent_toolset({"read"}))
        echo.configs[1].permission_policy.type = "always_allow"  # read
        with pytest.raises(ManagedAgentToolsetError, match="read is enabled under 'always_allow'"):
            check_agent_toolset([echo])

    def test_problems_are_listed_in_the_message(self) -> None:
        with pytest.raises(ManagedAgentToolsetError) as exc:
            check_agent_toolset([{"type": AGENT_TOOLSET_VERSION}])
        assert str(exc.value).count("\n- ") == len(exc.value.problems)


class TestRemotePathPolicy:
    def test_a_path_inside_the_root(self) -> None:
        assert WORKSPACE.check("/workspace/src/app.py") == "/workspace/src/app.py"

    def test_a_relative_path_is_taken_from_the_workdir(self) -> None:
        assert WORKSPACE.check("src/app.py") == "/workspace/src/app.py"

    @pytest.mark.parametrize(
        "path", ["/workspace/../etc/passwd", "../etc/passwd", "//etc/passwd", "/etc/passwd"]
    )
    def test_escapes_are_refused(self, path: str) -> None:
        with pytest.raises(PathValidationError) as exc:
            WORKSPACE.check(path)
        assert exc.value.violation_type == "outside_allowed_roots"
        assert exc.value.details == {"allowed_roots": ["/workspace"]}

    @pytest.mark.parametrize(
        ("path", "violation"),
        [
            ("~/.ssh/id_rsa", "home_relative"),
            ("$HOME/notes", "variable_reference"),
            ("/workspace/$SECRET/x", "variable_reference"),
            ("/workspace\\..\\etc", "invalid_path"),
            ("/workspace/a\x00b", "invalid_path"),
            (" /workspace/a", "invalid_path"),
            ("", "invalid_path"),
            (None, "invalid_path"),
            (["/workspace/a"], "invalid_path"),
            ("/workspace/" + "a" * 5000, "invalid_path"),
        ],
    )
    def test_paths_the_gate_cannot_reason_about(self, path: Any, violation: str) -> None:
        with pytest.raises(PathValidationError) as exc:
            WORKSPACE.check(path)
        assert exc.value.violation_type == violation

    @pytest.mark.parametrize(
        "path",
        [
            "/workspace/.env",
            "/workspace/app/.env.local",
            "/workspace/certs/server.PEM",
            "/workspace/.ssh/id_rsa",
            "/workspace/home/.aws/credentials",
            "/workspace/app/secrets/token",
        ],
    )
    def test_deny_patterns_and_no_pattern_in_the_refusal(self, path: str) -> None:
        with pytest.raises(PathValidationError) as exc:
            WORKSPACE.check(path)
        assert exc.value.violation_type == "denied_pattern"
        assert exc.value.details == {}
        assert "*" not in str(exc.value)

    def test_a_file_can_be_the_root(self) -> None:
        policy = RemotePathPolicy(allowed_roots=("/etc/os-release",))
        assert policy.check("/etc/os-release") == "/etc/os-release"
        for other in ("/etc/os-release2", "/etc/passwd", "/etc"):
            with pytest.raises(PathValidationError):
                policy.check(other)

    def test_the_depth_limit(self) -> None:
        with pytest.raises(PathValidationError) as exc:
            RemotePathPolicy(allowed_roots=("/",), max_path_depth=3).check("/a/b/c/d")
        assert exc.value.violation_type == "max_depth_exceeded"

    def test_checks_are_lexical(self) -> None:
        assert WORKSPACE.check("/workspace/link/../notes.txt") == "/workspace/notes.txt"

    def test_a_bare_string_root_is_one_root_not_its_characters(self) -> None:
        policy = RemotePathPolicy(allowed_roots="/workspace")  # type: ignore[arg-type]
        assert policy.allowed_roots == ("/workspace",)
        with pytest.raises(PathValidationError):
            policy.check("/w")

    @pytest.mark.parametrize("roots", [(), ("workspace",), ("",)])
    def test_bad_roots_are_refused(self, roots: tuple[str, ...]) -> None:
        with pytest.raises(ValueError):
            RemotePathPolicy(allowed_roots=roots)

    def test_it_is_frozen(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            WORKSPACE.workdir = "/"  # type: ignore[misc]


class TestGateConstruction:
    def test_an_unknown_tool(self) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="read_file"):
            ManagedAgentToolGate({"read_file"})

    @pytest.mark.parametrize("tool", ["read", "glob", "grep", "write", "edit"])
    def test_a_path_tool_needs_a_path_policy(self, tool: str) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="path_policy"):
            ManagedAgentToolGate({tool})

    def test_web_fetch_needs_an_endpoint_policy(self) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="endpoint_policy"):
            ManagedAgentToolGate({"web_fetch"})

    def test_write_with_only_a_write_policy(self) -> None:
        ManagedAgentToolGate({"write"}, write_path_policy=WORKSPACE)

    def test_a_wrong_policy_type(self) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="RemotePathPolicy"):
            ManagedAgentToolGate({"read"}, path_policy=object())  # type: ignore[arg-type]

    @pytest.mark.parametrize("pairs", [["github"], [("github",)], [("github", 3)]])
    def test_malformed_mcp_pairs(self, pairs: Any) -> None:
        with pytest.raises(ManagedAgentToolsetError, match="pairs"):
            ManagedAgentToolGate(allowed_mcp_tools=pairs)

    def test_the_toolset_matches_the_gate(self) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        enabled = [c["name"] for c in gate.agent_toolset()["configs"] if c["enabled"]]
        assert enabled == ["read"]


@pytest.mark.parametrize("shape", SHAPES)
class TestReview:
    def test_an_allowed_call_under_ask(self, shape: Callable[..., Any]) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        decision = gate.review(shape(_event()))
        assert decision.allowed and decision.needs_confirmation and decision.enforced
        assert decision.confirmation == {
            "type": "user.tool_confirmation",
            "tool_use_id": "sevt_01",
            "result": "allow",
        }
        assert decision.deny_message is None
        assert decision.checks == ("kill_switch", "tool_known", "allowed_tools", "input")

    def test_a_refused_call_under_ask(self, shape: Callable[..., Any]) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        decision = gate.review(shape(_event(tool_input={"file_path": "/etc/shadow"})))
        assert not decision.allowed
        assert decision.refusal is not None
        assert decision.refusal["block_reason"] == "path_violation"
        confirmation = decision.confirmation
        assert confirmation is not None
        assert confirmation["result"] == "deny"
        assert confirmation["deny_message"] == refusal_text(decision.refusal)
        assert confirmation["deny_message"].startswith("AIRLOCK_BLOCK")
        assert decision.checks[-1] == "input"

    def test_a_tool_not_allowed(self, shape: Callable[..., Any]) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        decision = gate.review(shape(_event("bash", {"command": "ls"})))
        assert not decision.allowed
        assert decision.checks[-1] == "allowed_tools"

    def test_a_tool_the_toolset_does_not_have(self, shape: Callable[..., Any]) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        decision = gate.review(shape(_event("read_file")))
        assert not decision.allowed
        assert decision.checks[-1] == "tool_known"

    def test_a_call_the_server_already_allowed(self, shape: Callable[..., Any]) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        refused = gate.review(
            shape(_event(tool_input={"file_path": "/etc/shadow"}, permission="allow"))
        )
        assert refused.confirmation is None
        assert refused.enforced is False
        allowed = gate.review(shape(_event(permission="allow")))
        assert allowed.confirmation is None and allowed.enforced is True

    def test_a_call_the_server_denied(self, shape: Callable[..., Any]) -> None:
        gate = ManagedAgentToolGate()
        event = _event("bash", {"command": "id"}, permission="deny")
        del event["evaluation"]  # a tool not enabled in the session carries none
        decision = gate.review(shape(event))
        assert decision.confirmation is None
        assert decision.enforced is True

    def test_no_evaluated_permission_means_nothing_to_confirm(
        self, shape: Callable[..., Any]
    ) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        decision = gate.review(shape(_event(permission=None)))
        assert decision.evaluated_permission is None
        assert decision.confirmation is None

    @pytest.mark.parametrize("event_type", ["agent.custom_tool_use", "agent.message", None])
    def test_events_that_cannot_be_confirmed(
        self, shape: Callable[..., Any], event_type: str | None
    ) -> None:
        event = _event()
        event["type"] = event_type
        with pytest.raises(UnreviewableEventError):
            ManagedAgentToolGate().review(shape(event))

    def test_an_event_without_an_id(self, shape: Callable[..., Any]) -> None:
        event = _event()
        del event["id"]
        with pytest.raises(UnreviewableEventError, match="id"):
            ManagedAgentToolGate().review(shape(event))

    def test_the_empty_gate_refuses_everything(self, shape: Callable[..., Any]) -> None:
        gate = ManagedAgentToolGate()
        for tool in AGENT_TOOLSET_TOOLS:
            assert not gate.review(shape(_event(tool, {}))).allowed


class TestFileTools:
    def test_input_that_is_not_an_object(self) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        assert not gate.review(_event(tool_input="/workspace/a")).allowed

    def test_a_read_without_a_path(self) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        assert not gate.review(_event(tool_input={"view_range": [1, 2]})).allowed

    def test_every_path_named_key_is_checked(self) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        decision = gate.review(
            _event(tool_input={"file_path": "/workspace/a", "path": "/etc/passwd"})
        )
        assert not decision.allowed

    def test_a_non_string_path(self) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        assert not gate.review(_event(tool_input={"file_path": 7})).allowed

    def test_write_uses_the_write_policy(self) -> None:
        gate = ManagedAgentToolGate(
            {"read", "write", "edit"},
            path_policy=RemotePathPolicy(allowed_roots=("/workspace",)),
            write_path_policy=RemotePathPolicy(allowed_roots=("/workspace/out",)),
        )
        assert gate.review(_event("read", {"file_path": "/workspace/src/a.py"})).allowed
        assert not gate.review(
            _event("write", {"file_path": "/workspace/src/a.py", "content": "x"})
        ).allowed
        assert gate.review(
            _event("write", {"file_path": "/workspace/out/a", "content": "x"})
        ).allowed
        assert not gate.review(
            _event("edit", {"file_path": "/workspace/a", "old_string": "a", "new_string": "b"})
        ).allowed

    def test_a_long_refusal_is_cut_to_the_limit(self) -> None:
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        decision = gate.review(_event(tool_input={"file_path": "/x/" + "a" * 5000}))
        assert decision.deny_message is not None
        assert len(decision.deny_message) == DENY_MESSAGE_MAX_CHARS


class TestSearchTools:
    @pytest.fixture
    def gate(self) -> ManagedAgentToolGate:
        return ManagedAgentToolGate({"glob", "grep"}, path_policy=WORKSPACE)

    @pytest.mark.parametrize(
        "tool_input",
        [{"pattern": "**/*.py"}, {"pattern": "src/*.py", "path": "/workspace/app"}],
    )
    def test_globs_inside_the_root(self, gate: ManagedAgentToolGate, tool_input: dict) -> None:
        assert gate.review(_event("glob", tool_input)).allowed

    @pytest.mark.parametrize(
        "tool_input",
        [
            {"pattern": "/etc/*"},
            {"pattern": "../*"},
            {"pattern": "**/../../etc/*"},
            {"pattern": "~/*"},
            {"pattern": "$HOME/*"},
            {"pattern": "**/*.env"},
            {"pattern": "**/.ssh/*"},
            {"pattern": "*", "path": "/etc"},
            {"pattern": 3},
            {"pattern": ""},
        ],
    )
    def test_globs_the_gate_refuses(self, gate: ManagedAgentToolGate, tool_input: dict) -> None:
        assert not gate.review(_event("glob", tool_input)).allowed

    def test_a_grep_pattern_is_a_regex_not_a_path(self, gate: ManagedAgentToolGate) -> None:
        assert gate.review(_event("grep", {"pattern": "^def .*$"})).allowed

    def test_a_grep_outside_the_root(self, gate: ManagedAgentToolGate) -> None:
        assert not gate.review(_event("grep", {"pattern": "root", "path": "/etc"})).allowed


class TestWebFetch:
    @pytest.fixture
    def gate(self) -> ManagedAgentToolGate:
        return ManagedAgentToolGate(
            {"web_fetch"}, endpoint_policy=EndpointPolicy(allowed_endpoints=["docs.example.com"])
        )

    def test_an_allowed_host(self, gate: ManagedAgentToolGate) -> None:
        assert gate.review(_event("web_fetch", {"url": "https://docs.example.com/a"})).allowed

    @pytest.mark.parametrize(
        "url",
        [
            "https://evil.example.net/x",
            "file:///etc/passwd",
            "gopher://docs.example.com/",
            "http://169.254.169.254/latest/meta-data",
            "not a url",
        ],
    )
    def test_refused_urls(self, gate: ManagedAgentToolGate, url: str) -> None:
        decision = gate.review(_event("web_fetch", {"url": url}))
        assert not decision.allowed
        assert decision.refusal is not None
        assert decision.refusal["block_reason"] == "endpoint_blocked"

    def test_no_url(self, gate: ManagedAgentToolGate) -> None:
        assert not gate.review(_event("web_fetch", {"query": "x"})).allowed

    def test_a_url_that_is_not_a_string(self, gate: ManagedAgentToolGate) -> None:
        assert not gate.review(_event("web_fetch", {"url": ["https://docs.example.com"]})).allowed


class TestBashAndWebSearch:
    def test_bash_without_a_check_is_refused(self) -> None:
        decision = ManagedAgentToolGate({"bash"}).review(_event("bash", {"command": "ls"}))
        assert not decision.allowed
        assert decision.deny_message is not None and "not parsed" in decision.deny_message

    def test_bash_with_a_check(self) -> None:
        seen: list[str] = []

        def only_ls(command: str) -> bool:
            seen.append(command)
            return command == "ls"

        gate = ManagedAgentToolGate({"bash"}, command_check=only_ls)
        assert gate.review(_event("bash", {"command": "ls"})).allowed
        assert not gate.review(_event("bash", {"command": "rm -rf /"})).allowed
        assert not gate.review(_event("bash", {"restart": True})).allowed
        assert seen == ["ls", "rm -rf /", ""]

    def test_a_truthy_answer_is_not_true(self) -> None:
        gate = ManagedAgentToolGate({"bash"}, command_check=lambda c: 1)  # type: ignore[arg-type,return-value]
        assert not gate.review(_event("bash", {"command": "ls"})).allowed

    def test_a_check_that_raises_refuses(self) -> None:
        def broken(command: str) -> bool:
            raise RuntimeError("boom")

        decision = ManagedAgentToolGate({"bash"}, command_check=broken).review(
            _event("bash", {"command": "ls"})
        )
        assert not decision.allowed
        assert decision.checks[-1] == "error"

    def test_a_non_string_command(self) -> None:
        gate = ManagedAgentToolGate({"bash"}, command_check=lambda c: True)
        assert not gate.review(_event("bash", {"command": ["ls"]})).allowed

    def test_web_search_is_checked_by_name(self) -> None:
        gate = ManagedAgentToolGate({"web_search"})
        assert gate.review(_event("web_search", {"query": "anything"})).allowed


class TestMcpTools:
    def test_an_allowlisted_pair(self) -> None:
        gate = ManagedAgentToolGate(allowed_mcp_tools=[("github", "list_issues")])
        decision = gate.review(
            _event("list_issues", {"repo": "a/b"}, event_type="agent.mcp_tool_use", server="github")
        )
        assert decision.allowed
        assert decision.mcp_server_name == "github"

    @pytest.mark.parametrize(
        ("server", "name"),
        [("github", "merge_pr"), ("gitlab", "list_issues"), (None, "list_issues")],
    )
    def test_anything_else(self, server: str | None, name: str) -> None:
        gate = ManagedAgentToolGate(allowed_mcp_tools=[("github", "list_issues")])
        event = _event(name, {}, event_type="agent.mcp_tool_use", server=server)
        assert not gate.review(event).allowed

    def test_the_policy_sees_the_mcp_name(self) -> None:
        gate = ManagedAgentToolGate(
            allowed_mcp_tools=[("github", "merge_pr")],
            policy=SecurityPolicy(denied_tools=["mcp__github__*"]),
        )
        event = _event("merge_pr", {}, event_type="agent.mcp_tool_use", server="github")
        decision = gate.review(event)
        assert not decision.allowed
        assert decision.checks[-1] == "policy"


class TestKillSwitchAndPolicy:
    def test_a_frozen_fleet_refuses_before_anything_else(self) -> None:
        bus = InMemoryTransport()
        signer = HMACBroadcastSigner(keyid="ops", key=b"k" * 32)
        registry.install(
            KillSwitchListener(signers=(signer,), transport=bus, poll_interval_seconds=0)
        )
        KillSwitchBroadcast(signer=signer, transport=bus).trigger(reason="incident 7")
        gate = ManagedAgentToolGate({"read"}, path_policy=WORKSPACE)
        decision = gate.review(_event())
        assert not decision.allowed
        assert decision.checks == ("kill_switch",)
        assert decision.refusal is not None
        assert decision.refusal["block_reason"] == "kill_switch"
        assert "incident 7" in (decision.deny_message or "")

    def test_a_denied_tool_without_quoting_the_pattern(self) -> None:
        gate = ManagedAgentToolGate(
            {"read"}, path_policy=WORKSPACE, policy=SecurityPolicy(denied_tools=["re*"])
        )
        decision = gate.review(_event())
        assert not decision.allowed
        assert decision.checks[-1] == "policy"
        assert "re*" not in (decision.deny_message or "")

    def test_a_rate_limit(self) -> None:
        gate = ManagedAgentToolGate(
            {"read"}, path_policy=WORKSPACE, policy=SecurityPolicy(rate_limits={"read": "1/hour"})
        )
        assert gate.review(_event()).allowed
        second = gate.review(_event(event_id="sevt_02"))
        assert second.refusal is not None
        assert second.refusal["block_reason"] == "rate_limit"

    def test_an_escalation_is_refused(self) -> None:
        gate = ManagedAgentToolGate(
            {"read"},
            path_policy=WORKSPACE,
            policy=SecurityPolicy(escalate_tools={"read": "a human reads every file read"}),
        )
        assert not gate.review(_event()).allowed


class TestDecision:
    def test_a_decision_is_frozen_and_hashable(self) -> None:
        decision = ToolUseDecision("sevt_1", "read", "agent.tool_use", "ask", True)
        hash(decision)
        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.allowed = False  # type: ignore[misc]

    def test_the_deny_message_never_carries_metadata(self) -> None:
        refusal = {
            "success": False,
            "status": "blocked",
            "error": "AIRLOCK_BLOCK: no",
            "metadata": {"resolved_path": "/root/.ssh/id_rsa"},
        }
        decision = ToolUseDecision(
            "sevt_1", "read", "agent.tool_use", "ask", False, refusal=refusal
        )
        assert decision.deny_message == "AIRLOCK_BLOCK: no"


class TestLegacyAudit:
    """``audit_managed_agent_invocation`` still works, and says it never gated a real call."""

    def _request(self, tool: str = "read") -> dict[str, Any]:
        return {
            "tool": tool,
            "betas": [MANAGED_AGENTS_BETA_HEADER],
            "toolset_version": AGENT_TOOLSET_VERSION,
        }

    def test_it_warns(self) -> None:
        with pytest.warns(FutureWarning, match="ManagedAgentToolGate"):
            audit_managed_agent_invocation(self._request(), ManagedAgentsAuditConfig(("read",)))

    def test_it_still_blocks(self) -> None:
        with pytest.warns(FutureWarning), pytest.raises(ManagedAgentToolBlocked):
            audit_managed_agent_invocation(
                self._request("bash"), ManagedAgentsAuditConfig(("read",))
            )
        request = self._request()
        request["betas"] = []
        with pytest.warns(FutureWarning), pytest.raises(ManagedAgentBetaHeaderMissingError):
            audit_managed_agent_invocation(request, ManagedAgentsAuditConfig(("read",)))
        request = self._request()
        request["toolset_version"] = "agent_toolset_99999999"
        with pytest.warns(FutureWarning), pytest.raises(UnknownToolsetVersionError):
            audit_managed_agent_invocation(request, ManagedAgentsAuditConfig(("read",)))

    def test_the_session_counter(self) -> None:
        session = ManagedAgentSession(session_id="s-1")
        with pytest.warns(FutureWarning):
            audit_managed_agent_invocation(
                self._request(), ManagedAgentsAuditConfig(("read",)), session=session
            )
        assert session.invocations == 1

    def test_building_the_config_does_not_warn(self) -> None:
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            ManagedAgentsAuditConfig()

    def test_sse_redaction(self) -> None:
        frame = 'data: {"output": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"}'
        assert "eyJhbGciOiJIUzI1NiJ9.payload.signature" not in redact_sse_event(frame)
        assert redact_sse_event('data: {"output": "Hello"}') == 'data: {"output": "Hello"}'


class TestPreset:
    def test_the_preset_gate_refuses_everything(self) -> None:
        cfg = claude_managed_agents_safe_defaults()
        assert isinstance(cfg["gate"], ManagedAgentToolGate)
        for tool in AGENT_TOOLSET_TOOLS:
            assert not cfg["gate"].review(_event(tool, {})).allowed

    def test_the_preset_toolset_enables_nothing_and_passes_the_check(self) -> None:
        cfg = claude_managed_agents_safe_defaults()
        assert not any(c["enabled"] for c in cfg["agent_toolset"]["configs"])
        check_agent_toolset([cfg["agent_toolset"]])

    def test_the_rest_of_the_mapping(self) -> None:
        cfg = claude_managed_agents_safe_defaults()
        assert cfg["toolset_tools"] == AGENT_TOOLSET_TOOLS
        assert cfg["harness_tools"] == AGENT_TOOLSET_TOOLS
        assert cfg["beta_header"] == MANAGED_AGENTS_BETA_HEADER
        assert cfg["toolset_version"] == AGENT_TOOLSET_VERSION
        assert cfg["source"] == "https://platform.claude.com/docs/en/managed-agents/tools"
        assert cfg["audit_config"].allowed_tools == ()

    def test_each_call_is_independent(self) -> None:
        first = claude_managed_agents_safe_defaults()
        mutated = copy.deepcopy(first["agent_toolset"])
        first["agent_toolset"]["configs"][0]["enabled"] = True
        assert claude_managed_agents_safe_defaults()["agent_toolset"] != first["agent_toolset"]
        assert mutated["configs"][0]["enabled"] is False


class TestExportsAndErrors:
    @pytest.mark.parametrize(
        "name",
        [
            "ManagedAgentToolGate",
            "ManagedAgentToolsetError",
            "RemotePathPolicy",
            "ToolUseDecision",
            "UnreviewableEventError",
            "ManagedAgentToolBlocked",
            "ManagedAgentBetaHeaderMissingError",
            "UnknownToolsetVersionError",
        ],
    )
    def test_top_level_exports(self, name: str) -> None:
        assert name in agent_airlock.__all__
        assert getattr(agent_airlock, name) is not None

    @pytest.mark.parametrize(
        "err",
        [
            ManagedAgentToolsetError,
            UnreviewableEventError,
            ManagedAgentBetaHeaderMissingError,
            ManagedAgentToolBlocked,
            UnknownToolsetVersionError,
        ],
    )
    def test_subclasses_airlock_error(self, err: type[Exception]) -> None:
        assert issubclass(err, AirlockError)

    def test_the_managed_sandbox_backend_points_to_the_gate(self) -> None:
        result = ManagedSandboxBackend().execute(lambda: None, (), {})
        assert result.error is not None
        assert "ManagedAgentToolGate" in result.error
        assert "examples/anthropic_integration.py" in result.error
