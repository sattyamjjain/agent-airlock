"""0.10.29: a permission-prompt tool for ``claude -p --permission-prompt-tool``.

Raised in anthropics/claude-code#99813: ``--permission-prompt-tool`` lets a headless run
hand each permission decision to an MCP tool. The shapes were read off Claude Code 2.1.316
by running it against a probe server: the tool is called with ``{"tool_name", "input",
"tool_use_id"}``; it answers with one text block holding ``{"behavior": "allow",
"updatedInput": ...}`` or ``{"behavior": "deny", "message": ...}``; ``"interrupt": true``
ends the run; and an answer that also carries ``structuredContent`` is refused as invalid.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import types
from collections.abc import Iterator
from typing import Any

import pytest

from agent_airlock.approvals import args_digest
from agent_airlock.kill_switch import (
    HMACBroadcastSigner,
    InMemoryTransport,
    KillSwitchBroadcast,
    KillSwitchListener,
    registry,
)
from agent_airlock.mcp.permission_prompt import TOOL_NAME, decide, permission_prompt_server
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict
from agent_airlock.policy import AgentIdentity, SecurityPolicy

COMMAND = {"command": "rm -rf build", "description": "Remove the build directory"}
# Assembled, so no secret scanner files this module.
SECRET = "sk-proj-" + "FAKEFAKEFAKEFAKEFAKE1234"


def _decide(policy: SecurityPolicy, tool: Any = "Bash", tool_input: Any = None, **kw: Any) -> Any:
    tool_use_id = kw.pop("tool_use_id", "toolu_1")
    request_input = dict(COMMAND) if tool_input is None else tool_input
    return asyncio.run(decide(policy, tool, request_input, tool_use_id, **kw))


def _denied(answer: dict[str, Any]) -> bool:
    return answer["behavior"] == "deny" and answer["message"].startswith("AIRLOCK_BLOCK")


class TestDecisions:
    def test_an_allowed_tool_runs_with_its_input(self) -> None:
        assert _decide(SecurityPolicy()) == {"behavior": "allow", "updatedInput": COMMAND}

    def test_a_denied_tool_is_denied_and_the_run_goes_on(self) -> None:
        answer = _decide(SecurityPolicy(denied_tools=["Bash"]))
        assert _denied(answer) and "interrupt" not in answer

    def test_a_tool_outside_the_allowlist_is_denied(self) -> None:
        policy = SecurityPolicy(allowed_tools=["Read", "mcp__github__*"])
        assert _denied(_decide(policy, "Bash"))
        assert _decide(policy, "mcp__github__get_issue", {})["behavior"] == "allow"

    def test_each_prompt_spends_a_rate_limit_token(self) -> None:
        policy = SecurityPolicy(rate_limits={"Bash": "1/hour"})
        assert _decide(policy)["behavior"] == "allow"
        assert _denied(_decide(policy))

    def test_an_identity_the_policy_requires_is_the_servers(self) -> None:
        policy = SecurityPolicy(require_agent_id=True)
        assert _denied(_decide(policy))  # a request from Claude Code names no agent
        assert _decide(policy, agent=AgentIdentity(agent_id="ci"))["behavior"] == "allow"


class _Approver:
    """Records each request and answers it as told."""

    def __init__(self, verdict: Any = OversightVerdict.GRANT, **how: Any) -> None:
        self.verdict, self.how = verdict, how
        self.requests: list[OversightRequest] = []

    def __call__(self, request: OversightRequest) -> Any:
        self.requests.append(request)
        if "raises" in self.how:
            raise self.how["raises"]
        time.sleep(self.how.get("delay", 0.0))
        if "answer" in self.how:
            return self.how["answer"]
        request_id = request.request_id if self.how.get("echo", True) else "another"
        return OversightResponse(request_id=request_id, verdict=self.verdict, approver="alice")


def _escalating(approver: Any = None, **kw: Any) -> SecurityPolicy:
    rules = {"escalate_tools": {"Bash": "runs shell commands"}, "approver": approver}
    return SecurityPolicy(**rules, **kw)


class TestEscalations:
    def test_a_granting_approver_allows_and_sees_the_call(self) -> None:
        approver = _Approver()
        assert _decide(_escalating(approver)) == {"behavior": "allow", "updatedInput": COMMAND}
        (request,) = approver.requests
        assert request.tool_name == "Bash"
        assert request.args_digest == args_digest(COMMAND)
        assert "rm -rf build" in request.args_preview["command"]
        assert request.args["tool_use_id"] == "toolu_1" and "tool_input" not in request.args

    def test_a_denying_approver_denies(self) -> None:
        assert _denied(_decide(_escalating(_Approver(OversightVerdict.DENY))))

    def test_the_request_shows_the_input_masked(self) -> None:
        approver = _Approver()
        command = {"command": f"curl -H 'Authorization: Bearer {SECRET}' https://api.example"}
        _decide(_escalating(approver), tool_input=command)
        (request,) = approver.requests
        assert request.args_digest == args_digest(command)
        assert SECRET not in repr(request)

    def test_a_grant_of_other_input_denies(self) -> None:
        approver = _Approver()

        def grant_other(request: OversightRequest) -> OversightResponse:
            approver(request)
            return OversightResponse(
                request.request_id, OversightVerdict.GRANT, args_digest="0" * 64
            )

        assert _denied(_decide(_escalating(grant_other)))
        echoed = _Approver()

        def grant_this(request: OversightRequest) -> OversightResponse:
            echoed(request)
            return OversightResponse(
                request.request_id, OversightVerdict.GRANT, args_digest=request.args_digest
            )

        assert _decide(_escalating(grant_this))["behavior"] == "allow"

    def test_input_that_cannot_be_bound_is_denied_without_asking(self) -> None:
        approver = _Approver()
        loop: list[Any] = []
        loop.append(loop)
        assert _denied(_decide(_escalating(approver), tool_input={"items": loop}))
        assert approver.requests == []

    def test_a_denied_escalation_spends_no_rate_token(self) -> None:
        verdicts = iter([OversightVerdict.DENY, OversightVerdict.GRANT, OversightVerdict.GRANT])

        def approver(request: OversightRequest) -> OversightResponse:
            return OversightResponse(request.request_id, next(verdicts))

        policy = _escalating(approver, rate_limits={"Bash": "1/hour"})
        assert _denied(_decide(policy))
        assert _decide(policy)["behavior"] == "allow"
        assert _denied(_decide(policy))  # the one token is spent now

    def test_with_no_approver_it_fails_closed(self) -> None:
        assert _denied(_decide(_escalating()))

    def test_an_approver_that_raises_denies(self) -> None:
        assert _denied(_decide(_escalating(_Approver(raises=RuntimeError("slack is down")))))

    def test_an_answer_to_another_request_denies(self) -> None:
        assert _denied(_decide(_escalating(_Approver(echo=False))))

    def test_an_answer_that_is_not_a_grant_denies(self) -> None:
        for answer in ("grant", None, {"verdict": "grant"}):
            assert _denied(_decide(_escalating(_Approver(answer=answer))))
        # The verdict as a plain string equals the enum member but is not it.
        assert _denied(_decide(_escalating(_Approver(verdict="grant"))))

    def test_a_timeout_verdict_denies(self) -> None:
        answer = _decide(_escalating(_Approver(OversightVerdict.TIMEOUT)))
        assert _denied(answer) and "timed out" in answer["message"]

    def test_an_approver_past_its_deadline_denies(self) -> None:
        policy = _escalating(_Approver(delay=0.5), escalation_timeout_seconds=0.05)

        async def timed() -> tuple[Any, float]:
            started = time.monotonic()  # asyncio.run then waits for the approver's thread
            answer = await decide(policy, "Bash", dict(COMMAND), "toolu_1")
            return answer, time.monotonic() - started

        answer, took = asyncio.run(timed())
        assert _denied(answer) and "timed out" in answer["message"]
        assert "0.05 seconds" in answer["message"] and took < 0.45

    def test_an_async_approver_is_awaited(self) -> None:
        async def approver(request: OversightRequest) -> OversightResponse:
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)

        assert _decide(_escalating(approver))["behavior"] == "allow"

    def test_a_refused_call_is_never_put_to_the_approver(self) -> None:
        approver = _Approver()
        assert _denied(_decide(_escalating(approver, denied_tools=["Bash"])))
        assert approver.requests == []


class TestMalformedRequests:
    @pytest.mark.parametrize(
        ("tool", "tool_input", "tool_use_id"),
        [
            (None, {}, "toolu_1"),
            ("", {}, "toolu_1"),
            (7, {}, "toolu_1"),
            ("Bash", None, "toolu_1"),
            ("Bash", ["ls"], "toolu_1"),
            ("Bash", "ls", "toolu_1"),
            ("Bash", {}, 5),
        ],
    )
    def test_it_is_denied(self, tool: Any, tool_input: Any, tool_use_id: Any) -> None:
        answer = asyncio.run(decide(SecurityPolicy(), tool, tool_input, tool_use_id))
        assert _denied(answer) and "malformed" in answer["message"]


@pytest.fixture
def frozen() -> Iterator[None]:
    """The real kill switch, engaged through a signed broadcast."""
    registry.clear()
    bus = InMemoryTransport()
    signer = HMACBroadcastSigner(keyid="ops-a", key=b"a" * 32)
    listener = KillSwitchListener(signers=(signer,), transport=bus, poll_interval_seconds=0)
    registry.install(listener)
    KillSwitchBroadcast(signer=signer, transport=bus).trigger(reason="incident 42")
    yield
    registry.clear()


class TestKillSwitch:
    def test_a_freeze_denies_everything_and_ends_the_run(self, frozen: None) -> None:
        answer = _decide(SecurityPolicy(), "Read", {"file_path": "README.md"})
        assert _denied(answer) and answer["interrupt"] is True
        assert "incident 42" in answer["message"]

    def test_a_freeze_comes_before_the_approver(self, frozen: None) -> None:
        approver = _Approver()
        assert _decide(_escalating(approver))["interrupt"] is True and approver.requests == []


@pytest.fixture
def fastmcp() -> Any:
    return pytest.importorskip("fastmcp")


def _call(server: Any, arguments: dict[str, Any]) -> Any:
    from fastmcp import Client

    async def call() -> Any:
        async with Client(server) as client:
            return await client.call_tool(TOOL_NAME, arguments)

    return asyncio.run(call())


class TestTheServer:
    def test_it_has_one_tool_with_no_output_schema(self, fastmcp: Any) -> None:
        server = permission_prompt_server(SecurityPolicy(), name="gate")

        async def tools() -> Any:
            async with fastmcp.Client(server) as client:
                return await client.list_tools()

        (tool,) = asyncio.run(tools())
        assert tool.name == "permission_prompt" and server.name == "gate"
        assert getattr(tool, "output_schema", None) is None

    def test_an_answer_is_one_text_block_of_json(self, fastmcp: Any) -> None:
        server = permission_prompt_server(SecurityPolicy(denied_tools=["Bash"]))
        result = _call(server, {"tool_name": "Bash", "input": COMMAND, "tool_use_id": "t"})
        (block,) = result.content
        assert block.type == "text" and result.structured_content is None
        assert _denied(json.loads(block.text))

    def test_a_malformed_call_is_answered_not_failed(self, fastmcp: Any) -> None:
        result = _call(permission_prompt_server(SecurityPolicy()), {"tool_name": 5})
        assert "malformed" in json.loads(result.content[0].text)["message"]

    def test_the_servers_identity_reaches_the_policy(self, fastmcp: Any) -> None:
        policy = SecurityPolicy(require_agent_id=True)
        server = permission_prompt_server(policy, agent=AgentIdentity(agent_id="ci"))
        result = _call(server, {"tool_name": "Read", "input": {}, "tool_use_id": "t"})
        assert json.loads(result.content[0].text)["behavior"] == "allow"


class TestWithoutTheExtra:
    def test_without_fastmcp_it_says_what_to_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "fastmcp", None)
        with pytest.raises(ImportError, match=r"agent-airlock\[mcp\]"):
            permission_prompt_server(SecurityPolicy())

    def test_a_fastmcp_with_no_output_schema_still_registers_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        registered: dict[str, Any] = {}

        class OldFastMCP:  # before 2.10: tool(name=..., description=...) -> decorator
            def __init__(self, name: str) -> None:
                self.name = name

            def tool(self, name: str | None = None, description: str | None = None) -> Any:
                return lambda fn: registered.setdefault(name or fn.__name__, fn)

        monkeypatch.setitem(sys.modules, "fastmcp", types.SimpleNamespace(FastMCP=OldFastMCP))
        permission_prompt_server(SecurityPolicy())
        answer = asyncio.run(registered["permission_prompt"]("Read", {}, "t"))
        assert json.loads(answer)["behavior"] == "allow"
