"""0.10.26: the call path reads what the root ``CLAUDE.md`` says it reads.

The ``/init`` drift audit of the call-flow section against ``core.py`` found four places
where the documented behaviour held only in part, each reproduced before it was fixed:

- A top-level string argument was a path by its key name, a leading separator, a drive
  prefix, a separator anywhere or a file extension, but not by the home-relative or
  parent-traversing shape the nested walk (``_looks_like_nested_path``) already read. A
  bare ``~`` or ``..`` under a parameter not named like a path never reached the filesystem
  gate, while the same value inside a list did, and a tool that calls
  ``os.path.expanduser`` on it reads the real home directory.
- ``@requires`` placed above ``@Airlock`` set its attribute on the wrapper ``@Airlock``
  returned, but the capability gate read the undecorated tool, so the requirement was never
  checked and the tool ran. Both orders are read now, and the requirements found along the
  whole ``__wrapped__`` chain are combined instead of the first one winning.
- A run marked with ``with AirlockContext(session_id=...)`` and no agent id gave its calls
  no session id (the ambient context was inherited only together with an agent id), so the
  per-run amplification ledger folded every such run into one anonymous key. The run ids
  now follow the rule ``_run_context`` applies.
- The endpoint gate refused an argument it could not read with ``Endpoint blocked:
  unknown`` and a hint about a URL that was never found. It now says what the filesystem
  and deserialization gates say for the same input.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import (
    Airlock,
    AirlockConfig,
    AirlockContext,
    Capability,
    CapabilityPolicy,
    EndpointPolicy,
    FilesystemPolicy,
    SecurityPolicy,
    get_current_context,
    requires,
)
from agent_airlock.amplification import AmplificationBudget
from agent_airlock.capabilities import get_required_capabilities
from agent_airlock.core import _looks_like_path

CALLS: list[str] = []


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """An allowed root holding the working directory, and a home outside it."""
    root = tmp_path / "root"
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(root)
    CALLS.clear()
    return {"root": root, "home": home}


def _refusal(result: Any) -> str | None:
    return result["block_reason"] if isinstance(result, dict) and not result["success"] else None


class TestTopLevelPathShape:
    def _tool(self, root: Path) -> Any:
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[root]), enable_audit_log=False
        )

        @Airlock(config=config)
        def read_note(label: str) -> str:
            """``label`` is not named like a path; the tool expands it anyway."""
            CALLS.append(os.path.expanduser(label))
            return "ran"

        return read_note

    @pytest.mark.parametrize("value", ["~", "..", "~/secrets", "../secrets"])
    def test_a_home_relative_or_traversing_value_reaches_the_gate(
        self, layout: dict[str, Path], value: str
    ) -> None:
        assert _refusal(self._tool(layout["root"])(label=value)) == "path_violation"
        assert CALLS == []

    def test_the_same_value_nested_was_already_refused(self, layout: dict[str, Path]) -> None:
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[layout["root"]]),
            enable_audit_log=False,
        )

        @Airlock(config=config)
        def read_many(labels: list[str]) -> int:
            return len(labels)

        assert _refusal(read_many(labels=["~"])) == "path_violation"

    def test_a_value_with_no_path_shape_still_runs(self, layout: dict[str, Path]) -> None:
        assert self._tool(layout["root"])(label="weekly notes") == "ran"

    def test_free_text_approximations_are_not_paths(self) -> None:
        assert _looks_like_path("label", "~5") is False
        assert _looks_like_path("label", "~ 10 minutes") is False
        assert _looks_like_path("label", "a..b") is False
        assert _looks_like_path("label", "~") is True
        assert _looks_like_path("label", "..") is True

    def test_without_a_filesystem_policy_nothing_is_gated(self) -> None:
        @Airlock(config=AirlockConfig(enable_audit_log=False))
        def echo(label: str) -> str:
            return label

        assert echo(label="~") == "~"


def _capability_config(*, grant: bool) -> AirlockConfig:
    policy = CapabilityPolicy(
        granted=Capability.NETWORK_HTTPS if grant else Capability.NONE,
        denied=Capability.NONE if grant else Capability.NETWORK_HTTPS,
    )
    return AirlockConfig(capability_policy=policy, enable_audit_log=False)


class TestRequiresAboveAirlock:
    def test_a_requirement_above_airlock_is_enforced(self) -> None:
        @requires(Capability.NETWORK_HTTPS)
        @Airlock(config=_capability_config(grant=False))
        def fetch(url: str) -> str:
            return "ran"

        assert _refusal(fetch(url="https://example.com")) == "capability_denied"

    def test_a_requirement_below_airlock_is_still_enforced(self) -> None:
        @Airlock(config=_capability_config(grant=False))
        @requires(Capability.NETWORK_HTTPS)
        def fetch(url: str) -> str:
            return "ran"

        assert _refusal(fetch(url="https://example.com")) == "capability_denied"

    def test_a_granted_requirement_above_airlock_runs(self) -> None:
        @requires(Capability.NETWORK_HTTPS)
        @Airlock(config=_capability_config(grant=True))
        def fetch(url: str) -> str:
            return "ran"

        assert fetch(url="https://example.com") == "ran"

    async def test_an_async_tool_above_is_enforced_too(self) -> None:
        @requires(Capability.NETWORK_HTTPS)
        @Airlock(config=_capability_config(grant=False))
        async def fetch(url: str) -> str:
            return "ran"

        assert _refusal(await fetch(url="https://example.com")) == "capability_denied"

    def test_requirements_along_the_chain_are_combined(self) -> None:
        policy = CapabilityPolicy(
            granted=Capability.NETWORK_HTTPS, denied=Capability.FILESYSTEM_WRITE
        )

        @requires(Capability.NETWORK_HTTPS)
        @Airlock(config=AirlockConfig(capability_policy=policy, enable_audit_log=False))
        @requires(Capability.FILESYSTEM_WRITE)
        def upload(path: str, url: str) -> str:
            return "ran"

        assert get_required_capabilities(upload) == (
            Capability.NETWORK_HTTPS | Capability.FILESYSTEM_WRITE
        )
        assert _refusal(upload(path="notes.txt", url="https://example.com")) == (
            "capability_denied"
        )


class _Carrier:
    """A framework run wrapper whose ``.context`` names the calling agent."""

    def __init__(self, context: AirlockContext[Any]) -> None:
        self.context = context


class TestSessionOnlyRun:
    @pytest.fixture
    def tool(self) -> Any:
        budget = AmplificationBudget(max_calls_per_run=1)

        @Airlock(
            policy=SecurityPolicy(amplification_budget=budget),
            config=AirlockConfig(enable_audit_log=False),
        )
        def step() -> str:
            context = get_current_context()
            assert context is not None
            return context.session_id or "<none>"

        return step

    def test_each_session_only_run_keeps_its_own_ledger(self, tool: Any) -> None:
        with AirlockContext(session_id="run-A"):
            assert tool() == "run-A"
            assert _refusal(tool()) == "amplification_exceeded"
        with AirlockContext(session_id="run-B"):
            # Until 0.10.26 this call was refused: both runs shared the anonymous ledger.
            assert tool() == "run-B"

    def test_a_call_with_its_own_agent_joins_an_agentless_run(self) -> None:
        @Airlock(config=AirlockConfig(enable_audit_log=False))
        def whoami(run: Any) -> tuple[str | None, str | None]:
            context = get_current_context()
            assert context is not None
            return context.agent_id, context.session_id

        with AirlockContext(session_id="run-S", workspace_id="ws-1"):
            assert whoami(_Carrier(AirlockContext(agent_id="me"))) == ("me", "run-S")

    def test_another_agents_run_is_not_inherited(self) -> None:
        @Airlock(config=AirlockConfig(enable_audit_log=False))
        def whoami(run: Any) -> tuple[str | None, str | None]:
            context = get_current_context()
            assert context is not None
            return context.agent_id, context.session_id

        with AirlockContext(agent_id="other", session_id="run-other"):
            assert whoami(_Carrier(AirlockContext(agent_id="me"))) == ("me", None)

    def test_identity_still_needs_an_ambient_agent_id(self) -> None:
        @Airlock(config=AirlockConfig(enable_audit_log=False))
        def whoami() -> tuple[str | None, list[str]]:
            context = get_current_context()
            assert context is not None
            return context.agent_id, list(context.roles)

        with AirlockContext(session_id="run-S", roles=["admin"]):
            assert whoami() == (None, [])
        with AirlockContext(agent_id="ag", session_id="run-S", roles=["admin"]):
            assert whoami() == ("ag", ["admin"])


class TestEndpointGateUninspectableWording:
    @pytest.fixture
    def fetch(self) -> Any:
        config = AirlockConfig(
            endpoint_policies={"fetch": EndpointPolicy(allowed_endpoints=["api.example.com"])},
            enable_audit_log=False,
        )

        @Airlock(config=config)
        def fetch(urls: list[Any]) -> int:
            return len(urls)

        return fetch

    def test_the_refusal_says_what_could_not_be_read(self, fetch: Any) -> None:
        urls: list[Any] = ["https://api.example.com/x"]
        urls.append(urls)

        result = fetch(urls=urls)

        assert result["block_reason"] == "endpoint_blocked"
        # The walk names where it stopped (``urls[1]`` is the element that is the list).
        assert (
            "could not check argument 'urls[1]': the container contains itself" in (result["error"])
        )
        assert "unknown" not in result["error"]
        hints = "\n".join(result["fix_hints"])
        assert "nested too deeply or contains itself" in hints
        assert "Allowed endpoints for this tool: api.example.com" in hints
        assert result["metadata"]["block_reason"].startswith("uninspectable_argument")
        assert result["metadata"]["argument"] == "urls[1]"

    def test_controls(self, fetch: Any) -> None:
        assert fetch(urls=["https://api.example.com/x"]) == 1
        refused = fetch(urls=["https://evil.example/x"])
        assert refused["block_reason"] == "endpoint_blocked"
        assert "evil.example" in refused["error"]
