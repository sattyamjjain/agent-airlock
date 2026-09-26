"""The identity a policy judges an ``@Airlock`` call by.

``SecurityPolicy.check(tool, agent=...)`` enforces ``require_agent_id`` and
``allowed_roles``, but ``@Airlock`` called it with no agent at all. So until 0.10.13 a
``require_agent_id`` policy, ``STRICT_POLICY`` among them, refused every call, however the
caller identified itself, and an ``allowed_roles`` policy let every call through, because
the role check was skipped when there was no agent. The policy tests only ever called
``check`` directly, with an agent, so neither showed.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agent_airlock import Airlock
from agent_airlock.context import AirlockContext
from agent_airlock.policy import (
    STRICT_POLICY,
    AgentIdentity,
    PolicyViolation,
    SecurityPolicy,
)


def _caller(agent_id: str, *roles: str) -> SimpleNamespace:
    """A framework context object, as the tool's first argument (``ctx.context``)."""
    return SimpleNamespace(context=SimpleNamespace(agent_id=agent_id, roles=list(roles)))


def _refused(result: Any) -> bool:
    return isinstance(result, dict) and result.get("status") == "blocked"


class TestAllowedRolesThroughAirlock:
    @pytest.fixture
    def delete(self) -> Any:
        @Airlock(policy=SecurityPolicy(allowed_roles=["admin"]))
        def delete_records(ctx: Any, table: str) -> str:
            return f"deleted {table}"

        return delete_records

    def test_a_caller_without_an_allowed_role_is_refused(self, delete: Any) -> None:
        result = delete(_caller("a1", "guest"), table="users")

        assert _refused(result)
        assert "required role" in result["error"]

    def test_a_caller_with_no_identity_is_refused(self, delete: Any) -> None:
        assert _refused(delete(None, table="users"))

    def test_a_caller_with_an_allowed_role_runs(self, delete: Any) -> None:
        assert delete(_caller("a2", "admin"), table="users") == "deleted users"

    async def test_an_async_tool_checks_roles_too(self) -> None:
        async def delete_records(ctx: Any, table: str) -> str:
            return f"deleted {table}"

        guarded: Any = Airlock(policy=SecurityPolicy(allowed_roles=["admin"]))(delete_records)

        assert _refused(await guarded(_caller("a1", "guest"), table="users"))
        assert await guarded(_caller("a2", "admin"), table="users") == "deleted users"


class TestRequireAgentIdThroughAirlock:
    def test_an_identified_caller_runs(self) -> None:
        @Airlock(policy=SecurityPolicy(require_agent_id=True))
        def read(ctx: Any, key: str) -> str:
            return f"read {key}"

        assert read(_caller("a1"), key="k") == "read k"
        assert _refused(read(None, key="k"))

    def test_strict_policy_runs_for_an_identified_caller(self) -> None:
        @Airlock(policy=STRICT_POLICY)
        def read(ctx: Any, key: str) -> str:
            return f"read {key}"

        assert read(_caller("a1"), key="k") == "read k"


class TestIdentitySetAroundTheCall:
    """A framework that passes the tool no context object leaves the host to set one."""

    @pytest.fixture
    def export(self) -> Any:
        @Airlock(policy=SecurityPolicy(allowed_roles=["admin"]))
        def export_report(name: str) -> str:
            return f"exported {name}"

        return export_report

    def test_a_host_context_supplies_the_identity(self, export: Any) -> None:
        with AirlockContext(agent_id="host-agent", roles=["admin"]):
            assert export(name="q3") == "exported q3"

        assert _refused(export(name="q3"))

    async def test_async_with_supplies_it_to_an_async_tool(self) -> None:
        async def export_report(name: str) -> str:
            return f"exported {name}"

        guarded: Any = Airlock(policy=SecurityPolicy(allowed_roles=["admin"]))(export_report)

        async with AirlockContext(agent_id="host-agent", roles=["admin"]):
            assert await guarded(name="q3") == "exported q3"

    def test_strict_policy_runs_inside_a_host_context(self) -> None:
        # The docs/guide/policy.md STRICT_POLICY example.
        @Airlock(policy=STRICT_POLICY)
        def my_tool(x: int) -> int:
            return x

        with AirlockContext(agent_id="agent-1"):
            assert my_tool(x=1) == 1
        assert _refused(my_tool(x=1))

    def test_the_calls_own_context_comes_first(self) -> None:
        @Airlock(policy=SecurityPolicy(allowed_roles=["admin"]))
        def delete_records(ctx: Any, table: str) -> str:
            return f"deleted {table}"

        with AirlockContext(agent_id="host-agent", roles=["admin"]):
            assert _refused(delete_records(_caller("a1", "guest"), table="users"))


class TestPolicyCheck:
    def test_allowed_roles_refuses_a_caller_with_no_identity(self) -> None:
        policy = SecurityPolicy(allowed_roles=["admin"])

        with pytest.raises(PolicyViolation) as exc_info:
            policy.check("any_tool", agent=None)

        assert exc_info.value.violation_type == "role_required"
        policy.check("any_tool", agent=AgentIdentity(agent_id="a1", roles=["admin"]))
