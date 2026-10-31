"""0.10.29: an empty allowlist that allows every tool says so, once per policy.

Raised in DataZooDE/erpl-adt#50 ("Failing closed on an unconfigured deployment is what
protects the self-hosters who never read the flag"), raknor-ai/agent-governance-standard#3
("agent-airlock fails a1 and a2 as it ships today") and langchain-ai/langgraph#8817. With the
default ``default_deny=False`` an empty ``allowed_tools`` allows every tool, and nothing said
so: ``PERMISSIVE_POLICY`` was an empty ``SecurityPolicy()``, and ``STRICT_POLICY`` has no
allowlist. This is the non-breaking half: a ``FutureWarning`` once per policy instance, and
``PERMISSIVE_POLICY = SecurityPolicy(allowed_tools=["*"])``, which allows the same tools.
Flipping the default is the 0.11.0 half (decision D3).
"""

from __future__ import annotations

import warnings

import pytest

from agent_airlock import Airlock
from agent_airlock.policy import PERMISSIVE_POLICY, PolicyViolation, SecurityPolicy

_MESSAGE = "empty allowed_tools and default_deny=False"


def _caught(policy: SecurityPolicy, *tools: str) -> list[warnings.WarningMessage]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for tool in tools:
            policy.check_tool_allowed(tool)
    return [
        w for w in caught if issubclass(w.category, FutureWarning) and _MESSAGE in str(w.message)
    ]


class TestEmptyAllowlistWarning:
    def test_warns_once_per_policy(self) -> None:
        assert len(_caught(SecurityPolicy(), "read_file", "write_file", "read_file")) == 1

    def test_each_instance_warns_once(self) -> None:
        assert len(_caught(SecurityPolicy(), "a")) == 1
        assert len(_caught(SecurityPolicy(), "a")) == 1

    def test_the_message_names_both_ways_out(self) -> None:
        (warning,) = _caught(SecurityPolicy(), "tool")
        text = str(warning.message)
        assert "allowed_tools=['*']" in text
        assert "default_deny=True" in text

    def test_the_tool_is_still_allowed(self) -> None:
        """Non-breaking: the warning changes nothing about what runs."""
        with pytest.warns(FutureWarning, match=_MESSAGE):
            SecurityPolicy().check_tool_allowed("anything")

    def test_through_the_decorator(self) -> None:
        @Airlock(policy=SecurityPolicy())
        def tool() -> str:
            return "ran"

        with pytest.warns(FutureWarning, match=_MESSAGE):
            assert tool() == "ran"


class TestNoWarning:
    @pytest.mark.parametrize(
        "policy",
        [
            SecurityPolicy(allowed_tools=["*"]),
            SecurityPolicy(allowed_tools=["read_*"]),
            SecurityPolicy(allowed_tools=["*"], default_deny=True),
        ],
        ids=["wildcard", "listed", "wildcard-default-deny"],
    )
    def test_an_allowlist_that_says_what_it_allows_is_quiet(self, policy: SecurityPolicy) -> None:
        assert _caught(policy, "read_file") == []

    def test_default_deny_is_quiet_and_refuses(self) -> None:
        policy = SecurityPolicy(default_deny=True)
        with warnings.catch_warnings():
            warnings.simplefilter("error", FutureWarning)
            with pytest.raises(PolicyViolation):
                policy.check_tool_allowed("read_file")

    def test_permissive_policy_allows_every_tool_quietly(self) -> None:
        assert PERMISSIVE_POLICY.allowed_tools == ["*"]
        assert _caught(PERMISSIVE_POLICY, "read_file", "rm_rf", "anything") == []

    def test_a_denied_tool_is_refused_before_the_warning(self) -> None:
        policy = SecurityPolicy(denied_tools=["rm_*"])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with pytest.raises(PolicyViolation):
                policy.check_tool_allowed("rm_rf")
        assert not [w for w in caught if _MESSAGE in str(w.message)]

    def test_the_warning_flag_is_not_part_of_the_frozen_digest(self) -> None:
        policy = SecurityPolicy()
        frozen = policy.freeze()
        _caught(frozen, "tool")
        frozen.verify_frozen()  # flipping the private flag is not drift
