"""0.10.29: every tool a policy runs is named by one of its rules, or the check fails.

A ``SecurityPolicy`` with an empty ``allowed_tools`` and ``default_deny=False`` admits any
tool it does not deny, so a tool added to a codebase was admitted without anyone deciding
to. ``airlock doctor`` and ``airlock verify`` found tool decorators without ``@Airlock``,
but nothing compared tools against a policy's entries. Raised in OpenHands/OpenHands#17055
(CI enumerates the registry and fails on any entry without a classification).
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import textwrap
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, SecurityPolicy
from agent_airlock.cli import __main__ as dispatcher
from agent_airlock.cli import policy as policy_cli
from agent_airlock.policy import PolicyEscalation, PolicyViolation
from agent_airlock.policy_coverage import CoverageClass, airlock_tools, classify_tool
from agent_airlock.testing import assert_policy_covers

TOOLS = """
from agent_airlock import Airlock
from agent_airlock.capabilities import Capability, requires


@Airlock()
def read_file(path: str) -> str:
    return path


@Airlock()
def search_users(query: str) -> str:
    return query


@requires(Capability.NETWORK_HTTPS)
@Airlock()
def wire_money(amount: int) -> int:
    return amount


@Airlock()
def delete_all() -> None:
    return None


def not_a_tool() -> None:
    return None
"""

POLICIES = """
from agent_airlock import SecurityPolicy

COVERED = SecurityPolicy(
    allowed_tools=["read_file", "search_*", "wire_*"],
    denied_tools=["delete_*"],
    escalate_tools={"wire_*": "money moves need a human"},
)
UNCOVERED = SecurityPolicy(denied_tools=["delete_*"])


def resolver(context):
    return COVERED
"""


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A package with four tools (one in a subpackage) and its policies, importable."""
    name = f"coverage_pkg_{uuid.uuid4().hex[:8]}"
    package = tmp_path / name
    (package / "sub").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "tools.py").write_text(textwrap.dedent(TOOLS), encoding="utf-8")
    (package / "policies.py").write_text(textwrap.dedent(POLICIES), encoding="utf-8")
    (package / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (package / "sub" / "again.py").write_text(
        f"from {name}.tools import read_file\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    yield name
    for module in [m for m in sys.modules if m == name or m.startswith(f"{name}.")]:
        del sys.modules[module]


def _run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = policy_cli.main(["coverage", *argv])
    return code, out.getvalue(), err.getvalue()


class TestTheCommand:
    def test_a_covered_module_exits_zero(self, project: str) -> None:
        code, out, _ = _run("--module", project, "--policy", f"{project}.policies:COVERED")
        assert code == 0
        assert "allowed_by_name      read_file" in out
        assert "allowed_by_pattern   search_users" in out
        assert "escalated            wire_money" in out
        assert "denied               delete_all" in out

    def test_an_uncovered_module_exits_one_and_names_the_tools(self, project: str) -> None:
        code, out, _ = _run("--module", project, "--policy", f"{project}.policies:UNCOVERED")
        assert code == 1
        assert "admitted_by_default" in out
        assert "read_file, search_users, wire_money" in out

    def test_json_lists_every_tool_with_its_rule(self, project: str) -> None:
        argv = ("--module", project, "--policy", f"{project}.policies:COVERED", "--format")
        code, out, _ = _run(*argv, "json")
        report = json.loads(out)
        assert code == 0 and report["uncovered"] == []
        rules = {entry["tool"]: entry["rule"] for entry in report["tools"]}
        assert rules == {
            "delete_all": "denied_tools: delete_*",
            "read_file": "allowed_tools: read_file",
            "search_users": "allowed_tools: search_*",
            "wire_money": "escalate_tools: wire_*",
        }

    @pytest.mark.parametrize(
        ("policy", "message"),
        [
            ("{p}.policies", "MODULE:NAME"),
            ("{p}.policies:resolver", "not a SecurityPolicy"),
            ("{p}.policies:MISSING", "MISSING"),
            ("no_such_module_xyz:POLICY", "no_such_module_xyz"),
        ],
    )
    def test_a_policy_that_cannot_be_loaded_exits_two(
        self, project: str, policy: str, message: str
    ) -> None:
        code, _, err = _run("--module", project, "--policy", policy.format(p=project))
        assert code == 2 and message in err

    def test_a_module_with_no_tools_exits_two(self, project: str) -> None:
        policy = f"{project}.policies:COVERED"
        code, _, err = _run("--module", f"{project}.policies", "--policy", policy)
        assert code == 2 and "found no @Airlock tools" in err

    def test_the_dispatcher_routes_it_with_the_same_flags(self) -> None:
        def flags(call: Callable[[], Any]) -> set[str]:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                with contextlib.suppress(SystemExit):
                    call()
            return {word for word in buf.getvalue().split() if word.startswith("--")}

        direct = flags(lambda: policy_cli.main(["coverage", "--help"]))
        routed = flags(lambda: dispatcher.main(["policy", "coverage", "--help"]))
        assert {"--module", "--policy", "--format"} <= direct
        assert routed == direct


class TestFindingTheTools:
    def test_tools_are_found_through_subpackages_and_requires(self, project: str) -> None:
        assert sorted(airlock_tools(project)) == [
            "delete_all",
            "read_file",
            "search_users",
            "wire_money",
        ]


class TestTheClasses:
    @pytest.mark.parametrize(
        ("policy", "tool", "expected"),
        [
            (SecurityPolicy(allowed_tools=["pay"]), "pay", CoverageClass.ALLOWED_BY_NAME),
            (SecurityPolicy(allowed_tools=["pay*"]), "payout", CoverageClass.ALLOWED_BY_PATTERN),
            (SecurityPolicy(allowed_tools=["pay"]), "refund", CoverageClass.DENIED),
            (SecurityPolicy(default_deny=True), "pay", CoverageClass.DENIED),
            (SecurityPolicy(denied_tools=["pay*"]), "pay", CoverageClass.DENIED),
            (SecurityPolicy(escalate_tools={"pay": "why"}), "pay", CoverageClass.ESCALATED),
            (SecurityPolicy(), "pay", CoverageClass.ADMITTED_BY_DEFAULT),
            (SecurityPolicy(denied_tools=["refund"]), "pay", CoverageClass.ADMITTED_BY_DEFAULT),
        ],
    )
    def test_each_class(self, policy: SecurityPolicy, tool: str, expected: CoverageClass) -> None:
        assert classify_tool(policy, tool).coverage is expected

    def test_a_denial_beats_an_escalation_and_an_allow(self) -> None:
        policy = SecurityPolicy(
            allowed_tools=["pay"], denied_tools=["pay"], escalate_tools={"pay": "x"}
        )
        assert classify_tool(policy, "pay").coverage is CoverageClass.DENIED

    def test_an_escalation_needs_the_allowlist_to_admit_the_tool_first(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read"], escalate_tools={"pay": "x"})
        assert classify_tool(policy, "pay").coverage is CoverageClass.DENIED
        allowed = SecurityPolicy(allowed_tools=["pay"], escalate_tools={"pay": "x"})
        assert classify_tool(allowed, "pay").coverage is CoverageClass.ESCALATED

    @pytest.mark.parametrize("tool", ["pay", "payout", "refund", "read", "wire_x", "delete"])
    @pytest.mark.parametrize(
        "make_policy",
        [
            lambda: SecurityPolicy(),
            lambda: SecurityPolicy(default_deny=True),
            lambda: SecurityPolicy(allowed_tools=["pay*", "read"], denied_tools=["delete"]),
            lambda: SecurityPolicy(escalate_tools={"wire_*": "x", "pay": "y"}),
            lambda: SecurityPolicy(
                allowed_tools=["wire_*", "read"], escalate_tools={"wire_x": "z"}
            ),
        ],
    )
    def test_the_class_matches_what_check_decides(
        self, make_policy: Callable[[], SecurityPolicy], tool: str
    ) -> None:
        coverage = classify_tool(make_policy(), tool).coverage
        try:
            make_policy().check(tool)
        except PolicyEscalation:
            assert coverage is CoverageClass.ESCALATED
        except PolicyViolation:
            assert coverage is CoverageClass.DENIED
        else:
            assert coverage not in (CoverageClass.DENIED, CoverageClass.ESCALATED)

    def test_classifying_spends_no_rate_limit_token(self) -> None:
        policy = SecurityPolicy(allowed_tools=["pay"], rate_limits={"pay": "1/hour"})

        @Airlock(policy=policy)
        def pay(amount: int) -> int:
            return amount

        for _ in range(5):
            classify_tool(policy, "pay")
        assert pay(amount=1) == 1


class TestAssertPolicyCovers:
    def test_it_fails_on_an_unlisted_tool(self) -> None:
        with pytest.raises(AssertionError, match="refund"):
            assert_policy_covers(["pay", "refund"], SecurityPolicy(denied_tools=["pay"]))

    def test_it_passes_and_returns_the_report(self) -> None:
        report = assert_policy_covers(["pay"], SecurityPolicy(allowed_tools=["pay"]))
        assert report.tools[0].coverage is CoverageClass.ALLOWED_BY_NAME

    def test_it_reads_tools_and_modules(self, project: str) -> None:
        @Airlock()
        def refund(amount: int) -> int:
            return amount

        assert_policy_covers([refund], SecurityPolicy(allowed_tools=["refund"]))
        module = sys.modules.get(project) or __import__(project)
        with pytest.raises(AssertionError, match="read_file"):
            assert_policy_covers(module, SecurityPolicy(denied_tools=["delete_*"]))

    def test_it_needs_a_policy_and_named_tools(self) -> None:
        with pytest.raises(TypeError, match="SecurityPolicy"):
            assert_policy_covers(["pay"], object())  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="name"):
            assert_policy_covers([object()], SecurityPolicy())  # type: ignore[list-item]
