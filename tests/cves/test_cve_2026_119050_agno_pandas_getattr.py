"""CVE-2026-119050 — Agno PandasTools: a model-chosen function name dispatched through ``getattr(pandas, ...)``.

Vulnerability (from NVD, CNA VulnCheck):
    "Agno through 3.1.11 contains an unsafe reflection vulnerability in PandasTools that
    allows attackers to invoke arbitrary pandas functions by supplying model-controlled
    function names to getattr(). Attackers can use prompt injection to make the agent call
    pandas.read_pickle on attacker-controlled paths for code execution, or call other
    readers to read local files." NVD names no fixed release (its range is "through
    3.1.11"), and none existed when ``docs/guide/dispatch-arguments.md`` was written
    (agno-agi/agno#8699). No triage issue exists: the watcher drops this record, since its
    text never names the MCP ecosystem (pinned in this module).

Advisory: https://www.vulncheck.com/advisories/agno-through-3.1.11-code-execution-via-pandastools-unsafe-reflection
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-119050
CVSS:     8.1 (HIGH) — CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H, CWE-470 (CVSS 4.0: 9.2 CRITICAL)

Airlock fit: partial.
    **In scope:** an argument that names the function a tool calls, which reaches
    ``getattr``: ``create_using_function`` in ``create_pandas_dataframe`` and ``operation``
    in ``run_dataframe_operation``. ``read_pickle`` is a plain identifier, so neither the
    shell screen nor the eval guards see it. ``ToolArgSinkGuard(dispatch_args=...)`` reads
    each as one name at step 2.75, before the tool runs: with an allowlist only the names it
    lists pass, and with an empty one ``DEFAULT_DISPATCH_DENY`` refuses private names,
    ``*pickle*``, ``read_*``, ``to_*`` and the rest. Both configurations refuse every name in
    the fixture as ``deny_dispatch_name``. ``reflection_sink_defaults`` claims this CVE.

    **Why partial:** the default denylist is a backstop, not a contract. It cannot see what
    an admitted method does with its parameters: ``DataFrame.query`` evaluates an expression
    string and is admitted (``TestDocumentedLimit``); an allowlist of the operations a tool
    supports is the control. The guard reads a dispatch argument at the top level only, and
    never the reader's path in ``function_parameters``. **Out of scope:** Agno's own
    ``getattr`` call, which is upstream's to fix. An existing guard (0.10.29) already refuses
    the shape, so this is a second-defence fixture, not a new guard.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape, is_relevant

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import list_active, reflection_sink_defaults

CVE = "CVE-2026-119050"

NVD_DESCRIPTION = (
    "Agno through 3.1.11 contains an unsafe reflection vulnerability in PandasTools that allows "
    "attackers to invoke arbitrary pandas functions by supplying model-controlled function "
    "names to getattr(). Attackers can use prompt injection to make the agent call "
    "pandas.read_pickle on attacker-controlled paths for code execution, or call other readers "
    "to read local files."
)
NVD_CWES = ["CWE-470"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_119050_agno_pandas_getattr.json").read_text(
        encoding="utf-8"
    )
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN_WITH_ALLOWLIST = [
    pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign_with_allowlist"]
]
BENIGN_WITH_DENYLIST = [
    pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign_with_denylist"]
]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]

ALLOWLISTS: dict[str, list[str]] = _FIXTURE["allowlists"]
#: Each argument with an empty allowlist: the default denylist decides.
DENYLIST_ONLY: dict[str, tuple[str, ...]] = dict.fromkeys(ALLOWLISTS, ())


def _policy(dispatch_args: dict[str, Any]) -> SecurityPolicy:
    # ``allowed_tools`` is explicit so the policy states it admits every tool rather than
    # warning that it does.
    return SecurityPolicy(
        allowed_tools=["*"], tool_arg_sink_guard=ToolArgSinkGuard(dispatch_args=dispatch_args)
    )


CONFIGURATIONS = [
    pytest.param(_policy(ALLOWLISTS), id="allowlist"),
    pytest.param(_policy(DENYLIST_ONLY), id="default-denylist"),
]


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """Stubs of PandasTools' two tools: each records the name it would have called, and
    nothing is read, unpickled or looked up."""

    @Airlock(policy=policy)
    def create_pandas_dataframe(
        dataframe_name: str, create_using_function: str, function_parameters: dict[str, Any]
    ) -> str:
        ran.append(create_using_function)
        return "ran"

    @Airlock(policy=policy)
    def run_dataframe_operation(
        dataframe_name: str, operation: str, operation_parameters: dict[str, Any]
    ) -> str:
        ran.append(operation)
        return "ran"

    return {
        "create_pandas_dataframe": create_pandas_dataframe,
        "run_dataframe_operation": run_dataframe_operation,
    }


def _call(policy: SecurityPolicy, entry: dict[str, Any]) -> tuple[Any, list[str]]:
    ran: list[str] = []
    return _tools(policy, ran)[entry["tool"]](**entry["arguments"]), ran


def _assert_refused(result: Any, entry: dict[str, Any]) -> None:
    assert isinstance(result, dict), f"the call ran and returned {result!r}"
    assert result["success"] is False
    assert result["status"] == "blocked"
    assert result["block_reason"] == "tool_arg_sink"
    assert result["error"].startswith("AIRLOCK_BLOCK")
    assert result["fix_hints"], "a refusal must say what to send instead"
    assert result["metadata"]["verdict"] == entry["verdict"]
    assert result["metadata"]["argument"] == entry["argument"]
    assert result["metadata"]["token"] == entry["token"]


class TestTheChosenNameIsRefused:
    @pytest.mark.parametrize("policy", CONFIGURATIONS)
    @pytest.mark.parametrize("entry", PAYLOADS)
    def test_it_is_refused_before_getattr_could_run(
        self, entry: dict[str, Any], policy: SecurityPolicy
    ) -> None:
        result, ran = _call(policy, entry)
        _assert_refused(result, entry)
        assert ran == []

    def test_the_refusal_never_quotes_the_deny_pattern(self) -> None:
        result, _ = _call(_policy(DENYLIST_ONLY), DISCLOSED)
        assert "*pickle*" not in json.dumps(result)

    def test_a_positional_name_is_read_under_its_parameter_name(self) -> None:
        ran: list[str] = []
        tool = _tools(_policy(ALLOWLISTS), ran)["create_pandas_dataframe"]
        result = tool("frame", "read_pickle", {"filepath_or_buffer": "upload.pkl"})
        _assert_refused(result, DISCLOSED)
        assert ran == []


class TestBenignCallsRun:
    @pytest.mark.parametrize("entry", BENIGN_WITH_ALLOWLIST)
    def test_an_allowlisted_name_runs(self, entry: dict[str, Any]) -> None:
        result, ran = _call(_policy(ALLOWLISTS), entry)
        assert result == "ran"
        assert len(ran) == 1

    @pytest.mark.parametrize("entry", BENIGN_WITH_DENYLIST)
    def test_a_name_the_denylist_does_not_match_runs(self, entry: dict[str, Any]) -> None:
        result, ran = _call(_policy(DENYLIST_ONLY), entry)
        assert result == "ran"
        assert len(ran) == 1


class TestThePreset:
    def test_deny_mode_refuses_the_disclosed_name(self) -> None:
        preset = reflection_sink_defaults(dispatch_args=ALLOWLISTS, mode="deny")
        result, ran = _call(preset["policy"], DISCLOSED)
        _assert_refused(result, DISCLOSED)
        assert ran == []

    def test_the_default_warn_mode_logs_and_runs_the_call(self) -> None:
        # Warn mode is the preset's day-one default and is not a refusal.
        result, ran = _call(reflection_sink_defaults(dispatch_args=ALLOWLISTS)["policy"], DISCLOSED)
        assert result == "ran"
        assert ran == ["read_pickle"]

    def test_the_preset_claims_this_cve(self) -> None:
        preset = reflection_sink_defaults(dispatch_args=ALLOWLISTS)
        assert preset["cves"] == (CVE,)
        assert preset["cwe"] == ("CWE-470",)
        assert "reflection_sink_defaults" in {meta.factory_name for meta in list_active()}


class TestDocumentedLimit:
    def test_the_default_denylist_admits_query_and_an_allowlist_refuses_it(self) -> None:
        entry = {
            "tool": "run_dataframe_operation",
            "arguments": {
                "dataframe_name": "frame",
                "operation": "query",
                "operation_parameters": {"expr": "a > 1"},
            },
        }
        result, ran = _call(_policy(DENYLIST_ONLY), entry)
        assert result == "ran"
        assert ran == ["query"]
        refused, _ = _call(_policy(ALLOWLISTS), entry)
        _assert_refused(
            refused, {"verdict": "deny_dispatch_name", "argument": "operation", "token": "query"}
        )

    def test_a_name_nested_in_another_argument_is_not_read(self) -> None:
        entry = {
            "tool": "create_pandas_dataframe",
            "arguments": {
                "dataframe_name": "frame",
                "create_using_function": "read_csv",
                "function_parameters": {"create_using_function": "read_pickle"},
            },
        }
        result, _ = _call(_policy(ALLOWLISTS), entry)
        assert result == "ran"


class TestScopeBoundary:
    def test_without_the_guard_nothing_else_on_the_call_path_refuses_it(self) -> None:
        result, ran = _call(SecurityPolicy(allowed_tools=["*"]), DISCLOSED)
        assert result == "ran"
        assert ran == ["read_pickle"]


class TestTheWatcherNeverFiledThis:
    """No MCP mention in the text, no sink word, and CWE-470 is not argument-shaped."""

    def test_the_relevance_filter_drops_it(self) -> None:
        assert is_relevant(NVD_DESCRIPTION) is False

    def test_it_would_only_ask_for_triage_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "triage-required"

    def test_the_text_alone_would_only_ask_for_triage(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "triage-required"

    def test_the_cwe_alone_would_only_ask_for_triage(self) -> None:
        assert classify_shape("", NVD_CWES) == "triage-required"
