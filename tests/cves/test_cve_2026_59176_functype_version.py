"""CVE-2026-59176 — functype-mcp-server: ``set_functype_version``'s ``version`` installs any package as functype through ``pnpm add``.

Vulnerability (from NVD, CNA GitHub):
    "Prior to 1.4.4, the `set_functype_version` MCP tool in `functype-mcp-server` accepts an
    unconstrained `version` string using only `z.string()` validation in
    `packages/mcp-server/src/index.ts` and interpolates it into `functype@<version>` for
    `pnpm add`. Package-alias syntaxes such as `file:`, `npm:`, URLs, or paths can cause an
    arbitrary local or remote package to be installed as functype. Immediately afterward,
    `initDocsData(true)` in `packages/mcp-server/src/lib/docs/data.ts` resolves
    `functype/cli` and dynamically imports the newly installed module, executing
    attacker-controlled JavaScript with the MCP server process's privileges." The record
    goes on to say the tool is enabled by default without authentication in stdio mode, and
    that a prompt-injected assistant can be induced to invoke it. Fixed in 1.4.4.

Advisory: https://github.com/jordanburke/functype/security/advisories/GHSA-wcjj-9m6g-2fr2
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-59176
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, CWE-829

Airlock fit: strong.
    **In scope:** an argument the server hands a package installer, which must be a bare
    version and was not. ``ToolArgSinkGuard(installer_args={"version"})`` requires a PEP 440
    version or an npm semver at step 2.75 and refuses every alias NVD names (``file:``,
    ``npm:``, a URL, a path) and their siblings (``github:``, ``git+``, whitespace) as
    ``deny_not_a_version``, before the tool runs.
    ``tool_arg_sink_defaults(installer_args={"version"}, mode="deny")`` does the same and
    claims this CVE. The argument has to be named: the preset's shell screen alone admits
    ``file:../evil``, which carries no shell syntax (``TestDocumentedLimit``).

    **Out of scope:** the dynamic import of what was installed, the tool being enabled
    without authentication in stdio mode, and the ``httpStream`` transport's reach: all three
    are functype's, and 1.4.4 fixes the argument at the source. A range (``>=1.4.4``) and a
    dist-tag (``latest``) are not bare versions and are refused too; resolve them on the
    host. An existing guard (0.10.28) already refuses the shape, so this is a second-defence
    fixture, not a new guard. Triage: #395.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard
from agent_airlock.policy_presets import TOOL_ARG_SINK_CVES, list_active, tool_arg_sink_defaults

CVE = "CVE-2026-59176"

NVD_DESCRIPTION = (
    "Functype is a family of TypeScript functional programming libraries. Prior to 1.4.4, the "
    "`set_functype_version` MCP tool in `functype-mcp-server` accepts an unconstrained "
    "`version` string using only `z.string()` validation in `packages/mcp-server/src/index.ts` "
    "and interpolates it into `functype@<version>` for `pnpm add`. Package-alias syntaxes such "
    "as `file:`, `npm:`, URLs, or paths can cause an arbitrary local or remote package to be "
    "installed as functype. Immediately afterward, `initDocsData(true)` in "
    "`packages/mcp-server/src/lib/docs/data.ts` resolves `functype/cli` and dynamically imports "
    "the newly installed module, executing attacker-controlled JavaScript with the MCP server "
    "process's privileges. Any MCP client able to send a `tools/call` request invoking the tool "
    "can exploit the flaw; the tool is enabled by default without authentication in `stdio` "
    "mode. A connected AI assistant susceptible to indirect prompt injection can also be "
    "induced to invoke it from a malicious document or web page. In non-default "
    "`TRANSPORT_TYPE=httpStream` deployments, a network-accessible attacker does not require "
    "local access. Successful execution can read process secrets, modify files, or terminate "
    "the server. This issue is fixed in `version` 1.4.4."
)
NVD_CWES = ["CWE-829"]

_FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "cve_2026_59176_functype_version.json").read_text(
        encoding="utf-8"
    )
)
PAYLOADS = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["benign"]]
REFUSED_ALTHOUGH_BENIGN = [
    pytest.param(entry, id=entry["id"]) for entry in _FIXTURE["refused_although_benign"]
]
DISCLOSED: dict[str, Any] = _FIXTURE["payloads"][0]

#: The guard on the argument NVD names. ``allowed_tools`` is explicit so the policy states it
#: admits every tool rather than warning that it does.
GUARDED = SecurityPolicy(
    allowed_tools=["*"], tool_arg_sink_guard=ToolArgSinkGuard(installer_args={"version"})
)


def _tools(policy: SecurityPolicy, ran: list[str]) -> dict[str, Any]:
    """A stub of ``set_functype_version``: it records that it ran and installs nothing."""

    @Airlock(policy=policy)
    def set_functype_version(version: str) -> str:
        ran.append("set_functype_version")
        return "ran"

    return {"set_functype_version": set_functype_version}


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


class TestEveryPackageAliasIsRefused:
    @pytest.mark.parametrize("entry", PAYLOADS)
    def test_it_is_refused_before_the_tool_runs(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED, entry)
        _assert_refused(result, entry)
        assert ran == []

    @pytest.mark.parametrize("entry", PAYLOADS)
    def test_the_refusal_names_the_token_never_the_value(self, entry: dict[str, Any]) -> None:
        result, _ = _call(GUARDED, entry)
        value = entry["arguments"][entry["argument"]]
        assert value not in result["error"]
        assert not any(value in hint for hint in result["fix_hints"])

    def test_the_four_alias_kinds_nvd_names_are_covered(self) -> None:
        tokens = {entry["token"] for entry in _FIXTURE["payloads"]}
        assert {"file:", "npm:", "https:", "/"} <= tokens


class TestBareVersionsRun:
    @pytest.mark.parametrize("entry", BENIGN)
    def test_it_runs(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED, entry)
        assert result == "ran"
        assert ran == [entry["tool"]]


class TestThePreset:
    def test_deny_mode_with_the_argument_named_refuses_the_disclosed_shape(self) -> None:
        policy = tool_arg_sink_defaults(installer_args={"version"}, mode="deny")["policy"]
        result, ran = _call(policy, DISCLOSED)
        _assert_refused(result, DISCLOSED)
        assert ran == []

    def test_the_default_warn_mode_logs_and_runs_the_call(self) -> None:
        # Warn mode is the preset's day-one default and is not a refusal.
        policy = tool_arg_sink_defaults(installer_args={"version"})["policy"]
        result, ran = _call(policy, DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]

    def test_the_preset_claims_this_cve(self) -> None:
        assert CVE in TOOL_ARG_SINK_CVES
        assert CVE in tool_arg_sink_defaults()["cves"]
        assert "tool_arg_sink_defaults" in {meta.factory_name for meta in list_active()}


class TestDocumentedLimit:
    def test_the_shell_screen_alone_admits_an_alias(self) -> None:
        # file:../evil holds no shell syntax. Only installer_args reads it as a version.
        result, ran = _call(tool_arg_sink_defaults(mode="deny")["policy"], DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]

    @pytest.mark.parametrize("entry", REFUSED_ALTHOUGH_BENIGN)
    def test_a_range_or_a_dist_tag_is_refused(self, entry: dict[str, Any]) -> None:
        result, ran = _call(GUARDED, entry)
        _assert_refused(result, entry)
        assert ran == []


class TestScopeBoundary:
    def test_without_the_guard_nothing_else_on_the_call_path_refuses_it(self) -> None:
        result, ran = _call(SecurityPolicy(allowed_tools=["*"]), DISCLOSED)
        assert result == "ran"
        assert ran == [DISCLOSED["tool"]]


class TestWatcherAdmittedThisOnTheText:
    """Filed as #395 on the text (``interpolat``, ``stdio``); CWE-829 is not in the
    argument-shaped set, so the CWE alone would only have asked for triage."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_would_only_ask_for_triage(self) -> None:
        assert classify_shape("", NVD_CWES) == "triage-required"
