"""CVE-2026-105740 — Langflow MCP stdio command and env injection.

Vulnerability (from NVD and GHSA-7w94-79vh-5mr2):
    Prior to Langflow 1.9.0, any authenticated Langflow user can achieve Remote
    Code Execution by adding an MCP server with the "Stdio" transport. The
    user-supplied ``command`` field is passed directly to ``bash -c "exec
    {command}"`` with zero validation, no allowlisting and no sandboxing, and
    executes immediately when the server list is fetched. Additionally, the
    ``env`` field allows arbitrary environment variable injection (e.g.
    ``LD_PRELOAD``, ``PATH`` override), which turns even an otherwise-benign
    launcher into an execution primitive. Fixed in Langflow 1.9.0.

Advisory: https://github.com/langflow-ai/langflow/security/advisories/GHSA-7w94-79vh-5mr2
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-105740
CVSS:     9.9 (CRITICAL) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H, CWE-78

Airlock fit: partial.
    The sibling of CVE-2026-105697, on the same stdio transport. That one is
    covered in ``test_cve_2026_105697_langflow_stdio_spawn.py``; this file exists
    for the half CVE-2026-105740 adds, the **env field**.

    **Out of scope: the authenticated-add primitive.** That any authenticated
    user may add a stdio server is Langflow's own authorization, the same route
    check CVE-2026-105697 turns on, and not expressible at the tool-call
    boundary. Langflow 1.9.0 is where it belongs.

    **In scope: the env-injection primitive.** ``McpSubprocessArgInjectionGuard``
    refuses an ``env`` mapping carrying a known code-loading variable
    (``LD_PRELOAD`` / ``PATH`` / ``PYTHONPATH`` / ...) *regardless of whether the
    command was allowlisted*, because env turns any binary into an execution
    primitive. This is a **second-defence fixture against the existing guard, not
    a new guard** — the guard already carries ``LD_PRELOAD`` and ``PATH`` in its
    default dangerous-env set, so no env handling needed changing for this CVE.

    The command half (``bash -c "exec {command}"``) is the same shape the
    CVE-2026-105697 module pins; here it is asserted only enough to show it is the
    env leg, not the command leg, doing the refusing once a launcher is
    allowlisted.
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

CVE = "CVE-2026-105740"

#: NVD's description, verbatim, so the classifier assertions are checked against
#: the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "Langflow is a tool for building and deploying AI-powered agents and workflows. Prior to "
    "1.9.0, any authenticated Langflow user can achieve Remote Code Execution (RCE) on the "
    'server by adding an MCP server with the "Stdio" transport. The user-supplied command field '
    'is passed directly to bash -c "exec {command}" with zero validation, no allowlisting, and '
    "no sandboxing. The command executes immediately when the server list is fetched. "
    "Additionally, the env field allows arbitrary environment variable injection (e.g., "
    "LD_PRELOAD, PATH override). This vulnerability is fixed in 1.9.0."
)

#: NVD's only CWE. CWE-78 is argument-shaped, and it is what filed this.
NVD_CWES = ["CWE-78"]

#: A launcher an operator *did* allowlist, so the command step passes and the
#: verdict below is about the env mapping rather than the program name.
_ALLOWED = frozenset({"uvx"})

#: The env-injection shapes NVD names. Each pairs an allowlisted launcher with an
#: env mapping that carries a code-loading variable, so the refusal is the env
#: leg — the distinctive half of this CVE.
_ENV_PAYLOADS: tuple[tuple[str, dict[str, Any], str], ...] = (
    (
        "ld_preload",
        {"command": "uvx", "args": ["mcp-server"], "env": {"LD_PRELOAD": "/tmp/evil.so"}},
        "env.LD_PRELOAD",
    ),
    (
        "path_override",
        {"command": "uvx", "args": ["mcp-server"], "env": {"PATH": "/tmp/evil:/usr/bin"}},
        "env.PATH",
    ),
)

#: The command leg, carried here only to show it is refused the same way the
#: sibling module pins in full.
_COMMAND_PAYLOAD: dict[str, Any] = {"command": "/bin/bash", "args": ["-c", "touch /tmp/x; id"]}

#: A clean allowlisted component with a benign env — the allow case.
_BENIGN: dict[str, Any] = {
    "command": "uvx",
    "args": ["mcp-server-git", "--repo", "/srv/repo"],
    "env": {"LOG_LEVEL": "info"},
}


class TestTheEnvInjectionPrimitiveIsRefused:
    """The half CVE-2026-105740 adds over its sibling: the ``env`` field."""

    @pytest.mark.parametrize(
        ("label", "config", "field"), _ENV_PAYLOADS, ids=[p[0] for p in _ENV_PAYLOADS]
    )
    def test_each_env_shape_is_denied(self, label: str, config: dict[str, Any], field: str) -> None:
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(config)
        assert decision.allowed is False, label
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_ENV, label
        assert decision.matched_field == field, label

    def test_the_env_leg_fires_even_when_the_command_is_allowlisted(self) -> None:
        """What makes this a distinct leg: the launcher is clean, the env is not.

        Allowlisting ``uvx`` gets the config past the command step, so the only
        thing left to refuse it is the env mapping. If the env check were absent,
        this would be admitted — which is the CVE.
        """
        guard = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED)
        assert guard.evaluate(dict(_ENV_PAYLOADS[0][1])).matched_field == "env.LD_PRELOAD"

    def test_the_command_leg_is_refused_too(self) -> None:
        """The shared half, pinned in full by the CVE-2026-105697 module."""
        decision = McpSubprocessArgInjectionGuard().evaluate(_COMMAND_PAYLOAD)
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND

    def test_a_clean_allowlisted_component_is_admitted(self) -> None:
        guard = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED)
        assert guard.evaluate(_BENIGN).verdict is McpSubprocessArgVerdict.ALLOW


class TestScopeBoundary:
    """Pin the half agent-airlock does **not** reach: the authenticated-add authz."""

    def test_the_guard_cannot_tell_who_added_the_server(self) -> None:
        """Identical configs, different submitters, same verdict.

        CVE-2026-105740 is that any authenticated user may add this at all. The
        submitter is not part of the spawn config, so the guard returns the same
        decision whoever sends it — which is why the fit says *partial*.
        """
        guard = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED)
        verdicts = {
            guard.evaluate(args).verdict
            for args in (
                _BENIGN,
                {**_BENIGN, "submitted_by": "non-admin-user"},
                {**_BENIGN, "submitted_by": "admin"},
            )
        }
        assert verdicts == {McpSubprocessArgVerdict.ALLOW}

    def test_preset_does_not_claim_this_cve(self) -> None:
        # The preset claims CVE-2026-42271, the guard's anchor. It does not claim
        # Langflow's missing authorization; it refuses the env the CVE smuggled in.
        preset = mcp_subprocess_arg_injection_guard_defaults()
        assert CVE not in str(preset.get("cves", ()))


class TestWatcherAdmittedThisOnTheCweSignal:
    """CWE-78 carried it; the full record also matches on the ``command`` / ``env`` sinks."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-78"]) == "candidate"
