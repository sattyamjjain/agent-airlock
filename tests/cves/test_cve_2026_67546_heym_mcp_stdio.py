"""CVE-2026-67546 — Heym's fetch-tools endpoint spawns a caller-supplied MCP stdio command.

Vulnerability (from NVD and GHSA-378x-q589-34mv):
    Heym before 0.0.75: ``POST /api/mcp/fetch-tools`` accepts a connection of any
    authenticated user, lowest role included. Its stdio transport resolves
    ``connection["command"]`` and spawns it with ``connection["args"]`` and an
    environment merged over ``os.environ``, on the shared backend host, before any MCP
    handshake. Fixed in 0.0.75, which starts stdio servers in a hardened container.

Advisory: https://github.com/heymrun/heym/security/advisories/GHSA-378x-q589-34mv
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-67546
CVSS:     8.8 (HIGH) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-94

Airlock fit: partial.
    The "both" case from ``docs/cve-triage.md``, splitting as CVE-2026-105797 and
    CVE-2026-79748 do.

    **Out of scope: the missing role gate.** Which principal may reach the endpoint is
    Heym's own identity model.

    **In scope: the spawn primitive it hands over.** The connection carries a stdio
    ``command`` / ``args`` of the caller's choosing, the shape
    :class:`~agent_airlock.mcp_spec.subprocess_arg_guard.McpSubprocessArgInjectionGuard`
    already refuses. A second-defence fixture against an existing guard, not a new guard.
"""

from __future__ import annotations

from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import mcp_subprocess_arg_injection_guard_defaults
from agent_airlock.mcp_spec.subprocess_arg_guard import (
    McpSubprocessArgInjectionGuard,
    McpSubprocessArgVerdict,
)

CVE = "CVE-2026-67546"

#: NVD's description, verbatim, so the classifier assertions read the real record.
NVD_DESCRIPTION = (
    "Heym builds and runs agentic systems and business-process automations on self-hosted "
    "infrastructure. Prior to version 0.0.75, the same POST /api/mcp/fetch-tools endpoint "
    "(any authenticated user, lowest role) also accepts the stdio transport, which spawns "
    "the attacker-supplied command with attacker-supplied args and an environment merged "
    "over os.environ. The process executes on the shared backend host before MCP protocol "
    "validation fails — so side effects fire regardless of whether the command speaks "
    "MCP. This is a distinct weakness class and exploit primitive from the SSRF (Advisory "
    "2) on the same endpoint, and needs a different fix (role gating / opt-in trust "
    "boundary rather than egress controls). This issue has been patched in version "
    "0.0.75."
)

NVD_CWES = ["CWE-94"]

_ALLOWED = frozenset({"uvx"})

#: The advisory's proof of concept, as the ``connection`` object the endpoint took.
_POC: dict[str, Any] = {
    "transport": "stdio",
    "command": "/bin/sh",
    "args": ["-c", "id > /tmp/pwned"],
}

_BENIGN: dict[str, Any] = {"transport": "stdio", "command": "uvx", "args": ["mcp-server-time"]}


class TestTheSpawnPrimitiveIsRefused:
    def test_the_advisory_s_connection_is_denied(self) -> None:
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(_POC)
        assert decision.allowed is False
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND
        assert decision.matched_field == "command"

    @pytest.mark.parametrize("transport", ["stdio", "", None, "sse"])
    def test_the_transport_field_does_not_change_it(self, transport: str | None) -> None:
        # Heym defaulted an absent transport to stdio; the guard never reads the field.
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(
            {**_POC, "transport": transport}
        )
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND

    def test_an_environment_that_loads_code_is_denied(self) -> None:
        # The endpoint merged the caller's environment over os.environ.
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(
            {**_BENIGN, "env": {"LD_PRELOAD": "/tmp/x.so"}}
        )
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_ENV

    def test_an_allowlisted_server_passes(self) -> None:
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(_BENIGN)
        assert decision.verdict is McpSubprocessArgVerdict.ALLOW


class TestScopeBoundary:
    def test_the_guard_cannot_see_the_caller_s_role(self) -> None:
        guard = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED)
        verdicts = {
            guard.evaluate({**_BENIGN, "requested_by": role}).verdict for role in ("user", "admin")
        }
        assert verdicts == {McpSubprocessArgVerdict.ALLOW}

    def test_preset_does_not_claim_this_cve(self) -> None:
        assert CVE not in mcp_subprocess_arg_injection_guard_defaults()["cves"]


class TestWatcherAdmittedThisOnTheCweSignal:
    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-94"]) == "candidate"
