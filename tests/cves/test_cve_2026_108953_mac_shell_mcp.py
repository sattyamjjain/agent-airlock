"""CVE-2026-108953 — mac-shell-mcp bypasses its command whitelist via shell metachars in args.

Vulnerability (from NVD and the upstream fix, retrieved 2026-10-19):
    mac-shell-mcp before 2.0.0 exposes an ``execute_command`` MCP tool guarded by a
    command whitelist. The whitelist vets the *command* but not its *arguments*, so a
    client calls an allowed command such as ``pwd`` and smuggles a forbidden command in
    the arguments behind a shell metacharacter — ``pwd ; …``, ``pwd && …``, a pipe,
    ``$( )`` or a backtick — which the server then runs through a shell as the server
    user, without approval. NVD, verbatim: *"mac-shell-mcp before 2.0.0 contains an OS
    command injection vulnerability that allows MCP clients to bypass the command
    whitelist by injecting shell metacharacters into execute_command arguments.
    Attackers or malicious prompts can call a safe command such as pwd with arguments
    like ';' to run forbidden commands as the server user without approval."* Fixed in
    2.0.0, whose commit stops building a shell string from the arguments.

Advisory: https://github.com/cfdude/mac-shell-mcp/issues/45
Fix:      https://github.com/cfdude/mac-shell-mcp/commit/932ce733cde07bb30b1f186303e6692dbb5d087a
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-108953
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
CWE:      CWE-78

Airlock fit: partial.
    **Out of scope: the whitelist and the approval gate.** Whether ``execute_command``
    is offered, what its command whitelist contains, and whether a human approves a run
    are decisions in mac-shell-mcp's own server, downstream of the tool call. A contract
    layer cannot impose them on someone else's server, and 2.0.0 is the right place for
    the fix.

    **In scope: the primitive.** Shell metacharacters riding in a caller-controlled
    argument is the documented in-scope shape (``docs/cve-triage.md``, "Metacharacter /
    escape neutralisation mismatch", anchored on CVE-2026-19591), and
    ``StdioCommandInjectionGuard`` already refuses it. So this is a **second-defence
    regression fixture against an existing guard, not a new guard** — the
    CVE-2026-77521 pattern. The guard runs on the argument, before the server ever
    builds a shell string, so it still fires when the whitelist is the only thing the
    server relied on.

    One honest boundary: a bare ``$VAR`` (no ``$(``) is not in the default metachar set
    and passes, because ``$`` appears in ordinary arguments and a blanket refusal would
    break them — the same line ``SafeURL`` draws for ``$name`` in CVE-2026-102911. Once
    the server still splices the value into a shell, ``$VAR`` would expand; the complete
    fix is the upstream one — 2.0.0 passes arguments as argv with no shell.
"""

from __future__ import annotations

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock.mcp_spec.stdio_command_injection_guard import (
    StdioCommandInjectionGuard,
    StdioCommandInjectionVerdict,
)
from agent_airlock.policy_presets import mcp_stdio_command_injection_preset_defaults

CVE = "CVE-2026-108953"

#: NVD's description, verbatim, so the classifier assertions below are checked against
#: the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "mac-shell-mcp before 2.0.0 contains an OS command injection vulnerability that "
    "allows MCP clients to bypass the command whitelist by injecting shell "
    "metacharacters into execute_command arguments. Attackers or malicious prompts can "
    "call a safe command such as pwd with arguments like ';' to run forbidden commands "
    "as the server user without approval."
)

#: NVD's CWE. CWE-78 is the argument-shaped one, and it is what filed this.
NVD_CWES = ["CWE-78"]

# What the `execute_command` tool is for: an allowed command, with or without plain args.
BENIGN: tuple[tuple[str, dict[str, object]], ...] = (
    ("bare allowed command", {"command": "pwd"}),
    ("allowed command with plain args", {"command": "ls", "args": ["-la", "/data"]}),
)

# The NVD payload shape — an allowed command (`pwd`) smuggling a forbidden one behind a
# metacharacter. Each carries the harmless `AIRLOCK_MARKER` sentinel where NVD's PoC runs
# a real command, so the fixture proves the refusal without ever running anything.
ESCAPES: tuple[tuple[str, dict[str, object]], ...] = (
    ("semicolon as its own arg", {"command": "pwd", "args": [";", "echo", "AIRLOCK_MARKER"]}),
    ("and-chaining", {"command": "pwd", "args": ["&&", "echo", "AIRLOCK_MARKER"]}),
    ("pipe", {"command": "pwd", "args": ["|", "echo", "AIRLOCK_MARKER"]}),
    ("dollar-paren substitution", {"command": "pwd", "args": ["$(echo AIRLOCK_MARKER)"]}),
    ("backtick substitution", {"command": "pwd", "args": ["`echo AIRLOCK_MARKER`"]}),
    ("inline semicolon in command", {"command": "pwd; echo AIRLOCK_MARKER"}),
)


def _guard() -> StdioCommandInjectionGuard:
    """Stock guard. No operator tuning — the default metachar set is enough."""
    return StdioCommandInjectionGuard()


class TestTheMetacharacterBypassIsRefused:
    """The half of this CVE that reaches a tool-call argument."""

    @pytest.mark.parametrize(("label", "payload"), ESCAPES, ids=[c[0] for c in ESCAPES])
    def test_each_bypass_shape_is_denied(self, label: str, payload: dict[str, object]) -> None:
        decision = _guard().evaluate(payload)
        assert decision.verdict is StdioCommandInjectionVerdict.DENY_SHELL_METACHAR, label
        assert decision.allowed is False

    @pytest.mark.parametrize(("label", "payload"), BENIGN, ids=[c[0] for c in BENIGN])
    def test_an_allowed_command_still_runs(self, label: str, payload: dict[str, object]) -> None:
        assert _guard().evaluate(payload).allowed is True, label

    def test_refusal_needs_no_operator_tuning(self) -> None:
        """If this ever needs configuration, the claim in the docstring changes."""
        stock = _guard().evaluate(ESCAPES[0][1])
        assert stock.verdict is StdioCommandInjectionVerdict.DENY_SHELL_METACHAR


class TestScopeBoundary:
    """Pin the halves agent-airlock does **not** reach, and the one metachar it misses."""

    def test_the_guard_cannot_see_the_whitelist_or_the_approval(self) -> None:
        # The guard's whole input is the spawn config. Whether the command was on
        # mac-shell-mcp's whitelist, or a human approved it, is not in that config and is
        # structurally invisible here: an allowed command passes regardless of either.
        guard = _guard()
        verdicts = {
            guard.evaluate(args).allowed
            for args in (
                {"command": "pwd"},
                {"command": "pwd", "approved_by": None},
                {"command": "pwd", "whitelisted": True},
            )
        }
        assert verdicts == {True}

    def test_a_bare_dollar_var_still_passes(self) -> None:
        # `$VAR` (no `$(`) is not in the default metachar set. `$` is ordinary in real
        # arguments, so a blanket refusal would break them; the cost is that a server
        # still splicing this into a shell would expand the variable. The complete fix
        # is the upstream one — argv with no shell.
        assert _guard().evaluate({"command": "echo", "args": ["$HOME"]}).allowed is True

    def test_preset_does_not_claim_this_cve(self) -> None:
        # The preset claims the CVEs it addresses. It does not address an unguarded
        # argument whitelist; it refuses the payload that whitelist let through.
        preset = mcp_stdio_command_injection_preset_defaults()
        assert CVE not in str(preset.get("cves", ()))


class TestWatcherAdmittedThisOnBothSignals:
    """Either signal alone would have filed it: the description and CWE-78."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_description_alone_files_it(self) -> None:
        # "shell" and "metachar(acters)" are both sink words.
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-78"]) == "candidate"
