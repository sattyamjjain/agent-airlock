"""CVE-2026-105797 — SimpleChat personal MCP plugin spawns an attacker-selected stdio process.

Vulnerability (from NVD and GHSA-h4mw-qw8m-5x4j):
    In SimpleChat 0.261.003 and 0.261.027, an authorization ordering flaw in
    ``POST /api/user/plugins`` lets an authenticated low-privileged user omit the
    top-level MCP ``type`` so that ``_reject_non_admin_mcp_stdio`` skips inspection
    before the type is restored from metadata. The stored personal action then
    reaches ``McpPluginFactory.create_connector``, and ``MCPStdioPlugin.connect``
    starts the attacker-selected operating-system process under the application
    service identity when the action tool is invoked. Exploitation requires
    personal plugins enabled and governance permitting MCP actions. Fixed in
    0.261.031 (which restores the type before the admin check runs).

Advisory: https://github.com/microsoft/simplechat/security/advisories/GHSA-h4mw-qw8m-5x4j
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-105797
CVSS:     8.8 (HIGH) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78, CWE-863

Airlock fit: partial.
    The "both" case from ``docs/cve-triage.md``, splitting the same way as
    CVE-2026-79748 (MCPHub).

    **Out of scope: the authorization ordering (CWE-863).** That
    ``_reject_non_admin_mcp_stdio`` runs before the ``type`` is restored, so
    omitting the top-level type skips the admin gate, is "incorrect authorization
    logic inside a router or hub" (``docs/cve-triage.md`` out-of-scope table): the
    bug is which principal may store the action, not the call's arguments. Only
    SimpleChat's own route can order that check correctly, and 0.261.031 does.

    **In scope: the spawn primitive the ordering flaw hands over.** The stored
    action carries a stdio ``command`` / ``args`` naming a caller-chosen process
    that ``MCPStdioPlugin.connect`` starts. That is the shape
    :class:`~agent_airlock.mcp_spec.subprocess_arg_guard.McpSubprocessArgInjectionGuard`
    already refuses deny-by-default for CVE-2026-42271, so this is a
    **second-defence regression fixture against an existing guard, not a new
    guard**. Crucially, the guard resolves the program from ``command`` / ``args``
    and never consults a top-level ``type`` discriminator, so the exact move this
    CVE uses — omit the ``type`` to skip inspection — does not skip the guard.
"""

from __future__ import annotations

from typing import Any

from scripts.cve_watcher import classify_shape

from agent_airlock import mcp_subprocess_arg_injection_guard_defaults
from agent_airlock.mcp_spec.subprocess_arg_guard import (
    McpSubprocessArgInjectionGuard,
    McpSubprocessArgVerdict,
)

CVE = "CVE-2026-105797"

#: NVD's description, verbatim, so the classifier assertions below are checked
#: against the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "SimpleChat is a secure AI conversation application with personal and group workspaces for "
    "document-grounded interactions. In versions 0.261.003 and 0.261.027, an authorization "
    "ordering flaw in POST /api/user/plugins allows an authenticated low-privileged user to omit "
    "the top-level MCP type so that _reject_non_admin_mcp_stdio skips inspection before the type "
    "is restored from metadata. The stored personal action can then reach "
    "McpPluginFactory.create_connector, and MCPStdioPlugin.connect starts the attacker-selected "
    "operating-system process under the application service identity when the action tool is "
    "invoked. Exploitation requires personal plugins to be enabled and governance to permit MCP "
    "actions, and it can expose or modify secrets and data available to the service or disrupt "
    "the service. This issue is fixed in version 0.261.031."
)

#: NVD's CWEs. CWE-78 is the argument-shaped one and is what filed this; CWE-863
#: is the authorization-ordering half, which is out of scope here.
NVD_CWES = ["CWE-78", "CWE-863"]

#: A stored personal-action stdio config whose command is a placeholder no
#: operator allowlisted. `--version` is a harmless arg: the point is only that an
#: un-vetted program is refused, so the payload needs no teeth.
_NON_ALLOWLISTED: dict[str, Any] = {
    "command": "placeholder-not-allowlisted",
    "args": ["--version"],
}

#: The same spawn config carrying the top-level MCP ``type`` SimpleChat strips to
#: skip its own admin gate. The guard must refuse this identically whether the
#: field is present or absent.
_NON_ALLOWLISTED_WITH_TYPE: dict[str, Any] = {"type": "mcp_stdio", **_NON_ALLOWLISTED}

#: What an operator actually registers: an allowlisted launcher, the benign shape
#: the other subprocess-arg modules use. Must pass, or the guard is a blunt
#: deny-all and useless to SimpleChat.
_BENIGN: dict[str, Any] = {"command": "uvx", "args": ["mcp-server-git", "--repo", "/srv/repo"]}

#: SimpleChat's realistic allowlist.
_ALLOWED = frozenset({"uvx"})


class TestTheStdioSpawnPrimitiveIsRefused:
    """The half agent-airlock reaches: a caller-chosen process is refused deny-by-default."""

    def test_non_allowlisted_command_is_denied(self) -> None:
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(
            _NON_ALLOWLISTED
        )
        assert decision.allowed is False
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND
        assert decision.matched_command == "placeholder-not-allowlisted"
        assert decision.matched_field == "command"

    def test_the_allowlisted_benign_config_passes(self) -> None:
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(_BENIGN)
        assert decision.verdict is McpSubprocessArgVerdict.ALLOW

    def test_empty_allowlist_denies_even_the_benign_config(self) -> None:
        # Deny-by-default: an operator who declares nothing gets nothing spawned.
        decision = McpSubprocessArgInjectionGuard().evaluate(_BENIGN)
        assert decision.allowed is False


class TestOmittingTheTypeDoesNotSkipTheGuard:
    """SimpleChat's exact move: strip the top-level ``type`` to skip inspection.

    The route's ``_reject_non_admin_mcp_stdio`` keyed off a ``type`` the caller
    could omit, so the inspection was skipped and the type restored afterward.
    agent-airlock's guard never reads a ``type`` field: it resolves the program
    from ``command`` / ``args``. So the same payload is refused whether or not the
    discriminator is present, which is the property SimpleChat's route lacked.
    """

    def test_refused_with_the_type_field_absent(self) -> None:
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(
            _NON_ALLOWLISTED
        )
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND

    def test_refused_with_the_type_field_present(self) -> None:
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(
            _NON_ALLOWLISTED_WITH_TYPE
        )
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND

    def test_the_verdict_is_identical_with_and_without_the_type(self) -> None:
        guard = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED)
        without = guard.evaluate(_NON_ALLOWLISTED)
        with_type = guard.evaluate(_NON_ALLOWLISTED_WITH_TYPE)
        assert without.verdict is with_type.verdict
        assert without.matched_command == with_type.matched_command == "placeholder-not-allowlisted"

    def test_a_bogus_type_does_not_rescue_a_non_allowlisted_command(self) -> None:
        decision = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED).evaluate(
            {"type": "not_stdio", **_NON_ALLOWLISTED}
        )
        assert decision.allowed is False


class TestScopeBoundary:
    """Pin the half agent-airlock does **not** reach: the route's authz ordering."""

    def test_the_guard_cannot_see_who_stored_the_action(self) -> None:
        """Identical configs, different submitters, same verdict.

        CVE-2026-105797 is that a low-privileged user may store this at all, by
        defeating an admin check that ran in the wrong order. The submitter is not
        in the spawn config, so the guard returns the same decision whoever sends
        it — which is why the fit says *partial*. SimpleChat 0.261.031 owns the
        ordering.
        """
        guard = McpSubprocessArgInjectionGuard(allowed_commands=_ALLOWED)
        verdicts = {
            guard.evaluate(cfg).verdict
            for cfg in (
                _BENIGN,
                {**_BENIGN, "stored_by": "low-privileged-user"},
                {**_BENIGN, "stored_by": "admin"},
            )
        }
        assert verdicts == {McpSubprocessArgVerdict.ALLOW}

    def test_preset_does_not_claim_this_cve(self) -> None:
        # The preset addresses CVE-2026-42271. It refuses this CVE's spawn config
        # without addressing the ordering defect, and must not say otherwise.
        preset = mcp_subprocess_arg_injection_guard_defaults()
        assert CVE not in preset["cves"]
        assert preset["cves"] == ("CVE-2026-42271",)


class TestWatcherAdmittedThisOnTheCweSignal:
    """CWE-78 carried it; CWE-863 is the out-of-scope authorization half."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-78"]) == "candidate"

    def test_the_authorization_cwe_alone_would_not_have(self) -> None:
        assert classify_shape("", ["CWE-863"]) == "triage-required"
