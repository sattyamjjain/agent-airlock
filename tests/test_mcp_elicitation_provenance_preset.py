"""MCP 2026-07-28 elicitation provenance preset (SEP-2260, v0.8.54+).

SEP-2260 makes any unsolicited server→client request invalid: a server may only raise an
elicitation within an active client-initiated request window. This preset is the
provenance (the *when*) axis, complementary to the shipped content classifier
`mcp_elicitation_guard_2026_04` (the *what*). **SEP-2260 is a spec id, not a CVE.**
"""

from __future__ import annotations

import inspect

import pytest

from agent_airlock.mcp_spec.elicitation_provenance import ElicitationProvenanceError, RequestWindow
from agent_airlock.policy_presets import (
    MCP_ELICITATION_PROVENANCE_2026_07,
    list_active,
    mcp_elicitation_guard_2026_04,
    mcp_elicitation_provenance_2026_07_defaults,
)


def _preset():
    return mcp_elicitation_provenance_2026_07_defaults()


class TestOutOfWindowDenied:
    def test_unsolicited_elicitation_denied(self) -> None:
        preset = _preset()
        window = preset["new_window"]()
        with pytest.raises(ElicitationProvenanceError) as exc:
            preset["check_solicited"](window, server_origin="github")
        assert exc.value.audit_event["event"] == "mcp.elicitation_provenance.refuse"
        assert exc.value.audit_event["reason"] == "unsolicited_elicitation"

    def test_elicitation_after_window_closed_denied(self) -> None:
        preset = _preset()
        window = preset["new_window"]()
        preset["begin_request"](window, "req-1")
        preset["end_request"](window, "req-1")
        with pytest.raises(ElicitationProvenanceError) as exc:
            preset["check_solicited"](window, server_origin="github")
        assert exc.value.audit_event["reason"] == "unsolicited_elicitation"

    def test_foreign_request_window_denied(self) -> None:
        preset = _preset()
        window = preset["new_window"]()
        preset["begin_request"](window, "req-1")
        with pytest.raises(ElicitationProvenanceError) as exc:
            preset["check_solicited"](window, request_id="req-999", server_origin="github")
        assert exc.value.audit_event["reason"] == "foreign_request_window"


class TestInWindowAllowed:
    def test_elicitation_inside_active_window_allowed(self) -> None:
        preset = _preset()
        window = preset["new_window"]()
        preset["begin_request"](window, "req-1")
        assert preset["check_solicited"](window, request_id="req-1", server_origin="github") is None

    def test_context_manager_window(self) -> None:
        preset = _preset()
        window = preset["new_window"]()
        with preset["request_window"](window, "req-2"):
            assert (
                preset["check_solicited"](window, request_id="req-2", server_origin="jira") is None
            )
        # After the context exits the window is closed → unsolicited again.
        with pytest.raises(ElicitationProvenanceError):
            preset["check_solicited"](window, server_origin="jira")


class TestComposesWithContentGuard:
    def test_content_classifier_preset_still_works(self) -> None:
        # The provenance guard (the WHEN) is complementary to the content classifier
        # (the WHAT) — the existing preset is untouched and still constructs.
        content = mcp_elicitation_guard_2026_04()
        assert content["preset_id"] == "mcp_elicitation_guard_2026_04"
        assert content["default_action"] == "block"


class TestPresetMetadata:
    def test_canonical_metadata(self) -> None:
        p = _preset()
        assert p["preset_id"] == "mcp_elicitation_provenance_2026_07"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-2260"
        assert p["owasp"] == "MCP07"
        assert p["provenance_error"] is ElicitationProvenanceError
        assert callable(p["new_window"]) and callable(p["check_solicited"])

    def test_named_constant_matches_factory(self) -> None:
        assert (
            MCP_ELICITATION_PROVENANCE_2026_07["preset_id"] == "mcp_elicitation_provenance_2026_07"
        )

    def test_new_window_type(self) -> None:
        assert isinstance(_preset()["new_window"](), RequestWindow)

    def test_cites_sep_2260_not_cve(self) -> None:
        src = inspect.getsource(mcp_elicitation_provenance_2026_07_defaults)
        assert "SEP-2260" in src
        assert "CVE-" not in src

    def test_discoverable_via_list_active(self) -> None:
        assert "mcp_elicitation_provenance_2026_07_defaults" in {m.preset_id for m in list_active()}
