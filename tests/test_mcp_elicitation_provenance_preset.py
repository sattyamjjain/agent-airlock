"""MCP 2026-07-28 elicitation provenance preset (SEP-2260, v0.8.54+).

SEP-2260 makes any unsolicited server→client request invalid: a server may only raise an
elicitation within an active client-initiated request window. This preset is the
provenance (the *when*) axis, complementary to the shipped content classifier
`mcp_elicitation_guard_2026_04` (the *what*). **SEP-2260 is a spec id, not a CVE.**
"""

from __future__ import annotations

import inspect

import pytest

from agent_airlock.mcp_spec.elicitation_provenance import (
    ElicitationProvenanceError,
    RequestWindow,
    begin_client_request,
    check_elicitation_solicited,
    client_request_window,
    end_client_request,
)
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


class TestJsonRpcIdTypesStayApart:
    """0.10.32: ``7`` and ``"7"`` are two requests.

    The window keyed ids by ``str()``, so both shared one slot: ending ``"7"`` closed the window
    while ``7`` still ran, and an elicitation claiming ``"7"`` passed while only ``7`` was in
    flight. The same coercion as modelcontextprotocol/python-sdk#3807 (there the dispatcher's
    in-flight table, where cancelling one id cancels the other).
    """

    def test_ending_the_string_leaves_the_integer_running(self) -> None:
        window = RequestWindow()
        begin_client_request(window, 7)
        begin_client_request(window, "7")
        end_client_request(window, "7")
        assert window.is_open
        assert check_elicitation_solicited(window, request_id=7) is None
        with pytest.raises(ElicitationProvenanceError) as exc:
            check_elicitation_solicited(window, request_id="7")
        assert exc.value.audit_event["reason"] == "foreign_request_window"

    def test_ending_the_integer_leaves_the_string_running(self) -> None:
        window = RequestWindow()
        begin_client_request(window, 7)
        begin_client_request(window, "7")
        end_client_request(window, 7)
        assert window.is_open
        assert check_elicitation_solicited(window, request_id="7") is None
        with pytest.raises(ElicitationProvenanceError) as exc:
            check_elicitation_solicited(window, request_id=7)
        assert exc.value.audit_event["reason"] == "foreign_request_window"

    @pytest.mark.parametrize(("running", "claimed"), [(7, "7"), ("7", 7), (0, "0"), (-1, "-1")])
    def test_one_type_does_not_solicit_for_the_other(
        self, running: object, claimed: object
    ) -> None:
        """The fail-open half: until 0.10.32 a claim on the twin passed."""
        window = RequestWindow()
        begin_client_request(window, running)  # type: ignore[arg-type]
        with pytest.raises(ElicitationProvenanceError) as exc:
            check_elicitation_solicited(window, request_id=claimed)  # type: ignore[arg-type]
        assert exc.value.audit_event["reason"] == "foreign_request_window"
        assert exc.value.audit_event["request_id"] == claimed

    def test_the_same_id_twice_is_one_slot(self) -> None:
        window = RequestWindow()
        begin_client_request(window, "7")
        begin_client_request(window, "7")
        end_client_request(window, "7")
        assert not window.is_open

    def test_the_window_holds_ids_as_they_were_sent(self) -> None:
        window = RequestWindow()
        begin_client_request(window, 7)
        begin_client_request(window, "7")
        assert window.active == {7, "7"}
        assert RequestWindow().active == set()
        assert not RequestWindow().is_open

    def test_ending_an_id_that_never_began_is_still_a_no_op(self) -> None:
        window = RequestWindow()
        begin_client_request(window, 7)
        end_client_request(window, "7")
        end_client_request(window, 8)
        assert window.active == {7}

    def test_the_context_manager_keeps_the_type(self) -> None:
        window = RequestWindow()
        begin_client_request(window, "7")
        with client_request_window(window, 7):
            assert check_elicitation_solicited(window, request_id=7) is None
        assert window.active == {"7"}

    def test_the_preset_takes_either_type(self) -> None:
        preset = _preset()
        window = preset["new_window"]()
        preset["begin_request"](window, 7)
        assert preset["check_solicited"](window, request_id=7) is None
        preset["end_request"](window, 7)
        assert not window.is_open


#: Not a string or an integer. ``True == 1`` and ``7.0 == 7`` hash alike, so without a refusal
#: the first two kinds would land in an integer's slot; the rest have no JSON-RPC id reading.
BAD_IDS = [True, False, 7.0, 1.5, float("nan"), b"7", ["7"], {"id": 7}, (7,), object()]


class TestAnIdThatIsNotAStringOrIntegerIsRefused:
    @pytest.mark.parametrize("bad", BAD_IDS)
    def test_begin(self, bad: object) -> None:
        window = RequestWindow()
        with pytest.raises(ElicitationProvenanceError) as exc:
            begin_client_request(window, bad)  # type: ignore[arg-type]
        assert exc.value.audit_event["reason"] == "invalid_request_id"
        assert exc.value.audit_event["request_id"] is None
        assert exc.value.audit_event["request_id_type"] == type(bad).__name__
        assert not window.is_open

    def test_begin_refuses_null_which_mcp_forbids(self) -> None:
        window = RequestWindow()
        with pytest.raises(ElicitationProvenanceError) as exc:
            begin_client_request(window, None)  # type: ignore[arg-type]
        assert exc.value.audit_event["reason"] == "invalid_request_id"
        assert not window.is_open

    @pytest.mark.parametrize("bad", BAD_IDS)
    def test_end_closes_nothing(self, bad: object) -> None:
        window = RequestWindow()
        begin_client_request(window, 1)
        begin_client_request(window, 7)
        with pytest.raises(ElicitationProvenanceError) as exc:
            end_client_request(window, bad)  # type: ignore[arg-type]
        assert exc.value.audit_event["reason"] == "invalid_request_id"
        assert window.active == {1, 7}

    @pytest.mark.parametrize(("running", "claimed"), [(1, True), (0, False), (7, 7.0), (1, 1.0)])
    def test_a_bool_or_float_does_not_claim_an_integers_slot(
        self, running: int, claimed: object
    ) -> None:
        """Python reads ``True in {1}`` as True: dropping ``str()`` alone would let this pass."""
        window = RequestWindow()
        begin_client_request(window, running)
        with pytest.raises(ElicitationProvenanceError) as exc:
            check_elicitation_solicited(window, request_id=claimed)  # type: ignore[arg-type]
        assert exc.value.audit_event["reason"] == "invalid_request_id"

    def test_check_refuses_it_on_a_closed_window_too(self) -> None:
        with pytest.raises(ElicitationProvenanceError) as exc:
            check_elicitation_solicited(RequestWindow(), request_id=True)  # type: ignore[arg-type]
        assert exc.value.audit_event["reason"] == "invalid_request_id"

    def test_no_claim_at_all_is_still_allowed_in_an_open_window(self) -> None:
        window = RequestWindow()
        begin_client_request(window, 7)
        assert check_elicitation_solicited(window) is None
        assert check_elicitation_solicited(window, request_id=None) is None

    def test_the_context_manager_never_opens(self) -> None:
        window = RequestWindow()
        with pytest.raises(ElicitationProvenanceError), client_request_window(window, True):  # type: ignore[arg-type]
            pytest.fail("the body of a refused window must not run")
        assert not window.is_open

    def test_the_refusal_is_a_value_error(self) -> None:
        with pytest.raises(ValueError, match="string or an integer"):
            begin_client_request(RequestWindow(), 7.0)  # type: ignore[arg-type]

    def test_an_id_whose_repr_raises_is_refused_cleanly(self) -> None:
        class Hostile:
            def __repr__(self) -> str:
                raise RuntimeError("no repr")

        with pytest.raises(ElicitationProvenanceError) as exc:
            begin_client_request(RequestWindow(), Hostile())  # type: ignore[arg-type]
        assert exc.value.audit_event["request_id_type"] == "Hostile"


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
