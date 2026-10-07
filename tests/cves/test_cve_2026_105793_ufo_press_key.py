"""CVE-2026-105793 — Microsoft UFO mobile MCP press_key argument injection.

Vulnerability (from NVD and GHSA-5cjx-4375-4877):
    Prior to UFO 3.0.9, the ``press_key`` tool in
    ``ufo/client/mcp/http_servers/mobile_mcp_server.py`` accepts a free-form
    ``key_code`` parameter and passes it to ``adb shell input keyevent``. The adb
    client joins the arguments into a remote command string that the Android
    shell reparses, letting an authenticated Mobile MCP caller run additional
    commands as the Android shell user on an authorized connected device.
    Exploitation needs a valid ``UFO_MCP_API_KEY``, adb on the host, and a
    reachable authorized device; it does not reach the host OS, Android root, or
    beyond the shell user. Fixed in 3.0.9 (by quoting the adb arguments in the
    callee).

Advisory: https://github.com/microsoft/UFO/security/advisories/GHSA-5cjx-4375-4877
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-105793
CVSS:     9.1 (CRITICAL) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L, CWE-78

Airlock fit: partial.
    Argument-shaped and authenticated, with no authorization half: the key_code
    value is the whole defect. What decides the outcome is the argument's *type*.

    **Out of scope: the reparsing shell.** That ``adb shell`` rejoins its
    arguments and the Android shell reparses them is a property of the callee, and
    the fix is to quote there, which UFO shipped in 3.0.9. A contract layer on the
    caller's side cannot change how a remote shell splits a string it is handed.

    **In scope: the argument's shape.** ``key_code`` has a narrow legal form, an
    Android keycode name or number. A tool that *declares* that shape gets the
    separator rejected by agent-airlock's strict validation with no new guard and
    no preset, which is the CVE-2025-68144 (git flag-shaped ref) primitive. This
    fixture pins that: a decorated ``press_key`` whose ``key_code`` is
    ``int | KEYCODE_...`` accepts a real keycode and refuses one carrying a shell
    separator. It is a second defence contingent on the schema the vulnerable tool
    did not declare, which is why the fit is *partial* rather than *strong*.
"""

from __future__ import annotations

from typing import Annotated

import pytest
from pydantic import StringConstraints
from scripts.cve_watcher import classify_shape

from agent_airlock.core import Airlock

#: ``key_code``'s narrow legal shape: an Android keycode name (``KEYCODE_HOME``)
#: or a bare numeric code (``3``). A tool author declaring this is what lets
#: strict validation refuse anything else.
KeyName = Annotated[str, StringConstraints(pattern=r"^KEYCODE_[A-Z0-9_]+$")]
KeyCode = int | KeyName

#: NVD's description, verbatim, so the classifier assertion is checked against the
#: real record rather than a paraphrase.
NVD_DESCRIPTION = (
    "Microsoft UFO is an open-source framework for intelligent automation across devices and "
    "platforms. Prior to 3.0.9, the press_key tool in "
    "ufo/client/mcp/http_servers/mobile_mcp_server.py accepts a free-form key_code parameter "
    "and passes it to `adb shell input keyevent`. The adb client joins the arguments into a "
    "remote command string that the Android shell reparses, allowing an authenticated Mobile "
    "MCP caller to execute additional commands as the Android shell user on an authorized "
    "connected device. Exploitation requires a valid UFO_MCP_API_KEY, adb on the host, and a "
    "reachable authorized device, and it does not establish host operating-system execution, "
    "Android root execution, or access beyond the Android shell-user privileges. This issue is "
    "fixed in version 3.0.9."
)
NVD_CWES = ["CWE-78"]

#: A separator followed by a harmless marker. The marker is `echo ok`, not a
#: destructive command: the point is only that strict validation refuses the
#: shape, so the payload needs no teeth.
_SEPARATOR_PAYLOADS: tuple[str, ...] = (
    "KEYCODE_HOME; echo ok",
    "KEYCODE_HOME && echo ok",
    "3; echo ok",
    "$(echo ok)",
)


def _press_key() -> Airlock:
    @Airlock(return_dict=True)
    def press_key(key_code: KeyCode) -> str:
        return f"adb shell input keyevent {key_code}"

    return press_key  # type: ignore[return-value]


class TestStrictTypingRefusesTheSeparator:
    """The half agent-airlock reaches: a declared key_code shape refuses injection."""

    def test_accepts_a_keycode_name(self) -> None:
        result = _press_key()(key_code="KEYCODE_HOME")
        assert isinstance(result, dict)
        assert result.get("success") is True
        assert result.get("result") == "adb shell input keyevent KEYCODE_HOME"

    def test_accepts_a_numeric_keycode(self) -> None:
        result = _press_key()(key_code=3)
        assert isinstance(result, dict)
        assert result.get("success") is True
        assert result.get("result") == "adb shell input keyevent 3"

    @pytest.mark.parametrize("payload", _SEPARATOR_PAYLOADS)
    def test_rejects_a_value_carrying_a_shell_separator(self, payload: str) -> None:
        result = _press_key()(key_code=payload)
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"
        assert result.get("block_reason") == "validation_error"


class TestTheReparsingShellIsOutOfReach:
    """The half that is the callee's: the string split happens after the call."""

    def test_a_free_form_key_code_would_pass_this_layer(self) -> None:
        """Declare key_code as a bare str and the separator sails through.

        This is the vulnerable tool's own shape: UFO took key_code as free text.
        The contract layer can only refuse what the schema narrows, so the fix for
        a tool that declines to narrow it is the callee's quoting (UFO 3.0.9), not
        anything expressible here.
        """

        @Airlock(return_dict=True)
        def press_key_freeform(key_code: str) -> str:
            return f"adb shell input keyevent {key_code}"

        result = press_key_freeform(key_code="KEYCODE_HOME; echo ok")
        assert isinstance(result, dict)
        assert result.get("success") is True


class TestWatcherAdmittedThisOnTheCweSignal:
    """CWE-78 is argument-shaped; it is what filed this."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-78"]) == "candidate"
