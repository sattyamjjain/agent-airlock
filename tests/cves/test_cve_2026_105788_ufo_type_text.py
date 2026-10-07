"""CVE-2026-105788 — Microsoft UFO mobile MCP type_text and launch_app injection.

Vulnerability (from NVD and GHSA-6ppj-5886-4f26):
    Prior to UFO 3.0.10, the ``type_text`` and ``launch_app`` tools in
    ``ufo/client/mcp/http_servers/mobile_mcp_server.py`` pass the authenticated
    caller-controlled ``text`` and ``package_name`` parameters into ``adb shell``
    command argument positions without comprehensive validation. The adb client
    joins those arguments into a remote command string that the Android shell
    reparses, letting shell metacharacters run additional commands as the Android
    shell user on an authorized connected device. Exploitation needs a valid
    Mobile MCP API key and a reachable authorized device; it does not reach the
    host OS, Android root, or beyond the shell user. Fixed in 3.0.10 (by quoting
    the adb arguments in the callee).

Advisory: https://github.com/microsoft/UFO/security/advisories/GHSA-6ppj-5886-4f26
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-105788
CVSS:     8.8 (HIGH) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H, CWE-78, CWE-88

Airlock fit: partial.
    Argument-shaped and authenticated, with no authorization half. The two
    parameters split on their *type*, and the sibling CVE-2026-105793 (press_key)
    is covered in ``test_cve_2026_105793_ufo_press_key.py``.

    **package_name has a narrow shape** — a dotted Android package name. A tool
    that declares it gets the separator refused by agent-airlock's strict
    validation, no new guard, the CVE-2025-68144 primitive. This fixture pins it.

    **text is free text by design.** No contract on the caller's side can make
    free text safe for a shell that reparses it: the field's whole purpose is to
    carry arbitrary characters, so a `str` accepts them, separator and all. That
    is not a gap in validation, it is the honest boundary of an argument contract,
    and the fix is the callee's quoting (UFO 3.0.10). The test below documents
    that boundary rather than asserting a refusal that would be wrong to expect.

    So the fit is *partial*: strict typing reaches ``package_name``, not ``text``.
"""

from __future__ import annotations

from typing import Annotated

import pytest
from pydantic import StringConstraints
from scripts.cve_watcher import classify_shape

from agent_airlock.core import Airlock

#: ``package_name``'s narrow legal shape: a dotted Android package name
#: (``com.example.app``). Declaring it is what lets strict validation refuse a
#: value carrying a shell separator.
PackageName = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
]

#: NVD's description, verbatim, so the classifier assertion is checked against the
#: real record rather than a paraphrase.
NVD_DESCRIPTION = (
    "Microsoft UFO is an open-source framework for intelligent automation across devices and "
    "platforms. Prior to 3.0.10, the type_text and launch_app tools in "
    "ufo/client/mcp/http_servers/mobile_mcp_server.py pass the authenticated caller-controlled "
    "text and package_name parameters into adb shell command argument positions without "
    "comprehensive validation. The adb client joins those arguments into a remote command "
    "string that the Android shell reparses, allowing shell metacharacters to execute "
    "additional commands on an authorized connected device as the Android shell user. "
    "Exploitation requires a valid Mobile MCP API key and a reachable device authorized for "
    "ADB, and it does not establish host operating-system execution, Android root execution, or "
    "access beyond the Android shell-user privileges. This issue is fixed in version 3.0.10."
)
NVD_CWES = ["CWE-78", "CWE-88"]

#: Separator plus a harmless marker; `echo ok` has no teeth because the point is
#: only the refusal of the shape.
_SEPARATOR_PAYLOADS: tuple[str, ...] = (
    "com.example.app; echo ok",
    "com.example.app && echo ok",
    "com.example.app | echo ok",
    "$(echo ok)",
)


def _launch_app() -> Airlock:
    @Airlock(return_dict=True)
    def launch_app(package_name: PackageName) -> str:
        return f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1"

    return launch_app  # type: ignore[return-value]


class TestStrictTypingRefusesTheSeparatorInPackageName:
    """The half agent-airlock reaches: a declared package_name shape refuses injection."""

    def test_accepts_a_dotted_package_name(self) -> None:
        result = _launch_app()(package_name="com.example.app")
        assert isinstance(result, dict)
        assert result.get("success") is True
        assert "com.example.app" in result.get("result", "")

    @pytest.mark.parametrize("payload", _SEPARATOR_PAYLOADS)
    def test_rejects_a_value_carrying_a_shell_separator(self, payload: str) -> None:
        result = _launch_app()(package_name=payload)
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"
        assert result.get("block_reason") == "validation_error"


class TestFreeTextIsTheCalleesQuotingNotTheContracts:
    """The honest boundary: a ``text`` field accepts free text, separator and all.

    This is not a refusal that regressed. ``type_text`` exists to send arbitrary
    characters to the device, so its argument contract is "any string". agent-
    airlock validates that the value is a string and admits it; the metacharacter
    is only dangerous once the callee hands it to a reparsing shell, which is where
    UFO 3.0.10 quotes it. Asserting a block here would be asserting the wrong fix.
    """

    def test_a_str_text_field_admits_a_separator_because_that_is_its_contract(self) -> None:
        @Airlock(return_dict=True)
        def type_text(text: str) -> str:
            return f"adb shell input text {text}"

        result = type_text(text="hello; echo ok")
        assert isinstance(result, dict)
        assert result.get("success") is True

    def test_plain_text_passes_too(self) -> None:
        @Airlock(return_dict=True)
        def type_text(text: str) -> str:
            return f"adb shell input text {text}"

        result = type_text(text="hello world")
        assert isinstance(result, dict)
        assert result.get("success") is True


class TestWatcherAdmittedThisOnTheCweSignal:
    """CWE-78 and CWE-88 are both argument-shaped; either files this."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_each_argument_shaped_cwe_alone_files_it(self) -> None:
        assert classify_shape("", ["CWE-78"]) == "candidate"
        assert classify_shape("", ["CWE-88"]) == "candidate"
