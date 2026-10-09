"""CVE-2026-104120 — modelcontextprotocol mcp-server-fetch fetch_url SSRF.

Vulnerability (from NVD / VulDB):
    modelcontextprotocol ``mcp-server-fetch`` and ``mcp-server-everything`` up to
    2026.6.4 expose a ``fetch_url`` tool (``mcp_server_fetch/server.py``) that
    takes a caller-supplied ``url`` / ``path`` and issues the request without
    restricting the destination. Manipulating that argument to point at a cloud
    metadata endpoint, loopback, or an RFC1918 host reaches internal resources —
    server-side request forgery, remotely, with a publicly disclosed exploit.
    **No fixed release existed when this was catalogued:** the fix pull request
    (modelcontextprotocol/servers#4890) awaited acceptance as of 2026-10-09, so
    for this CVE the second defence is the only one there is.

Advisory: https://github.com/modelcontextprotocol/servers/issues/4492
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-104120
CVSS:     7.3 (HIGH) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L, CWE-918

Airlock fit: strong.
    SSRF via a ``url`` argument is the documented in-scope shape
    (``docs/cve-triage.md``, "SSRF via a URL argument", anchored on
    CVE-2026-26118). The fetch tool's whole input *is* the destination, so the
    contract is a destination filter:
    :class:`~agent_airlock.ssrf_egress_guard.SSRFEgressGuard` refuses the
    dangerous ones — cloud metadata, loopback, link-local, RFC1918, and a public
    name that resolves or rebinds to any of them — on the **resolved IP**, while
    allowing a genuine public fetch, which is the tool's legitimate purpose.

    An existing guard already refuses the shape, so this is a **second-defence
    regression fixture against that guard, not a new guard** — the CVE-2026-47390
    pattern, one layer up on the tool's ``url`` argument. The preset's ``cves``
    tuple is deliberately **not** extended to name this CVE: it claims the CVE it
    was built for (CVE-2026-47390) and refuses this one's payload without
    claiming it.
"""

from __future__ import annotations

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock import SSRFEgressGuard, SSRFEgressVerdict
from agent_airlock.policy_presets import ssrf_egress_guard_defaults

CVE = "CVE-2026-104120"

#: NVD's description, verbatim, so the classifier assertions below are checked
#: against the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "A security vulnerability has been detected in modelcontextprotocol mcp-server-fetch and "
    "mcp-server-everything up to 2026.6.4. Affected is the function fetch_url of the file "
    "mcp_server_fetch/server.py of the component Fetch Tool. The manipulation of the argument "
    "url/path leads to server-side request forgery. The attack may be initiated remotely. The "
    "exploit has been disclosed publicly and may be used. The pull request to fix this issue "
    "awaits acceptance."
)
NVD_CWES = ["CWE-918"]


def _guard(**kw: object) -> SSRFEgressGuard:
    """SSRFEgressGuard with no live DNS, so literal-IP cases never touch the network.

    A resolver that refuses every name means a stray hostname can only pass by
    being a literal IP the guard classifies directly — never by an accidental
    system-resolver lookup in CI.
    """
    kw.setdefault("resolver", lambda h: (_ for _ in ()).throw(OSError("no dns in test")))
    return SSRFEgressGuard(**kw)  # type: ignore[arg-type]


#: The destinations a ``fetch_url`` caller can aim the ``url`` argument at, each a
#: literal IP so the verdict is about the destination class, not DNS. All are
#: internal and must be refused.
_SSRF_DESTINATIONS: tuple[tuple[str, str, SSRFEgressVerdict], ...] = (
    ("aws_imds", "http://169.254.169.254/latest/meta-data/", SSRFEgressVerdict.DENY_METADATA),
    ("loopback_v4", "http://127.0.0.1:8080/admin", SSRFEgressVerdict.DENY_LOOPBACK),
    ("loopback_v6", "http://[::1]/", SSRFEgressVerdict.DENY_LOOPBACK),
    ("rfc1918", "http://10.0.0.1/internal", SSRFEgressVerdict.DENY_PRIVATE),
    ("link_local", "http://169.254.1.1/", SSRFEgressVerdict.DENY_LINK_LOCAL),
)


class TestFetchUrlSsrfDestinationsRefused:
    """The in-scope primitive: the ``url`` argument's dangerous destinations are refused."""

    @pytest.mark.parametrize(
        ("label", "url", "verdict"), _SSRF_DESTINATIONS, ids=[d[0] for d in _SSRF_DESTINATIONS]
    )
    def test_each_internal_destination_is_denied(
        self, label: str, url: str, verdict: SSRFEgressVerdict
    ) -> None:
        decision = _guard().check_url(url)
        assert decision.allowed is False, label
        assert decision.verdict is verdict, label

    def test_the_url_argument_is_refused_by_the_arg_scan(self) -> None:
        """Modelled as the tool's argument: ``check`` scans the ``url`` field and denies."""
        decision = _guard().check({"url": "http://169.254.169.254/latest/meta-data/"})
        assert decision.allowed is False
        assert decision.verdict is SSRFEgressVerdict.DENY_METADATA


class TestTheFetchToolsLegitimatePurposeStillWorks:
    """Precision: a destination filter that blocked every fetch would be useless."""

    def test_a_public_url_is_allowed(self) -> None:
        guard = SSRFEgressGuard(resolver=lambda h: ["93.184.216.34"])
        assert guard.check_url("http://example.com/page.html").allowed is True

    def test_a_public_name_that_rebinds_to_metadata_is_denied_on_the_resolved_ip(self) -> None:
        # A fetch tool is handed hostnames, so the guard must judge the resolved
        # IP, not the innocuous literal string.
        guard = SSRFEgressGuard(resolver=lambda h: ["169.254.169.254"])
        decision = guard.check_url("http://totally-legit.example/")
        assert decision.allowed is False
        assert decision.verdict is SSRFEgressVerdict.DENY_METADATA


class TestPresetDoesNotClaimThisCve:
    """Second defence against the existing guard: it refuses, it does not claim."""

    def test_preset_refuses_the_metadata_fetch(self) -> None:
        from agent_airlock import SSRFEgressBlocked

        with pytest.raises(SSRFEgressBlocked):
            ssrf_egress_guard_defaults()["check"]("http://169.254.169.254/latest/meta-data/")

    def test_preset_does_not_name_this_cve(self) -> None:
        preset = ssrf_egress_guard_defaults()
        assert CVE not in preset["cves"]
        assert preset["cves"] == ("CVE-2026-47390",)


class TestWatcherAdmittedThisOnTheSinkSignal:
    """Why this record reached a human, pinned in both directions.

    CWE-918 is **not** in ``ARGUMENT_SHAPED_CWES`` — deliberately, because the two
    CWE-918 records in the watcher's first queue were DNS-rebinding TOCTOU, which
    is out of scope. What admitted this one is the sink phrase ``manipulation of
    the argument``, VulDB's NVD wording that names the defective parameter. Drop
    that phrase from the sink list and this record would have classified
    ``triage-required`` and opened no issue.
    """

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_cwe_alone_would_not_have_filed_it(self) -> None:
        assert classify_shape("", ["CWE-918"]) == "triage-required"

    def test_the_sink_phrase_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"
