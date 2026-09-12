"""CVE-2026-19753 — mcp-rdf-explorer explore_url takes an attacker-supplied URL into SSRF.

Vulnerability (NVD 2026-08-13):
    "A vulnerability was detected in Model Context Protocol mcp-rdf-explorer
    1.0.0. Affected is the function ``explore_url`` of the file ``src/index.ts``.
    Executing manipulation of the argument ``url`` can lead to server-side
    request forgery."

Advisory: https://nvd.nist.gov/vuln/detail/CVE-2026-19753
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-19753
CVSS:     7.3 (HIGH) — CWE-918

Airlock fit: strong.
    The defect is carried in a tool argument the caller supplies, named in the
    advisory, reaching an outbound fetch. That is the seam ``SSRFEgressGuard``
    sits on, and the guard refuses cloud metadata, loopback, link-local and
    IPv4-mapped-IPv6 targets while admitting a real SPARQL endpoint.

Why this file also exists as a watcher regression
-------------------------------------------------
    The interesting part is that **agent-airlock never saw this CVE**. Its
    triage watcher classified it ``triage-required`` and opened no issue, even
    though ``ssrf_egress_guard.py`` exists *because* of CVE-2026-47390, also
    CWE-918. The classifier keyed on CWE and on a sink-word list that had no
    term for "the argument is the defect".

    The fix, in v0.9.1, was a sink word rather than promoting CWE-918: the two
    CWE-918 records in the watcher's pinned first queue (CVE-2026-18905,
    CVE-2026-77822) are IBM ContextForge **DNS rebinding**, where the supplied
    URL is legitimate and the network layer betrays it after validation. A human
    dispositioned both out of scope and was right. See ``TestSsrfArgumentShape``
    in ``tests/test_cve_watcher.py`` for both directions; this file covers the
    guard, that one covers the triage.
"""

from __future__ import annotations

import pytest

from agent_airlock.ssrf_egress_guard import SSRFEgressGuard

#: Targets ``explore_url`` must not be talked into fetching.
_BLOCKED: tuple[tuple[str, str], ...] = (
    ("aws_imds", "http://169.254.169.254/latest/meta-data/"),
    ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
    ("loopback_admin", "http://127.0.0.1:8080/admin"),
    ("ipv4_mapped_imds", "http://[::ffff:169.254.169.254]/"),
    ("private_rfc1918", "http://10.0.0.5/internal"),
)

#: The tool's legitimate purpose: fetching public RDF/SPARQL endpoints.
_ALLOWED: tuple[tuple[str, str], ...] = (
    ("dbpedia", "https://dbpedia.org/sparql"),
    ("wikidata", "https://query.wikidata.org/sparql"),
)


class TestExploreUrlSsrfTargetsAreRefused:
    @pytest.mark.parametrize(("name", "url"), _BLOCKED)
    def test_blocked(self, name: str, url: str) -> None:
        decision = SSRFEgressGuard().check_url(url)
        assert decision.verdict != "allow", f"{name} must not be fetchable: {decision}"

    @pytest.mark.parametrize(("name", "url"), _ALLOWED)
    def test_the_tool_still_works(self, name: str, url: str) -> None:
        """A guard that blocks the tool's whole purpose is not a fix."""
        assert SSRFEgressGuard().check_url(url).verdict == "allow", name


class TestTheWatcherCanNowSeeThisShape:
    """The gap that let this CVE go unfiled, pinned at the triage layer.

    Kept in this file as well as in ``tests/test_cve_watcher.py`` because the
    two assert different things: there, that the classifier's verdict is right;
    here, that the classifier's verdict and the guard's coverage **agree**. A
    CVE this library refuses should not be one its own triage drops.
    """

    def test_the_advisory_text_classifies_as_a_candidate(self) -> None:
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from scripts.cve_watcher import classify_shape

        description = (
            "A vulnerability was detected in Model Context Protocol mcp-rdf-explorer "
            "1.0.0. Affected is the function explore_url of the file src/index.ts. "
            "Executing manipulation of the argument url can lead to server-side "
            "request forgery."
        )
        assert classify_shape(description, ("CWE-918",)) == "candidate"
