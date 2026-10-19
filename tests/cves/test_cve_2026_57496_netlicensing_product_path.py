"""CVE-2026-57496 — NetLicensing MCP splices product_number into a REST path, no segment check.

Vulnerability (from NVD and the upstream fix, retrieved 2026-10-19):
    NetLicensing MCP Server (Labs64) before 0.1.8: ``netlicensing_get_product`` passes
    the caller-controlled ``product_number`` into a REST path (consumed by ``nl_get()``)
    without path-segment validation. A traversal segment normalizes the intended product
    path onto the ``/token`` endpoint, whose response is serialized through ``_wrap_json``
    instead of ``_wrap_json_token_read`` — bypassing ``redact_token_read()`` and leaking
    plaintext APIKEY ``number`` and SHOP ``shopURL`` token values. A non-administrative
    API key can thereby recover an administrative token. Fixed in 0.1.8.

Advisory: https://github.com/Labs64/NetLicensing-MCP/security/advisories/GHSA-hxpf-9xvq-wph8
Fix:      https://github.com/Labs64/NetLicensing-MCP/commit/b8fd0ea76d533202573eb24add9fb2fbd9331496
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-57496
CVSS:     9.6 (CRITICAL) — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N
CWE:      CWE-22

Airlock fit: partial.
    The traversal rides in the ``product_number`` argument — the seam this library sits
    on — so ``SafePathValidator``, the same primitive that answers the git_init
    traversal (CVE-2025-68143), refuses any ``product_number`` carrying a ``..`` segment
    before it can be interpolated into the REST path and normalized onto ``/token``. Its
    pre-resolution check is a substring test, so the ``..%2F`` slash-encoded form is
    refused too.

    Two honest boundaries, both because the argument is a **URL** path segment, not a
    filesystem path, and no URL-path-segment guard exists — by design, a filesystem-path
    validator must not URL-decode, or it would reject legitimate filenames containing a
    literal ``%``:

    - A **fully** percent-encoded segment (``%2e%2e%2f``) carries no literal ``..`` and
      passes; whether it then traverses depends on the downstream HTTP layer, which is
      out of a filesystem-path validator's reach. ``TestScopeBoundary`` pins it.
    - The redaction bypass itself (``_wrap_json`` vs ``_wrap_json_token_read``) is
      server-side and structurally invisible here.

    The complete fix is the upstream path-segment validation in 0.1.8. This is a
    second-defence regression fixture against an existing primitive, not a new guard.
"""

from __future__ import annotations

import pytest
from scripts.cve_watcher import classify_shape

from agent_airlock.safe_types import SafePathValidationError, SafePathValidator

CVE = "CVE-2026-57496"

#: NVD's description, verbatim, so the classifier assertions below are checked against
#: the real record rather than a paraphrase of it.
NVD_DESCRIPTION = (
    "NetLicensing MCP Server is a natural-language interface that enables agentic "
    "applications to manage the software-licensing lifecycle in Labs64 NetLicensing. "
    "Prior to 0.1.8, netlicensing_get_product passes the caller-controlled "
    "product_number to src/netlicensing_mcp/tools/products.py, which interpolates it "
    "into a REST path consumed by nl_get() in src/netlicensing_mcp/client.py without "
    "path-segment validation. A traversal segment can be normalized from the intended "
    "product path to the /token endpoint, after which the response is serialized "
    "through _wrap_json instead of _wrap_json_token_read, bypassing redact_token_read() "
    "protections for APIKEY number and SHOP shopURL fields. An authenticated MCP client "
    "with a non-administrative API key can retrieve plaintext token values, and a "
    "recovered administrative token can provide broad read, write, and delete access to "
    "the NetLicensing account. This issue is fixed in version 0.1.8."
)

#: NVD's CWE. CWE-22 is **not** in ``ARGUMENT_SHAPED_CWES`` — see the watcher class below.
NVD_CWES = ["CWE-22"]

# Legitimate product numbers: safe relative identifiers the tool exists to look up.
BENIGN = ("P-DEMO-001", "PMGR-2026-0007", "demo-product")

# The exploit shape — a traversal segment in `product_number` that redirects the product
# path onto `/token`. `../token` is the real redirect; the AIRLOCK_MARKER variants are
# harmless placeholders, and `..%2F` is the slash-encoded form NVD's "normalized" covers.
TRAVERSALS = (
    "../token",
    "../AIRLOCK_MARKER",
    "../../token",
    "..%2FAIRLOCK_MARKER",
    "~/AIRLOCK_MARKER",
)


class TestTheTraversalSegmentIsRefused:
    """A `product_number` carrying `..` is refused before it reaches the REST path."""

    @pytest.mark.parametrize("product_number", BENIGN)
    def test_a_legitimate_product_number_passes(self, product_number: str) -> None:
        assert str(SafePathValidator()(product_number)) == product_number

    @pytest.mark.parametrize("product_number", TRAVERSALS)
    def test_a_traversal_product_number_is_refused(self, product_number: str) -> None:
        with pytest.raises(SafePathValidationError):
            SafePathValidator()(product_number)


class TestScopeBoundary:
    """What a filesystem-path validator cannot reach on a URL path segment, and why."""

    def test_a_fully_percent_encoded_segment_passes(self) -> None:
        # `%2e%2e%2f` carries no literal `..`, so the pre-resolution substring check does
        # not see it. URL-decoding it belongs to the HTTP layer, not to a filesystem-path
        # validator (which must not decode `%`, or it would reject real filenames). The
        # complete fix is the upstream path-segment validation in 0.1.8.
        assert str(SafePathValidator()("%2e%2e%2fAIRLOCK_MARKER")) == "%2e%2e%2fAIRLOCK_MARKER"


class TestWatcherAdmittedThisOnTheSinkWord:
    """CWE-22 did not file this; the word "interpolat" in the description did.

    Path-traversal CWEs are deliberately **not** in ``ARGUMENT_SHAPED_CWES`` — most
    CWE-22 in this ecosystem are server-side file reads the tool-call boundary never
    sees. What made this record a candidate is the sink word in "interpolates it into a
    REST path", which names a caller argument reaching a sink.
    """

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_description_alone_files_it(self) -> None:
        # "interpolat(es)" is the sink word that admitted this record.
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_would_not_have_filed_it(self) -> None:
        # CWE-22 is not argument-shaped by this module's definition.
        assert classify_shape("", ["CWE-22"]) == "triage-required"
