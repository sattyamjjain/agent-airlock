"""Guard: MCP spec-revision provenance stays honest (current vs legacy).

agent-airlock's mcp_spec guards target two MCP revisions. This pins the honest
statement of which is which so the module docstring, the ``SPEC_REVISIONS``
constant, and the README caveat cannot drift — including into an accidental
conformance claim:

* the negotiated ``MCP-Protocol-Version`` is the CURRENT ratified ``2026-07-28``
  (verified 2026-08-01: ``curl -o /dev/null -w '%{redirect_url}'
  https://modelcontextprotocol.io/specification/latest`` -> 307 to
  ``/specification/2026-07-28``; the versioning page states "The current protocol
  version is 2026-07-28"; the release is ``prerelease: false``, published
  2026-07-28T16:47:49Z);
* ``2025-11-25`` is recorded as ``legacy`` (the spec's own term for
  ``<= 2025-11-25``), still accepted on the wire for interop;
* the README still says these guards are NOT a conformance claim (no conformance
  suite has been run against this package).

Historical note (the irony worth recording): this file's prior revision
documented running exactly that ``/specification/latest`` redirect check and
asserting the OPPOSITE — that it resolved to ``2025-11-25`` and ``2026-07-28``
was a release candidate. The check was right; it just needed re-running. The
``2026-07-28`` release flipped to ``prerelease: false`` (published
2026-07-28T16:47:49Z) while the separate ``2026-07-28-RC`` tag stayed
``prerelease: true`` — the guard had pinned the RC tag.
"""

from __future__ import annotations

from pathlib import Path

from agent_airlock.mcp_spec import (
    PROTOCOL_VERSION,
    SPEC_REVISIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"


def test_protocol_version_is_the_current_ratified_revision() -> None:
    # The MCP-Protocol-Version header value is the current ratified revision.
    assert PROTOCOL_VERSION == "2026-07-28"


def test_spec_revisions_records_status() -> None:
    assert SPEC_REVISIONS["2026-07-28"] == "current"
    assert SPEC_REVISIONS["2025-11-25"] == "legacy"


def test_supported_versions_accept_current_and_legacy() -> None:
    # Newest first; both accepted on the wire.
    assert SUPPORTED_PROTOCOL_VERSIONS == ("2026-07-28", "2025-11-25")


def test_readme_keeps_no_conformance_claim_caveat() -> None:
    text = README.read_text(encoding="utf-8")
    # Stable phrases from the caveat above the OWASP MCP Top-10 table. The caveat
    # now states 2026-07-28 is the current ratified revision, but MUST keep
    # pinning that airlock makes no conformance claim.
    assert "not a conformance claim" in text, "README lost the no-conformance-claim caveat"
    assert "no MCP conformance suite has been run" in text, (
        "README lost the no-conformance-claim caveat"
    )
